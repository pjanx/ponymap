/*
 * ponymap.c: the experimental network scanner
 *
 * Copyright (c) 2014, Přemysl Janouch <p.janouch@gmail.com>
 * All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */

#include "utils.c"
#include "plugin-api.h"
#include <dirent.h>
#include <dlfcn.h>

// --- Configuration (application-specific) ------------------------------------

static struct config_item g_config_table[] =
{
	{ "plugin_dir",      NULL,              "Where to search for plugins"    },
	{ NULL,              NULL,              NULL                             }
};

// --- Application data --------------------------------------------------------

// The scan is a cartesian product of: [IP ranges] -> [ports] -> [services]

struct port_range
{
	LIST_HEADER (port_range)
	uint16_t start;                     ///< The beginning of the range
	uint16_t end;                       ///< The end of the range
};

static void
port_range_delete (struct port_range *self)
{
	free (self);
}

struct ip_range
{
	LIST_HEADER (ip_range)
	uint32_t start;                     ///< The beginning of the range
	uint32_t end;                       ///< The end of the range

	char *original_name;                ///< The name the user typed in
	uint32_t original_address;          ///< The address of `original_name'
};

static void
ip_range_delete (struct ip_range *self)
{
	free (self->original_name);
	free (self);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

struct target
{
	LIST_HEADER (target)
	size_t ref_count;                   ///< Reference count

	struct app_context *ctx;            ///< Application context

	uint32_t ip;                        ///< IP address
	char *hostname;                     ///< Hostname

	// TODO: some fields with results
	// XXX: what is the relation to `struct unit'?
};

// TODO: actually use this
enum transport_io_result
{
	TRANSPORT_IO_OK,                    ///< Completed successfully
	TRANSPORT_IO_EOF,                   ///< Connection shut down by peer
	TRANSPORT_IO_ERROR                  ///< Connection error
};

// The only real purpose of this is to abstract away TLS/SSL
struct transport
{
	LIST_HEADER (transport)

	const char *name;                   ///< Name of the transport

	/// Initialize the transport
	bool (*init) (struct unit *u);
	/// Destroy the user data pointer
	void (*cleanup) (struct unit *u);

	/// The underlying socket may have become readable, update `read_buffer';
	/// return false if the connection has failed.
	bool (*on_readable) (struct unit *u);
	/// The underlying socket may have become writeable, flush `write_buffer';
	/// return false if the connection has failed.
	bool (*on_writeable) (struct unit *u);
	/// Return event mask to use for the poller
	int (*get_poll_events) (struct unit *u);
};

struct unit
{
	struct target *target;              ///< Target context

	struct service *service;            ///< Service
	void *service_data;                 ///< User data for service

	struct transport *transport;        ///< Transport methods
	void *transport_data;               ///< User data for transport

	int socket_fd;                      ///< The TCP socket
	struct str read_buffer;             ///< Unprocessed input
	struct str write_buffer;            ///< Output yet to be sent out

	bool aborted;                       ///< Scan has been aborted
	bool success;                       ///< Service has been found
	struct str_vector info;             ///< Info resulting from the scan
};

static void
unit_init (struct unit *self)
{
	memset (self, 0, sizeof *self);

	str_init (&self->read_buffer);
	str_init (&self->write_buffer);
	str_vector_init (&self->info);
}

static void
unit_free (struct unit *self)
{
	str_free (&self->read_buffer);
	str_free (&self->write_buffer);
	str_vector_free (&self->info);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

struct job_generator
{
	struct ip_range *ip_range_iter;     ///< Current IP range
	uint32_t ip_iter;                   ///< IP iterator within the range
	struct target *current_target;      ///< Current target

	struct port_range *port_range_iter; ///< Current port range
	uint16_t port_iter;                 ///< Port iterator within the range

	struct str_map_iter svc_iter;       ///< Service iterator
	struct service *svc;                ///< Current service iterator value

	struct transport *transport_iter;   ///< Transport iterator
};

struct app_context
{
	struct str_map config;              ///< User configuration

	struct str_map svc_list;            ///< List of services to scan for
	struct port_range *port_list;       ///< List of ports to scan on
	struct ip_range *ip_list;           ///< List of IP's to scan

	struct str_map services;            ///< All registered services
	struct transport *transports;       ///< All available transports
	struct job_generator generator;     ///< Job generator

	SSL_CTX *ssl_ctx;                   ///< OpenSSL context
#if 0
	struct target *running_list;        ///< List of currently scanned targets
#endif
	struct poller poller;               ///< Manages polled descriptors
	bool quitting;                      ///< User requested quitting
	bool polling;                       ///< The event loop is running
};

static void
app_context_init (struct app_context *self)
{
	memset (self, 0, sizeof *self);

	str_map_init (&self->config);
	self->config.free = free;
	load_config_defaults (&self->config, g_config_table);

	str_map_init (&self->svc_list);
	str_map_init (&self->services);
	// Ignoring the generator so far

	poller_init (&self->poller);
	self->quitting = false;
	self->polling = false;
}

static void
app_context_free (struct app_context *self)
{
	str_map_free (&self->config);
	str_map_free (&self->svc_list);
	poller_free (&self->poller);

	for (struct ip_range *iter = self->ip_list; iter; )
	{
		struct ip_range *next = iter->next;
		ip_range_delete (iter);
		iter = next;
	}

	for (struct port_range *iter = self->port_list; iter; )
	{
		struct port_range *next = iter->next;
		port_range_delete (iter);
		iter = next;
	}

	if (self->ssl_ctx)
		SSL_CTX_free (self->ssl_ctx);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static void
try_finish_quit (struct app_context *ctx)
{
	if (ctx->quitting)
		ctx->polling = false;
}

static void
initiate_quit (struct app_context *ctx)
{
	ctx->quitting = true;
	try_finish_quit (ctx);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static void on_unit_ready (const struct pollfd *pfd, struct unit *u);

static void
unit_update_poller (struct unit *u, const struct pollfd *pfd)
{
	int new_events = u->transport->get_poll_events (u);
	hard_assert (new_events != 0);

	if (!pfd || pfd->events != new_events)
		poller_set (&u->target->ctx->poller, u->socket_fd, new_events,
			(poller_dispatcher_func) on_unit_ready, u);
}

static void
on_unit_ready (const struct pollfd *pfd, struct unit *u)
{
	struct transport *transport = u->transport;
	struct service *service = u->service;

	if (!transport->on_readable (u))
		; // TODO: cancel the unit
	if (u->read_buffer.len)
	{
		struct str *buf = &u->read_buffer;
		service->on_data (u->service_data, u, buf);
		str_remove_slice (buf, 0, buf->len);
	}

	// TODO: check if the unit has been aborted?
	if (!transport->on_writeable (u))
		; // TODO: cancel the unit

	unit_update_poller (u, pfd);
	return;

abort:
	// TODO: move to a function, guard against `aborted' in the API
	u->aborted = true;
	service->on_aborted (u->service_data, u);
}

// --- Signals -----------------------------------------------------------------

static int g_signal_pipe[2];            ///< A pipe used to signal... signals

/// Program termination has been requested by a signal
static volatile sig_atomic_t g_termination_requested;

static void
sigterm_handler (int signum)
{
	(void) signum;

	g_termination_requested = true;

	int original_errno = errno;
	if (write (g_signal_pipe[1], "t", 1) == -1)
		soft_assert (errno == EAGAIN);
	errno = original_errno;
}

static void
setup_signal_handlers (void)
{
	if (pipe (g_signal_pipe) == -1)
		exit_fatal ("%s: %s", "pipe", strerror (errno));

	set_cloexec (g_signal_pipe[0]);
	set_cloexec (g_signal_pipe[1]);

	// So that the pipe cannot overflow; it would make write() block within
	// the signal handler, which is something we really don't want to happen.
	// The same holds true for read().
	set_blocking (g_signal_pipe[0], false);
	set_blocking (g_signal_pipe[1], false);

	signal (SIGPIPE, SIG_IGN);

	struct sigaction sa;
	sa.sa_flags = SA_RESTART;
	sigemptyset (&sa.sa_mask);
	sa.sa_handler = sigterm_handler;
	if (sigaction (SIGINT, &sa, NULL) == -1
	 || sigaction (SIGTERM, &sa, NULL) == -1)
		exit_fatal ("sigaction: %s", strerror (errno));
}

// --- Plugins -----------------------------------------------------------------

static void
plugin_api_register_service (void *app_context, struct service *info)
{
	struct app_context *ctx = app_context;
	if (str_map_find (&ctx->services, info->name))
		print_error ("attempt to re-register duplicate service `%s'",
			info->name);
	else
		str_map_set (&ctx->services, info->name, info);
}

static ssize_t
plugin_api_unit_write (struct unit *u, const void *buf, size_t len)
{
	if (u->aborted)
		return -1;

	str_append_data (&u->write_buffer, buf, len);
	return len;
}

static void
plugin_api_unit_set_success (struct unit *u, bool success)
{
	u->success = success;
}

static void
plugin_api_unit_add_info (struct unit *u, const char *result)
{
	str_vector_add (&u->info, result);
}

static void
plugin_api_unit_abort (struct unit *u)
{
	// TODO
}

static struct plugin_api g_plugin_vtable =
{
	.register_service  = plugin_api_register_service,
	.unit_write        = plugin_api_unit_write,
	.unit_set_success  = plugin_api_unit_set_success,
	.unit_add_info     = plugin_api_unit_add_info,
	.unit_abort        = plugin_api_unit_abort
};

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static bool
load_one_plugin (struct app_context *ctx, const char *name, const char *path)
{
	void *table = dlopen (path, RTLD_LAZY | RTLD_LOCAL);
	if (!table)
	{
		print_error ("could not load `%s': %s", name, dlerror ());
		return false;
	}

	struct plugin_info *info = dlsym (table, "ponymap_plugin_info");
	if (!info)
		print_error ("could not load `%s': %s",
			name, "cannot find plugin info");
	else if (info->api_version != API_VERSION)
		print_error ("could not load `%s': %s",
			name, "cannot find plugin info");
	else if (!info->initialize (ctx, &g_plugin_vtable))
		print_error ("could not load `%s': %s",
			name, "plugin initialization failed");
	else
		return true;

	dlclose (table);
	return false;
}

static bool
load_plugins (struct app_context *ctx)
{
	const char *plugin_dir = str_map_find (&ctx->config, "plugin_dir");
	if (!plugin_dir)
	{
		print_fatal ("no plugin directory defined");
		return false;
	}

	DIR *dir = opendir (plugin_dir);
	if (!dir)
	{
		print_fatal ("%s: %s",
			"cannot open plugin directory", strerror (errno));
		return false;
	}

	bool success = false;
	struct dirent buf, *iter;
	while (true)
	{
		if (readdir_r (dir, &buf, &iter))
		{
			print_fatal ("%s: %s", "readdir_r", strerror (errno));
			break;
		}
		if (!iter)
		{
			success = true;
			break;
		}

		char *dot = strrchr (iter->d_name, '.');
		if (dot && !strcmp (dot, ".so"))
			continue;

		char *path = xstrdup_printf ("%s/%s", plugin_dir, iter->d_name);
		(void) load_one_plugin (ctx, iter->d_name, path);
		free (path);
	}
	closedir (dir);
	return success;
}

// --- Plain transport ---------------------------------------------------------

static bool
transport_plain_init (struct unit *u)
{
	(void) u;
	return true;
}

static void
transport_plain_cleanup (struct unit *u)
{
	(void) u;
}

static bool
transport_plain_on_readable (struct unit *u)
{
	struct str *buf = &u->read_buffer;
	ssize_t n_read;

	while (true)
	{
		str_ensure_space (buf, 512);
		n_read = recv (u->socket_fd, buf->str + buf->len,
			buf->alloc - buf->len - 1 /* null byte */, 0);

		if (n_read > 0)
		{
			buf->str[buf->len += n_read] = '\0';
			continue;
		}
		if (n_read == 0)
			// TODO: service->on_eof()
			return false;

		if (errno == EAGAIN)
			return true;
		if (errno == EINTR)
			continue;

		// TODO: service->on_error()
		print_debug ("%s: %s: %s", __func__, "recv", strerror (errno));
		return false;
	}
}

static bool
transport_plain_on_writeable (struct unit *u)
{
	struct str *buf = &u->write_buffer;
	ssize_t n_written;

	while (buf->len)
	{
		n_written = send (u->socket_fd, buf->str, buf->len, 0);
		if (n_written >= 0)
		{
			str_remove_slice (buf, 0, n_written);
			continue;
		}

		if (errno == EAGAIN)
			return true;
		if (errno == EINTR)
			continue;

		// TODO: service->on_error()
		print_debug ("%s: %s: %s", __func__, "send", strerror (errno));
		return false;
	}
	return true;
}

static int
transport_plain_get_poll_events (struct unit *u)
{
	int events = POLLIN;
	if (u->write_buffer.len)
		events |= POLLOUT;
	return events;
}

static struct transport g_transport_plain =
{
	.name             = "plain",
	.init             = transport_plain_init,
	.cleanup          = transport_plain_cleanup,
	.on_readable      = transport_plain_on_readable,
	.on_writeable     = transport_plain_on_writeable,
	.get_poll_events  = transport_plain_get_poll_events,
};

// --- SSL/TLS transport -------------------------------------------------------

struct transport_tls_data
{
	SSL *ssl;                           ///< SSL/TLS connection
	bool ssl_rx_want_tx;                ///< SSL_read() wants to write
	bool ssl_tx_want_rx;                ///< SSL_write() wants to read
};

static bool
transport_tls_init (struct unit *u)
{
	SSL *ssl = SSL_new (u->target->ctx->ssl_ctx);
	if (!ssl || !SSL_set_fd (ssl, u->socket_fd))
	{
		const char *error_info = ERR_error_string (ERR_get_error (), NULL);
		print_debug ("%s: %s",
			"could not initialize SSL/TLS connection", error_info);
		SSL_free (ssl);
		return false;
	}
	SSL_set_connect_state (ssl);

	struct transport_tls_data *data = xcalloc (1, sizeof *data);
	data->ssl = ssl;
	u->transport_data = data;
	return true;
}

static void
transport_tls_cleanup (struct unit *u)
{
	struct transport_tls_data *data = u->transport_data;
	SSL_free (data->ssl);
	free (data);
}

static bool
transport_tls_on_readable (struct unit *u)
{
	struct transport_tls_data *data = u->transport_data;
	if (data->ssl_tx_want_rx)
		return true;

	struct str *buf = &u->read_buffer;
	data->ssl_rx_want_tx = false;
	while (true)
	{
		str_ensure_space (buf, 4096);
		int n_read = SSL_read (data->ssl, buf->str + buf->len,
			buf->alloc - buf->len - 1 /* null byte */);

		const char *error_info = NULL;
		switch (xssl_get_error (data->ssl, n_read, &error_info))
		{
		case SSL_ERROR_NONE:
			buf->str[buf->len += n_read] = '\0';
			continue;
		case SSL_ERROR_ZERO_RETURN:
			// TODO: service->on_eof()
			return false;
		case SSL_ERROR_WANT_READ:
			return true;
		case SSL_ERROR_WANT_WRITE:
			data->ssl_rx_want_tx = true;
			return true;
		case XSSL_ERROR_TRY_AGAIN:
			continue;
		default:
			print_debug ("%s: %s: %s", __func__, "SSL_read", error_info);
			// TODO: service->on_error()
			return false;
		}
	}
}

static bool
transport_tls_on_writeable (struct unit *u)
{
	struct transport_tls_data *data = u->transport_data;
	if (data->ssl_rx_want_tx)
		return true;

	struct str *buf = &u->write_buffer;
	data->ssl_tx_want_rx = false;
	while (buf->len)
	{
		int n_written = SSL_write (data->ssl, buf->str, buf->len);

		const char *error_info = NULL;
		switch (xssl_get_error (data->ssl, n_written, &error_info))
		{
		case SSL_ERROR_NONE:
			str_remove_slice (buf, 0, n_written);
			continue;
		case SSL_ERROR_ZERO_RETURN:
			// TODO: service->on_eof()
			return false;
		case SSL_ERROR_WANT_WRITE:
			return true;
		case SSL_ERROR_WANT_READ:
			data->ssl_tx_want_rx = true;
			return true;
		case XSSL_ERROR_TRY_AGAIN:
			continue;
		default:
			print_debug ("%s: %s: %s", __func__, "SSL_write", error_info);
			// TODO: service->on_error()
			return false;
		}
	}
	return true;
}

static int
transport_tls_get_poll_events (struct unit *u)
{
	struct transport_tls_data *data = u->transport_data;

	int events = POLLIN;
	if (u->write_buffer.len || data->ssl_rx_want_tx)
		events |= POLLOUT;

	// While we're waiting for an opposite event, we ignore the original
	if (data->ssl_rx_want_tx)  events &= ~POLLIN;
	if (data->ssl_tx_want_rx)  events &= ~POLLOUT;
	return events;
}

static struct transport g_transport_tls =
{
	.name             = "SSL/TLS",
	.init             = transport_tls_init,
	.cleanup          = transport_tls_cleanup,
	.on_readable      = transport_tls_on_readable,
	.on_writeable     = transport_tls_on_writeable,
	.get_poll_events  = transport_tls_get_poll_events,
};

static void
initialize_tls (struct app_context *ctx)
{
	SSL_CTX *ssl_ctx = SSL_CTX_new (SSLv23_client_method ());
	if (!ctx)
	{
		const char *error_info = ERR_error_string (ERR_get_error (), NULL);
		print_error ("%s: %s", "could not initialize SSL/TLS", error_info);
		return;
	}

	// Fuck off, we're just scanning
	SSL_CTX_set_verify (ctx->ssl_ctx, SSL_VERIFY_NONE, NULL);
	SSL_CTX_set_mode (ctx->ssl_ctx,
		SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

	ctx->ssl_ctx = ssl_ctx;
	LIST_PREPEND (ctx->transports, &g_transport_tls);
}

// --- Scanning ----------------------------------------------------------------

static void
target_unref (struct target *self)
{
	if (!self || --self->ref_count)
		return;

	free (self->hostname);
	free (self);
}

static void
job_generator_new_target (struct app_context *ctx)
{
	struct job_generator *g = &ctx->generator;

	struct target *target = xcalloc (1, sizeof *target);
	target_unref (g->current_target);
	g->current_target = target;

	target->ref_count = 1;
	target->ip = g->ip_iter;
	if (g->ip_iter == g->ip_range_iter->original_address)
		target->hostname = xstrdup (g->ip_range_iter->original_name);
}

static void
job_generator_init (struct app_context *ctx)
{
	struct job_generator *g = &ctx->generator;

	g->ip_range_iter = ctx->ip_list;
	g->ip_iter = g->ip_range_iter->start;
	g->current_target = NULL;
	job_generator_new_target (ctx);

	g->port_range_iter = ctx->port_list;
	g->port_iter = g->port_range_iter->start;

	str_map_iter_init (&g->svc_iter, &ctx->svc_list);
	g->svc = str_map_iter_next (&g->svc_iter);

	g->transport_iter = ctx->transports;
}

static bool
job_generator_run (struct app_context *ctx, uint32_t ip, uint16_t port,
	struct service *service, struct transport *transport)
{
	int sockfd = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
	set_blocking (sockfd, false);

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl (ip);
	addr.sin_port = htons (port);

	if (connect (sockfd, (struct sockaddr *) &addr, sizeof addr))
		return false;

	struct unit *u = xcalloc (1, sizeof *u);
	// TODO: set a timer for timeout

	// Initialize the service
	u->service = service;
	u->service_data = service->scan_init (u);

	// Initialize the transport
	u->transport = transport;
	if (!transport->init (u))
		// TODO: cleanup
		return false;

	unit_update_poller (u, NULL);
	return true;
}

static bool
job_generator_step (struct app_context *ctx)
{
	struct job_generator *g = &ctx->generator;

	// XXX: we're probably going to need a way to distinguish
	//   between "try again" and "stop trying".
	if (!g->ip_range_iter)
		return false;
	if (!job_generator_run (ctx,
		g->ip_iter, g->port_iter, g->svc, g->transport_iter))
		return false;

	// Try to find the next available transport
	while (true)
	{
		if (!(g->transport_iter = g->transport_iter->next))
			break;
		if (g->transport_iter == &g_transport_tls
		 && !(g->svc->flags & SERVICE_SUPPORTS_TLS))
			continue;
		return true;
	}
	g->transport_iter = ctx->transports;

	// Try to find the next service to scan for
	if ((g->svc = str_map_iter_next (&g->svc_iter)))
		return true;
	str_map_iter_init (&g->svc_iter, &ctx->svc_list);
	g->svc = str_map_iter_next (&g->svc_iter);

	// Try to find the next port to scan
	if (g->port_iter != UINT16_MAX && g->port_iter < g->port_range_iter->end)
	{
		g->port_iter++;
		return true;
	}
	g->port_range_iter = g->port_range_iter->next;
	if (g->port_range_iter)
	{
		g->port_iter = g->port_range_iter->start;
		return true;
	}
	g->port_range_iter = ctx->port_list;
	g->port_iter = g->port_range_iter->start;

	// Try to find the next IP to scan
	if (g->ip_iter != UINT32_MAX && g->ip_iter < g->ip_range_iter->end)
	{
		g->ip_iter++;
		return true;
	}
	g->ip_range_iter = g->ip_range_iter->next;
	if (g->ip_range_iter)
	{
		g->ip_iter = g->ip_range_iter->start;
		return true;
	}

	// No more jobs to be created
	return false;
}

// --- Main program ------------------------------------------------------------

typedef bool (*list_foreach_fn) (void *, const char *);

static bool
list_foreach (const char *list, list_foreach_fn callback, void *user_data)
{
	struct str_vector items;
	str_vector_init (&items);

	bool success = false;
	split_str_ignore_empty (list, ',', &items);
	for (size_t i = 0; i < items.len; i++)
		if (!callback (user_data, strip_str_in_place (items.vector[i], " ")))
			goto fail;

	success = true;
fail:
	str_vector_free (&items);
	return success;
}

static bool
parse_port (const char *port, uint16_t *out)
{
	unsigned long x;
	struct servent *service;

	if ((service = getservbyname (port, "tcp")))
		*out = ntohs (service->s_port);
	else if (xstrtoul (&x, port, 10) && x <= UINT16_MAX)
		*out = x;
	else
		return false;
	return true;
}

static bool
add_port_range (struct app_context *ctx, const char *range)
{
	uint16_t start_port, end_port;
	const char *hyphen = strchr (range, '-');
	if (hyphen)
	{
		char start[hyphen - range + 1];
		memcpy (start, range, sizeof range - 1);
		start[sizeof start - 1] = '\0';

		const char *end = hyphen + 1;

		if (!parse_port (start, &start_port)
		 || !parse_port (end, &end_port))
			goto fail;
	}
	else if (!parse_port (range, &start_port))
		goto fail;
	else
		end_port = start_port;

	if (start_port > end_port)
		goto fail;

	struct port_range *pr = xcalloc (1, sizeof *pr);
	pr->start = start_port;
	pr->end = end_port;
	LIST_PREPEND (ctx->port_list, pr);
	return true;

fail:
	print_error ("%s: `%s'", "invalid port range", range);
	return false;
}

static bool
add_service (struct app_context *ctx, const char *name)
{
	// To be resolved later
	str_map_set (&ctx->svc_list, name, (void *) name);
	return true;
}

static bool
add_target (struct app_context *ctx, const char *target)
{
	char host[strlen (target) + 1];
	strcpy (host, target);

	unsigned long mask = 32;
	char *slash = strchr (host, '/');
	if (slash)
	{
		*slash++ = '\0';
		if (!xstrtoul (&mask, slash, 10) || mask > 32)
		{
			print_error ("invalid network mask in `%s'", target);
			return false;
		}
	}

	struct addrinfo hints = { .ai_family = AF_INET };
	struct addrinfo *result;
	int err = getaddrinfo (target, NULL, &hints, &result);
	if (err)
	{
		print_error ("cannot resolve `%s': %s", host, gai_strerror (err));
		return false;
	}

	struct ip_range *range = xcalloc (1, sizeof *range);
	uint32_t bitmask = ~(((uint64_t) 1 << (32 - mask)) - 1);

	hard_assert (result->ai_family == AF_INET);
	hard_assert (result->ai_addr->sa_family == AF_INET);
	uint32_t addr = ntohl (((struct sockaddr_in *)
		result->ai_addr)->sin_addr.s_addr);
	range->start = addr & bitmask;
	range->end   = addr | bitmask;
	freeaddrinfo (result);

	range->original_name = xstrdup (host);
	range->original_address = addr;

	LIST_PREPEND (ctx->ip_list, range);
	return true;
}

static void
merge_port_ranges (struct app_context *ctx)
{
	// Make sure that no port is scanned twice
	struct port_range *i1, *i2, *i2_next;
	for (i1 = ctx->port_list; i1; i1 = i1->next)
	for (i2 = ctx->port_list; i2; i2 = i2_next)
	{
		i2_next = i2->next;
		if (i1 == i2 || i1->end < i2->start || i2->end < i1->start)
			continue;

		i1->start = MIN (i1->start, i2->start);
		i1->end = MAX (i1->end, i2->end);
		LIST_UNLINK (ctx->port_list, i2);
		free (i2);
	}
}

static void
merge_ip_ranges (struct app_context *ctx)
{
	// Make sure that no IP is scanned twice
	struct ip_range *i1, *i2, *i2_next;
	for (i1 = ctx->ip_list; i1; i1 = i1->next)
	for (i2 = ctx->ip_list; i2; i2 = i2_next)
	{
		i2_next = i2->next;
		if (i1 == i2 || i1->end < i2->start || i2->end < i1->start)
			continue;

		i1->start = MIN (i1->start, i2->start);
		i1->end = MAX (i1->end, i2->end);
		LIST_UNLINK (ctx->ip_list, i2);
		free (i2);
	}
}

static bool
resolve_service_names (struct app_context *ctx)
{
	struct str_map_iter iter;
	str_map_iter_init (&iter, &ctx->svc_list);
	const char *name;
	bool success = true;
	while ((name = str_map_iter_next (&iter)))
	{
		struct service *service;
		if ((service = str_map_find (&ctx->services, name)))
		{
			str_map_set (&ctx->svc_list, name, service);
			continue;
		}
		print_error ("unknown service `%s'", name);
		success = false;
	}
	return success;
}

static void
on_signal_pipe_readable (const struct pollfd *fd, struct app_context *ctx)
{
	char *dummy;
	(void) read (fd->fd, &dummy, 1);

	if (g_termination_requested && !ctx->quitting)
	{
		initiate_quit (ctx);
	}
}

static void
print_usage (const char *program_name)
{
	fprintf (stderr,
		"Usage: %s [OPTION]... { ADDRESS [/MASK] }...\n"
		"Experimental network scanner.\n"
		"\n"
		"  -d, --debug     run in debug mode\n"
		"  -h, --help      display this help and exit\n"
		"  -V, --version   output version information and exit\n"
		"  -p, --port PORTS\n"
		"                  ports/port ranges, separated by commas\n"
		"  -s, --service SERVICES\n"
		"                  services to scan for\n"
		"  --write-default-cfg [FILENAME]\n"
		"                  write a default configuration file and exit\n",
		program_name);
}

int
main (int argc, char *argv[])
{
	const char *invocation_name = argv[0];

	struct app_context ctx;
	app_context_init (&ctx);

	// TODO: timeout for connect()
	// TODO: timeout for fingerprint/whatever
	static struct option opts[] =
	{
		{ "debug",             no_argument,       NULL, 'd' },
		{ "help",              no_argument,       NULL, 'h' },
		{ "version",           no_argument,       NULL, 'V' },
		{ "port",              required_argument, NULL, 'p' },
		{ "service",           required_argument, NULL, 's' },
		{ "write-default-cfg", optional_argument, NULL, 'w' },
		{ NULL,                0,                 NULL,  0  }
	};

	while (1)
	{
		int c, opt_index;

		c = getopt_long (argc, argv, "dhVp:s:", opts, &opt_index);
		if (c == -1)
			break;

		switch (c)
		{
		case 'd':
			g_debug_mode = true;
			break;
		case 'h':
			print_usage (invocation_name);
			exit (EXIT_SUCCESS);
		case 'V':
			printf (PROGRAM_NAME " " PROGRAM_VERSION "\n");
			exit (EXIT_SUCCESS);
		case 'p':
			if (!list_foreach (optarg,
				(list_foreach_fn) add_port_range, &ctx))
				exit (EXIT_FAILURE);
			break;
		case 's':
			if (!list_foreach (optarg,
				(list_foreach_fn) add_service, &ctx))
				exit (EXIT_FAILURE);
			break;
		case 'w':
			call_write_default_config (optarg, g_config_table);
			exit (EXIT_SUCCESS);
		default:
			print_error ("wrong options");
			exit (EXIT_FAILURE);
		}
	}

	argc -= optind;
	argv += optind;

	if (!argc)
	{
		print_usage (invocation_name);
		exit (EXIT_FAILURE);
	}

	// Resolve all the scan targets
	for (int i = 0; i < argc; i++)
		if (!add_target (&ctx, argv[i]))
			exit (EXIT_FAILURE);

	setup_signal_handlers ();

	SSL_library_init ();
	atexit (EVP_cleanup);
	SSL_load_error_strings ();
	// XXX: ERR_load_BIO_strings()?  Anything else?
	atexit (ERR_free_strings);

	struct error *e = NULL;
	if (!read_config_file (&ctx.config, &e))
	{
		print_error ("error loading configuration: %s", e->message);
		error_free (e);
		exit (EXIT_FAILURE);
	}

	poller_set (&ctx.poller, g_signal_pipe[0], POLLIN,
		(poller_dispatcher_func) on_signal_pipe_readable, &ctx);

	if (!load_plugins (&ctx))
		exit (EXIT_FAILURE);

	LIST_PREPEND (ctx.transports, &g_transport_plain);
	initialize_tls (&ctx);

	if (!ctx.port_list)
	{
		struct port_range *range = xcalloc (1, sizeof *range);
		range->start = 1;  // port 0 is reserved, not bothering with it
		range->end = 65535;
		ctx.port_list = range;
	}

	if (!ctx.svc_list.len)
	{
		struct str_map_iter iter;
		str_map_iter_init (&iter, &ctx.services);
		struct service *service;
		while ((service = str_map_iter_next (&iter)))
			str_map_set (&ctx.svc_list, service->name, service);
	}
	else
	{
		// So far we've only stored service _names_ to the hash map;
		// let's try to resolve them to actual services.
		if (!resolve_service_names (&ctx))
			exit (EXIT_FAILURE);
	}

	merge_port_ranges (&ctx);
	merge_ip_ranges (&ctx);

	// TODO: initate the scan -> generate as many jobs as possible

	ctx.polling = true;
	while (ctx.polling)
		poller_run (&ctx.poller);

	app_context_free (&ctx);
	return EXIT_SUCCESS;
}
