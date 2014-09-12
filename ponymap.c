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

#define DEFAULT_CONNECT_TIMEOUT  10
#define DEFAULT_SCAN_TIMEOUT     10

static struct config_item g_config_table[] =
{
	// TODO: set the default to the installation directory
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

	struct unit *running_units;         ///< All the currently running units
	// TODO: some fields with results
};

enum transport_io_result
{
	TRANSPORT_IO_OK = 0,                ///< Completed successfully
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
	enum transport_io_result (*on_readable) (struct unit *u);
	/// The underlying socket may have become writeable, flush `write_buffer';
	/// return false if the connection has failed.
	enum transport_io_result (*on_writeable) (struct unit *u);
	/// Return event mask to use for the poller
	int (*get_poll_events) (struct unit *u);
};

struct unit
{
	LIST_HEADER (unit)
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
	unsigned connect_timeout;           ///< Hard timeout for connect()
	unsigned scan_timeout;              ///< Hard timeout for service scans

	struct str_map svc_list;            ///< List of services to scan for
	struct port_range *port_list;       ///< List of ports to scan on
	struct ip_range *ip_list;           ///< List of IP's to scan

	struct str_map services;            ///< All registered services
	struct transport *transports;       ///< All available transports
	struct job_generator generator;     ///< Job generator

	SSL_CTX *ssl_ctx;                   ///< OpenSSL context
#if 0
	struct target *running_targets;     ///< List of currently scanned targets
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

	self->connect_timeout = DEFAULT_CONNECT_TIMEOUT;
	self->scan_timeout = DEFAULT_SCAN_TIMEOUT;

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

static void target_unref (struct target *self);
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
unit_abort (struct unit *u)
{
	if (u->aborted)
		return;

	u->aborted = true;
	u->service->on_aborted (u->service_data, u);
}

static void
unit_destroy (struct unit *u)
{
	LIST_UNLINK (u->target->running_units, u);
	target_unref (u->target);

	// TODO: transfer the results?
	free (u);
}

static void
on_unit_ready (const struct pollfd *pfd, struct unit *u)
{
	struct transport *transport = u->transport;
	struct service *service = u->service;
	enum transport_io_result result;

	if ((result = transport->on_readable (u)))
		goto exception;
	if (u->read_buffer.len)
	{
		struct str *buf = &u->read_buffer;
		service->on_data (u->service_data, u, buf);
		str_remove_slice (buf, 0, buf->len);

		if (u->aborted)
			return;
	}

	if (!(result = transport->on_writeable (u)))
	{
		if (!u->aborted)
			unit_update_poller (u, pfd);
		return;
	}

exception:
	if (result == TRANSPORT_IO_EOF)
		service->on_eof (u->service_data, u);
	else if (result == TRANSPORT_IO_ERROR)
		service->on_error (u->service_data, u);

	unit_abort (u);
	unit_destroy (u);
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
	// TODO: abort and kill all units
	try_finish_quit (ctx);
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
	unit_abort (u);
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

static enum transport_io_result
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
			return TRANSPORT_IO_EOF;

		if (errno == EAGAIN)
			return TRANSPORT_IO_OK;
		if (errno == EINTR)
			continue;

		print_debug ("%s: %s: %s", __func__, "recv", strerror (errno));
		return TRANSPORT_IO_ERROR;
	}
}

static enum transport_io_result
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
			return TRANSPORT_IO_OK;
		if (errno == EINTR)
			continue;

		print_debug ("%s: %s: %s", __func__, "send", strerror (errno));
		return TRANSPORT_IO_ERROR;
	}
	return TRANSPORT_IO_OK;
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

static enum transport_io_result
transport_tls_on_readable (struct unit *u)
{
	struct transport_tls_data *data = u->transport_data;
	if (data->ssl_tx_want_rx)
		return TRANSPORT_IO_OK;

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
			return TRANSPORT_IO_EOF;
		case SSL_ERROR_WANT_READ:
			return true;
		case SSL_ERROR_WANT_WRITE:
			data->ssl_rx_want_tx = true;
			return true;
		case XSSL_ERROR_TRY_AGAIN:
			continue;
		default:
			print_debug ("%s: %s: %s", __func__, "SSL_read", error_info);
			return TRANSPORT_IO_ERROR;
		}
	}
}

static enum transport_io_result
transport_tls_on_writeable (struct unit *u)
{
	struct transport_tls_data *data = u->transport_data;
	if (data->ssl_rx_want_tx)
		return TRANSPORT_IO_OK;

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
			return TRANSPORT_IO_EOF;
		case SSL_ERROR_WANT_WRITE:
			return TRANSPORT_IO_OK;
		case SSL_ERROR_WANT_READ:
			data->ssl_tx_want_rx = true;
			return TRANSPORT_IO_OK;
		case XSSL_ERROR_TRY_AGAIN:
			continue;
		default:
			print_debug ("%s: %s: %s", __func__, "SSL_write", error_info);
			return TRANSPORT_IO_ERROR;
		}
	}
	return TRANSPORT_IO_OK;
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

	// TODO: present the results; if we've been interrupted by the user,
	//   say that they're only partial

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

static void
on_unit_connected (const struct pollfd *pfd, struct unit *u)
{
	// TODO: we haven't received the connect event
	//   -> reset the connect timer
	//   -> set the scan timer
	unit_update_poller (u, NULL);
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

	bool established;
	if (!connect (sockfd, (struct sockaddr *) &addr, sizeof addr))
		established = true;
	else if (errno == EINPROGRESS)
		established = false;
	else
		return false;

	struct unit *u = xcalloc (1, sizeof *u);
	// TODO: set a timer for timeout: established ? scan : connect

	// Initialize the service
	u->service = service;
	u->service_data = service->scan_init (u);

	// Initialize the transport
	u->transport = transport;
	if (!transport->init (u))
	{
		xclose (sockfd);
		service->scan_free (u->service_data);
		free (u);
		return false;
	}

	if (established)
		unit_update_poller (u, NULL);
	else
		poller_set (&u->target->ctx->poller, u->socket_fd, POLLOUT,
			(poller_dispatcher_func) on_unit_connected, u);
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

// --- Option handler ----------------------------------------------------------

// Simple wrapper for the getopt_long API to make it easier to use and maintain.

#define OPT_USAGE_ALIGNMENT_COLUMN 30   ///< Alignment for option descriptions

enum
{
	OPT_OPTIONAL_ARG  = (1 << 0),       ///< The argument is optional
	OPT_LONG_ONLY     = (1 << 1)        ///< Ignore the short name in opt_string
};

// All options need to have both a short name, and a long name.  The short name
// is what is returned from opt_handler_get().  It is possible to define a value
// completely out of the character range combined with the OPT_LONG_ONLY flag.
//
// When `arg_hint' is defined, the option is assumed to have an argument.

struct opt
{
	int short_name;                     ///< The single-letter name
	const char *long_name;              ///< The long name
	const char *arg_hint;               ///< Option argument hint
	int flags;                          ///< Option flags
	const char *description;            ///< Option description
};

struct opt_handler
{
	int argc;                           ///< The number of program arguments
	char **argv;                        ///< Program arguments

	const char *arg_hint;               ///< Program arguments hint
	const char *description;            ///< Description of the program

	const struct opt *opts;             ///< The list of options
	size_t opts_len;                    ///< The length of the option array

	struct option *options;             ///< The list of options for getopt
	char *opt_string;                   ///< The `optstring' for getopt
};

static void
opt_handler_free (struct opt_handler *self)
{
	free (self->options);
	free (self->opt_string);
}

static void
opt_handler_init (struct opt_handler *self, int argc, char **argv,
	const struct opt *opts, const char *arg_hint, const char *description)
{
	memset (self, 0, sizeof *self);
	self->argc = argc;
	self->argv = argv;
	self->arg_hint = arg_hint;
	self->description = description;

	size_t len = 0;
	for (const struct opt *iter = opts; iter->long_name; iter++)
		len++;

	self->opts = opts;
	self->opts_len = len;
	self->options = xcalloc (len + 1, sizeof *self->options);

	struct str opt_string;
	str_init (&opt_string);

	for (size_t i = 0; i < len; i++)
	{
		const struct opt *opt = opts + i;
		struct option *mapped = self->options + i;

		mapped->name = opt->long_name;
		if (!opt->arg_hint)
			mapped->has_arg = no_argument;
		else if (opt->flags & OPT_OPTIONAL_ARG)
			mapped->has_arg = optional_argument;
		else
			mapped->has_arg = required_argument;
		mapped->val = opt->short_name;

		if (opt->flags & OPT_LONG_ONLY)
			continue;

		str_append_c (&opt_string, opt->short_name);
		if (opt->arg_hint)
		{
			str_append_c (&opt_string, ':');
			if (opt->flags & OPT_OPTIONAL_ARG)
				str_append_c (&opt_string, ':');
		}
	}

	self->opt_string = str_steal (&opt_string);
}

static void
opt_handler_usage (struct opt_handler *self)
{
	struct str usage;
	str_init (&usage);

	str_append_printf (&usage, "Usage: %s [OPTION]... %s\n",
		self->argv[0], self->arg_hint ? self->arg_hint : "");
	str_append_printf (&usage, "%s\n\n", self->description);

	for (size_t i = 0; i < self->opts_len; i++)
	{
		struct str row;
		str_init (&row);

		const struct opt *opt = self->opts + i;
		if (!(opt->flags & OPT_LONG_ONLY))
			str_append_printf (&row, "  -%c, ", opt->short_name);
		else
			str_append (&row, "      ");
		str_append_printf (&row, "--%s", opt->long_name);
		if (opt->arg_hint)
			str_append_printf (&row, (opt->flags & OPT_OPTIONAL_ARG)
				? " [%s]" : " %s", opt->arg_hint);

		if (row.len + 2 <= OPT_USAGE_ALIGNMENT_COLUMN)
		{
			str_append (&row, "  ");
			str_append_printf (&usage, "%-*s%s\n",
				OPT_USAGE_ALIGNMENT_COLUMN, row.str, opt->description);
		}
		else
			str_append_printf (&usage, "%s\n%-*s%s\n", row.str,
				OPT_USAGE_ALIGNMENT_COLUMN, "", opt->description);

		str_free (&row);
	}

	fputs (usage.str, stderr);
	str_free (&usage);
}

static int
opt_handler_get (struct opt_handler *self)
{
	return getopt_long (self->argc, self->argv,
		self->opt_string, self->options, NULL);
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
		initiate_quit (ctx);
}

static void
parse_program_arguments (struct app_context *ctx, int argc, char **argv)
{
	static const struct opt opts[] =
	{
		{ 'd', "debug", NULL, 0, "run in debug mode" },
		{ 'h', "help", NULL, 0, "display this help and exit" },
		{ 'V', "version", NULL, 0, "output version information and exit" },
		{ 'p', "ports", "PORTS", 0,
		  "ports/port ranges, separated by commas" },
		{ 's', "service", "SERVICES", 0,
		  "services to scan for, separated by commas" },
		{ 't', "connect-timeout", "TIMEOUT", 0,
		  "timeout for connect, in seconds"
		  " (default: " XSTRINGIFY (DEFAULT_CONNECT_TIMEOUT) ")" },
		{ 'T', "scan-timeout", "TIMEOUT", 0,
		  "timeout for service scans, in seconds"
		  " (default: " XSTRINGIFY (DEFAULT_SCAN_TIMEOUT) ")" },
		{ 'w', "write-default-cfg", "FILENAME",
		  OPT_OPTIONAL_ARG | OPT_LONG_ONLY,
		  "write a default configuration file and exit" },
		{ 0, NULL, NULL, 0, NULL }
	};

	struct opt_handler oh;
	opt_handler_init (&oh, argc, argv, opts,
		"{ ADDRESS [/MASK] }...", "Experimental network scanner.");

	int c;
	while ((c = opt_handler_get (&oh)) != -1)
	{
		switch (c)
		{
			unsigned long ul;
		case 'd':
			g_debug_mode = true;
			break;
		case 'h':
			opt_handler_usage (&oh);
			exit (EXIT_SUCCESS);
		case 'V':
			printf (PROGRAM_NAME " " PROGRAM_VERSION "\n");
			exit (EXIT_SUCCESS);
		case 'p':
			if (!list_foreach (optarg, (list_foreach_fn) add_port_range, ctx))
				exit (EXIT_FAILURE);
			break;
		case 's':
			if (!list_foreach (optarg, (list_foreach_fn) add_service, ctx))
				exit (EXIT_FAILURE);
			break;
		case 't':
			if (!xstrtoul (&ul, optarg, 10) || !ul)
			{
				print_error ("invalid value for %s", "connect timeout");
				exit (EXIT_FAILURE);
			}
			ctx->connect_timeout = ul;
			break;
		case 'T':
			if (!xstrtoul (&ul, optarg, 10) || !ul)
			{
				print_error ("invalid value for %s", "scan timeout");
				exit (EXIT_FAILURE);
			}
			ctx->scan_timeout = ul;
			break;
		case 'w':
			call_write_default_config (optarg, g_config_table);
			exit (EXIT_SUCCESS);
		default:
			print_error ("wrong options");
			opt_handler_usage (&oh);
			exit (EXIT_FAILURE);
		}
	}

	argc -= optind;
	argv += optind;

	if (!argc)
	{
		opt_handler_usage (&oh);
		exit (EXIT_FAILURE);
	}

	for (int i = 0; i < argc; i++)
		if (!add_target (ctx, argv[i]))
			exit (EXIT_FAILURE);

	opt_handler_free (&oh);
}

int
main (int argc, char *argv[])
{
	struct app_context ctx;
	app_context_init (&ctx);
	parse_program_arguments (&ctx, argc, argv);

	setup_signal_handlers ();

	SSL_library_init ();
	atexit (EVP_cleanup);
	SSL_load_error_strings ();
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
