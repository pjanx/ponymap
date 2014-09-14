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
#include <arpa/inet.h>

#include <curses.h>
#include <term.h>

#include <jansson.h>

// --- Configuration (application-specific) ------------------------------------

#define DEFAULT_CONNECT_TIMEOUT  10
#define DEFAULT_SCAN_TIMEOUT     10

static struct config_item g_config_table[] =
{
	// TODO: set the default to the installation directory
	{ "plugin_dir",      NULL,              "Where to search for plugins"    },
	{ NULL,              NULL,              NULL                             }
};

// --- Fancy terminal output ---------------------------------------------------

static struct
{
	bool initialized;                   ///< Terminal is available
	bool stdout_is_tty;                 ///< `stdout' is a terminal
	bool stderr_is_tty;                 ///< `stderr' is a terminal

	char *color_set[8];                 ///< Codes to set the foreground colour
}
g_terminal;

static void
init_terminal (void)
{
	int tty_fd = -1;
	if ((g_terminal.stderr_is_tty = isatty (STDERR_FILENO)))
		tty_fd = STDERR_FILENO;
	if ((g_terminal.stdout_is_tty = isatty (STDOUT_FILENO)))
		tty_fd = STDOUT_FILENO;

	if (tty_fd == -1 || setupterm (NULL, tty_fd, NULL) == ERR)
		return;

	// Make sure all terminal features used by us are supported
	if (!set_a_foreground || !orig_pair
	 || !enter_standout_mode || !exit_standout_mode
	 || !clr_bol || !cursor_left)
	{
		del_curterm (cur_term);
		return;
	}

	for (size_t i = 0; i < N_ELEMENTS (g_terminal.color_set); i++)
		g_terminal.color_set[i] = xstrdup (tparm (set_a_foreground,
			i, 0, 0, 0, 0, 0, 0, 0, 0));

	g_terminal.initialized = true;
}

static void
free_terminal (void)
{
	if (!g_terminal.initialized)
		return;

	for (size_t i = 0; i < N_ELEMENTS (g_terminal.color_set); i++)
		free (g_terminal.color_set[i]);
	del_curterm (cur_term);
}

typedef int (*terminal_printer_fn) (int);

static int
putchar_stderr (int c)
{
	return fputc (c, stderr);
}

static terminal_printer_fn
get_terminal_printer (FILE *stream)
{
	if (!g_terminal.initialized)
		return NULL;

	if (stream == stdout && g_terminal.stdout_is_tty)
		return putchar;
	if (stream == stderr && g_terminal.stderr_is_tty)
		return putchar_stderr;
	return NULL;
}

static void
print_color (FILE *stream, int color, const char *s)
{
	terminal_printer_fn printer = get_terminal_printer (stream);

	if (printer && color != -1)
		tputs (g_terminal.color_set[color], 1, printer);

	fputs (s, stream);

	if (printer && color != -1)
		tputs (orig_pair, 1, printer);
}

static void
print_bold (FILE *stream, const char *s)
{
	terminal_printer_fn printer = get_terminal_printer (stream);

	if (printer)
		tputs (enter_standout_mode, 1, printer);

	fputs (s, stream);

	if (printer)
		tputs (exit_standout_mode, 1, printer);
}

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

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

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

	/// All units that have ended, successfully finding a service.  These don't
	/// hold a reference to us as they're considered a part of this object;
	/// we hold a reference to them.
	struct unit *results;

	/// All currently running units for this target, holding a reference to us.
	/// They remove themselves from this list upon terminating.  The purpose of
	/// this list is making it possible to abort them forcefully.
	struct unit *running_units;
};

static struct target *target_ref (struct target *self);
static void target_unref (struct target *self);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

struct unit
{
	LIST_HEADER (unit)
	size_t ref_count;                   ///< Reference count
	struct target *target;              ///< Target context

	uint16_t port;                      ///< The scanned port

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

static struct unit *unit_ref (struct unit *self);
static void unit_unref (struct unit *self);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

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
	/// Return event mask to use in the poller
	int (*get_poll_events) (struct unit *u);
};

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

#define INDICATOR_INTERVAL  500

struct indicator
{
	unsigned position;                  ///< The current animation character
	const char *frames;                 ///< All the characters
	size_t frames_len;                  ///< The number of characters

	bool shown;                         ///< The indicator is shown on screen
	char *status;                       ///< The status text
};

static void
indicator_init (struct indicator *self)
{
	static const char frames[] = "-\\|/";
	self->position = 0;
	self->frames = frames;
	self->frames_len = sizeof frames - 1;

	self->status = NULL;
	self->shown = false;
}

static void
indicator_free (struct indicator *self)
{
	free (self->status);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

struct generator
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

	json_t *json_results;               ///< The results as a JSON value
	const char *json_filename;          ///< The filename to write JSON to

	SSL_CTX *ssl_ctx;                   ///< OpenSSL context

	struct str_map svc_list;            ///< List of services to scan for
	struct port_range *port_list;       ///< List of ports to scan on
	struct ip_range *ip_list;           ///< List of IP's to scan

	struct str_map services;            ///< All registered services
	struct transport *transports;       ///< All available transports
	struct generator generator;         ///< Unit generator
	struct indicator indicator;         ///< Status indicator

	struct target *running_targets;     ///< List of currently scanned targets

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
	indicator_init (&self->indicator);
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
	if (self->json_results)
		json_decref (self->json_results);
}

// --- Progress indicator ------------------------------------------------------

static void indicator_set_timer (struct app_context *ctx);

static void
on_indicator_tick (struct app_context *ctx)
{
	struct indicator *self = &ctx->indicator;
	if (!self->shown)
		return;

	// TODO: animate
	indicator_set_timer (ctx);
}

static void
indicator_set_timer (struct app_context *ctx)
{
	poller_timers_add (&ctx->poller.timers,
		(poller_timer_fn) on_indicator_tick, ctx, INDICATOR_INTERVAL);
}

static void
indicator_show (struct indicator *self)
{
	if (!g_terminal.initialized || !g_terminal.stdout_is_tty)
		return;

	// TODO
}

// --- Scan units --------------------------------------------------------------

static void on_unit_ready (const struct pollfd *pfd, struct unit *u);

static struct unit *
unit_ref (struct unit *self)
{
	self->ref_count++;
	return self;
}

static void
unit_unref (struct unit *self)
{
	if (!self || --self->ref_count)
		return;

	target_unref (self->target);

	str_free (&self->read_buffer);
	str_free (&self->write_buffer);
	str_vector_free (&self->info);

	free (self);
}

static void
unit_abort (struct unit *u)
{
	if (u->aborted)
		return;

	u->aborted = true;
	u->service->on_aborted (u->service_data, u);

	u->transport->cleanup (u);
	u->transport_data = NULL;

	u->service->scan_free (u->service_data);
	u->service_data = NULL;

	xclose (u->socket_fd);
	u->socket_fd = -1;

	// We're no longer running
	LIST_UNLINK (u->target->running_units, u);

	// Get rid of all timers
	struct poller *poller = &u->target->ctx->poller;
	ssize_t i;
	while ((i = poller_timers_find_by_data (&poller->timers, u)) != -1)
		poller_timers_remove_at_index (&poller->timers, i);

	if (u->success)
	{
		// Now we're a part of the target
		LIST_PREPEND (u->target->results, u);
		target_unref (u->target);
		u->target = NULL;
	}
	else
		unit_unref (u);
}

static void
unit_update_poller (struct unit *u, const struct pollfd *pfd)
{
	int new_events = u->transport->get_poll_events (u);
	hard_assert (new_events != 0);

	if (!pfd || pfd->events != new_events)
		poller_set (&u->target->ctx->poller, u->socket_fd, new_events,
			(poller_dispatcher_fn) on_unit_ready, u);
}

static void
on_unit_ready (const struct pollfd *pfd, struct unit *u)
{
	struct transport *transport = u->transport;
	struct service *service = u->service;
	enum transport_io_result result;

	// We hold a reference so that unit_abort(), which may also be
	// called by handlers within the service, doesn't free the unit.
	unit_ref (u);

	if ((result = transport->on_readable (u)))
		goto exception;
	if (u->read_buffer.len)
	{
		struct str *buf = &u->read_buffer;
		service->on_data (u->service_data, u, buf);
		str_remove_slice (buf, 0, buf->len);

		if (u->aborted)
			goto end;
	}

	if ((result = transport->on_writeable (u)))
		goto exception;
	if (!u->aborted)
		unit_update_poller (u, pfd);
	goto end;

exception:
	if (result == TRANSPORT_IO_EOF)
		service->on_eof (u->service_data, u);
	else if (result == TRANSPORT_IO_ERROR)
		service->on_error (u->service_data, u);

	unit_abort (u);

end:
	unit_unref (u);
}

static void
unit_start_scan (struct unit *u)
{
	struct app_context *ctx = u->target->ctx;
	poller_timers_add (&ctx->poller.timers,
		(poller_timer_fn) unit_abort, u, ctx->scan_timeout);
	unit_update_poller (u, NULL);
}

static void
on_unit_connected (const struct pollfd *pfd, struct unit *u)
{
	(void) pfd;
	struct app_context *ctx = u->target->ctx;

	ssize_t i = poller_timers_find (&ctx->poller.timers,
		(poller_timer_fn) unit_abort, u);
	hard_assert (i != -1);
	poller_timers_remove_at_index (&ctx->poller.timers, i);

	int error;
	socklen_t error_len = sizeof error;
	if (!getsockopt (pfd->fd, SOL_SOCKET, SO_ERROR, &error, &error_len)
	 && error != 0)
	{
		// XXX: what if we get EADDRNOTAVAIL in here?  Can we?  If yes,
		//   we'll have to return the request back to the generator to retry.
		// XXX: we could also call bind separately, with INADDR_ANY, 0.
		//   Then EADDRINUSE (as per man 2 bind) means port exhaustion.
		//   But POSIX seems to say that this can block, too.
		soft_assert (error != EADDRNOTAVAIL);

		unit_abort (u);
		return;
	}

	unit_start_scan (u);
}

static struct unit *
unit_new (struct target *target, int socket_fd, uint16_t port,
	struct service *service, struct transport *transport)
{
	struct unit *u = xcalloc (1, sizeof *u);
	u->ref_count = 1;
	u->target = target_ref (target);
	u->socket_fd = socket_fd;
	u->port = port;
	u->service = service;
	u->transport = transport;

	str_init (&u->read_buffer);
	str_init (&u->write_buffer);
	str_vector_init (&u->info);

	if (!transport->init (u))
	{
		unit_unref (u);
		return NULL;
	}

	u->service_data = service->scan_init (u);
	LIST_PREPEND (target->running_units, u);
	return u;
}

enum unit_make_result
{
	UNIT_MAKE_OK,                       ///< Operation completed successfully
	UNIT_MAKE_ERROR,                    ///< Unspecified error occured
	UNIT_MAKE_TRY_AGAIN                 ///< Try again later
};

static enum unit_make_result
unit_make (struct target *target, uint32_t ip, uint16_t port,
	struct service *service, struct transport *transport)
{
	// TODO: more exhaustive checking of errno

	struct app_context *ctx = target->ctx;
	int socket_fd = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (socket_fd == -1)
		return errno == EMFILE
			? UNIT_MAKE_TRY_AGAIN
			: UNIT_MAKE_ERROR;
	set_blocking (socket_fd, false);

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl (ip);
	addr.sin_port = htons (port);

	bool connected;
	if (!connect (socket_fd, (struct sockaddr *) &addr, sizeof addr))
		connected = true;
	else if (errno == EINPROGRESS)
		connected = false;
	else
		return errno == EADDRNOTAVAIL
			? UNIT_MAKE_TRY_AGAIN
			: UNIT_MAKE_ERROR;

	struct unit *u;
	if (!(u = unit_new (target, socket_fd, port, service, transport)))
	{
		xclose (socket_fd);
		return UNIT_MAKE_ERROR;
	}

	if (connected)
		unit_start_scan (u);
	else
	{
		poller_timers_add (&ctx->poller.timers,
			(poller_timer_fn) unit_abort, u, ctx->connect_timeout);
		poller_set (&ctx->poller, u->socket_fd, POLLOUT,
			(poller_dispatcher_fn) on_unit_connected, u);
	}
	return UNIT_MAKE_OK;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static void
try_finish_quit (struct app_context *ctx)
{
	if (ctx->quitting && !ctx->running_targets)
		ctx->polling = false;
}

static void
initiate_quit (struct app_context *ctx)
{
	ctx->quitting = true;

	// Abort all running units
	struct target *t_iter, *t_next;
	for (t_iter = ctx->running_targets; t_iter; t_iter = t_next)
	{
		t_next = t_iter->next;

		struct unit *u_iter, *u_next;
		for (u_iter = t_iter->running_units; u_iter; u_iter = u_next)
		{
			u_next = u_iter->next;
			unit_abort (u_iter);
		}
	}

	// Let the current target die
	target_unref (ctx->generator.current_target);
	ctx->generator.current_target = NULL;

	try_finish_quit (ctx);
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

// --- Job generation and result aggregation -----------------------------------

struct target_dump_data
{
	char address[INET_ADDRSTRLEN];      ///< The IP address as a string

	struct unit **results;              ///< Results sorted by service
	size_t results_len;                 ///< Number of results
};

static void
target_dump_json (struct target *self, struct target_dump_data *data)
{
	json_t *o = json_object ();
	json_array_append_new (self->ctx->json_results, o);

	json_object_set_new (o, "address", json_string (data->address));
	if (self->hostname)
		json_object_set_new (o, "hostname", json_string (self->hostname));
	if (self->ctx->quitting)
		json_object_set_new (o, "partial", json_boolean (true));

	json_t *services = json_array ();
	json_object_set_new (o, "services", services);

	struct service *last_service = NULL;
	json_t *service, *ports;
	for (size_t i = 0; i < data->results_len; i++)
	{
		struct unit *u = data->results[i];
		if (u->service != last_service)
		{
			service = json_object ();
			json_array_append_new (services, service);
			json_object_set_new (service, "name",
				json_string (u->service->name));
			json_object_set_new (service, "transport",
				json_string (u->transport->name));
			json_object_set_new (service, "ports", ports);

			last_service = u->service;
			ports = json_array ();
		}

		json_t *port = json_object ();
		json_array_append_new (ports, port);
		json_object_set_new (port, "port", json_integer (u->port));

		json_t *info = json_array ();
		json_object_set_new (port, "info", info);
		for (size_t k = 0; k < u->info.len; k++)
			json_array_append_new (info, json_string (u->info.vector[k]));
	}
}

static void
target_dump_terminal (struct target *self, struct target_dump_data *data)
{
	// TODO: hide the indicator -> ncurses
	// TODO: present the results; if we've been interrupted by the user,
	//   self->ctx->quitting, state that they're only partial
	// TODO: show the indicator again
}

static int
unit_cmp_by_service (const void *ax, const void *bx)
{
	const struct unit *a = ax, *b = bx;
	return strcmp (a->service->name, b->service->name);
}

static void
target_dump_results (struct target *self)
{
	struct app_context *ctx = self->ctx;
	struct target_dump_data data;

	uint32_t address = htonl (self->ip);
	if (!inet_ntop (AF_INET, &address, data.address, sizeof data.address))
	{
		print_error ("%s: %s", "inet_ntop", strerror (errno));
		return;
	}

	size_t len = 0;
	for (struct unit *iter = self->results; iter; iter = iter->next)
		len++;

	struct unit *sorted[len];
	data.results = sorted;
	data.results_len = len;

	for (struct unit *iter = self->results; iter; iter = iter->next)
		sorted[--len] = iter;

	// Sort them by service name so that they can be grouped
	qsort (sorted, N_ELEMENTS (sorted), sizeof *sorted, unit_cmp_by_service);

	if (ctx->json_results)
		target_dump_json (self, &data);
	target_dump_terminal (self, &data);
}

static struct target *
target_ref (struct target *self)
{
	self->ref_count++;
	return self;
}

static void
target_unref (struct target *self)
{
	if (!self || --self->ref_count)
		return;

	if (self->results)
		target_dump_results (self);

	// These must have been aborted already (although we could do that in here)
	hard_assert (!self->running_units);

	struct unit *iter, *next;
	for (iter = self->results; iter; iter = next)
	{
		next = iter->next;
		unit_unref (iter);
	}

	LIST_UNLINK (self->ctx->running_targets, self);

	free (self->hostname);
	free (self);
}

static void
generator_make_target (struct app_context *ctx)
{
	struct generator *g = &ctx->generator;

	struct target *target = xcalloc (1, sizeof *target);
	hard_assert (g->current_target == NULL);
	g->current_target = target;

	target->ref_count = 1;
	target->ip = g->ip_iter;
	if (g->ip_iter == g->ip_range_iter->original_address)
		target->hostname = xstrdup (g->ip_range_iter->original_name);

	LIST_PREPEND (ctx->running_targets, target);
}

static void
generator_init (struct app_context *ctx)
{
	struct generator *g = &ctx->generator;

	g->ip_range_iter = ctx->ip_list;
	g->ip_iter = g->ip_range_iter->start;
	g->current_target = NULL;
	generator_make_target (ctx);

	g->port_range_iter = ctx->port_list;
	g->port_iter = g->port_range_iter->start;

	str_map_iter_init (&g->svc_iter, &ctx->svc_list);
	g->svc = str_map_iter_next (&g->svc_iter);

	g->transport_iter = ctx->transports;
}

static bool
generator_step (struct app_context *ctx)
{
	struct generator *g = &ctx->generator;

	// XXX: we're probably going to need a way to distinguish
	//   between "try again" and "stop trying".
	if (!g->ip_range_iter)
		return false;

	if (!g->current_target)
		generator_make_target (ctx);
	if (unit_make (g->current_target, g->ip_iter, g->port_iter,
		g->svc, g->transport_iter) != UNIT_MAKE_OK)
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

	// Moving on to the next target
	target_unref (g->current_target);
	g->current_target = NULL;

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
		{ 'j', "json-output", "FILENAME", OPT_LONG_ONLY,
		  "write the results as JSON" },
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
	case 'j':
		ctx->json_results = json_array ();
		ctx->json_filename = optarg;
		break;
	case 'w':
		call_write_default_config (optarg, g_config_table);
		exit (EXIT_SUCCESS);
	default:
		print_error ("wrong options");
		opt_handler_usage (&oh);
		exit (EXIT_FAILURE);
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

	init_terminal ();
	atexit (free_terminal);

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
		(poller_dispatcher_fn) on_signal_pipe_readable, &ctx);

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

	// TODO: initate the scan -> generate as many units as possible

	ctx.polling = true;
	while (ctx.polling)
		poller_run (&ctx.poller);

	if (ctx.json_results && !json_dump_file (ctx.json_results,
		ctx.json_filename, JSON_INDENT (2) | JSON_SORT_KEYS | JSON_ENCODE_ANY))
		print_error ("failed to write JSON output");

	app_context_free (&ctx);
	return EXIT_SUCCESS;
}
