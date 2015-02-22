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
#include <inttypes.h>

#include <dirent.h>
#include <dlfcn.h>
#include <arpa/inet.h>
#include <sys/resource.h>

#include <curses.h>
#include <term.h>

#include <jansson.h>

// --- Configuration (application-specific) ------------------------------------

#define DEFAULT_CONNECT_TIMEOUT  10
#define DEFAULT_SCAN_TIMEOUT     10

static struct config_item g_config_table[] =
{
	{ "plugin_dir",      PLUGIN_DIR,        "Where to search for plugins"    },
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

	int err;
	if (tty_fd == -1 || setupterm (NULL, tty_fd, &err) == ERR)
		return;

	// Make sure all terminal features used by us are supported
	if (!set_a_foreground || !orig_pair
	 || !enter_standout_mode || !exit_standout_mode
	 || !carriage_return || !cursor_left || !clr_eol)
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
	char ip_string[INET_ADDRSTRLEN];    ///< IP address as a string
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

	struct service *service;            ///< Service
	void *service_data;                 ///< User data for service

	struct transport *transport;        ///< Transport methods
	void *transport_data;               ///< User data for transport

	int socket_fd;                      ///< The TCP socket
	uint16_t port;                      ///< The scanned port
	struct str read_buffer;             ///< Unprocessed input
	struct str write_buffer;            ///< Output yet to be sent out

	struct poller_timer timeout_event;  ///< Timeout event
	struct poller_fd fd_event;          ///< FD event

	struct str_vector info;             ///< Info resulting from the scan
	bool scan_started;                  ///< Whether the scan has been started
	bool abortion_requested;            ///< Abortion requested by service
	bool aborted;                       ///< Scan has been aborted
	bool success;                       ///< Service has been found
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
	struct poller_timer timer;          ///< The animation timer

	const char *frames;                 ///< All the characters
	size_t frames_len;                  ///< The number of characters

	char *status;                       ///< The status text
	unsigned position;                  ///< The current animation character
	bool shown;                         ///< The indicator is shown on screen
};

static void indicator_init (struct indicator *self, struct poller *poller);

static void
indicator_free (struct indicator *self)
{
	free (self->status);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

struct generator
{
	struct target *current_target;      ///< Current target

	struct ip_range *ip_range_iter;     ///< Current IP range
	struct port_range *port_range_iter; ///< Current port range
	uint32_t ip_iter;                   ///< IP iterator within the range
	uint16_t port_iter;                 ///< Port iterator within the range

	struct str_map_iter svc_iter;       ///< Service iterator
	struct service *svc;                ///< Current service iterator value

	struct transport *transport_iter;   ///< Transport iterator
};

static bool generator_step (struct app_context *ctx);
static void on_generator_step_requested (struct app_context *ctx);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

struct app_context
{
	struct str_map config;              ///< User configuration
	unsigned connect_timeout;           ///< Timeout for connect() in sec.
	unsigned scan_timeout;              ///< Timeout for service scans in sec.

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

	size_t stats_hosts;                 ///< How many hosts we've scanned
	size_t stats_results;               ///< How many services we've found

	// We need this list ordered from the oldest running target,
	// therefore we track the tail to allow O(1) appends.

	struct target *running_targets;     ///< List of currently scanned targets
	struct target *running_tail;        ///< The tail link of `running_targets'

	struct poller poller;               ///< Manages polled descriptors
	struct poller_idle step_event;      ///< Idle event to make more units
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
	indicator_init (&self->indicator, &self->poller);
	// Ignoring the generator so far

	poller_init (&self->poller);
	self->quitting = false;
	self->polling = false;

	poller_idle_init (&self->step_event, &self->poller);
	self->step_event.dispatcher = (poller_idle_fn) on_generator_step_requested;
	self->step_event.user_data = self;
}

static void
app_context_free (struct app_context *self)
{
	str_map_free (&self->config);
	str_map_free (&self->svc_list);
	str_map_free (&self->services);
	indicator_free (&self->indicator);
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

// TODO: make it so that the indicator is hidden while printing messages to
//   the same terminal -> wrapper for log_message_stdio().

static void
indicator_set_timer (struct indicator *self)
{
	poller_timer_set (&self->timer, INDICATOR_INTERVAL);
}

static void
on_indicator_tick (struct indicator *self)
{
	if (!self->shown)
		return;

	if (++self->position >= self->frames_len)
		self->position = 0;

	tputs (cursor_left, 1, putchar);
	putchar (self->frames[self->position]);
	fflush (stdout);
	indicator_set_timer (self);
}

static void
indicator_init (struct indicator *self, struct poller *poller)
{
	poller_timer_init (&self->timer, poller);
	self->timer.dispatcher = (poller_timer_fn) on_indicator_tick;
	self->timer.user_data = self;

	static const char frames[] = "-\\|/";
	self->position = 0;
	self->frames = frames;
	self->frames_len = sizeof frames - 1;

	self->status = NULL;
	self->shown = false;
}

static void
indicator_show (struct indicator *self)
{
	if (self->shown || !g_terminal.initialized || !g_terminal.stdout_is_tty)
		return;

	tputs (carriage_return, 1, putchar);
	printf ("%s... %c", self->status, self->frames[self->position]);
	tputs (clr_eol, 1, putchar);
	fflush (stdout);

	self->shown = true;
	indicator_set_timer (self);
}

static void
indicator_hide (struct indicator *self)
{
	if (!self->shown)
		return;

	tputs (carriage_return, 1, putchar);
	tputs (clr_eol, 1, putchar);
	fflush (stdout);

	self->shown = false;
	poller_timer_reset (&self->timer);
}

static void
indicator_set_status (struct indicator *self, char *status)
{
	bool refresh = self->shown;
	indicator_hide (self);

	free (self->status);
	self->status = status;

	if (refresh)
		indicator_show (self);
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
	if (u->scan_started)
	{
		if (u->service->on_aborted)
			u->service->on_aborted (u->service_data);
		u->service->scan_free (u->service_data);
	}

	u->transport->cleanup (u);
	xclose (u->socket_fd);

	poller_timer_reset (&u->timeout_event);

	// This way we avoid a syscall with epoll
	u->fd_event.closed = true;
	poller_fd_reset (&u->fd_event);

	u->transport_data = NULL;
	u->service_data = NULL;
	u->socket_fd = -1;

	// We're no longer running
	LIST_UNLINK (u->target->running_units, u);

	// We might have made it possible to launch new units; we cannot run
	// the generator right now, though, as we could spin in a long loop
	poller_idle_set (&u->target->ctx->step_event);

	if (u->success)
	{
		struct target *target = u->target;
		target->ctx->stats_results++;

		// Now we're a part of the target
		LIST_PREPEND (target->results, u);
		u->target = NULL;
		target_unref (target);
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
		poller_fd_set (&u->fd_event, new_events);
}

static void
on_unit_ready (const struct pollfd *pfd, struct unit *u)
{
	struct service *service = u->service;
	struct transport *transport = u->transport;
	enum transport_io_result result;
	bool got_eof = false;

	if ((result = transport->on_readable (u)) == TRANSPORT_IO_ERROR)
		goto error;
	got_eof |= result == TRANSPORT_IO_EOF;

	if (u->read_buffer.len)
	{
		struct str *buf = &u->read_buffer;
		service->on_data (u->service_data, buf->str, buf->len);
		str_remove_slice (buf, 0, buf->len);

		if (u->abortion_requested)
			goto abort;
	}

	if ((result = transport->on_writeable (u)) == TRANSPORT_IO_ERROR)
		goto error;
	got_eof |= result == TRANSPORT_IO_EOF;

	if (got_eof)
	{
		if (service->on_eof)
			service->on_eof (u->service_data);
		if (u->abortion_requested || !u->write_buffer.len)
			goto abort;
	}

	unit_update_poller (u, pfd);
	return;

error:
	if (service->on_error)
		service->on_error (u->service_data);

abort:
	unit_abort (u);
}

static void
unit_start_scan (struct unit *u)
{
	u->scan_started = true;
	poller_timer_set (&u->timeout_event, u->target->ctx->scan_timeout * 1000);

	u->service_data = u->service->scan_init (u->service, u);
	u->fd_event.dispatcher = (poller_fd_fn) on_unit_ready;
	unit_update_poller (u, NULL);
}

static void
on_unit_connected (const struct pollfd *pfd, struct unit *u)
{
	(void) pfd;

	poller_timer_reset (&u->timeout_event);

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

	poller_timer_init (&u->timeout_event, &target->ctx->poller);
	u->timeout_event.dispatcher = (poller_timer_fn) unit_abort;
	u->timeout_event.user_data = u;

	poller_fd_init (&u->fd_event, &target->ctx->poller, socket_fd);
	u->fd_event.dispatcher = (poller_fd_fn) on_unit_connected;
	u->fd_event.user_data = u;

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
	{
		xclose (socket_fd);
		return errno == EADDRNOTAVAIL
			? UNIT_MAKE_TRY_AGAIN
			: UNIT_MAKE_ERROR;
	}

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
		poller_timer_set (&u->timeout_event, ctx->connect_timeout * 1000);
		poller_fd_set (&u->fd_event, POLLOUT);
	}

	return UNIT_MAKE_OK;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static void
try_finish_quit (struct app_context *ctx)
{
	if (!ctx->running_targets && !ctx->generator.current_target)
		ctx->polling = false;
}

static void
initiate_quit (struct app_context *ctx)
{
	ctx->quitting = true;
	indicator_set_status (&ctx->indicator, xstrdup ("Quitting"));

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

static const char *
plugin_api_get_config (void *app_context, const char *key)
{
	struct app_context *ctx = app_context;
	return str_map_find (&ctx->config, key);
}

static const char *
plugin_api_unit_get_address (struct unit *u)
{
	return u->target->ip_string;
}

static ssize_t
plugin_api_unit_write (struct unit *u, const void *buf, size_t len)
{
	if (u->abortion_requested || u->aborted)
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
	u->abortion_requested = true;
}

static struct plugin_api g_plugin_vtable =
{
	.register_service  = plugin_api_register_service,
	.get_config        = plugin_api_get_config,
	.unit_get_address  = plugin_api_unit_get_address,
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
			name, "incompatible API version");
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
		if (!dot || strcmp (dot, ".so"))
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
	// XXX: maybe set `ssl_rx_want_tx' to force a handshake?
	u->transport_data = data;
	return true;
}

static void
transport_tls_add_certificate_info (struct unit *u, X509 *cert)
{
	char *subject = X509_NAME_oneline (X509_get_subject_name (cert), NULL, 0);
	char *issuer  = X509_NAME_oneline (X509_get_issuer_name  (cert), NULL, 0);

	str_vector_add_owned (&u->info, xstrdup_printf ("%s: %s",
		"certificate subject", subject));
	str_vector_add_owned (&u->info, xstrdup_printf ("%s: %s",
		"certificate issuer", issuer));

	free (subject);
	free (issuer);
}

static void
transport_tls_cleanup (struct unit *u)
{
	struct transport_tls_data *data = u->transport_data;
	if (u->success)
	{
		X509 *cert = SSL_get_peer_certificate (data->ssl);
		if (cert)
		{
			transport_tls_add_certificate_info (u, cert);
			X509_free (cert);
		}
	}
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
			return TRANSPORT_IO_OK;
		case SSL_ERROR_WANT_WRITE:
			data->ssl_rx_want_tx = true;
			return TRANSPORT_IO_OK;
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
	SSL_CTX_set_verify (ssl_ctx, SSL_VERIFY_NONE, NULL);
	SSL_CTX_set_mode (ssl_ctx,
		SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

	ctx->ssl_ctx = ssl_ctx;
	LIST_PREPEND (ctx->transports, &g_transport_tls);
}

// --- Tree printer ------------------------------------------------------------

struct node
{
	struct node *next;                  ///< The next sibling in order
	struct node *children;              ///< Children of this node
	char *text;                         ///< Text of this node
	bool bold;                          ///< Whether to print in bold font
};

static struct node *
node_new (char *text)
{
	struct node *self = xcalloc (1, sizeof *self);
	self->text = text;
	return self;
}

static void
node_delete (struct node *self)
{
	struct node *iter, *next;
	for (iter = self->children; iter; iter = next)
	{
		next = iter->next;
		node_delete (iter);
	}
	free (self->text);
	free (self);
}

struct node_print_level
{
	struct node_print_level *next;      ///< Next print level
	const char *start;                  ///< Starting indentation
	const char *continuation;           ///< Continuation
	bool started;                       ///< Printed starting indentation
};

struct node_print_data
{
	struct node_print_level *head;      ///< The first level
	struct node_print_level **tail;     ///< Where to place further levels
};

static char *
node_escape_text (const char *text)
{
	struct str filtered;
	str_init (&filtered);

	int c;
	while ((c = *text++))
		str_append_c (&filtered,
			(isascii (c) && (isgraph (c) || c == ' ')) ? c : '.');

	return str_steal (&filtered);
}

static void
node_print_tree_level (struct node *self, struct node_print_data *data)
{
	struct str indent;
	str_init (&indent);

	for (struct node_print_level *iter = data->head; iter; iter = iter->next)
	{
		bool started = iter->started;
		iter->started = true;
		str_append (&indent, started ? iter->continuation : iter->start);
	}

	fputs (indent.str, stdout);
	str_free (&indent);

	char *escaped = node_escape_text (self->text);
	if (self->bold)
		print_bold (stdout, escaped);
	else
		fputs (escaped, stdout);
	fputc ('\n', stdout);
	free (escaped);

	struct node_print_level level;
	level.next = NULL;
	level.start = " |- ";
	level.continuation = " |  ";
	level.started = false;

	struct node_print_level **prev_tail = data->tail;
	*data->tail = &level;
	data->tail = &level.next;

	for (struct node *iter = self->children; iter; iter = iter->next)
	{
		if (!iter->next)
		{
			level.start = " '- ";
			level.continuation = "    ";
		}
		level.started = false;
		node_print_tree_level (iter, data);
	}

	data->tail = prev_tail;
	*data->tail = NULL;
}

static void
node_print_tree (struct node *self)
{
	struct node_print_data data;
	data.head = NULL;
	data.tail = &data.head;

	node_print_tree_level (self, &data);
}

// --- Job generation and result aggregation -----------------------------------

struct target_dump_data
{
	struct unit **results;              ///< Results sorted by service
	size_t results_len;                 ///< Number of results
};

static void
target_dump_json (struct target *self, struct target_dump_data *data)
{
	json_t *o = json_object ();
	json_array_append_new (self->ctx->json_results, o);

	json_object_set_new (o, "address", json_string (self->ip_string));
	if (self->hostname)
		json_object_set_new (o, "hostname", json_string (self->hostname));
	if (self->ctx->quitting)
		json_object_set_new (o, "partial", json_boolean (true));

	json_t *services = json_array ();
	json_object_set_new (o, "services", services);

	struct service *last_service = NULL;
	struct transport *last_transport = NULL;
	json_t *service, *ports;
	for (size_t i = 0; i < data->results_len; i++)
	{
		struct unit *u = data->results[i];
		if (u->service != last_service || u->transport != last_transport)
		{
			service = json_object ();
			ports = json_array ();

			json_array_append_new (services, service);
			json_object_set_new (service, "name",
				json_string (u->service->name));
			json_object_set_new (service, "transport",
				json_string (u->transport->name));
			json_object_set_new (service, "ports", ports);

			last_service = u->service;
			last_transport = u->transport;
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
	indicator_hide (&self->ctx->indicator);

	struct str tmp;
	str_init (&tmp);
	str_append (&tmp, self->ip_string);
	if (self->hostname)
		str_append_printf (&tmp, " (%s)", self->hostname);
	if (self->ctx->quitting)
		str_append_printf (&tmp, " (%s)", "partial");

	struct node *root = node_new (str_steal (&tmp));
	root->bold = true;

	struct service *last_service = NULL;
	struct transport *last_transport = NULL;
	struct node *service, **s_tail = &root->children, *port, **p_tail;
	for (size_t i = 0; i < data->results_len; i++)
	{
		struct unit *u = data->results[i];
		if (u->service != last_service || u->transport != last_transport)
		{
			*s_tail = service = node_new (xstrdup_printf ("%s (%s)",
				u->service->name, u->transport->name));
			s_tail = &service->next;
			p_tail = &service->children;

			last_service = u->service;
			last_transport = u->transport;
		}

		port = *p_tail = node_new (xstrdup_printf ("port %" PRIu16, u->port));
		p_tail = &port->next;

		struct node *info, **i_tail = &port->children;
		for (size_t k = 0; k < u->info.len; k++)
		{
			info = *i_tail = node_new (xstrdup (u->info.vector[k]));
			i_tail = &info->next;
		}
	}

	node_print_tree (root);
	node_delete (root);
	putchar ('\n');

	indicator_show (&self->ctx->indicator);
}

static int
unit_cmp_by_order (const void *ax, const void *bx)
{
	const struct unit **ay = (void *) ax, **by = (void *) bx;
	const struct unit *a = *ay, *b = *by;
	int x = strcmp (a->service->name, b->service->name);
	if (!x) x = strcmp (a->transport->name, b->transport->name);
	if (!x) x = (int) a->port - (int) b->port;
	return x;
}

static void
target_dump_results (struct target *self)
{
	struct app_context *ctx = self->ctx;
	struct target_dump_data data;

	size_t len = 0;
	for (struct unit *iter = self->results; iter; iter = iter->next)
		len++;

	struct unit *sorted[len];
	data.results = sorted;
	data.results_len = len;

	for (struct unit *iter = self->results; iter; iter = iter->next)
		sorted[--len] = iter;

	// Sort them by service name so that they can be grouped
	qsort (sorted, N_ELEMENTS (sorted), sizeof *sorted, unit_cmp_by_order);

	if (ctx->json_results)
		target_dump_json (self, &data);
	target_dump_terminal (self, &data);
}

static void
target_update_indicator (struct target *self)
{
	char *status = xstrdup_printf ("Scanning %s", self->ip_string);
	struct indicator *indicator = &self->ctx->indicator;
	if (!indicator->status || strcmp (status, indicator->status))
		indicator_set_status (&self->ctx->indicator, status);
	else
		free (status);
	indicator_show (&self->ctx->indicator);
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

	struct app_context *ctx = self->ctx;
	LIST_UNLINK_WITH_TAIL (ctx->running_targets, ctx->running_tail, self);
	if (!ctx->running_targets)
		indicator_hide (&ctx->indicator);
	else if (!ctx->quitting && ctx->running_targets)
		target_update_indicator (ctx->running_targets);

	free (self->hostname);
	free (self);

	try_finish_quit (ctx);
}

static void
generator_make_target (struct app_context *ctx)
{
	hard_assert (!ctx->quitting);
	struct generator *g = &ctx->generator;

	struct target *target = xcalloc (1, sizeof *target);
	hard_assert (g->current_target == NULL);
	g->current_target = target;

	target->ref_count = 1;
	target->ctx = ctx;
	target->ip = g->ip_iter;

	uint32_t address = htonl (target->ip);
	if (!inet_ntop (AF_INET, &address,
		target->ip_string, sizeof target->ip_string))
	{
		print_error ("%s: %s", "inet_ntop", strerror (errno));
		*target->ip_string = '\0';
	}

	if (g->ip_iter == g->ip_range_iter->original_address
	 && strcmp (target->ip_string, g->ip_range_iter->original_name))
		target->hostname = xstrdup (g->ip_range_iter->original_name);

	LIST_APPEND_WITH_TAIL (ctx->running_targets, ctx->running_tail, target);
	target_update_indicator (ctx->running_targets);

	ctx->stats_hosts++;
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

	if (ctx->quitting || !g->ip_range_iter)
		return false;
	if (!g->current_target)
		generator_make_target (ctx);

	switch (unit_make (g->current_target,
		g->ip_iter, g->port_iter, g->svc, g->transport_iter))
	{
	case UNIT_MAKE_OK:
	case UNIT_MAKE_ERROR:
		break;
	case UNIT_MAKE_TRY_AGAIN:
		// TODO: set a timer for a few seconds, we might eventually get lucky
		return false;
	}

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

static void
on_generator_step_requested (struct app_context *ctx)
{
	poller_idle_reset (&ctx->step_event);
	while (generator_step (ctx))
		;
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
	str_map_set (&ctx->svc_list, name, xstrdup (name));
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
	int err = getaddrinfo (host, NULL, &hints, &result);
	if (err)
	{
		print_error ("cannot resolve `%s': %s", host, gai_strerror (err));
		return false;
	}

	struct ip_range *range = xcalloc (1, sizeof *range);
	uint32_t bitmask = ((uint64_t) 1 << (32 - mask)) - 1;

	hard_assert (result->ai_family == AF_INET);
	hard_assert (result->ai_addr->sa_family == AF_INET);
	uint32_t addr = ntohl (((struct sockaddr_in *)
		result->ai_addr)->sin_addr.s_addr);
	range->start = addr & ~bitmask;
	range->end   = addr |  bitmask;
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
	char *name = NULL;
	bool success = true;
	while (free (name), (name = str_map_iter_next (&iter)))
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
		opt_handler_usage (&oh, stdout);
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
		opt_handler_usage (&oh, stderr);
		exit (EXIT_FAILURE);
	}

	argc -= optind;
	argv += optind;

	if (!argc)
	{
		opt_handler_usage (&oh, stderr);
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
	srand (time (NULL));

	// Set the maximum count of file descriptorts to the hard limit
	struct rlimit limit;
	if (getrlimit (RLIMIT_NOFILE, &limit))
		print_warning ("%s: %s", "getrlimit failed", strerror (errno));
	else
	{
		limit.rlim_cur = limit.rlim_max;
		if (setrlimit (RLIMIT_NOFILE, &limit))
			print_warning ("%s: %s", "setrlimit failed", strerror (errno));
	}

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

	struct poller_fd signal_event;
	poller_fd_init (&signal_event, &ctx.poller, g_signal_pipe[0]);
	signal_event.dispatcher = (poller_fd_fn) on_signal_pipe_readable;
	signal_event.user_data = &ctx;
	poller_fd_set (&signal_event, POLLIN);

	if (!load_plugins (&ctx))
		exit (EXIT_FAILURE);

	// TODO: make the order unimportant; this hopes all services support
	//   the plain transport and that it is the first on the list
	initialize_tls (&ctx);
	LIST_PREPEND (ctx.transports, &g_transport_plain);

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

	// Initate the scan: generate as many units as possible
	generator_init (&ctx);
	while (generator_step (&ctx))
		;

	ctx.polling = true;
	while (ctx.polling)
		poller_run (&ctx.poller);

	printf ("Scanned %zu %s, identified %zu %s\n",
		ctx.stats_hosts,   ctx.stats_hosts   == 1 ? "host"    : "hosts",
		ctx.stats_results, ctx.stats_results == 1 ? "service" : "services");

	if (ctx.json_results && json_dump_file (ctx.json_results,
		ctx.json_filename, JSON_INDENT (2) | JSON_SORT_KEYS | JSON_ENCODE_ANY))
		print_error ("failed to write JSON output");

	app_context_free (&ctx);
	return EXIT_SUCCESS;
}
