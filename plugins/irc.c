/*
 * http.c: IRC service detection plugin
 *
 * Copyright (c) 2014, Přemysl Janouch <p.janouch@gmail.com>
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

#define LIBERTY_WANT_PROTO_IRC

#include "config.h"
#include "../liberty/liberty.c"
#include "../plugin-api.h"

// --- Selected IRC stuff ------------------------------------------------------

#define IRC_MAX_NICKNAME  9             ///< The limit from RFC 2812

#define IRC_RPL_WELCOME   1
#define IRC_RPL_MYINFO    4

// --- Service detection -------------------------------------------------------

static struct plugin_data
{
	void *ctx;                          ///< Application context
	struct plugin_api *api;             ///< Plugin API vtable
}
g_data;

struct scan_data
{
	struct str input;                   ///< Input buffer
	struct unit *u;                     ///< Scan unit
};

static void *
scan_init (struct service *service, struct unit *u)
{
	(void) service;

	char nick[IRC_MAX_NICKNAME + 1];
	size_t i;
	for (i = 0; i < sizeof nick - 1; i++)
		nick[i] = 'a' + rand () % ('z' - 'a' + 1);
	nick[i] = '\0';

	struct str hello;
	str_init (&hello);
	str_append_printf (&hello,
		"NICK %s\r\nUSER %s 8 * :%s\r\n", nick, nick, nick);
	g_data.api->unit_write (u, hello.str, hello.len);
	str_free (&hello);

	struct scan_data *scan = xcalloc (1, sizeof *scan);
	str_init (&scan->input);
	scan->u = u;
	return scan;
}

static void
scan_free (void *handle)
{
	struct scan_data *scan = handle;
	str_free (&scan->input);
	free (scan);
}

static void
on_irc_message (const struct irc_message *msg, const char *raw, void *user_data)
{
	(void) raw;
	struct scan_data *scan = user_data;

	unsigned long code;
	if (!irc_strcmp (msg->command, "PING"))
	{
		// Without this we might be unable to finish registration
		struct str pong;
		str_init (&pong);
		str_append_printf (&pong, "PONG :%s\r\n",
			msg->params.len > 0 ? msg->params.vector[0] : "");
		g_data.api->unit_write (scan->u, pong.str, pong.len);
	}
	else if (strlen (msg->command) == 3 && xstrtoul (&code, msg->command, 10))
	{
		// It looks like we've successfully registered
		if (msg->prefix && code == IRC_RPL_WELCOME)
			g_data.api->unit_set_success (scan->u, true);

		// Extract the server name at least
		if (code == IRC_RPL_MYINFO && msg->params.len > 0)
		{
			char *info = xstrdup_printf ("%s: %s",
				"server name", msg->params.vector[1]);
			g_data.api->unit_add_info (scan->u, info);
			free (info);

			g_data.api->unit_stop (scan->u);
		}
	}
}

static void
on_data (void *handle, const void *data, size_t len)
{
	struct scan_data *scan = handle;
	str_append_data (&scan->input, data, len);
	irc_process_buffer (&scan->input, on_irc_message, scan);
}

static struct service g_irc_service =
{
	.name        = "IRC",
	.flags       = SERVICE_SUPPORTS_TLS,

	.scan_init   = scan_init,
	.scan_free   = scan_free,
	.on_data     = on_data,
	.on_eof      = NULL,
	.on_error    = NULL,
	.on_stopped  = NULL
};

static bool
initialize (void *ctx, struct plugin_api *api)
{
	g_data = (struct plugin_data) { .ctx = ctx, .api = api };
	api->register_service (ctx, &g_irc_service);
	return true;
}

struct plugin_info ponymap_plugin_info =
{
	.api_version  = API_VERSION,
	.initialize   = initialize
};
