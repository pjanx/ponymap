/*
 * http.c: HTTP service detection plugin
 *
 * Copyright (c) 2014, Přemysl Eric Janouch <p@janouch.name>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted.
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

#include "config.h"
#include "../liberty/liberty.c"
#include "../plugin-api.h"

#include "../http-parser/http_parser.h"

// --- Service detection -------------------------------------------------------

static struct plugin_data
{
	void *ctx;                          ///< Application context
	struct plugin_api *api;             ///< Plugin API vtable
}
g_data;

enum header_state
{
	STATE_FIELD,                        ///< We've been parsing a field so far
	STATE_VALUE                         ///< We've been parsing a value so far
};

struct scan_data
{
	struct unit *u;                     ///< Scan unit

	http_parser parser;                 ///< HTTP parser
	enum header_state state;            ///< What did we get last time?
	struct str field;                   ///< Field part buffer
	struct str value;                   ///< Value part buffer
};

static void
on_header_read (struct scan_data *scan)
{
	if (!strcasecmp_ascii (scan->field.str, "Server"))
	{
		char *info = xstrdup_printf ("%s: %s",
			"server software", scan->value.str);
		g_data.api->unit_add_info (scan->u, info);
		free (info);
	}
}

static int
on_header_field (http_parser *parser, const char *at, size_t len)
{
	struct scan_data *scan = parser->data;
	if (scan->state == STATE_VALUE)
	{
		on_header_read (scan);
		str_reset (&scan->field);
		str_reset (&scan->value);
	}
	str_append_data (&scan->field, at, len);
	scan->state = STATE_FIELD;
	return 0;
}

static int
on_header_value (http_parser *parser, const char *at, size_t len)
{
	struct scan_data *data = parser->data;
	str_append_data (&data->value, at, len);
	data->state = STATE_VALUE;
	return 0;
}

static int
on_headers_complete (http_parser *parser)
{
	struct scan_data *scan = parser->data;
	if (scan->state == STATE_VALUE)
		on_header_read (scan);

	// We've got this far, this must be an HTTP server
	g_data.api->unit_set_success (scan->u, true);
	g_data.api->unit_stop (scan->u);
	return 1;
}

static void *
scan_init (struct service *service, struct unit *u)
{
	(void) service;

	struct str hello = str_make ();
	str_append_printf (&hello, "GET / HTTP/1.0\r\n"
		"Host: %s\r\n\r\n", g_data.api->unit_get_address (u));
	g_data.api->unit_write (u, hello.str, hello.len);
	str_free (&hello);

	struct scan_data *scan = xcalloc (1, sizeof *scan);
	http_parser_init (&scan->parser, HTTP_RESPONSE);
	scan->parser.data = scan;

	scan->state = STATE_FIELD;
	scan->field = str_make ();
	scan->value = str_make ();

	scan->u = u;
	return scan;
}

static void
scan_free (void *handle)
{
	struct scan_data *scan = handle;
	str_free (&scan->field);
	str_free (&scan->value);
	free (scan);
}

static void
on_data (void *handle, const void *data, size_t len)
{
	static const http_parser_settings http_settings =
	{
		.on_header_field      = on_header_field,
		.on_header_value      = on_header_value,
		.on_headers_complete  = on_headers_complete,
	};

	struct scan_data *scan = handle;
	http_parser *parser = &scan->parser;
	size_t n_parsed = http_parser_execute (parser, &http_settings, data, len);

	if (parser->upgrade)
	{
		// We should never get here though because `on_headers_complete'
		// is called first and ends up stopping the unit.
		g_data.api->unit_add_info (scan->u, "upgrades to a different protocol");
		g_data.api->unit_stop (scan->u);
	}
	else if (n_parsed != len && parser->http_errno != HPE_CB_headers_complete)
		g_data.api->unit_stop (scan->u);
}

static void
on_eof (void *handle)
{
	on_data (handle, NULL, 0);
}

static struct service g_http_service =
{
	.name        = "HTTP",
	.flags       = SERVICE_SUPPORTS_TLS,

	.scan_init   = scan_init,
	.scan_free   = scan_free,
	.on_data     = on_data,
	.on_eof      = on_eof,
	.on_error    = NULL,
	.on_stopped  = NULL
};

static bool
initialize (void *ctx, struct plugin_api *api)
{
	g_data = (struct plugin_data) { .ctx = ctx, .api = api };
	api->register_service (ctx, &g_http_service);
	return true;
}

struct plugin_info ponymap_plugin_info =
{
	.api_version  = API_VERSION,
	.initialize   = initialize
};
