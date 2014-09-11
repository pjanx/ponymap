/*
 * http.c: HTTP service detection plugin
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

#include "../utils.c"
#include "../plugin-api.h"

// --- Service detection -------------------------------------------------------

static struct plugin_data
{
	void *ctx;                          ///< Application context
	struct plugin_api *api;             ///< Plugin API vtable
}
g_data;

static void *
scan_init (struct unit *u)
{
	// TODO
	return NULL;
}

static void
scan_free (void *handle)
{
	// TODO
}

static void
on_data (void *handle, struct unit *u, struct str *data)
{
	// TODO
}

static void
on_eof (void *handle, struct unit *u)
{
	// TODO
}

static void
on_error (void *handle, struct unit *u)
{
	// TODO
}

static void
on_aborted (void *handle, struct unit *u)
{
	// TODO
}

static struct service g_http_service =
{
	.name        = "HTTP",
	.flags       = SERVICE_SUPPORTS_TLS,

	.scan_init   = scan_init,
	.scan_free   = scan_free,
	.on_data     = on_data,
	.on_eof      = on_eof,
	.on_error    = on_error,
	.on_aborted  = on_aborted
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
