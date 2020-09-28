/*
 * ssh.c: SSH service detection plugin
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

// --- Service detection -------------------------------------------------------

static struct plugin_data
{
	void *ctx;                          ///< Application context
	struct plugin_api *api;             ///< Plugin API vtable
}
g_data;

struct scan_data
{
	struct unit *u;                     ///< Scan unit
	struct str input;                   ///< Input buffer
};

static void *
scan_init (struct service *service, struct unit *u)
{
	(void) service;

	struct scan_data *scan = xcalloc (1, sizeof *scan);
	scan->input = str_make ();
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
on_data (void *handle, const void *data, size_t len)
{
	// See RFC 4253 -- we check for a valid SSH banner
	struct scan_data *scan = handle;
	if (scan->input.len + len > 255)
		goto end_scan;

	str_append_data (&scan->input, data, len);
	char *input = scan->input.str;
	char *nl = strstr (input, "\r\n");
	if (!nl)
		return;

	if (strncmp (input, "SSH-", 4))
		goto end_scan;

	*nl = '\0';
	g_data.api->unit_add_info (scan->u, input);
	g_data.api->unit_set_success (scan->u, true);

end_scan:
	g_data.api->unit_stop (scan->u);
}

static struct service g_ssh_service =
{
	.name        = "SSH",
	.flags       = 0,

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
	api->register_service (ctx, &g_ssh_service);
	return true;
}

struct plugin_info ponymap_plugin_info =
{
	.api_version  = API_VERSION,
	.initialize   = initialize
};
