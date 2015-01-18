/*
 * http.c: IRC service detection plugin
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

// --- IRC utilities -----------------------------------------------------------

struct irc_message
{
	struct str_map tags;                ///< IRC 3.2 message tags
	char *prefix;                       ///< Message prefix
	char *command;                      ///< IRC command
	struct str_vector params;           ///< Command parameters
};

static void
irc_parse_message_tags (const char *tags, struct str_map *out)
{
	struct str_vector v;
	str_vector_init (&v);
	split_str_ignore_empty (tags, ';', &v);

	for (size_t i = 0; i < v.len; i++)
	{
		char *key = v.vector[i], *equal_sign = strchr (key, '=');
		if (equal_sign)
		{
			*equal_sign = '\0';
			str_map_set (out, key, xstrdup (equal_sign + 1));
		}
		else
			str_map_set (out, key, xstrdup (""));
	}

	str_vector_free (&v);
}

static void
irc_parse_message (struct irc_message *msg, const char *line)
{
	str_map_init (&msg->tags);
	msg->tags.free = free;

	msg->prefix = NULL;
	msg->command = NULL;
	str_vector_init (&msg->params);

	// IRC 3.2 message tags
	if (*line == '@')
	{
		size_t tags_len = strcspn (++line, " ");
		char *tags = xstrndup (line, tags_len);
		irc_parse_message_tags (tags, &msg->tags);
		free (tags);

		line += tags_len;
		while (*line == ' ')
			line++;
	}

	// Prefix
	if (*line == ':')
	{
		size_t prefix_len = strcspn (++line, " ");
		msg->prefix = xstrndup (line, prefix_len);
		line += prefix_len;
	}

	// Command name
	{
		while (*line == ' ')
			line++;

		size_t cmd_len = strcspn (line, " ");
		msg->command = xstrndup (line, cmd_len);
		line += cmd_len;
	}

	// Arguments
	while (true)
	{
		while (*line == ' ')
			line++;

		if (*line == ':')
		{
			str_vector_add (&msg->params, ++line);
			break;
		}

		size_t param_len = strcspn (line, " ");
		if (!param_len)
			break;

		str_vector_add_owned (&msg->params, xstrndup (line, param_len));
		line += param_len;
	}
}

static void
irc_free_message (struct irc_message *msg)
{
	str_map_free (&msg->tags);
	free (msg->prefix);
	free (msg->command);
	str_vector_free (&msg->params);
}

static void
irc_process_buffer (struct str *buf,
	void (*callback)(const struct irc_message *, const char *, void *),
	void *user_data)
{
	char *start = buf->str, *end = start + buf->len;
	for (char *p = start; p + 1 < end; p++)
	{
		// Split the input on newlines
		if (p[0] != '\r' || p[1] != '\n')
			continue;

		*p = 0;

		struct irc_message msg;
		irc_parse_message (&msg, start);
		callback (&msg, start, user_data);
		irc_free_message (&msg);

		start = p + 2;
	}

	// XXX: we might want to just advance some kind of an offset to avoid
	//   moving memory around unnecessarily.
	str_remove_slice (buf, 0, start - buf->str);
}

static int
irc_tolower (int c)
{
	if (c == '[')   return '{';
	if (c == ']')   return '}';
	if (c == '\\')  return '|';
	if (c == '~')   return '^';
	return c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c;
}

static size_t
irc_strxfrm (char *dest, const char *src, size_t n)
{
	size_t len = strlen (src);
	while (n-- && (*dest++ = irc_tolower (*src++)))
		;
	return len;
}

static int
irc_strcmp (const char *a, const char *b)
{
	int x;
	while (*a || *b)
		if ((x = irc_tolower (*a++) - irc_tolower (*b++)))
			return x;
	return 0;
}

static int
irc_fnmatch (const char *pattern, const char *string)
{
	size_t pattern_size = strlen (pattern) + 1;
	size_t string_size  = strlen (string)  + 1;
	char x_pattern[pattern_size], x_string[string_size];
	irc_strxfrm (x_pattern, pattern, pattern_size);
	irc_strxfrm (x_string,  string,  string_size);
	return fnmatch (x_pattern, x_string, 0);
}

// --- Other selected IRC stuff ------------------------------------------------

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

			g_data.api->unit_abort (scan->u);
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
	.on_aborted  = NULL
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
