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

// --- Service detection -------------------------------------------------------

static struct plugin_data
{
	void *ctx;                          ///< Application context
	struct plugin_api *api;             ///< Plugin API vtable
}
g_data;

static bool
initialize (void *ctx, struct plugin_api *api)
{
	g_data = (struct plugin_data) { .ctx = ctx, .api = api };
	// TODO: register a service
	return true;
}

struct plugin_info ponymap_plugin_info =
{
	.api_version  = API_VERSION,
	.initialize   = initialize
};
