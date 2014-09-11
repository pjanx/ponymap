/*
 * utils.c: utilities
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

#define PROGRAM_NAME "ponymap"
#define PROGRAM_VERSION "alpha"

#define _POSIX_C_SOURCE 199309L
#define _XOPEN_SOURCE 600

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include <time.h>
#include <limits.h>

#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <strings.h>
#include <regex.h>
#include <libgen.h>
#include <syslog.h>
#include <fnmatch.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>

#ifndef NI_MAXHOST
#define NI_MAXHOST 1025
#endif // ! NI_MAXHOST

#ifndef NI_MAXSERV
#define NI_MAXSERV 32
#endif // ! NI_MAXSERV

#include <getopt.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "siphash.h"

extern char **environ;

#ifdef _POSIX_MONOTONIC_CLOCK
#define CLOCK_BEST CLOCK_MONOTONIC
#else // ! _POSIX_MONOTIC_CLOCK
#define CLOCK_BEST CLOCK_REALTIME
#endif // ! _POSIX_MONOTONIC_CLOCK

#if defined __GNUC__
#define ATTRIBUTE_PRINTF(x, y) __attribute__ ((format (printf, x, y)))
#else // ! __GNUC__
#define ATTRIBUTE_PRINTF(x, y)
#endif // ! __GNUC__

#if defined __GNUC__ && __GNUC__ >= 4
#define ATTRIBUTE_SENTINEL __attribute__ ((sentinel))
#else // ! __GNUC__ || __GNUC__ < 4
#define ATTRIBUTE_SENTINEL
#endif // ! __GNUC__ || __GNUC__ < 4

#define N_ELEMENTS(a) (sizeof (a) / sizeof ((a)[0]))

#define BLOCK_START  do {
#define BLOCK_END    } while (0)

#define MIN(a, b)  ((a) < (b) ? (a) : (b))
#define MAX(a, b)  ((a) > (b) ? (a) : (b))

// --- Logging -----------------------------------------------------------------

static void
log_message_syslog (int prio, const char *quote, const char *fmt, va_list ap)
{
	va_list va;
	va_copy (va, ap);
	int size = vsnprintf (NULL, 0, fmt, va);
	va_end (va);
	if (size < 0)
		return;

	char buf[size + 1];
	if (vsnprintf (buf, sizeof buf, fmt, ap) >= 0)
		syslog (prio, "%s%s", quote, buf);
}

static void
log_message_stdio (int prio, const char *quote, const char *fmt, va_list ap)
{
	(void) prio;
	FILE *stream = stderr;

	fputs (quote, stream);
	vfprintf (stream, fmt, ap);
	fputs ("\n", stream);
}

static void (*g_log_message_real) (int, const char *, const char *, va_list)
	= log_message_stdio;

static void
log_message (int priority, const char *quote, const char *fmt, ...)
	ATTRIBUTE_PRINTF (3, 4);

static void
log_message (int priority, const char *quote, const char *fmt, ...)
{
	va_list ap;
	va_start (ap, fmt);
	g_log_message_real (priority, quote, fmt, ap);
	va_end (ap);
}

// `fatal' is reserved for unexpected failures that would harm further operation

#define print_fatal(...)    log_message (LOG_ERR,     "fatal: ",   __VA_ARGS__)
#define print_error(...)    log_message (LOG_ERR,     "error: ",   __VA_ARGS__)
#define print_warning(...)  log_message (LOG_WARNING, "warning: ", __VA_ARGS__)
#define print_status(...)   log_message (LOG_INFO,    "-- ",       __VA_ARGS__)

#define exit_fatal(...)                                                        \
	BLOCK_START                                                                \
		print_fatal (__VA_ARGS__);                                             \
		exit (EXIT_FAILURE);                                                   \
	BLOCK_END

// --- Debugging and assertions ------------------------------------------------

// We should check everything that may possibly fail with at least a soft
// assertion, so that any causes for problems don't slip us by silently.
//
// `g_soft_asserts_are_deadly' may be useful while running inside a debugger.

static bool g_debug_mode;               ///< Debug messages are printed
static bool g_soft_asserts_are_deadly;  ///< soft_assert() aborts as well

#define print_debug(...)                                                       \
	BLOCK_START                                                                \
		if (g_debug_mode)                                                      \
			log_message (LOG_DEBUG, "debug: ", __VA_ARGS__);                   \
	BLOCK_END

static void
assertion_failure_handler (bool is_fatal, const char *file, int line,
	const char *function, const char *condition)
{
	if (is_fatal)
	{
		print_fatal ("assertion failed [%s:%d in function %s]: %s",
			file, line, function, condition);
		abort ();
	}
	else
		print_debug ("assertion failed [%s:%d in function %s]: %s",
			file, line, function, condition);
}

#define soft_assert(condition)                                                 \
	((condition) ? true :                                                      \
		(assertion_failure_handler (g_soft_asserts_are_deadly,                 \
		__FILE__, __LINE__, __func__, #condition), false))

#define hard_assert(condition)                                                 \
	((condition) ? (void) 0 :                                                  \
		assertion_failure_handler (true,                                       \
		__FILE__, __LINE__, __func__, #condition))

// --- Safe memory management --------------------------------------------------

// When a memory allocation fails and we need the memory, we're usually pretty
// much fucked.  Use the non-prefixed versions when there's a legitimate
// worry that an unrealistic amount of memory may be requested for allocation.

// XXX: it's not a good idea to use print_message() as it may want to allocate
//   further memory for printf() and the output streams.  That may fail.

static void *
xmalloc (size_t n)
{
	void *p = malloc (n);
	if (!p)
		exit_fatal ("malloc: %s", strerror (errno));
	return p;
}

static void *
xcalloc (size_t n, size_t m)
{
	void *p = calloc (n, m);
	if (!p && n && m)
		exit_fatal ("calloc: %s", strerror (errno));
	return p;
}

static void *
xrealloc (void *o, size_t n)
{
	void *p = realloc (o, n);
	if (!p && n)
		exit_fatal ("realloc: %s", strerror (errno));
	return p;
}

static void *
xreallocarray (void *o, size_t n, size_t m)
{
	if (m && n > SIZE_MAX / m)
	{
		errno = ENOMEM;
		exit_fatal ("reallocarray: %s", strerror (errno));
	}
	return xrealloc (o, n * m);
}

static char *
xstrdup (const char *s)
{
	return strcpy (xmalloc (strlen (s) + 1), s);
}

static char *
xstrndup (const char *s, size_t n)
{
	size_t size = strlen (s);
	if (n > size)
		n = size;

	char *copy = xmalloc (n + 1);
	memcpy (copy, s, n);
	copy[n] = '\0';
	return copy;
}

// --- Double-linked list helpers ----------------------------------------------

#define LIST_HEADER(type)                                                      \
	struct type *next;                                                         \
	struct type *prev;

#define LIST_PREPEND(head, link)                                               \
	BLOCK_START                                                                \
		(link)->prev = NULL;                                                   \
		(link)->next = (head);                                                 \
		if ((link)->next)                                                      \
			(link)->next->prev = (link);                                       \
		(head) = (link);                                                       \
	BLOCK_END

#define LIST_UNLINK(head, link)                                                \
	BLOCK_START                                                                \
		if ((link)->prev)                                                      \
			(link)->prev->next = (link)->next;                                 \
		else                                                                   \
			(head) = (link)->next;                                             \
		if ((link)->next)                                                      \
			(link)->next->prev = (link)->prev;                                 \
	BLOCK_END

// --- Dynamically allocated string array --------------------------------------

struct str_vector
{
	char **vector;
	size_t len;
	size_t alloc;
};

static void
str_vector_init (struct str_vector *self)
{
	self->alloc = 4;
	self->len = 0;
	self->vector = xcalloc (sizeof *self->vector, self->alloc);
}

static void
str_vector_free (struct str_vector *self)
{
	unsigned i;
	for (i = 0; i < self->len; i++)
		free (self->vector[i]);

	free (self->vector);
	self->vector = NULL;
}

static void
str_vector_reset (struct str_vector *self)
{
	str_vector_free (self);
	str_vector_init (self);
}

static void
str_vector_add_owned (struct str_vector *self, char *s)
{
	self->vector[self->len] = s;
	if (++self->len >= self->alloc)
		self->vector = xreallocarray (self->vector,
			sizeof *self->vector, (self->alloc <<= 1));
	self->vector[self->len] = NULL;
}

static void
str_vector_add (struct str_vector *self, const char *s)
{
	str_vector_add_owned (self, xstrdup (s));
}

static void
str_vector_add_args (struct str_vector *self, const char *s, ...)
	ATTRIBUTE_SENTINEL;

static void
str_vector_add_args (struct str_vector *self, const char *s, ...)
{
	va_list ap;

	va_start (ap, s);
	while (s)
	{
		str_vector_add (self, s);
		s = va_arg (ap, const char *);
	}
	va_end (ap);
}

static void
str_vector_add_vector (struct str_vector *self, char **vector)
{
	while (*vector)
		str_vector_add (self, *vector++);
}

static void
str_vector_remove (struct str_vector *self, size_t i)
{
	hard_assert (i < self->len);
	free (self->vector[i]);
	memmove (self->vector + i, self->vector + i + 1,
		(self->len-- - i) * sizeof *self->vector);
}

// --- Dynamically allocated strings -------------------------------------------

// Basically a string builder to abstract away manual memory management.

struct str
{
	char *str;                          ///< String data, null terminated
	size_t alloc;                       ///< How many bytes are allocated
	size_t len;                         ///< How long the string actually is
};

/// We don't care about allocations that are way too large for the content, as
/// long as the allocation is below the given threshold.  (Trivial heuristics.)
#define STR_SHRINK_THRESHOLD (1 << 20)

static void
str_init (struct str *self)
{
	self->alloc = 16;
	self->len = 0;
	self->str = strcpy (xmalloc (self->alloc), "");
}

static void
str_free (struct str *self)
{
	free (self->str);
	self->str = NULL;
	self->alloc = 0;
	self->len = 0;
}

static void
str_reset (struct str *self)
{
	str_free (self);
	str_init (self);
}

static char *
str_steal (struct str *self)
{
	char *str = self->str;
	self->str = NULL;
	str_free (self);
	return str;
}

static void
str_ensure_space (struct str *self, size_t n)
{
	// We allocate at least one more byte for the terminating null character
	size_t new_alloc = self->alloc;
	while (new_alloc <= self->len + n)
		new_alloc <<= 1;
	if (new_alloc != self->alloc)
		self->str = xrealloc (self->str, (self->alloc = new_alloc));
}

static void
str_append_data (struct str *self, const char *data, size_t n)
{
	str_ensure_space (self, n);
	memcpy (self->str + self->len, data, n);
	self->len += n;
	self->str[self->len] = '\0';
}

static void
str_append_c (struct str *self, char c)
{
	str_append_data (self, &c, 1);
}

static void
str_append (struct str *self, const char *s)
{
	str_append_data (self, s, strlen (s));
}

static void
str_append_str (struct str *self, const struct str *another)
{
	str_append_data (self, another->str, another->len);
}

static int
str_append_vprintf (struct str *self, const char *fmt, va_list va)
{
	va_list ap;
	int size;

	va_copy (ap, va);
	size = vsnprintf (NULL, 0, fmt, ap);
	va_end (ap);

	if (size < 0)
		return -1;

	va_copy (ap, va);
	str_ensure_space (self, size);
	size = vsnprintf (self->str + self->len, self->alloc - self->len, fmt, ap);
	va_end (ap);

	if (size > 0)
		self->len += size;

	return size;
}

static int
str_append_printf (struct str *self, const char *fmt, ...)
	ATTRIBUTE_PRINTF (2, 3);

static int
str_append_printf (struct str *self, const char *fmt, ...)
{
	va_list ap;

	va_start (ap, fmt);
	int size = str_append_vprintf (self, fmt, ap);
	va_end (ap);
	return size;
}

static void
str_remove_slice (struct str *self, size_t start, size_t length)
{
	size_t end = start + length;
	hard_assert (end <= self->len);
	memmove (self->str + start, self->str + end, self->len - end);
	self->str[self->len -= length] = '\0';

	// Shrink the string if the allocation becomes way too large
	if (self->alloc >= STR_SHRINK_THRESHOLD && self->len < (self->alloc >> 2))
		self->str = xrealloc (self->str, self->alloc >>= 2);
}

// --- Errors ------------------------------------------------------------------

// Error reporting utilities.  Inspired by GError, only much simpler.

struct error
{
	char *message;                      ///< Textual description of the event
};

static void
error_set (struct error **e, const char *message, ...) ATTRIBUTE_PRINTF (2, 3);

static void
error_set (struct error **e, const char *message, ...)
{
	if (!e)
		return;

	va_list ap;
	va_start (ap, message);
	int size = vsnprintf (NULL, 0, message, ap);
	va_end (ap);

	hard_assert (size >= 0);

	struct error *tmp = xmalloc (sizeof *tmp);
	tmp->message = xmalloc (size + 1);

	va_start (ap, message);
	size = vsnprintf (tmp->message, size + 1, message, ap);
	va_end (ap);

	hard_assert (size >= 0);

	soft_assert (*e == NULL);
	*e = tmp;
}

static void
error_free (struct error *e)
{
	free (e->message);
	free (e);
}

static void
error_propagate (struct error **destination, struct error *source)
{
	if (!destination)
	{
		error_free (source);
		return;
	}

	soft_assert (*destination == NULL);
	*destination = source;
}

// --- String hash map ---------------------------------------------------------

// The most basic <string, managed pointer> map (or associative array).

struct str_map_link
{
	LIST_HEADER (str_map_link)

	void *data;                         ///< Payload
	size_t key_length;                  ///< Length of the key without '\0'
	char key[];                         ///< The key for this link
};

struct str_map
{
	struct str_map_link **map;          ///< The hash table data itself
	size_t alloc;                       ///< Number of allocated entries
	size_t len;                         ///< Number of entries in the table
	void (*free) (void *);              ///< Callback to destruct the payload

	/// Callback that transforms all key values for storage and comparison;
	/// has to behave exactly like strxfrm().
	size_t (*key_xfrm) (char *dest, const char *src, size_t n);
};

// As long as you don't remove the current entry, you can modify the map.
// Use `link' directly to access the data.

struct str_map_iter
{
	struct str_map *map;                ///< The map we're iterating
	size_t next_index;                  ///< Next table index to search
	struct str_map_link *link;          ///< Current link
};

#define STR_MAP_MIN_ALLOC 16

typedef void (*str_map_free_func) (void *);

static void
str_map_init (struct str_map *self)
{
	self->alloc = STR_MAP_MIN_ALLOC;
	self->len = 0;
	self->free = NULL;
	self->key_xfrm = NULL;
	self->map = xcalloc (self->alloc, sizeof *self->map);
}

static void
str_map_free (struct str_map *self)
{
	struct str_map_link **iter, **end = self->map + self->alloc;
	struct str_map_link *link, *tmp;

	for (iter = self->map; iter < end; iter++)
		for (link = *iter; link; link = tmp)
		{
			tmp = link->next;
			if (self->free)
				self->free (link->data);
			free (link);
		}

	free (self->map);
	self->map = NULL;
}

static void
str_map_iter_init (struct str_map_iter *self, struct str_map *map)
{
	self->map = map;
	self->next_index = 0;
	self->link = NULL;
}

static void *
str_map_iter_next (struct str_map_iter *self)
{
	struct str_map *map = self->map;
	if (self->link)
		self->link = self->link->next;
	while (!self->link)
	{
		if (self->next_index >= map->alloc)
			return NULL;
		self->link = map->map[self->next_index++];
	}
	return self->link->data;
}

static uint64_t
str_map_hash (const char *s, size_t len)
{
	static unsigned char key[16] = "SipHash 2-4 key!";
	return siphash (key, (const void *) s, len);
}

static uint64_t
str_map_pos (struct str_map *self, const char *s)
{
	size_t mask = self->alloc - 1;
	return str_map_hash (s, strlen (s)) & mask;
}

static uint64_t
str_map_link_hash (struct str_map_link *self)
{
	return str_map_hash (self->key, self->key_length);
}

static void
str_map_resize (struct str_map *self, size_t new_size)
{
	struct str_map_link **old_map = self->map;
	size_t i, old_size = self->alloc;

	// Only powers of two, so that we don't need to compute the modulo
	hard_assert ((new_size & (new_size - 1)) == 0);
	size_t mask = new_size - 1;

	self->alloc = new_size;
	self->map = xcalloc (self->alloc, sizeof *self->map);
	for (i = 0; i < old_size; i++)
	{
		struct str_map_link *iter = old_map[i], *next_iter;
		while (iter)
		{
			next_iter = iter->next;
			uint64_t pos = str_map_link_hash (iter) & mask;
			LIST_PREPEND (self->map[pos], iter);
			iter = next_iter;
		}
	}

	free (old_map);
}

static void
str_map_set_real (struct str_map *self, const char *key, void *value)
{
	uint64_t pos = str_map_pos (self, key);
	struct str_map_link *iter = self->map[pos];
	for (; iter; iter = iter->next)
	{
		if (strcmp (key, iter->key))
			continue;

		// Storing the same data doesn't destroy it
		if (self->free && value != iter->data)
			self->free (iter->data);

		if (value)
		{
			iter->data = value;
			return;
		}

		LIST_UNLINK (self->map[pos], iter);
		free (iter);
		self->len--;

		// The array should be at least 1/4 full
		if (self->alloc >= (STR_MAP_MIN_ALLOC << 2)
		 && self->len < (self->alloc >> 2))
			str_map_resize (self, self->alloc >> 2);
		return;
	}

	if (!value)
		return;

	if (self->len >= self->alloc)
	{
		str_map_resize (self, self->alloc << 1);
		pos = str_map_pos (self, key);
	}

	// Link in a new element for the given <key, value> pair
	size_t key_length = strlen (key);
	struct str_map_link *link = xmalloc (sizeof *link + key_length + 1);
	link->data = value;
	link->key_length = key_length;
	memcpy (link->key, key, key_length + 1);

	LIST_PREPEND (self->map[pos], link);
	self->len++;
}

static void
str_map_set (struct str_map *self, const char *key, void *value)
{
	if (!self->key_xfrm)
	{
		str_map_set_real (self, key, value);
		return;
	}
	char tmp[self->key_xfrm (NULL, key, 0) + 1];
	self->key_xfrm (tmp, key, sizeof tmp);
	str_map_set_real (self, tmp, value);
}

static void *
str_map_find_real (struct str_map *self, const char *key)
{
	struct str_map_link *iter = self->map[str_map_pos (self, key)];
	for (; iter; iter = iter->next)
		if (!strcmp (key, (const char *) iter + sizeof *iter))
			return iter->data;
	return NULL;
}

static void *
str_map_find (struct str_map *self, const char *key)
{
	if (!self->key_xfrm)
		return str_map_find_real (self, key);

	char tmp[self->key_xfrm (NULL, key, 0) + 1];
	self->key_xfrm (tmp, key, sizeof tmp);
	return str_map_find_real (self, tmp);
}

// --- File descriptor utilities -----------------------------------------------

static void
set_cloexec (int fd)
{
	soft_assert (fcntl (fd, F_SETFD, fcntl (fd, F_GETFD) | FD_CLOEXEC) != -1);
}

static bool
set_blocking (int fd, bool blocking)
{
	int flags = fcntl (fd, F_GETFL);
	hard_assert (flags != -1);

	bool prev = !(flags & O_NONBLOCK);
	if (blocking)
		flags &= ~O_NONBLOCK;
	else
		flags |=  O_NONBLOCK;

	hard_assert (fcntl (fd, F_SETFL, flags) != -1);
	return prev;
}

static void
xclose (int fd)
{
	while (close (fd) == -1)
		if (!soft_assert (errno == EINTR))
			break;
}

// --- Polling -----------------------------------------------------------------

// Basically the poor man's GMainLoop/libev/libuv.  It might make some sense
// to instead use those tested and proven libraries but we don't need much
// and it's interesting to implement.

// At the moment the FD's are stored in an unsorted array.  This is not ideal
// complexity-wise but I don't think I have much of a choice with poll(),
// and neither with epoll for that matter.
//
//                         unsorted array       sorted array
//           search             O(n)       O(log n) [O(log log n)]
//           insert by fd       O(n)                O(n)
//           delete by fd       O(n)                O(n)
//
// Insertion in the unsorted array can be reduced to O(1) if I maintain a
// bitmap of present FD's but that's still not a huge win.
//
// I don't expect this to be much of an issue, as there are typically not going
// to be that many FD's to watch, and the linear approach is cache-friendly.

typedef void (*poller_dispatcher_func) (const struct pollfd *, void *);
typedef void (*poller_timer_func) (void *);

#define POLLER_MIN_ALLOC 16

struct poller_timer_info
{
	int64_t when;                       ///< When is the timer to expire
	poller_timer_func dispatcher;       ///< Event dispatcher
	void *user_data;                    ///< User data
};

struct poller_timers
{
	struct poller_timer_info *info;     ///< Min-heap of timers
	size_t len;                         ///< Number of scheduled timers
	size_t alloc;                       ///< Number of timers allocated
};

static void
poller_timers_init (struct poller_timers *self)
{
	self->alloc = POLLER_MIN_ALLOC;
	self->len = 0;
	self->info = xmalloc (self->alloc * sizeof *self->info);
}

static void
poller_timers_free (struct poller_timers *self)
{
	free (self->info);
}

static int64_t
poller_timers_get_current_time (void)
{
#ifdef _POSIX_TIMERS
	struct timespec tp;
	hard_assert (clock_gettime (CLOCK_BEST, &tp) != -1);
	return (int64_t) tp.tv_sec * 1000 + (int64_t) tp.tv_nsec / 1000000;
#else
	struct timeval tp;
	gettimeofday (&tp, NULL);
	return (int64_t) tp.tv_sec * 1000 + (int64_t) tp.tv_usec / 1000;
#endif
}

static void
poller_timers_heapify_down (struct poller_timers *self, size_t index)
{
	typedef struct poller_timer_info info_t;
	info_t *end = self->info + self->len;

	while (true)
	{
		info_t *parent = self->info + index;
		info_t *left   = self->info + 2 * index + 1;
		info_t *right  = self->info + 2 * index + 2;

		info_t *largest = parent;
		if (left  < end && left->when  > largest->when)
			largest = left;
		if (right < end && right->when > largest->when)
			largest = right;
		if (parent == largest)
			break;

		info_t tmp = *parent;
		*parent = *largest;
		*largest = tmp;

		index = largest - self->info;
	}
}

static void
poller_timers_remove_at_index (struct poller_timers *self, size_t index)
{
	hard_assert (index < self->len);
	if (index == --self->len)
		return;

	self->info[index] = self->info[self->len];
	poller_timers_heapify_down (self, index);
}

static void
poller_timers_dispatch (struct poller_timers *self)
{
	int64_t now = poller_timers_get_current_time ();
	while (self->len && self->info->when <= now)
	{
		struct poller_timer_info info = *self->info;
		poller_timers_remove_at_index (self, 0);
		info.dispatcher (info.user_data);
	}
}

static void
poller_timers_heapify_up (struct poller_timers *self, size_t index)
{
	while (index != 0)
	{
		size_t parent = (index - 1) / 2;
		if (self->info[parent].when <= self->info[index].when)
			break;

		struct poller_timer_info tmp = self->info[parent];
		self->info[parent] = self->info[index];
		self->info[index] = tmp;

		index = parent;
	}
}

static ssize_t
poller_timers_find (struct poller_timers *self,
	poller_timer_func dispatcher, void *data)
{
	// NOTE: there may be duplicates.
	for (size_t i = 0; i < self->len; i++)
		if (self->info[i].dispatcher == dispatcher
		 && self->info[i].user_data == data)
			return i;
	return -1;
}

static ssize_t
poller_timers_find_by_data (struct poller_timers *self, void *data)
{
	for (size_t i = 0; i < self->len; i++)
		if (self->info[i].user_data == data)
			return i;
	return -1;
}

static void
poller_timers_add (struct poller_timers *self,
	poller_timer_func dispatcher, void *data, int timeout_ms)
{
	if (self->len == self->alloc)
		self->info = xreallocarray (self->info,
			self->alloc <<= 1, sizeof *self->info);

	self->info[self->len] = (struct poller_timer_info) {
		.when = poller_timers_get_current_time () + timeout_ms,
		.dispatcher = dispatcher, .user_data = data };
	poller_timers_heapify_up (self, self->len++);
}

static int
poller_timers_get_poll_timeout (struct poller_timers *self)
{
	if (!self->len)
		return -1;

	int64_t timeout = self->info->when - poller_timers_get_current_time ();
	if (timeout <= 0)
		return 0;
	if (timeout > INT_MAX)
		return INT_MAX;
	return timeout;
}

#ifdef __linux__

// I don't really need this, I've basically implemented this just because I can.

#include <sys/epoll.h>

struct poller_info
{
	int fd;                             ///< Our file descriptor
	short events;                       ///< The poll() events we registered for
	poller_dispatcher_func dispatcher;  ///< Event dispatcher
	void *user_data;                    ///< User data
};

struct poller
{
	int epoll_fd;                       ///< The epoll FD
	struct poller_info **info;          ///< Information associated with each FD
	struct epoll_event *revents;        ///< Output array for epoll_wait()
	size_t len;                         ///< Number of polled descriptors
	size_t alloc;                       ///< Number of entries allocated

	struct poller_timers timers;        ///< Timeouts

	/// Index of the element in `revents' that's about to be dispatched next.
	int dispatch_next;

	/// The total number of entries stored in `revents' by epoll_wait().
	int dispatch_total;
};

static void
poller_init (struct poller *self)
{
	self->epoll_fd = epoll_create (POLLER_MIN_ALLOC);
	hard_assert (self->epoll_fd != -1);
	set_cloexec (self->epoll_fd);

	self->len = 0;
	self->alloc = POLLER_MIN_ALLOC;
	self->info = xcalloc (self->alloc, sizeof *self->info);
	self->revents = xcalloc (self->alloc, sizeof *self->revents);

	poller_timers_init (&self->timers);

	self->dispatch_next = 0;
	self->dispatch_total = 0;
}

static void
poller_free (struct poller *self)
{
	for (size_t i = 0; i < self->len; i++)
	{
		struct poller_info *info = self->info[i];
		hard_assert (epoll_ctl (self->epoll_fd,
			EPOLL_CTL_DEL, info->fd, (void *) "") != -1);
		free (info);
	}

	poller_timers_free (&self->timers);

	xclose (self->epoll_fd);
	free (self->info);
	free (self->revents);
}

static ssize_t
poller_find_by_fd (struct poller *self, int fd)
{
	for (size_t i = 0; i < self->len; i++)
		if (self->info[i]->fd == fd)
			return i;
	return -1;
}

static void
poller_ensure_space (struct poller *self)
{
	if (self->len < self->alloc)
		return;

	self->alloc <<= 1;
	hard_assert (self->alloc != 0);

	self->revents = xreallocarray
		(self->revents, sizeof *self->revents, self->alloc);
	self->info = xreallocarray
		(self->info, sizeof *self->info, self->alloc);
}

static short
poller_epoll_to_poll_events (uint32_t events)
{
	short result = 0;
	if (events & EPOLLIN)   result |= POLLIN;
	if (events & EPOLLOUT)  result |= POLLOUT;
	if (events & EPOLLERR)  result |= POLLERR;
	if (events & EPOLLHUP)  result |= POLLHUP;
	if (events & EPOLLPRI)  result |= POLLPRI;
	return result;
}

static uint32_t
poller_poll_to_epoll_events (short events)
{
	uint32_t result = 0;
	if (events & POLLIN)   result |= EPOLLIN;
	if (events & POLLOUT)  result |= EPOLLOUT;
	if (events & POLLERR)  result |= EPOLLERR;
	if (events & POLLHUP)  result |= EPOLLHUP;
	if (events & POLLPRI)  result |= EPOLLPRI;
	return result;
}

static void
poller_set (struct poller *self, int fd, short events,
	poller_dispatcher_func dispatcher, void *data)
{
	ssize_t index = poller_find_by_fd (self, fd);
	bool modifying = true;
	if (index == -1)
	{
		poller_ensure_space (self);
		self->info[index = self->len++] = xcalloc (1, sizeof **self->info);
		modifying = false;
	}

	struct poller_info *info = self->info[index];
	info->fd = fd;
	info->events = events;
	info->dispatcher = dispatcher;
	info->user_data = data;

	struct epoll_event event;
	event.events = poller_poll_to_epoll_events (events);
	event.data.ptr = info;
	hard_assert (epoll_ctl (self->epoll_fd,
		modifying ? EPOLL_CTL_MOD : EPOLL_CTL_ADD, fd, &event) != -1);
}

static void
poller_remove_from_dispatch (struct poller *self,
	const struct poller_info *info)
{
	if (!self->dispatch_total)
		return;

	int i;
	for (i = self->dispatch_next; i < self->dispatch_total; i++)
		if (self->revents[i].data.ptr == info)
			break;
	if (i == self->dispatch_total)
		return;

	if (i != --self->dispatch_total)
		self->revents[i] = self->revents[self->dispatch_total];
}

static void
poller_remove_at_index (struct poller *self, size_t index)
{
	hard_assert (index < self->len);
	struct poller_info *info = self->info[index];

	poller_remove_from_dispatch (self, info);
	hard_assert (epoll_ctl (self->epoll_fd,
		EPOLL_CTL_DEL, info->fd, (void *) "") != -1);

	free (info);
	if (index != --self->len)
		self->info[index] = self->info[self->len];
}

static void
poller_run (struct poller *self)
{
	// Not reentrant
	hard_assert (!self->dispatch_total);

	int n_fds;
	do
		n_fds = epoll_wait (self->epoll_fd, self->revents, self->len,
			poller_timers_get_poll_timeout (&self->timers));
	while (n_fds == -1 && errno == EINTR);

	if (n_fds == -1)
		exit_fatal ("%s: %s", "epoll", strerror (errno));

	poller_timers_dispatch (&self->timers);

	self->dispatch_next = 0;
	self->dispatch_total = n_fds;

	while (self->dispatch_next < self->dispatch_total)
	{
		struct epoll_event *revents = self->revents + self->dispatch_next;
		struct poller_info *info = revents->data.ptr;

		struct pollfd pfd;
		pfd.fd = info->fd;
		pfd.revents = poller_epoll_to_poll_events (revents->events);
		pfd.events = info->events;

		self->dispatch_next++;
		info->dispatcher (&pfd, info->user_data);
	}

	self->dispatch_next = 0;
	self->dispatch_total = 0;
}

#else  // !__linux__

struct poller_info
{
	poller_dispatcher_func dispatcher;  ///< Event dispatcher
	void *user_data;                    ///< User data
};

struct poller
{
	struct pollfd *fds;                 ///< Polled descriptors
	struct poller_info *fds_info;       ///< Additional information for each FD
	size_t len;                         ///< Number of polled descriptors
	size_t alloc;                       ///< Number of entries allocated

	struct poller_timers timers;        ///< Timers
	int dispatch_next;                  ///< The next dispatched FD or -1
};

static void
poller_init (struct poller *self)
{
	self->alloc = POLLER_MIN_ALLOC;
	self->len = 0;
	self->fds = xcalloc (self->alloc, sizeof *self->fds);
	self->fds_info = xcalloc (self->alloc, sizeof *self->fds_info);
	poller_timers_init (&self->timers);
	self->dispatch_next = -1;
}

static void
poller_free (struct poller *self)
{
	free (self->fds);
	free (self->fds_info);
	poller_timers_free (&self->timers);
}

static ssize_t
poller_find_by_fd (struct poller *self, int fd)
{
	for (size_t i = 0; i < self->len; i++)
		if (self->fds[i].fd == fd)
			return i;
	return -1;
}

static void
poller_ensure_space (struct poller *self)
{
	if (self->len < self->alloc)
		return;

	self->alloc <<= 1;
	self->fds = xreallocarray (self->fds, sizeof *self->fds, self->alloc);
	self->fds_info = xreallocarray
		(self->fds_info, sizeof *self->fds_info, self->alloc);
}

static void
poller_set (struct poller *self, int fd, short events,
	poller_dispatcher_func dispatcher, void *data)
{
	ssize_t index = poller_find_by_fd (self, fd);
	if (index == -1)
	{
		poller_ensure_space (self);
		index = self->len++;
	}

	struct pollfd *new_entry = self->fds + index;
	memset (new_entry, 0, sizeof *new_entry);
	new_entry->fd = fd;
	new_entry->events = events;

	self->fds_info[index] = (struct poller_info) { dispatcher, data };
}

static void
poller_remove_at_index (struct poller *self, size_t index)
{
	hard_assert (index < self->len);
	if (index == --self->len)
		return;

	// Make sure that we don't disrupt the dispatch loop; kind of crude
	if ((int) index < self->dispatch_next)
	{
		memmove (self->fds + index, self->fds + index + 1,
			(self->len - index) * sizeof *self->fds);
		memmove (self->fds_info + index, self->fds_info + index + 1,
			(self->len - index) * sizeof *self->fds_info);
		self->dispatch_next--;
	}
	else
	{
		self->fds[index]      = self->fds[self->len];
		self->fds_info[index] = self->fds_info[self->len];
	}
}

static void
poller_run (struct poller *self)
{
	// Not reentrant
	hard_assert (self->dispatch_next == -1);

	int result;
	do
		result = poll (self->fds, self->len,
			poller_timers_get_poll_timeout (&self->timers));
	while (result == -1 && errno == EINTR);

	if (result == -1)
		exit_fatal ("%s: %s", "poll", strerror (errno));

	poller_timers_dispatch (&self->timers);

	for (int i = 0; i < (int) self->len; )
	{
		struct pollfd pfd = self->fds[i];
		struct poller_info *info = self->fds_info + i;
		self->dispatch_next = ++i;
		if (pfd.revents)
			info->dispatcher (&pfd, info->user_data);
		i = self->dispatch_next;
	}

	self->dispatch_next = -1;
}

#endif  // !__linux__

// --- Utilities ---------------------------------------------------------------

static void
split_str_ignore_empty (const char *s, char delimiter, struct str_vector *out)
{
	const char *begin = s, *end;

	while ((end = strchr (begin, delimiter)))
	{
		if (begin != end)
			str_vector_add_owned (out, xstrndup (begin, end - begin));
		begin = ++end;
	}

	if (*begin)
		str_vector_add (out, begin);
}

static char *
strip_str_in_place (char *s, const char *stripped_chars)
{
	char *end = s + strlen (s);
	while (end > s && strchr (stripped_chars, end[-1]))
		*--end = '\0';

	char *start = s + strspn (s, stripped_chars);
	if (start > s)
		memmove (s, start, end - start + 1);
	return s;
}

static char *
join_str_vector (const struct str_vector *v, char delimiter)
{
	if (!v->len)
		return xstrdup ("");

	struct str result;
	str_init (&result);
	str_append (&result, v->vector[0]);
	for (size_t i = 1; i < v->len; i++)
		str_append_printf (&result, "%c%s", delimiter, v->vector[i]);
	return str_steal (&result);
}

static char *xstrdup_printf (const char *, ...) ATTRIBUTE_PRINTF (1, 2);

static char *
xstrdup_printf (const char *format, ...)
{
	va_list ap;
	struct str tmp;
	str_init (&tmp);
	va_start (ap, format);
	str_append_vprintf (&tmp, format, ap);
	va_end (ap);
	return str_steal (&tmp);
}

static bool
str_append_env_path (struct str *output, const char *var, bool only_absolute)
{
	const char *value = getenv (var);

	if (!value || (only_absolute && *value != '/'))
		return false;

	str_append (output, value);
	return true;
}

static void
get_xdg_home_dir (struct str *output, const char *var, const char *def)
{
	str_reset (output);
	if (!str_append_env_path (output, var, true))
	{
		str_append_env_path (output, "HOME", false);
		str_append_c (output, '/');
		str_append (output, def);
	}
}

static void
get_xdg_config_dirs (struct str_vector *out)
{
	struct str config_home;
	str_init (&config_home);
	get_xdg_home_dir (&config_home, "XDG_CONFIG_HOME", ".config");
	str_vector_add (out, config_home.str);
	str_free (&config_home);

	const char *xdg_config_dirs;
	if ((xdg_config_dirs = getenv ("XDG_CONFIG_DIRS")))
		split_str_ignore_empty (xdg_config_dirs, ':', out);
}

static char *
resolve_config_filename (const char *filename)
{
	// Absolute path is absolute
	if (*filename == '/')
		return xstrdup (filename);

	struct str_vector paths;
	str_vector_init (&paths);
	get_xdg_config_dirs (&paths);

	struct str file;
	str_init (&file);

	char *result = NULL;
	for (unsigned i = 0; i < paths.len; i++)
	{
		// As per spec, relative paths are ignored
		if (*paths.vector[i] != '/')
			continue;

		str_reset (&file);
		str_append_printf (&file, "%s/" PROGRAM_NAME "/%s",
			paths.vector[i], filename);

		struct stat st;
		if (!stat (file.str, &st))
		{
			result = str_steal (&file);
			break;
		}
	}

	str_vector_free (&paths);
	str_free (&file);
	return result;
}

static bool
ensure_directory_existence (const char *path, struct error **e)
{
	struct stat st;

	if (stat (path, &st))
	{
		if (mkdir (path, S_IRWXU | S_IRWXG | S_IRWXO))
		{
			error_set (e, "cannot create directory `%s': %s",
				path, strerror (errno));
			return false;
		}
	}
	else if (!S_ISDIR (st.st_mode))
	{
		error_set (e, "cannot create directory `%s': %s",
			path, "file exists but is not a directory");
		return false;
	}
	return true;
}

static bool
mkdir_with_parents (char *path, struct error **e)
{
	char *p = path;

	// XXX: This is prone to the TOCTTOU problem.  The solution would be to
	//   rewrite the function using the {mkdir,fstat}at() functions from
	//   POSIX.1-2008, ideally returning a file descriptor to the open
	//   directory, with the current code as a fallback.  Or to use chdir().
	while ((p = strchr (p + 1, '/')))
	{
		*p = '\0';
		bool success = ensure_directory_existence (path, e);
		*p = '/';

		if (!success)
			return false;
	}

	return ensure_directory_existence (path, e);
}

static bool
set_boolean_if_valid (bool *out, const char *s)
{
	if      (!strcasecmp (s, "yes"))    *out = true;
	else if (!strcasecmp (s, "no"))     *out = false;
	else if (!strcasecmp (s, "on"))     *out = true;
	else if (!strcasecmp (s, "off"))    *out = false;
	else if (!strcasecmp (s, "true"))   *out = true;
	else if (!strcasecmp (s, "false"))  *out = false;
	else return false;

	return true;
}

static bool
xstrtoul (unsigned long *out, const char *s, int base)
{
	char *end;
	errno = 0;
	*out = strtoul (s, &end, base);
	return errno == 0 && !*end && end != s;
}

static bool
read_line (FILE *fp, struct str *s)
{
	int c;
	bool at_end = true;

	str_reset (s);
	while ((c = fgetc (fp)) != EOF)
	{
		at_end = false;
		if (c == '\r')
			continue;
		if (c == '\n')
			break;
		str_append_c (s, c);
	}

	return !at_end;
}

#define XSSL_ERROR_TRY_AGAIN INT_MAX

/// A small wrapper around SSL_get_error() to simplify further handling
static int
xssl_get_error (SSL *ssl, int result, const char **error_info)
{
	int error = SSL_get_error (ssl, result);
	switch (error)
	{
	case SSL_ERROR_NONE:
	case SSL_ERROR_ZERO_RETURN:
	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
		return error;
	case SSL_ERROR_SYSCALL:
		if ((error = ERR_get_error ()))
			*error_info = ERR_error_string (error, NULL);
		else if (result == 0)
			// An EOF that's not according to the protocol is still an EOF
			return SSL_ERROR_ZERO_RETURN;
		else
		{
			if (errno == EINTR)
				return XSSL_ERROR_TRY_AGAIN;
			*error_info = strerror (errno);
		}
		return SSL_ERROR_SSL;
	default:
		if ((error = ERR_get_error ()))
			*error_info = ERR_error_string (error, NULL);
		else
			*error_info = "Unknown error";
		return SSL_ERROR_SSL;
	}
}

static char *
format_host_port_pair (const char *host, const char *port)
{
	// IPv6 addresses mess with the "colon notation"; let's go with RFC 2732
	if (strchr (host, ':'))
		return xstrdup_printf ("[%s]:%s", host, port);
	return xstrdup_printf ("%s:%s", host, port);
}

// --- Regular expressions -----------------------------------------------------

static regex_t *
regex_compile (const char *regex, int flags, struct error **e)
{
	regex_t *re = xmalloc (sizeof *re);
	int err = regcomp (re, regex, flags);
	if (!err)
		return re;

	char buf[regerror (err, re, NULL, 0)];
	regerror (err, re, buf, sizeof buf);

	free (re);
	error_set (e, "%s: %s", "failed to compile regular expression", buf);
	return NULL;
}

static void
regex_free (void *regex)
{
	regfree (regex);
	free (regex);
}

// The cost of hashing a string is likely to be significantly smaller than that
// of compiling the whole regular expression anew, so here is a simple cache.
// Adding basic support for subgroups is easy: check `re_nsub' and output into
// a `struct str_vector' (if all we want is the substrings).

static void
regex_cache_init (struct str_map *cache)
{
	str_map_init (cache);
	cache->free = regex_free;
}

static bool
regex_cache_match (struct str_map *cache, const char *regex, int flags,
	const char *s, struct error **e)
{
	regex_t *re = str_map_find (cache, regex);
	if (!re)
	{
		re = regex_compile (regex, flags, e);
		if (!re)
			return false;
		str_map_set (cache, regex, re);
	}
	return regexec (re, s, 0, NULL, 0) != REG_NOMATCH;
}

// --- Configuration -----------------------------------------------------------

// The keys are stripped of surrounding whitespace, the values are not.

struct config_item
{
	const char *key;
	const char *default_value;
	const char *description;
};

static void
load_config_defaults (struct str_map *config, const struct config_item *table)
{
	for (; table->key != NULL; table++)
		if (table->default_value)
			str_map_set (config, table->key, xstrdup (table->default_value));
		else
			str_map_set (config, table->key, NULL);
}

static bool
read_config_file (struct str_map *config, struct error **e)
{
	char *filename = resolve_config_filename (PROGRAM_NAME ".conf");
	if (!filename)
		return true;

	FILE *fp = fopen (filename, "r");
	if (!fp)
	{
		error_set (e, "could not open `%s' for reading: %s",
			filename, strerror (errno));
		return false;
	}

	struct str line;
	str_init (&line);

	bool errors = false;
	for (unsigned line_no = 1; read_line (fp, &line); line_no++)
	{
		char *start = line.str;
		if (*start == '#')
			continue;

		while (isspace (*start))
			start++;

		char *end = strchr (start, '=');
		if (end)
		{
			char *value = end + 1;
			do
				*end = '\0';
			while (isspace (*--end));

			str_map_set (config, start, xstrdup (value));
		}
		else if (*start)
		{
			error_set (e, "line %u in config: %s", line_no, "malformed input");
			errors = true;
			break;
		}
	}

	str_free (&line);
	fclose (fp);
	return !errors;
}

static char *
write_default_config (const char *filename, const char *prolog,
	const struct config_item *table, struct error **e)
{
	struct str path, base;

	str_init (&path);
	str_init (&base);

	if (filename)
	{
		char *tmp = xstrdup (filename);
		str_append (&path, dirname (tmp));
		strcpy (tmp, filename);
		str_append (&base, basename (tmp));
		free (tmp);
	}
	else
	{
		get_xdg_home_dir (&path, "XDG_CONFIG_HOME", ".config");
		str_append (&path, "/" PROGRAM_NAME);
		str_append (&base, PROGRAM_NAME ".conf");
	}

	if (!mkdir_with_parents (path.str, e))
		goto error;

	str_append_c (&path, '/');
	str_append_str (&path, &base);

	FILE *fp = fopen (path.str, "w");
	if (!fp)
	{
		error_set (e, "could not open `%s' for writing: %s",
			path.str, strerror (errno));
		goto error;
	}

	if (prolog)
		fputs (prolog, fp);

	errno = 0;
	for (; table->key != NULL; table++)
	{
		fprintf (fp, "# %s\n", table->description);
		if (table->default_value)
			fprintf (fp, "%s=%s\n", table->key, table->default_value);
		else
			fprintf (fp, "#%s=\n", table->key);
	}
	fclose (fp);
	if (errno)
	{
		error_set (e, "writing to `%s' failed: %s", path.str, strerror (errno));
		goto error;
	}

	str_free (&base);
	return str_steal (&path);

error:
	str_free (&base);
	str_free (&path);
	return NULL;

}

static void
call_write_default_config (const char *hint, const struct config_item *table)
{
	static const char *prolog =
	"# " PROGRAM_NAME " " PROGRAM_VERSION " configuration file\n"
	"#\n"
	"# Relative paths are searched for in ${XDG_CONFIG_HOME:-~/.config}\n"
	"# /" PROGRAM_NAME " as well as in $XDG_CONFIG_DIRS/" PROGRAM_NAME "\n"
	"\n";

	struct error *e = NULL;
	char *filename = write_default_config (hint, prolog, table, &e);
	if (!filename)
	{
		print_error ("%s", e->message);
		error_free (e);
		exit (EXIT_FAILURE);
	}
	print_status ("configuration written to `%s'", filename);
	free (filename);
}
