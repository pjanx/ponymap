/*
 * plugin-api.h: plugin API for ponymap
 *
 * Copyright (c) 2014, Přemysl Janouch <p@janouch.name>
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

#ifndef PLUGIN_API_H
#define PLUGIN_API_H

// This API is meant to be as simplistic as is realistically possible.

/// The version of the API, and by extension, of all the following structs
#define API_VERSION 1

///< Opaque object with data relating to a service scan
struct unit;

enum
{
	SERVICE_SUPPORTS_TLS = (1 << 0)     ///< Plain TLS can be used
};

struct service
{
	const char *name;                   ///< Name of the service
	int flags;                          ///< Service flags
	void *user_data;                    ///< User data

	// scan_init -> on_data* -> [on_eof/on_error] -> on_stopped -> scan_free

	/// Initialize a scan, returning a handle to it
	void *(*scan_init) (struct service *self, struct unit *u);

	/// Destroy the handle created for the scan
	void (*scan_free) (void *handle);

	/// We have received some data from the peer
	void (*on_data) (void *handle, const void *data, size_t len);

	/// Server has closed the connection
	void (*on_eof) (void *handle);

	// XXX: do we need these at all?  Is there any use for them?

	/// Network or other error has occured
	void (*on_error) (void *handle);

	/// The scan has been stopped
	void (*on_stopped) (void *handle);
};

struct plugin_api
{
	/// Register the plugin for a service
	void (*register_service) (void *ctx, struct service *info);

	/// Retrieve an item from the configuration
	const char *(*get_config) (void *ctx, const char *key);

	/// Get the IP address of the target as a string
	const char *(*unit_get_address) (struct unit *u);

	/// Send some data to the peer
	ssize_t (*unit_write) (struct unit *u, const void *buf, size_t len);

	/// Mark the scan as un/successful
	void (*unit_set_success) (struct unit *u, bool success);

	/// Add some information resulting from the scan
	void (*unit_add_info) (struct unit *u, const char *result);

	/// Abort the scan, close the connection
	void (*unit_stop) (struct unit *u);
};

struct plugin_info
{
	/// Version of the API used by this plugin
	int32_t api_version;

	/// Let the plugin initialize itself and register any services.
	/// The context needs to be passed to the relevant API functions.
	bool (*initialize) (void *ctx, struct plugin_api *api);
};

#endif  // ! PLUGIN_API_H
