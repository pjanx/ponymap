/*
 * lua-loader.c: Lua plugin loader plugin
 *
 * Copyright (c) 2015, Přemysl Janouch <p.janouch@gmail.com>
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

// I can't really recommend using this interface as it adds a lot of overhead

#include "../utils.c"
#include "../plugin-api.h"

#include <dirent.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

// --- Utilities ---------------------------------------------------------------

static struct plugin_data
{
	void *ctx;                          ///< Application context
	struct plugin_api *api;             ///< Plugin API vtable
}
g_data;

static void *
xlua_alloc (void *ud, void *ptr, size_t o_size, size_t n_size)
{
	(void) ud;
	(void) o_size;

	if (n_size)
		return realloc (ptr, n_size);

	free (ptr);
	return NULL;
}

static int
xlua_panic (lua_State *L)
{
	// XXX: we might be able to do something better
	print_fatal ("Lua panicked: %s", lua_tostring (L, -1));
	lua_close (L);
	exit (EXIT_FAILURE);
	return 0;
}

// --- Unit wrapper ------------------------------------------------------------

struct unit_wrapper
{
	struct unit *unit;                  ///< The underlying unit
};

#define UNIT_METATABLE "unit"

static int
xlua_unit_get_address (lua_State *L)
{
	struct unit_wrapper *data = luaL_checkudata (L, 1, UNIT_METATABLE);
	lua_pushstring (L, g_data.api->unit_get_address (data->unit));
	return 1;
}

static int
xlua_unit_write (lua_State *L)
{
	struct unit_wrapper *data = luaL_checkudata (L, 1, UNIT_METATABLE);
	size_t buffer_len;
	const char *buffer = luaL_checklstring (L, 2, &buffer_len);
	lua_pushinteger (L, g_data.api->unit_write
		(data->unit, buffer, buffer_len));
	return 1;
}

static int
xlua_unit_set_success (lua_State *L)
{
	struct unit_wrapper *data = luaL_checkudata (L, 1, UNIT_METATABLE);
	bool success = lua_toboolean (L, 2);
	g_data.api->unit_set_success (data->unit, success);
	return 0;
}

static int
xlua_unit_add_info (lua_State *L)
{
	struct unit_wrapper *data = luaL_checkudata (L, 1, UNIT_METATABLE);
	const char *info = luaL_checkstring (L, 2);
	g_data.api->unit_add_info (data->unit, info);
	return 0;
}

static int
xlua_unit_abort (lua_State *L)
{
	struct unit_wrapper *data = luaL_checkudata (L, 1, UNIT_METATABLE);
	g_data.api->unit_abort (data->unit);
	return 0;
}

static int
xlua_unit_destroy (lua_State *L)
{
	// TODO: when creating the wrapper object, increase the reference
	//   count for the unit and decrease it in here again.  If we don't do
	//   this, the Lua plugin may cause a use-after-free error.
	(void) L;
	return 0;
}

static luaL_Reg xlua_unit_table[] =
{
	{ "get_address",      xlua_unit_get_address },
	{ "write",            xlua_unit_write       },
	{ "set_success",      xlua_unit_set_success },
	{ "add_info",         xlua_unit_add_info    },
	{ "abort",            xlua_unit_abort       },
	{ "__gc",             xlua_unit_destroy     },
	{ NULL,               NULL                  }
};

// --- Scan wrapper ------------------------------------------------------------

struct service_data
{
	struct service *service;            ///< The corresponding service
	lua_State *L;                       ///< Lua state
	int new_scan_cb_ref;                ///< Reference to "new_scan" callback
};

struct scan_data
{
	struct service *service;            ///< The corresponding service
	struct unit *unit;                  ///< The corresponding unit
	lua_State *L;                       ///< Lua state
	int scan_ref;                       ///< Reference to scan data in Lua
};

static void *
scan_init (struct service *self, struct unit *unit)
{
	struct service_data *service = self->user_data;
	lua_geti (service->L, LUA_REGISTRYINDEX, service->new_scan_cb_ref);

	// Wrap the unit in Lua userdata so that Lua code can use it
	struct unit_wrapper *wrapper =
		lua_newuserdata (service->L, sizeof *wrapper);
	wrapper->unit = unit;
	luaL_setmetatable (service->L, UNIT_METATABLE);

	// Ask for a Lua object (table) to use for protocol detection
	if (lua_pcall (service->L, 1, 1, 0))
	{
		print_error ("Lua: service `%s': new_scan: %s",
			service->service->name, lua_tostring (service->L, -1));
		lua_pop (service->L, 1);
		return NULL;
	}

	if (!lua_istable (service->L, -1))
	{
		print_error ("Lua: service `%s': new_scan must return a table",
			service->service->name);
		return NULL;
	}

	// Return a scan handle
	struct scan_data *data = xmalloc (sizeof *data);
	data->service = self;
	data->L = service->L;
	data->scan_ref = luaL_ref (service->L, LUA_REGISTRYINDEX);
	data->unit = unit;
	return data;
}

static void
scan_free (void *handle)
{
	if (!handle)
		return;

	struct scan_data *data = handle;
	luaL_unref (data->L, LUA_REGISTRYINDEX, data->scan_ref);
	free (handle);
}

static void
handle_scan_method_failure (struct scan_data *data)
{
	print_error ("Lua: service `%s': %s", data->service->name,
		lua_tostring (data->L, -1));
	g_data.api->unit_abort (data->unit);
	lua_pop (data->L, 1);
}

static bool
prepare_scan_method (struct scan_data *data, const char *method_name)
{
	if (!data)
		return false;

	lua_geti (data->L, LUA_REGISTRYINDEX, data->scan_ref);
	lua_getfield (data->L, -1, method_name);
	if (lua_isnil (data->L, -1))
	{
		lua_pop (data->L, 2);
		return false;
	}

	if (!lua_isfunction (data->L, -1))
	{
		lua_pop (data->L, 2);
		lua_pushfstring (data->L, "`%s' must be a function", method_name);
		handle_scan_method_failure (data);
		return false;
	}

	// Swap the first two values on the stack, so that the function
	// is first and the object we're calling it on is second
	lua_insert (data->L, -2);
	return true;
}

static void
on_data (void *handle, const void *network_data, size_t len)
{
	struct scan_data *data = handle;
	if (!prepare_scan_method (data, "on_data"))
		return;

	lua_pushlstring (data->L, network_data, len);
	if (lua_pcall (data->L, 2, 0, 0))
		handle_scan_method_failure (data);
}

static void
on_eof (void *handle)
{
	struct scan_data *data = handle;
	if (!prepare_scan_method (data, "on_eof"))
		return;
	if (lua_pcall (data->L, 1, 0, 0))
		handle_scan_method_failure (data);
}

static void
on_error (void *handle)
{
	struct scan_data *data = handle;
	if (!prepare_scan_method (data, "on_error"))
		return;
	if (lua_pcall (data->L, 1, 0, 0))
		handle_scan_method_failure (data);
}

static void
on_aborted (void *handle)
{
	struct scan_data *data = handle;
	if (!prepare_scan_method (data, "on_aborted"))
		return;
	if (lua_pcall (data->L, 1, 0, 0))
		handle_scan_method_failure (data);
}

// --- Top-level interface -----------------------------------------------------

static int
xlua_register_service (lua_State *L)
{
	// Validate and decode the arguments
	luaL_checktype (L, 1, LUA_TTABLE);

	lua_getfield (L, 1, "name");
	if (!lua_isstring (L, -1))
		return luaL_error (L, "service registration failed: "
			"invalid or missing `%s'", "name");
	const char *name = lua_tostring (L, -1);
	lua_pop (L, 1);

	lua_getfield (L, 1, "flags");
	lua_Unsigned flags;
	if (lua_isnil (L, -1))
		flags = 0;
	else if (lua_isinteger (L, -1))
		flags = lua_tointeger (L, -1);
	else
		return luaL_error (L, "service registration failed: "
			"invalid or missing `%s'", "flags");
	lua_pop (L, 1);

	lua_getfield (L, 1, "new_scan");
	if (!lua_isfunction (L, -1))
		return luaL_error (L, "service registration failed: "
			"invalid or missing `%s'", "new_scan");

	// Reference the "new_scan" function for later use
	struct service_data *data = xcalloc (1, sizeof *data);
	data->L = L;
	data->new_scan_cb_ref = luaL_ref (L, LUA_REGISTRYINDEX);

	// Register a new service that proxies calls to Lua code
	struct service *s = data->service = xcalloc (1, sizeof *s);
	s->name       = xstrdup (name);
	s->flags      = flags;
	s->user_data  = data;

	s->scan_init  = scan_init;
	s->scan_free  = scan_free;
	s->on_data    = on_data;
	s->on_eof     = on_eof;
	s->on_error   = on_error;
	s->on_aborted = on_aborted;

	g_data.api->register_service (g_data.ctx, s);
	return 0;
}

static int
xlua_get_config (lua_State *L)
{
	const char *key = luaL_checkstring (L, 1);
	lua_pushstring (L, g_data.api->get_config (g_data.ctx, key));
	return 0;
}

static luaL_Reg xlua_library[] =
{
	{ "register_service", xlua_register_service },
	{ "get_config",       xlua_get_config       },
	{ NULL,               NULL                  }
};

static bool
load_one_plugin (lua_State *L, const char *name, const char *path)
{
	int ret;
	if (!(ret = luaL_loadfile (L, path))
	 && !(ret = lua_pcall (L, 0, 0, 0)))
		return true;

	print_error ("Lua: could not load `%s': %s", name, lua_tostring (L, -1));
	lua_pop (L, 1);
	return false;
}

static bool
initialize (void *ctx, struct plugin_api *api)
{
	g_data = (struct plugin_data) { .ctx = ctx, .api = api };

	if (sizeof (lua_Integer) < 8)
	{
		print_error ("%s: %s", "Lua",
			"at least 64-bit Lua integers are required");
		return false;
	}

	const char *plugin_dir = api->get_config (ctx, "plugin_dir");
	if (!plugin_dir)
	{
		print_fatal ("%s: %s", "Lua", "no plugin directory defined");
		return false;
	}

	DIR *dir = opendir (plugin_dir);
	if (!dir)
	{
		print_fatal ("%s: %s: %s", "Lua",
			"cannot open plugin directory", strerror (errno));
		return false;
	}

	bool success = false;
	lua_State *L;
	if (!(L = lua_newstate (xlua_alloc, NULL)))
	{
		print_fatal ("%s: %s", "Lua", "initialization failed");
		goto end;
	}

	lua_atpanic (L, xlua_panic);
	luaL_openlibs (L);

	// Register the ponymap library
	luaL_newlib (L, xlua_library);
	lua_pushinteger (L, SERVICE_SUPPORTS_TLS);
	lua_setfield (L, -2, "SERVICE_SUPPORTS_TLS");
	lua_setglobal (L, PROGRAM_NAME);

	// Create a metatable for the units
	luaL_newmetatable (L, UNIT_METATABLE);
	lua_pushvalue (L, -1);
	lua_setfield (L, -2, "__index");
	luaL_setfuncs (L, xlua_unit_table, 0);

	struct dirent buf, *iter;
	while (true)
	{
		if (readdir_r (dir, &buf, &iter))
		{
			print_fatal ("%s: %s: %s", "Lua", "readdir_r", strerror (errno));
			break;
		}
		if (!iter)
		{
			success = true;
			break;
		}

		char *dot = strrchr (iter->d_name, '.');
		if (!dot || strcmp (dot, ".lua"))
			continue;

		char *path = xstrdup_printf ("%s/%s", plugin_dir, iter->d_name);
		(void) load_one_plugin (L, iter->d_name, path);
		free (path);
	}

end:
	closedir (dir);
	return success;
}

struct plugin_info ponymap_plugin_info =
{
	.api_version  = API_VERSION,
	.initialize   = initialize
};
