--
-- socks.lua: SOCKS service detection plugin
--
-- Copyright (c) 2015, Přemysl Janouch <p.janouch@gmail.com>
-- All rights reserved.
--
-- Permission to use, copy, modify, and/or distribute this software for any
-- purpose with or without fee is hereby granted, provided that the above
-- copyright notice and this permission notice appear in all copies.
--
-- THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
-- WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
-- MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
-- SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
-- WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
-- OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
-- CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
--

-- This plugin serves as an example of how to write Lua plugins for ponymap

-- SOCKS 4

local Socks4 = {}
Socks4.__index = Socks4

function Socks4.new (unit)
	unit:write (string.pack ("> I1 I1 I2 I1 I1 I1 I1 z",
		4, 1, 80, 127, 0, 0, 1, ""))
	return setmetatable ({ unit = unit, buf = "" }, Socks4)
end

function Socks4:on_data (data)
	self.buf = self.buf .. data
	if #self.buf >= 8 then
		null, code = string.unpack ("> I1 I1", self.buf)
		if null == 0 and code >= 90 and code <= 93 then
			self.unit:set_success (true)
		end
		self.unit:abort ()
	end
end

-- SOCKS 4A

local Socks4A = {}
Socks4A.__index = Socks4A

function Socks4A.new (unit)
	unit:write (string.pack ("> I1 I1 I2 I4 z z",
		4, 1, 80, 1, "", "google.com"))
	return setmetatable ({ unit = unit, buf = "" }, Socks4A)
end

Socks4A.on_data = Socks4.on_data

-- SOCKS 5

local Socks5 = {}
Socks5.__index = Socks5

function Socks5.new (unit)
	unit:write (string.pack ("> I1 I1 I1", 5, 1, 0))
	return setmetatable ({ unit = unit, buf = "" }, Socks5)
end

function Socks5:on_data (data)
	self.buf = self.buf .. data
	if #self.buf >= 2 then
		version, result = string.unpack ("> I1 I1", self.buf)
		if version == 5 and (result == 0 or result == 255) then
			if result == 0 then
				self.unit:add_info ("no authentication required")
			end
			self.unit:set_success (true)
		end
		self.unit:abort ()
	end
end

-- Register everything

ponymap.register_service ({
	name = "SOCKS4",
	flags = 0,
	new_scan = Socks4.new
})

-- At the moment this is nearly useless
-- ponymap.register_service ({
-- 	name = "SOCKS4A",
-- 	flags = 0,
-- 	new_scan = Socks4A.new
-- })

ponymap.register_service ({
	name = "SOCKS5",
	flags = 0,
	new_scan = Socks5.new
})
