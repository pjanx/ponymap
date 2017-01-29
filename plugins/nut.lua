--
-- nut.lua: Network UPS Tools service detection plugin
--
-- Copyright (c) 2017, Přemysl Janouch <p.janouch@gmail.com>
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

ponymap.check_api_version (1)

local NUT = {}
NUT.__index = NUT

function NUT.new (unit)
	unit:write ("LIST UPS\n")
	return setmetatable ({ unit = unit, buf = "", in_list = false }, NUT)
end

-- Bare words and quoted strings with escape sequences, separated by spaces;
-- unfortunately Lua patterns are too weak to use them for this trivial task
function NUT.parse (line)
	local result, state, field, c = {}, 0, ""
	for c in (line .. " "):gmatch (".") do
		if state == 0 then
			if c == "\"" then state = 2
			elseif c ~= " "  then field = c state = 1 end
		elseif state == 1 then
			if c == " " then table.insert (result, field) field = "" state = 0
			elseif c == "\"" then state = 2
			else field = field .. c end
		elseif state == 2 then
			if c == "\\" then state = 3
			elseif c == "\"" then state = 1
			else field = field .. c end
		elseif state == 3 then field = field .. c state = 2 end
	end
	return result
end

function NUT:process (line)
	if not self.in_list then
		if line:match ("^BEGIN LIST UPS$") then
			self.unit:add_info ("no authentication required")
			self.unit:set_success (true)
			self.in_list = true
			return true
		elseif line:match ("^ERR ACCESS-DENIED") then
			self.unit:set_success (true)
		end
	else
		local fields = self.parse (line)
		if #fields == 3 and fields[1] == "UPS" then
			self.unit:add_info ("UPS: " .. fields[2] .. " - " .. fields[3])
			return true
		end
	end
end

function NUT:on_data (data)
	self.buf = self.buf .. data
	repeat
		local line, rest = self.buf:match ("([^\n]*)\n(.*)")
		if not line then return end
		self.buf = rest
	until not self:process (line)
	self.unit:stop ()
end

ponymap.register_service {
	name = "NUT",
	flags = 0,
	new_scan = NUT.new
}
