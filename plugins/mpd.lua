--
-- mpd.lua: Music Player Daemon service detection plugin
--
-- Copyright (c) 2015, Přemysl Eric Janouch <p@janouch.name>
--
-- Permission to use, copy, modify, and/or distribute this software for any
-- purpose with or without fee is hereby granted.
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

local MPD = {}
MPD.__index = MPD

function MPD.new (unit)
	return setmetatable ({ unit = unit, buf = "" }, MPD)
end

function MPD:on_data (data)
	self.buf = self.buf .. data
	local line = self.buf:match ("([^\n]*)\n")
	if line then
		local version = line:match ("OK MPD (.*)")
		if version then
			self.unit:add_info ("version " .. version)
			self.unit:set_success (true)
		end
		self.unit:stop ()
	end
end

ponymap.register_service { name="MPD", flags=0, new_scan=MPD.new }
