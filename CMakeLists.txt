cmake_minimum_required (VERSION 3.0)
project (ponymap VERSION 0.1.0 LANGUAGES C)

# Moar warnings
if ("${CMAKE_C_COMPILER_ID}" MATCHES "GNU" OR CMAKE_COMPILER_IS_GNUCC)
	# -Wunused-function is pretty annoying here, as everything is static
	set (CMAKE_C_FLAGS
		"${CMAKE_C_FLAGS} -std=c99 -Wall -Wextra -Wno-unused-function")
endif ()

# Dependencies
set (CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/liberty/cmake)
include (AddThreads)

find_package (Curses)
find_package (PkgConfig REQUIRED)
pkg_check_modules (jansson REQUIRED jansson)
pkg_check_modules (libssl REQUIRED libssl libcrypto)
pkg_check_modules (ncursesw ncursesw)

if ("${CMAKE_SYSTEM_NAME}" MATCHES "BSD")
	# Need this in FreeBSD and OpenBSD respectively;
	# our POSIX version macros make it undefined
	add_definitions (-D__BSD_VISIBLE=1 -D_BSD_SOURCE=1)
endif ()

if (ncursesw_FOUND)
	set (project_libraries ${ncursesw_LIBRARIES})
	include_directories (${ncursesw_INCLUDE_DIRS})
	link_directories (${ncursesw_LIBRARY_DIRS})
elseif (CURSES_FOUND)
	set (project_libraries ${CURSES_LIBRARY})
	include_directories (${CURSES_INCLUDE_DIR})
else ()
	message (SEND_ERROR "Curses not found")
endif ()

# FIXME: for "lua" we also need to check that it is < 5.5
#   which doesn't seem to be possible with FindPkgConfig
pkg_search_module (lua lua5.3 lua-5.3 lua5.4 lua-5.4 lua>=5.3)
option (WITH_LUA "Enable experimental support for Lua plugins" ${lua_FOUND})

if (WITH_LUA)
	if (NOT lua_FOUND)
		message (FATAL_ERROR "Lua library not found")
	endif ()

	list (APPEND project_libraries ${lua_LIBRARIES})
	include_directories (${lua_INCLUDE_DIRS})
	link_directories (${lua_LIBRARY_DIRS})
endif ()

list (APPEND project_libraries ${libssl_LIBRARIES} ${jansson_LIBRARIES})
include_directories (${libssl_INCLUDE_DIRS} ${jansson_INCLUDE_DIRS})
link_directories (${libssl_LIBRARY_DIRS} ${jansson_LIBRARY_DIRS})

# -lrt is only for glibc < 2.17
# -liconv may or may not be a part of libc
foreach (extra iconv dl rt)
	find_library (extra_lib_${extra} ${extra})
	if (extra_lib_${extra})
		list (APPEND project_libraries ${extra})
	endif ()
endforeach ()

# Project source files
set (project_sources ${PROJECT_NAME}.c)
set (project_headers ${PROJECT_BINARY_DIR}/config.h)

# Generate a configuration file
include (GNUInstallDirs)
set (plugin_dir ${CMAKE_INSTALL_LIBDIR}/${PROJECT_NAME})
configure_file (${PROJECT_SOURCE_DIR}/config.h.in ${PROJECT_BINARY_DIR}/config.h)
include_directories (${PROJECT_SOURCE_DIR} ${PROJECT_BINARY_DIR})

# Build and install the main executable
add_executable (${PROJECT_NAME} ${project_sources} ${project_headers})
target_link_libraries (${PROJECT_NAME} ${project_libraries})
add_threads (${PROJECT_NAME})

install (TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
install (FILES LICENSE DESTINATION ${CMAKE_INSTALL_DOCDIR})

# Build the HTTP plugin
add_library (plugin-http SHARED plugins/http.c plugin-api.h
	http-parser/http_parser.c http-parser/http_parser.h)
target_link_libraries (plugin-http ${project_libraries})
add_threads (plugin-http)
set_target_properties (plugin-http PROPERTIES OUTPUT_NAME http PREFIX "")
install (TARGETS plugin-http DESTINATION ${plugin_dir})

# Build the other plugins
set (plugins irc ssh)
set (lua_plugins socks)

if (WITH_LUA)
	list (APPEND plugins lua-loader)
	foreach (lua_plugin ${lua_plugins})
		install (FILES plugins/${lua_plugin}.lua DESTINATION ${plugin_dir})
	endforeach ()
endif ()
foreach (plugin ${plugins})
	set (target plugin-${plugin})
	add_library (${target} SHARED plugins/${plugin}.c plugin-api.h)
	target_link_libraries (${target} ${project_libraries})
	add_threads (${target})
	set_target_properties (${target} PROPERTIES OUTPUT_NAME ${plugin} PREFIX "")
	install (TARGETS ${target} DESTINATION ${plugin_dir})
endforeach ()

# Generate documentation from program help
find_program (HELP2MAN_EXECUTABLE help2man)
if (NOT HELP2MAN_EXECUTABLE)
	message (FATAL_ERROR "help2man not found")
endif ()

foreach (page ${PROJECT_NAME})
	set (page_output "${PROJECT_BINARY_DIR}/${page}.1")
	list (APPEND project_MAN_PAGES "${page_output}")
	add_custom_command (OUTPUT ${page_output}
		COMMAND ${HELP2MAN_EXECUTABLE} -N
			"${PROJECT_BINARY_DIR}/${page}" -o ${page_output}
		DEPENDS ${page}
		COMMENT "Generating man page for ${page}" VERBATIM)
endforeach ()

add_custom_target (docs ALL DEPENDS ${project_MAN_PAGES})

foreach (page ${project_MAN_PAGES})
	string (REGEX MATCH "\\.([0-9])$" manpage_suffix "${page}")
	install (FILES "${page}"
		DESTINATION "${CMAKE_INSTALL_MANDIR}/man${CMAKE_MATCH_1}")
endforeach ()

# CPack
set (CPACK_PACKAGE_DESCRIPTION_SUMMARY "Experimental network scanner")
set (CPACK_PACKAGE_VENDOR "Premysl Eric Janouch")
set (CPACK_PACKAGE_CONTACT "Přemysl Eric Janouch <p@janouch.name>")
set (CPACK_RESOURCE_FILE_LICENSE "${PROJECT_SOURCE_DIR}/LICENSE")

set (CPACK_GENERATOR "TGZ;ZIP")
set (CPACK_PACKAGE_FILE_NAME
	"${PROJECT_NAME}-${PROJECT_VERSION}-${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}")
set (CPACK_PACKAGE_INSTALL_DIRECTORY "${PROJECT_NAME}-${PROJECT_VERSION}")

set (CPACK_SOURCE_GENERATOR "TGZ;ZIP")
set (CPACK_SOURCE_IGNORE_FILES "/\\\\.git;/build;/CMakeLists.txt.user")
set (CPACK_SOURCE_PACKAGE_FILE_NAME "${PROJECT_NAME}-${PROJECT_VERSION}")

set (CPACK_SET_DESTDIR TRUE)
include (CPack)
