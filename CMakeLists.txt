project (ponymap C)
cmake_minimum_required (VERSION 2.8.5)

# Moar warnings
if ("${CMAKE_C_COMPILER_ID}" MATCHES "GNU" OR CMAKE_COMPILER_IS_GNUC)
	# -Wunused-function is pretty annoying here, as everything is static
	set (CMAKE_C_FLAGS "-std=c99 -Wall -Wextra -Wno-unused-function")
endif ("${CMAKE_C_COMPILER_ID}" MATCHES "GNU" OR CMAKE_COMPILER_IS_GNUC)

# Build options
option (WITH_LUA "Enable experimental support for Lua 5.3 plugins" ON)

# Version
set (project_VERSION_MAJOR "0")
set (project_VERSION_MINOR "1")
set (project_VERSION_PATCH "0")

set (project_VERSION "${project_VERSION_MAJOR}")
set (project_VERSION "${project_VERSION}.${project_VERSION_MINOR}")
set (project_VERSION "${project_VERSION}.${project_VERSION_PATCH}")

if ("${CMAKE_SYSTEM_NAME}" MATCHES "BSD")
	# Need this in FreeBSD and OpenBSD respectively;
	# our POSIX version macros make it undefined
	add_definitions (-D__BSD_VISIBLE=1 -D_BSD_SOURCE=1)
endif ("${CMAKE_SYSTEM_NAME}" MATCHES "BSD")

# Dependencies
find_package (Curses)
find_package (PkgConfig REQUIRED)
pkg_check_modules (jansson REQUIRED jansson)
pkg_check_modules (libssl REQUIRED libssl libcrypto)
pkg_check_modules (ncursesw ncursesw)

if (ncursesw_FOUND)
	set (project_libraries ${ncursesw_LIBRARIES})
	include_directories (${ncursesw_INCLUDE_DIRS})
	link_directories (${ncursesw_LIBRARY_DIRS})
elseif (CURSES_FOUND)
	set (project_libraries ${CURSES_LIBRARY})
	include_directories (${CURSES_INCLUDE_DIR})
else (CURSES_FOUND)
	message (SEND_ERROR "Curses not found")
endif (ncursesw_FOUND)

if (WITH_LUA)
	# FIXME: for "lua" we also need to check that it is < 5.4
	#   which doesn't seem to be possible with FindPkgConfig
	pkg_search_module (lua REQUIRED lua5.3 lua-5.3 lua>=5.3)
	list (APPEND project_libraries ${lua_LIBRARIES})
	include_directories (${lua_INCLUDE_DIRS})
	link_directories (${lua_LIBRARY_DIRS})
endif (WITH_LUA)

list (APPEND project_libraries ${libssl_LIBRARIES} ${jansson_LIBRARIES})
include_directories (${libssl_INCLUDE_DIRS} ${jansson_INCLUDE_DIRS})
link_directories (${libssl_LIBRARY_DIRS} ${jansson_LIBRARY_DIRS})

# -lpthread is only there for debugging (gdb & errno)
# -lrt is only for glibc < 2.17
foreach (extra iconv dl rt pthread)
	find_library (extra_lib ${extra})
	if (extra_lib)
		list (APPEND project_libraries ${extra})
	endif (extra_lib)
endforeach (extra)

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

install (TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
install (FILES LICENSE DESTINATION ${CMAKE_INSTALL_DOCDIR})

# Build the HTTP plugin
add_library (plugin-http SHARED plugins/http.c plugin-api.h
	http-parser/http_parser.c http-parser/http_parser.h)
target_link_libraries (plugin-http ${project_libraries})
set_target_properties (plugin-http PROPERTIES OUTPUT_NAME http PREFIX "")
install (TARGETS plugin-http DESTINATION ${plugin_dir})

# Build the other plugins
set (plugins irc ssh)
set (lua_plugins socks)

if (WITH_LUA)
	list (APPEND plugins lua-loader)
	foreach (lua_plugin ${lua_plugins})
		install (FILES plugins/${lua_plugin}.lua DESTINATION ${plugin_dir})
	endforeach (lua_plugin)
endif (WITH_LUA)
foreach (plugin ${plugins})
	set (target plugin-${plugin})
	add_library (${target} SHARED plugins/${plugin}.c plugin-api.h)
	target_link_libraries (${target} ${project_libraries})
	set_target_properties (${target} PROPERTIES OUTPUT_NAME ${plugin} PREFIX "")
	install (TARGETS ${target} DESTINATION ${plugin_dir})
endforeach (plugin)

# Generate documentation from program help
find_program (HELP2MAN_EXECUTABLE help2man)
if (NOT HELP2MAN_EXECUTABLE)
	message (FATAL_ERROR "help2man not found")
endif (NOT HELP2MAN_EXECUTABLE)

foreach (page ${PROJECT_NAME})
	set (page_output "${PROJECT_BINARY_DIR}/${page}.1")
	list (APPEND project_MAN_PAGES "${page_output}")
	add_custom_command (OUTPUT ${page_output}
		COMMAND ${HELP2MAN_EXECUTABLE} -N
			"${PROJECT_BINARY_DIR}/${page}" -o ${page_output}
		DEPENDS ${page}
		COMMENT "Generating man page for ${page}" VERBATIM)
endforeach (page)

add_custom_target (docs ALL DEPENDS ${project_MAN_PAGES})

foreach (page ${project_MAN_PAGES})
	string (REGEX MATCH "\\.([0-9])" manpage_suffix "${page}")
	install (FILES "${page}"
		DESTINATION "${CMAKE_INSTALL_MANDIR}/man${CMAKE_MATCH_1}")
endforeach (page)

# CPack
set (CPACK_PACKAGE_DESCRIPTION_SUMMARY "Experimental network scanner")
set (CPACK_PACKAGE_VERSION ${project_VERSION})
set (CPACK_PACKAGE_VENDOR "Premysl Janouch")
set (CPACK_PACKAGE_CONTACT "Přemysl Janouch <p.janouch@gmail.com>")
set (CPACK_RESOURCE_FILE_LICENSE "${PROJECT_SOURCE_DIR}/LICENSE")

set (CPACK_GENERATOR "TGZ;ZIP")
set (CPACK_PACKAGE_FILE_NAME
	"${PROJECT_NAME}-${project_VERSION}-${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}")
set (CPACK_PACKAGE_INSTALL_DIRECTORY "${PROJECT_NAME}-${project_VERSION}")

set (CPACK_SOURCE_GENERATOR "TGZ;ZIP")
set (CPACK_SOURCE_IGNORE_FILES "/\\\\.git;/build;/CMakeLists.txt.user")
set (CPACK_SOURCE_PACKAGE_FILE_NAME "${PROJECT_NAME}-${project_VERSION}")

set (CPACK_SET_DESTDIR TRUE)
include (CPack)
