SHELL = /bin/sh
CC = clang
# -Wunused-function is pretty annoying here, as everything is static
CFLAGS = -std=c99 -Wall -Wextra -Wpedantic -Wno-unused-function -ggdb
# -lpthread is only there for debugging (gdb & errno)
# -lrt is only for glibc < 2.17
LDFLAGS = `pkg-config --libs libssl jansson` -lpthread -lrt -ldl -lcurses
LDFLAGS_PLUGIN = $(LDFLAGS) -shared -fPIC

.PHONY: all clean
.SUFFIXES:

targets = ponymap ponymap.1 plugins/http.so plugins/irc.so plugins/ssh.so

all: $(targets)

clean:
	rm -f $(targets)

ponymap: ponymap.c utils.c plugin-api.h siphash.c
	$(CC) ponymap.c siphash.c -o $@ $(CFLAGS) $(LDFLAGS)

ponymap.1: ponymap
	help2man -No $@ ./$<

plugins/%.so: plugins/%.c utils.c plugin-api.h
	$(CC) $< -o $@ $(CFLAGS) $(LDFLAGS_PLUGIN)

plugins/http.so: plugins/http.c utils.c plugin-api.h \
	http-parser/http_parser.c http-parser/http_parser.h
	$(CC) $< http-parser/http_parser.c -o $@ $(CFLAGS) $(LDFLAGS_PLUGIN)
