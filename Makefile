SHELL = /bin/sh
CC = clang
# -Wunused-function is pretty annoying here, as everything is static
CFLAGS = -std=c99 -Wall -Wextra -Wno-unused-function -ggdb
# -lpthread is only there for debugging (gdb & errno)
# -lrt is only for glibc < 2.17
LDFLAGS = `pkg-config --libs libssl` -lpthread -lrt -ldl -lcurses

.PHONY: all clean
.SUFFIXES:

targets = ponymap plugins/http.so plugins/irc.so

all: $(targets)

clean:
	rm -f $(targets)

ponymap: ponymap.c utils.c plugin-api.h siphash.c
	$(CC) ponymap.c siphash.c -o $@ $(CFLAGS) $(LDFLAGS)

plugins/%.so: plugins/%.c utils.c plugin-api.h
	$(CC) $< -o $@ $(CFLAGS) $(LDFLAGS) -shared -fPIC
