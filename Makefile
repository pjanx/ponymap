SHELL = /bin/sh
CC = clang
# -Wunused-function is pretty annoying here, as everything is static
CFLAGS = -std=c99 -Wall -Wextra -Wno-unused-function -ggdb
# -lpthread is only there for debugging (gdb & errno)
# -lrt is only for glibc < 2.17
LDFLAGS = `pkg-config --libs libssl` -lpthread -lrt -ldl

.PHONY: all clean
.SUFFIXES:

targets = ponymap

all: $(targets)

clean:
	rm -f $(targets)

ponymap: ponymap.c utils.c siphash.c
	$(CC) ponymap.c siphash.c -o $@ $(CFLAGS) $(LDFLAGS)

