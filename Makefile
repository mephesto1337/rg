CC=gcc
CPPFLAGS=-D_POSIX_C_SOURCE $(shell pkg-config --cflags r_bin r_util)
CFLAGS=-W -Wall -Wextra -Wshadow -Werror -std=c99

LD=gcc
LDFLAGS=
LIBS=-lcapstone $(shell pkg-config --libs r_bin r_util)

SRC=$(wildcard src/*.c)
OBJ=$(SRC:src/%.c=obj/%.o)
BIN=rg

_X := $(shell mkdir -p obj)

DEBUG ?= 0

ifneq ($(DEBUG), 0)
	CPPFLAGS += -DDDEBUG
	CFLAGS += -g -O0
else
	CFLAGS += -O3
endif

.PHONY : all clean

all : $(BIN)

$(BIN) : $(OBJ)
	$(LD) $(LDFLAGS) -o $@ $^ $(LIBS)
ifeq ($(DEBUG), 0)
	strip $@
endif

obj/%.o : src/%.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ -c $<

install:
	install -m 755 $(BIN) /usr/local/bin/

clean :
	rm -f $(OBJ) $(BIN)
