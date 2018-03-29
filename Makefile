CC=gcc
CPPFLAGS=-D_POSIX_C_SOURCE
CFLAGS=-W -Wall -Wextra -Wshadow -Werror -std=c99

LD=gcc
LDFLAGS=
LIBS=-lcapstone

SRC=$(wildcard src/*.c)
OBJ=$(SRC:src/%.c=obj/%.o)
BIN=rg

DEBUG ?= 0

ifneq ($(DEBUG), 0)
	CPPFLAGS += -DDDEBUG
	CFLAGS += -g -O0
else
	CFLAGS += -O2
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

clean :
	rm -f $(OBJ) $(BIN)
