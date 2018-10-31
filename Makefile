CC=gcc
CPPFLAGS=-D_POSIX_C_SOURCE
CFLAGS=-W -Wall -Wextra -Wshadow -Werror -std=c99

CARGO_FLAGS=
CARGO_TARGET_DIR=
RUST_LIB_NAMES=pe elf
RUST_ROOT_DIR=rust
CPPFLAGS += -I$(RUST_ROOT_DIR)/exe/ressources

LD=gcc
LDFLAGS=
LIBS=-lcapstone -ldl -lpthread

SRC=$(wildcard src/*.c)
OBJ=$(SRC:src/%.c=obj/%.o)
BIN=rg

_X := $(shell mkdir -p obj)

DEBUG ?= 0

ifneq ($(DEBUG), 0)
	CPPFLAGS += -DDEBUG
	CFLAGS += -g -O0
	CARGO_TARGET_DIR=debug
else
	CFLAGS += -O3
	CARGO_TARGET_DIR=release
	CARGO_FLAGS=--release
endif

RUST_LIBS=$(foreach rdir,$(RUST_LIB_NAMES),$(RUST_ROOT_DIR)/$(rdir)/target/$(CARGO_TARGET_DIR)/lib$(rdir).a)

.PHONY : all clean

all : $(BIN)

$(BIN) : $(OBJ) $(RUST_LIBS)
	$(LD) $(LDFLAGS) -o $@ $^ $(LIBS)
ifeq ($(DEBUG), 0)
	strip $@
endif

%.a :
	cd $(RUST_ROOT_DIR)/$(shell basename $@ | sed -re 's/^lib//; s/[.]a$$//') && \
	cargo build $(CARGO_FLAGS)

obj/%.o : src/%.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ -c $<

install:
	install -m 755 $(BIN) /usr/local/bin/

clean :
	rm -f $(OBJ) $(BIN)
	for lib in $(RUST_LIB_NAMES); do \
		cargo clean --manifest-path=$(RUST_ROOT_DIR)/$$lib/Cargo.toml; \
	done
