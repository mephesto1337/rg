/*
 * rg, a small tool to find gadgets in a binary
 * Copyright (C) 2018 mephesto1337
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __GADGET_H__
#define __GADGET_H__

#include <capstone/capstone.h>
#include <stdint.h>

#include "colors.h"

#define INSTRUCTION_OPCODE_MAX_SIZE 8

struct gadget_end_s {
    const uint8_t opcodes[INSTRUCTION_OPCODE_MAX_SIZE];
    uint16_t size;
    uint16_t match_size;
    uint16_t previous;
    const char *mnemonic;
};

struct gadget_color_s {
    const char *address;
    const char *mnemonic;
    const char *op_str;
    const char *no_colors;
};

static const struct gadget_color_s gadget_colors[] = {
    { .address = PRINTF_COLOR_RED,  .mnemonic = PRINTF_COLOR_YELLOW,    .op_str = PRINTF_COLOR_WHITE,   .no_colors = PRINTF_COLOR_NONE  },
    { .address = "",                .mnemonic = "",                     .op_str = "",                   .no_colors = ""                 },
};

static const struct gadget_end_s gadget_x86_32_ends[] = {
    { .mnemonic = "ret",        .size = 1,  .previous = 1,  .match_size = 1,    .opcodes = { 0xc3 },        },
    { .mnemonic = "ret",        .size = 3,  .previous = 1,  .match_size = 1,    .opcodes = { 0xc2 },        },
    { .mnemonic = "int",        .size = 2,  .previous = 0,  .match_size = 2,    .opcodes = { 0xcd, 0x80 }   },
    { .mnemonic = "call",       .size = 2,  .previous = 0,  .match_size = 1,    .opcodes = { 0xff },        },
    { .mnemonic = "jmp",        .size = 2,  .previous = 0,  .match_size = 1,    .opcodes = { 0xff },        },
    { .mnemonic = NULL,         .size = 0,  .previous = 0,  .match_size = 0,    .opcodes = { 0x00 },        },
};

static const struct gadget_end_s gadget_x86_64_ends[] = {
    { .mnemonic = "ret",        .size = 1,  .previous = 1,  .match_size = 1,    .opcodes = { 0xc3 },        },
    { .mnemonic = "ret",        .size = 3,  .previous = 1,  .match_size = 1,    .opcodes = { 0xc2 },        },
    { .mnemonic = "syscall",    .size = 2,  .previous = 0,  .match_size = 2,    .opcodes = { 0x0f, 0x05 }   },
    { .mnemonic = "call",       .size = 2,  .previous = 0,  .match_size = 1,    .opcodes = { 0xff },        },
    { .mnemonic = "call",       .size = 3,  .previous = 0,  .match_size = 2,    .opcodes = { 0x41, 0xff },  },
    { .mnemonic = "jmp",        .size = 2,  .previous = 0,  .match_size = 1,    .opcodes = { 0xff },        },
    { .mnemonic = "jmp",        .size = 3,  .previous = 0,  .match_size = 2,    .opcodes = { 0x41, 0xff },  },
    { .mnemonic = NULL,         .size = 0,  .previous = 0,  .match_size = 0,    .opcodes = { 0x00 },        },
};

typedef void (*found_gadget_callback_t)(const cs_insn *instrs, size_t count, size_t offset, void *data);

void generic_search_gadgets(const char *arch, int bits, const uint8_t *code, size_t size, size_t depth, found_gadget_callback_t cb, void *data);
void print_gadgets(const cs_insn *instrs, size_t count, size_t offset, void *data);
void search_and_print_gadgets(const char *arch, int bits, const uint8_t *code, size_t size, size_t depth, size_t base_address);
void search_and_print_color_gadgets(const char *arch, int bits, const uint8_t *code, size_t size, size_t depth, size_t base_address);

#endif // __GADGET_H__
