#ifndef __GADGET64_H__
#define __GADGET64_H__

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
};

static const struct gadget_end_s gadget_ends[] = {
    { .mnemonic = "ret",        .size = 1,  .previous = 1,  .match_size = 1,    .opcodes = { 0xc3 },        },
    { .mnemonic = "ret",        .size = 3,  .previous = 1,  .match_size = 1,    .opcodes = { 0xc3 },        },
    { .mnemonic = "call",       .size = 5,  .previous = 0,  .match_size = 1,    .opcodes = { 0xe8 },        },
    { .mnemonic = "jmp",        .size = 5,  .previous = 0,  .match_size = 1,    .opcodes = { 0xe9 },        },
    { .mnemonic = "syscall",    .size = 2,  .previous = 0,  .match_size = 2,    .opcodes = { 0x0f, 0x05 }   },   
};

static const struct gadget_color_s gadget_colors[] = {
    { .address = PRINTF_COLOR_RED,  .mnemonic = PRINTF_COLOR_YELLOW,    .op_str = PRINTF_COLOR_WHITE    },
    { .address = "",                .mnemonic = "",                     .op_str = ""                    },
};

typedef void (*found_gadget_callback_t)(const cs_insn *instrs, size_t count, size_t offset, void *data);

void generic_search_gadgets_64b(const uint8_t *code, size_t size, size_t depth, found_gadget_callback_t cb, void *data);
void print_gadgets(const cs_insn *instrs, size_t count, size_t offset, void *data);
void search_and_print_gadgets_64b(const uint8_t *code, size_t size, size_t depth, Elf64_Addr base_address);
void search_and_print_color_gadgets_64b(const uint8_t *code, size_t size, size_t depth, Elf64_Addr base_address);

#endif // __GADGET64_H__
