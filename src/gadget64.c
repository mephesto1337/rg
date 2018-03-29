#include <capstone/capstone.h>
#include <elf.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "check.h"
#include "colors.h"
#include "gadget64.h"
#include "utils.h"


struct print_gadgets_args_s {
    Elf64_Addr base_address;
    const struct gadget_color_s *colors;
};

bool is_valid_gadget_64b(const cs_insn *instrs, size_t count_before);

void generic_search_gadgets_64b(const uint8_t *code, size_t size, size_t depth, found_gadget_callback_t cb, void *data) {
    size_t len;
    csh cs_handle = (csh)-1;
    cs_insn *instrs = NULL;

    CHK_CS(cs_open(CS_ARCH_X86, CS_MODE_64, &cs_handle));

    for ( size_t offset = 0; offset < size; offset++ ) {
        len = cs_disasm(cs_handle, &code[offset], size - offset, 0, depth, &instrs);
        for ( size_t i = 0; i < len; i++ ) {
            if ( is_valid_gadget_64b(&instrs[i], i) ) {
                cb(instrs, i + 1, offset, data);
                break;
            }
        }
    }
    
    cs_close(&cs_handle);
    fail:
    return;
}

void print_gadgets(const cs_insn *instrs, size_t count, size_t offset, void *data) {
    const struct print_gadgets_args_s *args = (const struct print_gadgets_args_s *)data;

    printf("%s%lx%s: ", args->colors->address, args->base_address + offset, args->colors->no_colors);
    for ( size_t i = 0; i < count; i++ ) {
        if ( i > 0 ) {
            printf("; ");
        }
        printf("%s%s%s %s%s%s", args->colors->mnemonic, instrs[i].mnemonic, args->colors->no_colors, args->colors->op_str, instrs[i].op_str, args->colors->no_colors);
    }
    printf("\n");
}

inline void search_and_print_gadgets_64b(const uint8_t *code, size_t size, size_t depth, Elf64_Addr base_address) {
    const struct print_gadgets_args_s args = {
        .base_address = base_address,
        .colors = &gadget_colors[1]
    };
    generic_search_gadgets_64b(code, size, depth, print_gadgets, (void *)&args);
}

inline void search_and_print_color_gadgets_64b(const uint8_t *code, size_t size, size_t depth, Elf64_Addr base_address) {
    const struct print_gadgets_args_s args = {
        .base_address = base_address,
        .colors = &gadget_colors[0]
    };
    generic_search_gadgets_64b(code, size, depth, print_gadgets, (void *)&args);
}

inline bool is_valid_gadget_64b(const cs_insn *instrs, size_t count_before) {
    const struct gadget_end_s *g = NULL;

    for ( size_t i = 0; i < ARRAY_SIZE(gadget_ends); i++ ) {
        g = &gadget_ends[i];
        if (    count_before >= g->previous &&
                instrs->size == g->size && 
                memcmp(instrs->bytes, g->opcodes, g->match_size) == 0 &&
                strncmp(instrs->mnemonic, g->mnemonic, sizeof(g->mnemonic) - 1) == 0
            ) {
            return true;
        }
    }

    return false;
}
