#include <capstone/capstone.h>
#include <elf.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "check.h"
#include "colors.h"
#include "gadget.h"
#include "utils.h"


struct print_gadgets_args_s {
    size_t base_address;
    const struct gadget_color_s *colors;
};

bool is_valid_gadget(const struct gadget_end_s *gadget_ends, const cs_insn *instrs, size_t count_before);
bool select_gadget_end(const char *arch, int bits, const struct gadget_end_s **gadget_ends);
bool select_capstone_params(const char *arch, int bits, enum cs_arch *carch, enum cs_mode *cmode);

void generic_search_gadgets(const char *arch, int bits, const uint8_t *code, size_t size, size_t depth, found_gadget_callback_t cb, void *data) {
    size_t len;
    const struct gadget_end_s *gadget_ends = NULL;
    cs_arch carch;
    cs_mode cmode;
    csh cs_handle = (csh)-1;
    cs_insn *instrs = NULL;

    CHK_FALSE(select_gadget_end(arch, bits, &gadget_ends));
    CHK_FALSE(select_capstone_params(arch, bits, &carch, &cmode));
    CHK_CS(cs_open(carch, cmode, &cs_handle));

    for ( size_t offset = 0; offset < size; offset++ ) {
        len = cs_disasm(cs_handle, &code[offset], size - offset, 0, depth, &instrs);
        for ( size_t i = 0; i < len; i++ ) {
            if ( is_valid_gadget(gadget_ends, &instrs[i], i) ) {
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

        printf("%s%s%s%s%s%s%s", args->colors->mnemonic, instrs[i].mnemonic, args->colors->no_colors, *instrs[i].op_str == '\0' ? "" : " ", args->colors->op_str, instrs[i].op_str, args->colors->no_colors);
    }
    printf("\n");
}

void search_and_print_gadgets(const char *arch, int bits, const uint8_t *code, size_t size, size_t depth, size_t base_address) {
    const struct print_gadgets_args_s args = {
        .base_address = base_address,
        .colors = &gadget_colors[1]
    };
    generic_search_gadgets(arch, bits, code, size, depth, print_gadgets, (void *)&args);
}

void search_and_print_color_gadgets(const char *arch, int bits, const uint8_t *code, size_t size, size_t depth, size_t base_address) {
    const struct print_gadgets_args_s args = {
        .base_address = base_address,
        .colors = &gadget_colors[0]
    };
    generic_search_gadgets(arch, bits, code, size, depth, print_gadgets, (void *)&args);
}

inline bool is_valid_gadget(const struct gadget_end_s *gadget_ends, const cs_insn *instrs, size_t count_before) {
    for ( const struct gadget_end_s *g = gadget_ends; g->mnemonic != NULL; g++ ) {
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

bool select_gadget_end(const char *arch, int bits, const struct gadget_end_s **gadget_ends) {
    if ( strcmp(arch, "x86") == 0 ) {
        switch ( bits ) {
            case 32 :
                *gadget_ends = gadget_x86_32_ends;
                break;
            case 64 :
                *gadget_ends = gadget_x86_64_ends;
                break;
            default :
                goto fail;
        }
        return true;
    }

    fail:
    perror("No gadgets for arch %s / %d bits", arch, bits);
    return false;
}

bool select_capstone_params(const char *arch, int bits, enum cs_arch *carch, enum cs_mode *cmode) {
    if ( strcmp(arch, "x86") == 0 ) {
        *carch = CS_ARCH_X86;
        switch ( bits ) {
            case 16 :
                *cmode = CS_MODE_16;
                break;
            case 32 :
                *cmode = CS_MODE_32;
                break;
            case 64 :
                *cmode = CS_MODE_64;
                break;
            default :
                goto fail;
        }
        return true;
    }

    fail:
    perror("Unsupported disasembly arch %s / %d bits", arch, bits);
    return false;
}
