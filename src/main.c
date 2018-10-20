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

#include <elf.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <unistd.h>

#include "check.h"
#include "gadget.h"
#include "options.h"
#include "utils.h"
#include "exe_c_api.h"
GENERATE_BINDINGS(rs_pe);
GENERATE_BINDINGS(rs_elf32);
GENERATE_BINDINGS(rs_elf64);

#define DEFAULT_DEPTH 3UL

void usage(const char *progname);
int quiet_fprintf(FILE *stream, const char *format, ...) __attribute((format(printf, 2, 3)));
const rs_parse_t parsers[] = { rs_pe_parse_helper, rs_elf32_parse_helper, rs_elf64_parse_helper, NULL };

struct  {
    bool help;
    size_t offset;
    size_t base_address;
    bool raw;
    size_t depth;
    const char *color;
    const char *arch;
    int bits;
    bool quiet;
} rg_options = {
    .help = false,
    .offset = 0UL,
    .base_address = 0UL,
    .raw = false,
    .depth = DEFAULT_DEPTH,
    .color = "auto",
    .arch = "x86",
    .bits = 64,
    .quiet = false,
};
typedef void (*search_and_print_gadgets_t)(const char *, int, const uint8_t *, size_t, size_t, size_t);

const struct prog_option_s options[] = {
    { .gnu_opt = { "help",           no_argument,        NULL,   'h'},  .type = BOOL,   .value.b  = &rg_options.help            },
    { .gnu_opt = { "offset",         required_argument,  NULL,   'o'},  .type = ULONG,  .value.ul = &rg_options.offset          },
    { .gnu_opt = { "base-address",   required_argument,  NULL,   'B'},  .type = ULONG,  .value.ul = &rg_options.base_address    },
    { .gnu_opt = { "raw",            no_argument,        NULL,   'r'},  .type = BOOL,   .value.b  = &rg_options.raw             },
    { .gnu_opt = { "depth",          required_argument,  NULL,   'd'},  .type = ULONG,  .value.ul = &rg_options.depth           },
    { .gnu_opt = { "color",          required_argument,  NULL,   'c'},  .type = STRING, .value.s  = &rg_options.color           },
    { .gnu_opt = { "arch",           required_argument,  NULL,   'a'},  .type = STRING, .value.s  = &rg_options.arch            },
    { .gnu_opt = { "bits",           required_argument,  NULL,   'b'},  .type = INT,    .value.i  = &rg_options.bits            },
    { .gnu_opt = { "quiet",          no_argument,        NULL,   'q'},  .type = BOOL,   .value.b  = &rg_options.quiet           },
    { .gnu_opt = { NULL,             0,                  NULL,   0  },                                      },
};

int main(int argc, char *const argv[]) {
    struct stat st;
    int fd = -1;
    void *addr = MAP_FAILED;
    void *start_addr = NULL;
    const uint8_t *code = NULL;
    size_t code_size = 0;
    rs_object_t obj = { NULL, NULL };
    rs_section_t *section = NULL;
    rs_info_t *info = NULL;
    size_t nsections;
    search_and_print_gadgets_t sapg = search_and_print_gadgets;

    if ( ! parse_options(options, argc, argv) ) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }
    if ( rg_options.help ) {
        usage(argv[0]);
        return EXIT_SUCCESS;
    }
    if (argv[optind] == NULL) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    if ( strcmp(rg_options.color, "auto") == 0 && isatty(STDOUT_FILENO) == 1 ) {
        sapg = search_and_print_color_gadgets;
    } else if ( strcmp(rg_options.color, "always") == 0 ) {
        sapg = search_and_print_color_gadgets;
    } else {
        sapg = search_and_print_gadgets;
    }
    argv += (size_t)optind;
    argc -= optind;

    for ( int i = 0; i < argc; i++ ) {
        CHK_NEG(fd = open(argv[i], O_RDONLY));
        CHK_NEG(fstat(fd, &st));
        if ( st.st_size < 0 ) {
            perror("File (%s) size is negative, skipping", argv[i]);
            goto fail;
        }
        if ( rg_options.offset > (size_t)st.st_size ) {
            perror("Offset is biger than filesize, skipping \"%s\"", argv[i]);
            goto fail;
        }
        CHK_MMAP(addr = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_SHARED, fd, 0));
        start_addr = ADDR_OFFSET(addr, rg_options.offset);
        if ( rg_options.raw ) {
            code = (const uint8_t *)start_addr;
            code_size = (size_t)st.st_size - rg_options.offset;
            sapg(rg_options.arch, rg_options.bits, code, code_size, rg_options.depth, (Elf64_Addr)rg_options.base_address);
        } else {
            obj.handle = NULL;
            for ( size_t idx = 0; parsers[idx] != NULL; idx++ ) {
                if ( parsers[idx](&obj, (const uint8_t *)start_addr, st.st_size - rg_options.offset) ) {
                    break;
                }
            }
            if ( obj.handle == NULL ) {
                quiet_fprintf(stderr, "Did not recognized anythind, using raw mode\n");
                code = (const uint8_t *)start_addr;
                code_size = (size_t)st.st_size - rg_options.offset;
                sapg(rg_options.arch, rg_options.bits, code, code_size, rg_options.depth, (Elf64_Addr)rg_options.base_address);
                goto fail;
            } else {
                info = obj.ops->get_info(obj.handle);
                quiet_fprintf(stderr, "Recognized %s on system %s with \"%s\"\n", info->arch, info->os, argv[i]);
                nsections = obj.ops->get_number_of_sections(obj.handle);
                for ( size_t idx = 0; idx < nsections; idx++ ) {
                    CHK_NULL(section = obj.ops->get_section_at(obj.handle, idx));
                    if ( (section->flags & 5U) != 5U ) {
                        continue;
                    }
                    quiet_fprintf(stderr, "Searching in section %s\n", section->name);
                    code = (const uint8_t *)ADDR_OFFSET(start_addr, section->paddr);
                    sapg(info->arch, info->bits, code, section->size, rg_options.depth, (Elf64_Addr)(section->vaddr + rg_options.base_address));
                    obj.ops->free_section(section);
                }
            }
            obj.ops->free_exe(obj.handle);
        }

        fail:
        SAFE_MUNMAP(addr, (size_t)st.st_size);
        SAFE_CLOSE(fd);
    }

    return EXIT_SUCCESS;
}

void usage(const char *progname) {
    fprintf(
        stderr,
        "Usage : %s [OPTIONS] FILE [FILE2...]\n"
        "  -h, --help         : shows this message and exits.\n"
        "  -o, --offset       : start reading files at offset.\n"
        "  -B, --base-address : set base adress for gadget printing.\n"
        "  -r, --raw          : input files are not ELF/PE/etc, but raw code.\n"
        "  -d, --depth        : maximum gadget length (default is %lu).\n"
        "  -c, --color        : Use color : auto (yes if stdout is a TTY), always, never.\n"
        "  -a, --arch         : set arch for raw mode.\n"
        "  -b, --bits         : set address width for raw mode.\n"
        "  -q, --quiet        : be quiet.\n"
        "  FILE               : an executable file (like ELF, PE, anything radare2 supports).\n"
        , progname, DEFAULT_DEPTH
    );
}

inline int quiet_fprintf(FILE *stream, const char *format, ...) {
    va_list args;
    int ret = 0;

    if ( ! rg_options.quiet ) {
        va_start(args, format);
        ret = vfprintf(stream, format, args);
        va_end(args);
    }
    return ret;
}
