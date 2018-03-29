#include <elf.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "check.h"
#include "gadget64.h"
#include "options.h"
#include "readelf64.h"
#include "utils.h"

#define DEFAULT_DEPTH 3UL

void usage(const char *progname);

struct  {
    bool help;
    size_t offset;
    size_t base_address;
    bool raw;
    size_t depth;
    bool color;
} rg_options = {
    .help = false,
    .offset = 0UL,
    .base_address = 0UL,
    .raw = false,
    .depth = DEFAULT_DEPTH,
    .color = false
};
typedef void (*search_and_print_gadgets_t)(const uint8_t *, size_t, size_t, Elf64_Addr);

const struct prog_option_s options[] = {
    { .gnu_opt = { "help",           no_argument,        NULL,   'h'},  .type = BOOL,   .value.b  = &rg_options.help            },
    { .gnu_opt = { "offset",         required_argument,  NULL,   'o'},  .type = ULONG,  .value.ul = &rg_options.offset          },
    { .gnu_opt = { "base-address",   required_argument,  NULL,   'b'},  .type = ULONG,  .value.ul = &rg_options.base_address    },
    { .gnu_opt = { "raw",            no_argument,        NULL,   'r'},  .type = BOOL,   .value.b  = &rg_options.raw             },
    { .gnu_opt = { "depth",          required_argument,  NULL,   'd'},  .type = ULONG,  .value.ul = &rg_options.depth           },
    { .gnu_opt = { "color",          no_argument,        NULL,   'c'},  .type = BOOL,   .value.b  = &rg_options.color           },
    { .gnu_opt = { NULL,             0,                  NULL,   0  },                                      },
};

int main(int argc, char *const argv[]) {
    struct stat st;
    int fd = -1;
    void *addr = NULL;
    void *start_addr = NULL; 
    const uint8_t *code = NULL;
    size_t code_size = 0;
    const Elf64_Ehdr *ehdr = NULL;
    const Elf64_Shdr *shdr = NULL;
    size_t s_idx;
    const char *shstrtab = NULL;
    search_and_print_gadgets_t search_and_print_gadgets = search_and_print_gadgets_64b;

    if ( ! parse_options(options, argc, argv) ) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }
    if ( rg_options.help ) {
        usage(argv[0]);
        return EXIT_SUCCESS;
    }
    if ( rg_options.color ) {
        search_and_print_gadgets = search_and_print_color_gadgets_64b;
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
            search_and_print_gadgets(code, code_size, rg_options.depth, (Elf64_Addr)rg_options.base_address);
        } else {
            ehdr = (const Elf64_Ehdr *)start_addr;
            shstrtab = get_string_table_64b(ehdr);
            s_idx = 0;
            while ( (shdr = get_code_section_64b(ehdr, &s_idx)) != NULL ) {
                fprintf(stderr, "Searching in section %s\n", &shstrtab[shdr->sh_name]);
                code = get_section_data_64b(ehdr, shdr, &code_size);
                search_and_print_gadgets(code, code_size, rg_options.depth, (Elf64_Addr)rg_options.base_address);
                s_idx++;
            }
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
        "Usage : %s [OPTIONS] ELF [ELF2...]\n"
        "  -h, --help         : shows this message and exits.\n"
        "  -o, --offset       : start reading files at offset.\n"
        "  -b, --base-address : set base adress for gadget printing.\n"
        "  -r, --raw          : input files are not ELF, but raw code.\n"
        "  -d, --depth        : maximum gadget length (default is %lu).\n"
        "  -c, --color        : use color output.\n"
        "  ELF                : an ELF64 file.\n"
        , progname, DEFAULT_DEPTH
    );
}
