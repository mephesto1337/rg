#include <elf.h>
#include <fcntl.h>
#include <getopt.h>
#include <libr/r_bin.h>
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
#include "readelf64.h"
#include "utils.h"

#define DEFAULT_DEPTH 3UL

void usage(const char *progname);
int quiet_fprintf(FILE *stream, const char *format, ...) __attribute((format(printf, 2, 3)));

struct  {
    bool help;
    size_t offset;
    size_t base_address;
    bool raw;
    size_t depth;
    bool color;
    const char *arch;
    int bits;
    bool quiet;
} rg_options = {
    .help = false,
    .offset = 0UL,
    .base_address = 0UL,
    .raw = false,
    .depth = DEFAULT_DEPTH,
    .color = false,
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
    { .gnu_opt = { "color",          no_argument,        NULL,   'c'},  .type = BOOL,   .value.b  = &rg_options.color           },
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
    RBin *bin = NULL;
    const RList *list = NULL;
    const RListIter *iter = NULL;
    const RBinSection *section = NULL;
    const RBinInfo *info = NULL;
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

    if ( rg_options.color ) {
        sapg = search_and_print_color_gadgets;
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
            CHK_NULL(bin = r_bin_new());
            CHK_NULL(bin->iob.io = r_io_new());
            CHK_FALSE(r_io_bind(bin->iob.io, &bin->iob));
            bin->io_owned = true;
            CHK_FALSE(r_bin_load_as(bin, argv[i], rg_options.base_address, 0, -1, -1, false, rg_options.offset, argv[i]));
            CHK_NULL(info = r_bin_get_info(bin));
            quiet_fprintf(stderr, "Recognized %s for %s on system %s with \"%s\"\n", info->bclass, info->arch, info->os, argv[i]);
            CHK_NULL(list = r_bin_get_sections(bin));
            r_list_foreach(list, iter, section) {
                if ( ( section->srwx & 5 ) != 5 ) {
                    continue;
                }
                quiet_fprintf(stderr, "Searching in section %s\n", section->name);
                code = (const uint8_t *)ADDR_OFFSET(start_addr, section->paddr);
                sapg(info->arch, info->bits, code, section->size, rg_options.depth, (Elf64_Addr)(section->vaddr + rg_options.base_address));
            }
            SAFE_RBIN_FREE(bin);
        }

        fail:
        SAFE_RBIN_FREE(bin);
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
        "  -c, --color        : use color output.\n"
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
