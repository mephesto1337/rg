#include <elf.h>

#include "check.h"
#include "readelf64.h"
#include "utils.h"

const char* get_string_table_64b(const Elf64_Ehdr *ehdr) {
    const Elf64_Shdr *shdr = NULL;

    if ( ehdr->e_shstrndx < ehdr->e_shnum ) {
        shdr = (const Elf64_Shdr *)ADDR_OFFSET(ehdr, ehdr->e_shoff);
        return (const char *)ADDR_OFFSET(ehdr, shdr[ehdr->e_shstrndx].sh_offset);
    }
    return NULL;
}

const Elf64_Shdr *get_section_by_flags_and_type_64b(const Elf64_Ehdr *ehdr, Elf64_Xword flags, Elf64_Word type, size_t *idx) {
    const Elf64_Shdr *shdr = NULL;
    const Elf64_Shdr *found = NULL;
    const Elf64_Shdr *shdr_array = NULL;
    size_t _idx = 0;
    shdr_array = (const Elf64_Shdr *)ADDR_OFFSET(ehdr, ehdr->e_shoff);

    if ( idx ) {
        _idx = *idx;
    }

    while ( _idx < (size_t)ehdr->e_shnum ) {
        shdr = &shdr_array[_idx];
        if ( (type == (Elf64_Word)-1 || type == shdr->sh_type ) && ( shdr->sh_flags & flags ) == flags )  {
            found = shdr;
            break;
        }
        _idx++;
    }

    if ( idx ) {
        *idx = _idx;
    }

    return found;
}

inline const uint8_t* get_section_data_64b(const Elf64_Ehdr *ehdr, const Elf64_Shdr *shdr, size_t *len) {
    *len = (size_t)shdr->sh_size;
    return (const uint8_t *)ADDR_OFFSET(ehdr, shdr->sh_offset);
}
