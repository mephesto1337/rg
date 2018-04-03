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
