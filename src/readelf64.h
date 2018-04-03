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

#ifndef __READELF64_H__
#define __READELF64_H__

#include <elf.h>
#include <stdint.h>

const char* get_string_table_64b(const Elf64_Ehdr *ehdr);
const Elf64_Shdr *get_section_by_flags_and_type_64b(const Elf64_Ehdr *ehdr, Elf64_Xword flags, Elf64_Word type, size_t *idx);
#define get_section_by_flags_64b(ehdr, flags, idx)  get_section_by_flags_and_type_64b(ehdr, flags, (Elf64_Word)-1, idx)
#define get_section_by_type_64b(ehdr, type, idx)    get_section_by_flags_and_type_64b(ehdr, 0, type, idx)
#define get_code_section_64b(ehdr, idx) get_section_by_flags_64b(ehdr, SHF_EXECINSTR, idx)
#define get_data_section_64b(ehdr, idx) get_section_by_flags_64b(ehdr, SHF_ALLOC | SHF_WRITE, idx)

const uint8_t* get_section_data_64b(const Elf64_Ehdr *ehdr, const Elf64_Shdr *shdr, size_t *len);


#endif // __READELF64_H__
