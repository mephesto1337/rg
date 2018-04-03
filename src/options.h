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

#ifndef __OPTIONS_H__
#define __OPTIONS_H__

#include <getopt.h>
#include <stdbool.h>
#include <unistd.h>

enum prog_option_type_e {
	BOOL,
	INT,
	UINT,
	LONG,
	ULONG,
	STRING,
	CUSTOM
};

union prog_option_value_u {
	bool b;
	int i;
	unsigned int ui;
	long l;
	unsigned long ul;
	const char *s;
	void *custom;
};

union prog_option_ptr_value_u {
	bool *b;
	int *i;
	unsigned int *ui;
	long *l;
	unsigned long *ul;
	const char **s;
	void **custom;
};

struct prog_option_s;

typedef bool (*option_from_string_t)(const char *s, const struct prog_option_s *po);

struct prog_option_s {
	struct option gnu_opt;
	enum prog_option_type_e type;
	union prog_option_ptr_value_u value;
	option_from_string_t parse;
};

bool parse_options(const struct prog_option_s *options, int argc, char *const argv[]);
bool parse_bool(const char *s, const struct prog_option_s *po);
bool parse_int(const char *s, const struct prog_option_s *po);
bool parse_uint(const char *s, const struct prog_option_s *po);
bool parse_long(const char *s, const struct prog_option_s *po);
bool parse_ulong(const char *s, const struct prog_option_s *po);
bool parse_string(const char *s, const struct prog_option_s *po);

#endif // __OPTIONS_H__
