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

#include <assert.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "check.h"
#include "options.h"
#include "utils.h"

#define OPTION_BUFFER_SIZE      128
#define IS_LAST_OPTIONS(opt)	\
	( (opt)->gnu_opt.name == NULL && (opt)->gnu_opt.has_arg == 0 && (opt)->gnu_opt.flag == NULL && (opt)->gnu_opt.val == 0 )

bool generic_parse(const char *s, const struct prog_option_s *po);

bool parse_options(const struct prog_option_s *options, int argc, char *const argv[]) {
	int n;
	bool use_short_opt;
	char long_opt[OPTION_BUFFER_SIZE];
	char *short_opt = &long_opt[0];
	const struct prog_option_s *po = NULL;

	for ( optind = 1; optind < argc; optind++ ) {
		if ( sscanf(argv[optind], "-%" STRINGIFY(OPTION_BUFFER_SIZE) "[0-9a-zA-Z]", long_opt) == 1 ) {
			use_short_opt = true;
            short_opt = &long_opt[0];
			optarg = argv[optind + 1];
		} else if ( (n = sscanf(argv[optind], "--%" STRINGIFY(OPTION_BUFFER_SIZE) "[^=]%*[=]", long_opt)) > 0 ) {
			use_short_opt = false;
			if ( n == 1 ) {
				optarg = argv[optind + 1];
			} else {
				optarg = strchr(argv[optind], '=');
			}
		}  else {
			return true;
		}

		for ( po = options; ! IS_LAST_OPTIONS(po); po++ ) {
			if ( use_short_opt ) {
                short_opt = &long_opt[0];
                while ( *short_opt ) {
                    if ( po->gnu_opt.val == *short_opt ) {
                        goto found_option;
                    }
                    short_opt++;
                 }
			} else {
				if ( strcmp(po->gnu_opt.name, long_opt) == 0 ) {
                    goto found_option;
				}
			}
		}

        found_option:
		if ( IS_LAST_OPTIONS(po) ) {
			return false;
		} else {
            optind += po->gnu_opt.has_arg;
			if ( ! generic_parse(po->gnu_opt.has_arg == no_argument ? NULL : optarg, po) ) {
				perror("Cannot get %s from \"%s\"", po->gnu_opt.name, optarg);
				return false;
			}
		}
	}

	return true;
}

bool parse_bool(const char *s, const struct prog_option_s *po) {
	assert ( po->type == BOOL );
	if ( s == NULL ) {
		*po->value.b = true;
		return true;
	} else {
		int i;
		if ( sscanf(s, "%d", &i) == 1 ) {
			*po->value.b = (bool)!!i;
		} else if ( strcasecmp(s, "y") == 0 || strcasecmp(s, "yes") == 0 ) {
			*po->value.b = true;
			return true;
		} else if ( strcasecmp(s, "n") == 0 || strcasecmp(s, "no") == 0 ) {
			*po->value.b = false;
			return true;
		}
	}
	return false;
}

bool parse_int(const char *s, const struct prog_option_s *po) {
	assert ( po->type == INT );
	return (bool)(sscanf(s, "%d", po->value.i) == 1);
}

bool parse_uint(const char *s, const struct prog_option_s *po) {
	assert ( po->type == UINT );
	return (bool)(sscanf(s, "%u", po->value.ui) == 1);
}

bool parse_long(const char *s, const struct prog_option_s *po) {
	assert ( po->type == LONG );
	return (bool)(sscanf(s, "0x%lx", po->value.l) == 1 || sscanf(s, "%ld", po->value.l) == 1);
}

bool parse_ulong(const char *s, const struct prog_option_s *po) {
	assert ( po->type == ULONG );
	return (bool)(sscanf(s, "0x%lx", po->value.ul) == 1 || sscanf(s, "%lu", po->value.ul) == 1);
}

bool parse_string(const char *s, const struct prog_option_s *po) {
	assert ( po->type == STRING );
	*po->value.s = s;
	return true;
}

bool generic_parse(const char *s, const struct prog_option_s *po) {
	if ( po->parse ) {
		return po->parse(s, po);
	} else {
		switch ( po->type ) {
			case BOOL :
				return parse_bool(s, po);
			case INT :
				return parse_int(s, po);
			case UINT :
				return parse_uint(s, po);
			case LONG :
				return parse_long(s, po);
			case ULONG :
				return parse_ulong(s, po);
			case STRING :
				return parse_string(s, po);
			case CUSTOM :
				return false;
			default :
				return false;
		}
	}
}
