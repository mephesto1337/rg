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
