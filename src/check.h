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

#ifndef __CHECK_H__
#define __CHECK_H__

#include <capstone/capstone.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#define perror(fmt, ...)    \
    do { \
        if ( errno > 0 ) { \
            fprintf(stderr, "[ERROR] " fmt " (errno=%d / %s)\n", ## __VA_ARGS__, errno, strerror(errno)); \
        } else { \
            fprintf(stderr, "[ERROR] " fmt "\n", ## __VA_ARGS__); \
        } \
        errno = 0; \
    } while ( 0 )

#define CHK(expr, is_error) \
    do { \
        errno = 0; \
        if ( (expr) is_error ) { \
            perror("(%s) %s", #expr, #is_error); \
            goto fail; \
        } \
    } while ( 0 )


#define CHK_NEG(expr)   CHK(expr, < 0)
#define CHK_NULL(expr)  CHK(expr, == NULL)
#define CHK_MMAP(expr)  CHK(expr, == MAP_FAILED)
#define CHK_CS(expr)    CHK(expr, != CS_ERR_OK)
#define CHK_FALSE(expr) CHK(expr, == false)

#endif // __CHECK_H__
