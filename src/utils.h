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

#ifndef __UTILS_H__
#define __UTILS_H__

#include <capstone/capstone.h>
#include <libr/r_bin.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#define ADDR_OFFSET(addr, off)  ((void *)((ssize_t)addr + (ssize_t)off))
#define ARRAY_SIZE(array)       (sizeof(array) / sizeof(array[0]))
#define __STRINGIFY(x)          #x
#define STRINGIFY(x)            __STRINGIFY(x)

#define SAFE_XXX(func, handle, nullval, ...)    \
    do { \
        if ( (handle) != nullval ) { \
            func(handle, ## __VA_ARGS__ ); \
        } \
        (handle) = nullval; \
    } while ( 0 )

#define SAFE_MUNMAP(ptr, size)  SAFE_XXX(munmap, ptr, MAP_FAILED, size)
#define SAFE_CLOSE(handle)      SAFE_XXX(close, handle, -1)
#define SAFE_FREE(ptr)          SAFE_XXX(free, ptr, NULL)
#define SAFE_RBIN_FREE(ptr)     SAFE_XXX(r_bin_free, ptr, NULL)

#endif // __UTILS_H__
