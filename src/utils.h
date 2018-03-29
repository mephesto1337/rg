#ifndef __UTILS_H__
#define __UTILS_H__

#include <capstone/capstone.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#define ADDR_OFFSET(addr, off)  ((void *)((ssize_t)addr + (ssize_t)off))
#define ARRAY_SIZE(array)       (sizeof(array) / sizeof(array[0]))
#define __STRINGIFY(x)          #x
#define STRINGIGY(x)            __STRINGIFY(x)

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

#endif // __UTILS_H__
