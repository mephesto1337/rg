#ifndef __CHECK_H__
#define __CHECK_H__

#include <capstone/capstone.h>
#include <errno.h>
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
        if ( (expr) is_error ) { \
            perror("(%s) %s", #expr, #is_error); \
            goto fail; \
        } \
    } while ( 0 )


#define CHK_NEG(expr)   CHK(expr, < 0)
#define CHK_NULL(expr)  CHK(expr, == NULL)
#define CHK_MMAP(expr)  CHK(expr, == MAP_FAILED)
#define CHK_CS(expr)    CHK(expr, != CS_ERR_OK)

#endif // __CHECK_H__
