#ifndef __COLORS_H__
#define __COLORS_H__

#include "utils.h"

#define PRINTF_COLOR(x)     "\033[0;1;" STRINGIGY(x) "m"
#define PRINTF_COLOR_WHITE  "\033[0;1m"
#define PRINTF_COLOR_RED    PRINTF_COLOR(31)
#define PRINTF_COLOR_GREEN  PRINTF_COLOR(32)
#define PRINTF_COLOR_YELLOW PRINTF_COLOR(33)
#define PRINTF_COLOR_BLUE   PRINTF_COLOR(34)
#define PRINTF_COLOR_NONE   "\033[0m"

#endif // __COLORS_H__
