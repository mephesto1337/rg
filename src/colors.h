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

#ifndef __COLORS_H__
#define __COLORS_H__

#include "utils.h"

#define PRINTF_COLOR(x)     "\033[0;1;" STRINGIFY(x) "m"
#define PRINTF_COLOR_WHITE  "\033[0;1m"
#define PRINTF_COLOR_RED    PRINTF_COLOR(31)
#define PRINTF_COLOR_GREEN  PRINTF_COLOR(32)
#define PRINTF_COLOR_YELLOW PRINTF_COLOR(33)
#define PRINTF_COLOR_BLUE   PRINTF_COLOR(34)
#define PRINTF_COLOR_NONE   "\033[0m"

#endif // __COLORS_H__
