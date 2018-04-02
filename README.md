# RG (a fast ROP gadget extractor)

## Introduction

RG is a small and fast tool to find *x86* ROP gadgets in files.  It was
initially written to extract gadgets from big files (such as *vmlinux*) in a
minimum amount of time.  It's written in C.  For now, it supports ELF and
RAW formats as input files.

## Installation

RG requires [radare2](https://github.com/radare/radare2) libraries, so
install [radare2](https://github.com/radare/radare2) first with:

    git clone --depth 1 https://github.com/radare/radare2
    cd radare2
    ./sys/install.sh

Then clone this repository and type:

    make
    make install

## Usage

Here is the usage output:

```
$ ./rg
Usage : ./rg [OPTIONS] ELF [ELF2...]
  -h, --help         : shows this message and exits.
  -o, --offset       : start reading files at offset.
  -B, --base-address : set base adress for gadget printing.
  -r, --raw          : input files are not ELF, but raw code.
  -d, --depth        : maximum gadget length (default is 3).
  -c, --color        : use color output.
  -a, --arch         : set arch for raw mode.
  -b, --bits         : set address width for raw mode.
  ELF                : an ELF64 file.
```

## Examples

To extract "``pop rdi``" gadgets from an ELF (*/bin/true*):

```sh
$ ./rg /bin/true | grep "pop rdi"
Recognized ELF64 for x86 on system linux with "/bin/true"
Searching in section .init
Searching in section .plt
Searching in section .plt.got
Searching in section .text
23e9: pop rdi; ret
3034: pop rdi; ret
[...]
```

If the binary is compiled as a shared object, you can specify a *base
address*:

```sh
$ ./rg -B 0x555555554000 /bin/true
[...]
```

