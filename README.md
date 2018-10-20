# RG (a fast ROP gadget extractor)

## Introduction

RG is a small and fast tool to find *x86* ROP gadgets in files.  It was
initially written to extract gadgets from big files (such as *vmlinux*) in a
minimum amount of time.  It's written in C.  For now, it supports ELF and
RAW formats as input files.

## Installation

RG requires [rust](https://www.rust-lang.org/fr-FR/install.html), and some
parsers implementing the [exe trait](https://github.com/mephesto1337/exe) :

	- [elf](https://github.com/mephesto1337/elf)
	- [pe](https://github.com/mephesto1337/pe)


Then you are good to go !

    mkdir rust && cd rust
    git clone https://github.com/mephesto1337/elf
    git clone https://github.com/mephesto1337/pe
	cd ..
	make

## Usage

Here is the usage output:

```
$ rg
Usage : rg [OPTIONS] FILE [FILE2...]
  -h, --help         : shows this message and exits.
  -o, --offset       : start reading files at offset.
  -B, --base-address : set base adress for gadget printing.
  -r, --raw          : input files are not ELF/PE/etc, but raw code.
  -d, --depth        : maximum gadget length (default is 3).
  -c, --color        : Use color : auto (yes if stdout is a TTY), always, never.
  -a, --arch         : set arch for raw mode.
  -b, --bits         : set address width for raw mode.
  -q, --quiet        : be quiet.
  FILE               : an executable file (like ELF, PE, anything radare2 supports).
```

## Examples

To extract "``pop rdi``" gadgets from an ELF (*/bin/true*):

```sh
$ rg /bin/true | grep "pop rdi"
Recognized ELF64 for x86 on system linux with "/bin/true"
Searching in section .init
Searching in section .text
2643: pop rdi; ret
2dfe: pop rdi; ret
[...]
```

If the binary is compiled as a shared object, you can specify a *base
address*:

```sh
$ rg -B 0x555555554000 /bin/true
Recognized ELF64 for x86 on system linux with "/bin/true"
Searching in section .init
Searching in section .text
55555555529b: test rax, rax; je 7; call rax
55555555529c: test eax, eax; je 6; call rax
55555555529d: sal byte ptr [rdx + rax - 1], 0xd0; add rsp, 8; ret
55555555529e: je 4; call rax
5555555552a0: call rax
5555555552a2: add rsp, 8; ret
5555555552a3: add esp, 8; ret
5555555552b3: je 5; xor eax, eax; ret
5555555552b5: xor eax, eax; ret
55555555532e: sal byte ptr [rsp + rax + 0x31], 0xc0; pop rbx; ret
[....]
```

