---
id: index
title: Number mashing writeup
description: Writeup for challenge "number mashing" of Down Under CTF 2024
---

My second writeup for Down Under CTF 2024. Feedback is much appreciated.

## Prologue

Difficulty: beginner

Category: reverse engineering

Solved: 299

!!! quote "Description"
    Mash your keyboard numpad in a specific order and a flag might just pop out!

Input files:

[number_mashing](https://github.com/DownUnderCTF/Challenges_2024_Public/blob/f2797a33d8f5851508f37e854afceedf85eee8a3/beginner/number-mashing/src/number-mashing)

NB:


* Following indices bases system is used to avoid ambiguity. Whenever element of a collection is referenced by **number**, 0-based index implied. 
 
  Ie, element `0` of list `[1, 2, 4, 8, 16]` is `1`, Element `3` is `8`.
  
  When element is reference in explanation with **word** (first, third...), 1-based system is implied.

  Ie, first character of string `Hello World!` is `H`, fifth is `o`.

* Solution code was redacted for readability purposes. Due to time pressure during the competition I was using a lot of one-letter variables and questionable code structure.

## My struggle

Check what type of file we got:

```sh
$ file number-mashing 
number-mashing:
 ELF 64-bit LSB pie executable, # 64bit
 ARM aarch64,         # ARM machine need to run 
 version 1 (SYSV),
 dynamically linked,
 interpreter /lib/ld-linux-aarch64.so.1,
 BuildID[sha1]=ab93f9bc0ec8c3d321da1b7e954e739e13ee8ab1,
 for GNU/Linux 3.7.0,
 not stripped # likely a readable code can be extracted
```

I didn't have arm environment ready at that moment, so won't be able to run the binary locally. Instead, lets fire up
[ghidra](https://ghidra-sre.org/) and try to understand the code, as mentioned above it should make a lot of sense
given binary is not stripped.

??? note "original ghydra output"
    ```c
    undefined8 main(void)
    {
      local_8 = ___stack_chk_guard;
      setvbuf(_stdout,(char *)0x0,2,0);
      setvbuf(_stdin,(char *)0x0,2,0);
      printf("Give me some numbers: ");
      __isoc99_scanf("%d %d",&local_11c,&local_118);
      if (((local_11c == 0) || (local_118 == 0)) || (local_118 == 1)) {
        puts("Nope!");
                        /* WARNING: Subroutine does not return */
        exit(1);
      }
      local_114 = 0;
      if (local_118 != 0) {
        local_114 = local_11c / local_118;
      }
      if (local_114 != local_11c) {
        puts("Nope!");
                        /* WARNING: Subroutine does not return */
        exit(1);
      }
      local_110 = fopen("flag.txt","r");
      fread(&local_108,1,0x100,local_110);
      printf("Correct! %s\n",&local_108);
      if (local_8 - ___stack_chk_guard != 0) {
                        /* WARNING: Subroutine does not return */
        __stack_chk_fail(&__stack_chk_guard,0,0,local_8 - ___stack_chk_guard);
      }
      return 0;
    }
    ```

We can see print, scanf, then some calculations. Cleaned version with extra comments:
!!! note "cleaned source code"
    ```c
    #include <stdio.h>
    
    void main() {
      int first, second;
      printf("Give me some numbers: "); 
      scanf("%d %d", &first ,&second); # read two numbers: first and second
      # check that first is not 0 and second is no 0 nor 1
      if (((first == 0) || (second == 0)) || (second == 1)) {
        puts("Nope!");
        exit(1);
      }
      int res = first / second; # divide
      if (res != first) { # check that result is equal to first number
        puts("Nope!");
        exit(1);
      }
      puts("Here is your flag flag!");
    }
    ```
**Now the task is clear: we are looking for two numbers such that when one is divided by the other the result is equal to dividend.**

Usually we would achieve it with by having second number as one `4 / 1 = 4`, but extra condition in the code that we should use 1.

Quick check with my times table confirmed that calculus won't help us here. Instead, we want to take advantage
of overflow. Goal is to find such numbers that result won't fit into the register and when truncated will be equal to dividend.
Its quite easy to do with multiplication, for example for 1 byte numbers: `0x10 * 0x11 = 0x110`, which is truncated to `0x10`.

To experiment locally I've compiled the code above `gcc -o number-mashing number-mashing.c`.

After a bit trial and error within constraints that second cannot be large number, in fact only -1 makes sense 
(and maybe 2 if we treat divide by two as shift right where flag bit is carried). And first number should have 
top bits sets, so they will be truncated by flag bit.
Testing with following inputs -2147483648 -1 gives us something interesting:
```sh
$ ./number-mashing      
Give me some numbers: -2147483648 -1
zsh: floating point exception  ./number-mashing
```
On x86 architecture idiv assembly instruction is used, quick google _idiv floating point exception_ bring us to 
[stackoverflow](https://stackoverflow.com/questions/56303282/why-idiv-with-1-causes-floating-point-exception).
idiv will raise an exception in two cases:

* You divide by zero
* The division result is not in the range that can be represented by the `eax` register

Indeed, range for 4 byte number is from -2147483648 to 2147483647, so result of `-2147483648 / -1 = 2147483648` doesn't fit in 
the range above, hence we got error.

On arm architecture sdiv instruction is used, it doesn't raise exception, instead carry flag is set in cpsr register.

Connecting to the challenge server and submitting two numbers got us the flag.

## Epilogue

* Official website: [https://downunderctf.com/](https://downunderctf.com/)
* Official writeups: https://github.com/DownUnderCTF/Challenges_2024_Public

*[sdiv]: signed division arm instruction
*[idiv]: signed division x86 instuction
