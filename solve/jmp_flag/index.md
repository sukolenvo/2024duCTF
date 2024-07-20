---
id: index
title: Jmp flag writeup
description: Writeup for challenge "Jmp flag" of Down Under CTF 2024
---

## Prologue

Difficulty: easy

Category: reverse engineering

Solved: 71

!!! quote "Description"
    The flag is just a hop, a skip and a jump away.

Input files:

* [jmp_flag binary](https://github.com/DownUnderCTF/Challenges_2024_Public/blob/f2797a33d8f5851508f37e854afceedf85eee8a3/rev/jmp-flag/publish/jmp_flag)

NB:


* Following indices bases system is used to avoid ambiguity. Whenever element of a collection is referenced by **number**, 0-based index implied. 
 
  Ie, element `0` of list `[1, 2, 4, 8, 16]` is `1`, Element `3` is `8`.
  
  When element is reference in explanation with **word** (first, third...), 1-based system is implied.

  Ie, first character of string `Hello World!` is `H`, fifth is `o`.

* Solution code was redacted for readability purposes. Due to time pressure during the competition I was using a lot of one-letter variables and questionable code structure.

* I am using gdb with [pwndbg](https://github.com/pwndbg/pwndbg) plugin

## My struggle

### Analysis

Running the binary doesn't reveal much:

```bash
$ ./jmp_flag   
aaaaa
Incorrect!
```

Let open [Ghidra](https://ghidra-sre.org/). First thing is to understand the flow of the program: `entry` function is language
generated wrapper. And program specific code starts with function `FUN_00105300`:

```c  title="protram entrypoint"
undefined8 FUN_00105300(void)

{
  __isoc99_scanf("%64s",&local_58);                                     # read 64 characters into variable local_58 
  for (local_5c = 0; local_5c < 0x40; local_5c = local_5c + 1) {        # iterate from 0 to 64
    FUN_00101280((int)*(char *)((long)&local_58 + (long)local_5c));     # call FUN_00101280 with one character at a time
  }
  iVar1 = FUN_00101200();                                               # check something?
  if (iVar1 == 0) {
    puts("Incorrect!");                                                 # our input is wrong
  }
  else {
    printf("Correct! DUCTF{%s}\n",&local_58);                           # print local_58 as flag
  }
  return 0;
}
```

On success program prints out our input - this means we won't find the flag in the binary. Instead, our goal is to find
input that would satisfy algorithm encoded in the program.

```c title="win check function"
bool FUN_00101200(void)
{
  return DAT_00109010 == 0;
}
```

Function that check if answer is correct or not is very short: our task is to make sure global variable DAT_00109010 is 0. 
Note that that that DAT_00109010 is 8 byte value with initial value 0xFFFFFFFFFFFFFFFF.

```c title="loop function"
void FUN_00101280(char param_1)
{
  (*(FUN_00101300 + (long)param_1 * 0x80 + 4))();
  return;
}
```

As we can see this function that is also very short: it converts character that we enter into number (ascii)
then multiplies is by 0x80 and uses it as on offset to jump to (base address is 0x00101300). Depending on character,
it would jump to:

 **ascii value** | **address** 
 --------------- | ------------
 0x00 | FUN_00101300 + 0 
 0x01 | FUN_00101300 + 0x80 
 0x02 | FUN_00101300 + 0x100 
 0x03 | FUN_00101300 + 0x180 
 ... | ... 

(I ignored +4 in the formula for now for readability purposes - its constant it doesn't change much).


Lets see what is at those addresses. I can see few different type of functions:

```c
// there are a lot of functions that are just setting global DAT_00109010 to 0xffffff
void FUN_00101300(void)
{
  DAT_00109010 = 0xffffffffffffffff;
  return;
}

// there are also functions that do `and` comparison of the global and if result is 0 - xors global with a constant
ulong FUN_00102b80(void)
{
  ulong uVar1;
  uVar1 = DAT_00109010 & 0x1000002020000;
  if (uVar1 == 0) {
    uVar1 = DAT_00109010 ^ 0x40000;
    DAT_00109010 = uVar1;
  }
  return uVar1;
}
```

As a first step I went through all functions and extracted test constants and xor values:

??? info "extracted constants"
    ```py
    actions = [
        [0x77ffdfecdeefdffe, 0x200000000],
        [0x77ffdfeedeeffffe, 0x200000000000],
        [0x77d95024c2c7c1de, 0x200],
        [0x77db512cc6efc3de, 0x1000],
        [0x75c9502402c7c1de, 0x40000000],
        [0x2000000, 0x20000],
        [0x77d9512cc6efc3de, 0x2000000000000],
        [0x77ffdfecceefdffe, 0x10000000],
        [0x408100200286804c, 0x400000],
        [0x77fffffedeeffffe, 1],
        [0x81000002060000, 0x800000],
        [0x77ffffffdfefffff, 0x8000000000000000],
        [0x1000002060000, 0x80000000000000],
        [0x77db512cc6efd3de, 0x20],
        [0x71c9502402c7c1de, 0x400000000000000],
        [0x81000002860000, 8],
        [0x77d95024c6efc3de, 0x10000000000],
        [0x6089002002c7814c, 0x80],
        [0xf7ffffffffefffff, 0x800000000000000],
        [0x71c9002402c7c1de, 0x400000000000],
        [0x70c9002402c7c1de, 0x100000000000000],
        [0x6089002002c781cc, 0x10],
        [0x75c95024c2c7c1de, 0x10000000000000],
        [0x1000002020000, 0x40000],
        [0x77ffffeedeeffffe, 0x1000000000],
        [0x6089002002c6814c, 0x10000],
        [0x6081002002c6814c, 0x8000000000000],
        [0x77d95124c6efc3de, 0x800000000],
        [0x77ff57acceefd7fe, 0x800],
        [0x4081002002c6804c, 0x100],
        [0x77d95024c6cfc3de, 0x200000],
        [0x4081000002868048, 4],
        [0x71c9402402c7c1de, 0x100000000000],
        [0x2020000, 0x1000000000000],
        [0x77ff57ecceefdffe, 0x800000000000],
        [0x70c9002402c7c1dc, 2],
        [0x77ffdfeedeefdffe, 0x2000],
        [0x77db512cceefd3fe, 0x20000000000],
        [0x6089002002c781dc, 0x40000000000000],
        [0x408100000286804c, 0x2000000000],
        [0x4081000002860008, 0x8000],
        [0x70c9002002c781dc, 0x4000],
        [0x77d95024c2c7c3de, 0x4000000],
        [0x77db512cc6efd3fe, 0x8000000],
        [0x4081000002868008, 0x40],
        [0x77db532cceefd3fe, 0x20000000000000],
        [0x75c9502442c7c1de, 0x80000000],
        [0xffffffffffefffff, 0x100000],
        [0x77fb532cceefd3fe, 0x400],
        [0x77ff57acceefdffe, 0x4000000000],
        [0x77d95024c6c7c3de, 0x80000],
        [0x60c9002002c781dc, 0x1000000000000000],
        [0, 0x2000000],
        [0x77fffffedeefffff, 0x1000000],
        [0x70c9002002c7c1dc, 0x400000000],
        [0xf7ffffffdfefffff, 0x20000000],
        [0x77fb532cceefd7fe, 0x4000000000000],
        [0x77ff53acceefd7fe, 0x40000000000],
        [0x77ffd7ecceefdffe, 0x80000000000],
        [0x81000002860008, 0x4000000000000000],
        [0x77ff532cceefd7fe, 0x8000000000],
        [0x4081002002c6814c, 0x2000000000000000],
        [0x77fffffedfefffff, 0x100000000],
        [0x75d95024c2c7c1de, 0x200000000000000]
    ]
    ```

I can see that there are 64 functions. Each one unsets one specific bit (different for all of them) and also has a different
test constant. Because unset bit is always different we have to call all of them exactly once. Here are few first steps of the program:

1. We start with global value 0xFFFFFFFFFFFFFFFF 
2. Only one function can be executed (test for other functions fails): line 54 [0, 0x2000000]
3. Now we have global value 0xFFFFFFFFFDFFFFFF 
4. Only one new function can be executed (test for other functions fails): line 7 [0x2000000, 0x20000]
5. Now we have global value 0xFFFFFFFFFDFDFFFF
6. Only one new function can be executed (test for other functions fails): line 35 [0x2020000, 0x1000000000000]
7. and so on

So, there is only one specific order in which we can call this functions to unset all bits and get global value to 0.

### Solution

We can get find the order in which functions should be executed:

=== "order functions"

    ```py
    # reorder all functions to be sorted in order that should be executed
    # function is array where first number is test value of the function and second number is bit that it sets
    def order_functions(functions):
        # keep track of bits we have unset so far
        bits_processed = 0
        ordered = [] # result
        for i in range(64):
            for function in functions:
                # if function's test number matches bits that were unset - this function should be executed next
                if function[0] == bits_processed:
                    # update bits set
                    bits_processed += function[1]
                    # add this function to the end of result
                    ordered.append(function)
                    break
        return ordered
    ```

=== "output"

    ```py
    test=0x0 xor_value=0x2000000
    test=0x2000000 xor_value=0x20000
    test=0x2020000 xor_value=0x1000000000000
    test=0x1000002020000 xor_value=0x40000
    test=0x1000002060000 xor_value=0x80000000000000
    test=0x81000002060000 xor_value=0x800000
    test=0x81000002860000 xor_value=0x8
    test=0x81000002860008 xor_value=0x4000000000000000
    test=0x4081000002860008 xor_value=0x8000
    test=0x4081000002868008 xor_value=0x40
    test=0x4081000002868048 xor_value=0x4
    test=0x408100000286804c xor_value=0x2000000000
    test=0x408100200286804c xor_value=0x400000
    test=0x4081002002c6804c xor_value=0x100
    test=0x4081002002c6814c xor_value=0x2000000000000000
    test=0x6081002002c6814c xor_value=0x8000000000000
    test=0x6089002002c6814c xor_value=0x10000
    test=0x6089002002c7814c xor_value=0x80
    test=0x6089002002c781cc xor_value=0x10
    test=0x6089002002c781dc xor_value=0x40000000000000
    test=0x60c9002002c781dc xor_value=0x1000000000000000
    test=0x70c9002002c781dc xor_value=0x4000
    test=0x70c9002002c7c1dc xor_value=0x400000000
    test=0x70c9002402c7c1dc xor_value=0x2
    test=0x70c9002402c7c1de xor_value=0x100000000000000
    test=0x71c9002402c7c1de xor_value=0x400000000000
    test=0x71c9402402c7c1de xor_value=0x100000000000
    test=0x71c9502402c7c1de xor_value=0x400000000000000
    test=0x75c9502402c7c1de xor_value=0x40000000
    test=0x75c9502442c7c1de xor_value=0x80000000
    test=0x75c95024c2c7c1de xor_value=0x10000000000000
    test=0x75d95024c2c7c1de xor_value=0x200000000000000
    test=0x77d95024c2c7c1de xor_value=0x200
    test=0x77d95024c2c7c3de xor_value=0x4000000
    test=0x77d95024c6c7c3de xor_value=0x80000
    test=0x77d95024c6cfc3de xor_value=0x200000
    test=0x77d95024c6efc3de xor_value=0x10000000000
    test=0x77d95124c6efc3de xor_value=0x800000000
    test=0x77d9512cc6efc3de xor_value=0x2000000000000
    test=0x77db512cc6efc3de xor_value=0x1000
    test=0x77db512cc6efd3de xor_value=0x20
    test=0x77db512cc6efd3fe xor_value=0x8000000
    test=0x77db512cceefd3fe xor_value=0x20000000000
    test=0x77db532cceefd3fe xor_value=0x20000000000000
    test=0x77fb532cceefd3fe xor_value=0x400
    test=0x77fb532cceefd7fe xor_value=0x4000000000000
    test=0x77ff532cceefd7fe xor_value=0x8000000000
    test=0x77ff53acceefd7fe xor_value=0x40000000000
    test=0x77ff57acceefd7fe xor_value=0x800
    test=0x77ff57acceefdffe xor_value=0x4000000000
    test=0x77ff57ecceefdffe xor_value=0x800000000000
    test=0x77ffd7ecceefdffe xor_value=0x80000000000
    test=0x77ffdfecceefdffe xor_value=0x10000000
    test=0x77ffdfecdeefdffe xor_value=0x200000000
    test=0x77ffdfeedeefdffe xor_value=0x2000
    test=0x77ffdfeedeeffffe xor_value=0x200000000000
    test=0x77ffffeedeeffffe xor_value=0x1000000000
    test=0x77fffffedeeffffe xor_value=0x1
    test=0x77fffffedeefffff xor_value=0x1000000
    test=0x77fffffedfefffff xor_value=0x100000000
    test=0x77ffffffdfefffff xor_value=0x8000000000000000
    test=0xf7ffffffdfefffff xor_value=0x20000000
    test=0xf7ffffffffefffff xor_value=0x800000000000000
    test=0xffffffffffefffff xor_value=0x100000
    ```

Now we need to find out what offset corresponds to each function. I don't have it yet and not looking to map each 64 values manually.
Therefore, I wrote a script for that:

1. calculate address we jump for a character;
2. disassemble function at address from step 1. Sample output
   ```asm hl_lines="5 10"
    f3 0f 1e fa             endbr64
    55                      push   rbp
    48 89 e5                mov    rbp, rsp
    48 8b 05 81 4c 00 00    mov    rax, QWORD PTR [rip+0x4c81]        
    48 ba de c1 c7 02 24 40 c9 71   movabs rdx, 0x71c9402402c7c1de
    48 21 d0                and    rax, rdx
    48 85 c0                test   rax, rax
    75 27                   jne    0x48
    48 8b 05 68 4c 00 00    mov    rax, QWORD PTR [rip+0x4c68]        
    48 ba 00 00 00 00 00 10 00 00   movabs rdx, 0x100000000000
    48 31 d0                xor    rax, rdx
    48 89 05 54 4c 00 00    mov    QWORD PTR [rip+0x4c54], rax     
    48 8b 05 4d 4c 00 00    mov    rax, QWORD PTR [rip+0x4c4d]   
    48 85 c0                test   rax, rax
    eb 01                   jmp    0x49
    90                      nop
    90                      nop
    5d                      pop    rbp
    c3                      ret
   ```
3. For each function check if test_number and xor_number are in the snippet. Given each function has unique test number and xor value - this
uniquely identifies snippet to function relation. Few values that were not resolved uniquely I handled manually.

One thing to point out is that Ghidra decoded idea of function FUN_00101280 correctly, but formula turns out to be slightly
different (this doesn't change logic, just different start address and offset multiplier). Correct values are taken disassembly of `FUN_00101280`.

```py
# calculate ascii value that corresponds to each function and store it as a third value in the function
# As a result each function wil be array of 3 values: test_value, xor_value, ascii_char_value
def find_offsets(functions):
    elfexe = ELF('/home/kali/Documents/mypy/Downloads/jmp_flag')
    # corrected base of the jump
    jmp_base = 0x12a4
    # collect all assembly snippets
    asms = []
    # for each character 1..256
    for i in range(1, 256):
        # corrected formula to calculate offset
        offset = (i << 7) + 0x60
        # disassemble first 100 bytes of the function
        function_asm = disasm(elfexe.read(jmp_base + offset, 100), arch='amd64')
        asms.append(function_asm)

    # find character for each function
    for function in functions:
        # list of possible matching assembly snippets
        matching_asm_snippets = []
        for asm_snippet in asms:
            # check if snippet contains test value (function[0]) in hex
            # and contains xor_value (function[1]) in hex (except for small numbers 512, 4096,... as they generate too many falsematches)
            if (hex(function[0]) + "\n") in asm_snippet and (
                    hex(function[1]) in asm_snippet or function[1] in [512, 4096, 2048, 256, 8192, 32768, 16384, 1024]):
                matching_asm_snippets.append(asm_snippet)
        # if there is only one matching assembly - we good, resolved automatically
        if len(matching_asm_snippets) == 1:
            function.append(asms.index(matching_asm_snippets[0]))
        # otherwise some hardcoded values
        else:
            if function[1] == 131072:
                function.append(asms.index(matching_asm_snippets[0]))
            elif function[0] == 0:
                function.append(115)
            else:
                print(function, matching_asm_snippets)
```

Now that we know character for each function and in what order to enter those characters we just loop through them and print out.
Full script:

??? success "solve.py"
    ```py
    from pwn import *
    
    actions = [
        [0x77ffdfecdeefdffe, 0x200000000],
        [0x77ffdfeedeeffffe, 0x200000000000],
        [0x77d95024c2c7c1de, 0x200],
        [0x77db512cc6efc3de, 0x1000],
        [0x75c9502402c7c1de, 0x40000000],
        [0x2000000, 0x20000],
        [0x77d9512cc6efc3de, 0x2000000000000],
        [0x77ffdfecceefdffe, 0x10000000],
        [0x408100200286804c, 0x400000],
        [0x77fffffedeeffffe, 1],
        [0x81000002060000, 0x800000],
        [0x77ffffffdfefffff, 0x8000000000000000],
        [0x1000002060000, 0x80000000000000],
        [0x77db512cc6efd3de, 0x20],
        [0x71c9502402c7c1de, 0x400000000000000],
        [0x81000002860000, 8],
        [0x77d95024c6efc3de, 0x10000000000],
        [0x6089002002c7814c, 0x80],
        [0xf7ffffffffefffff, 0x800000000000000],
        [0x71c9002402c7c1de, 0x400000000000],
        [0x70c9002402c7c1de, 0x100000000000000],
        [0x6089002002c781cc, 0x10],
        [0x75c95024c2c7c1de, 0x10000000000000],
        [0x1000002020000, 0x40000],
        [0x77ffffeedeeffffe, 0x1000000000],
        [0x6089002002c6814c, 0x10000],
        [0x6081002002c6814c, 0x8000000000000],
        [0x77d95124c6efc3de, 0x800000000],
        [0x77ff57acceefd7fe, 0x800],
        [0x4081002002c6804c, 0x100],
        [0x77d95024c6cfc3de, 0x200000],
        [0x4081000002868048, 4],
        [0x71c9402402c7c1de, 0x100000000000],
        [0x2020000, 0x1000000000000],
        [0x77ff57ecceefdffe, 0x800000000000],
        [0x70c9002402c7c1dc, 2],
        [0x77ffdfeedeefdffe, 0x2000],
        [0x77db512cceefd3fe, 0x20000000000],
        [0x6089002002c781dc, 0x40000000000000],
        [0x408100000286804c, 0x2000000000],
        [0x4081000002860008, 0x8000],
        [0x70c9002002c781dc, 0x4000],
        [0x77d95024c2c7c3de, 0x4000000],
        [0x77db512cc6efd3fe, 0x8000000],
        [0x4081000002868008, 0x40],
        [0x77db532cceefd3fe, 0x20000000000000],
        [0x75c9502442c7c1de, 0x80000000],
        [0xffffffffffefffff, 0x100000],
        [0x77fb532cceefd3fe, 0x400],
        [0x77ff57acceefdffe, 0x4000000000],
        [0x77d95024c6c7c3de, 0x80000],
        [0x60c9002002c781dc, 0x1000000000000000],
        [0, 0x2000000],
        [0x77fffffedeefffff, 0x1000000],
        [0x70c9002002c7c1dc, 0x400000000],
        [0xf7ffffffdfefffff, 0x20000000],
        [0x77fb532cceefd7fe, 0x4000000000000],
        [0x77ff53acceefd7fe, 0x40000000000],
        [0x77ffd7ecceefdffe, 0x80000000000],
        [0x81000002860008, 0x4000000000000000],
        [0x77ff532cceefd7fe, 0x8000000000],
        [0x4081002002c6814c, 0x2000000000000000],
        [0x77fffffedfefffff, 0x100000000],
        [0x75d95024c2c7c1de, 0x200000000000000]
    ]
    
    # calculate ascii value that corresponds to each function and store it as a third value in the function
    # As a result each function wil be array of 3 values: test_value, xor_value, ascii_char_value
    def find_offsets(functions):
        elfexe = ELF('/home/kali/Documents/mypy/Downloads/jmp_flag')
        # corrected base of the jump
        jmp_base = 0x12a4
        # collect all assembly snippets
        asms = []
        # for each character 1..256
        for i in range(1, 256):
            # corrected formula to calculate offset
            offset = (i << 7) + 0x60
            # disassemble first 100 bytes of the function
            function_asm = disasm(elfexe.read(jmp_base + offset, 100), arch='amd64')
            asms.append(function_asm)
    
        # find character for each function
        for function in functions:
            # list of possible matching assembly snippets
            matching_asm_snippets = []
            for asm_snippet in asms:
                # check if snippet contains test value (function[0]) in hex
                # and contains xor_value (function[1]) in hex (except for small numbers 512, 4096,... as they generate too many falsematches)
                if (hex(function[0]) + "\n") in asm_snippet and (
                        hex(function[1]) in asm_snippet or function[1] in [512, 4096, 2048, 256, 8192, 32768, 16384, 1024]):
                    matching_asm_snippets.append(asm_snippet)
            # if there is only one matching assembly - we good, resolved automatically
            if len(matching_asm_snippets) == 1:
                function.append(asms.index(matching_asm_snippets[0]))
            # otherwise some hardcoded values
            else:
                if function[1] == 131072:
                    function.append(asms.index(matching_asm_snippets[0]))
                elif function[0] == 0:
                    function.append(115)
                else:
                    print(function, matching_asm_snippets)
    
    
    # reorder all functions to be sorted in order that should be executed
    # function is array where first number is test value of the function and second number is bit that it sets
    def order_functions(functions):
        # keep track of bits we have unset so far
        bits_processed = 0
        ordered = []  # result
        for i in range(64):
            for function in functions:
                # if function's test number matches bits that were unset - this function should be executed next
                if function[0] == bits_processed:
                    # update bits set
                    bits_processed += function[1]
                    # add this function to the end of result
                    ordered.append(function)
                    break
        return ordered
    
    
    find_offsets(actions)
    
    result = order_functions(actions)
    
    for i in range(len(result)):
        print(chr(result[i][2] + 1), end="")
    
    ```


## Epilogue

* Official website: [https://downunderctf.com/](https://downunderctf.com/)
* Official writeups: https://github.com/DownUnderCTF/Challenges_2024_Public
