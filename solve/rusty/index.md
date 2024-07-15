---
id: index
title: Rusty vault writeup
description: Writeup for challenge "Rusty vault" of Down Under CTF 2024
---

## Prologue

Difficulty: easy

Category: reverse engineering

Solved: 81

!!! quote "Description"
    I've learnt all the secure coding practices. I only use memory safe languages and military grade encryption. Surely, you can't break into my vault.

Input files:

??? info "encoding.txt"
    

NB:


* Following indices bases system is used to avoid ambiguity. Whenever element of a collection is referenced by **number**, 0-based index implied. 
 
  Ie, element `0` of list `[1, 2, 4, 8, 16]` is `1`, Element `3` is `8`.
  
  When element is reference in explanation with **word** (first, third...), 1-based system is implied.

  Ie, first character of string `Hello World!` is `H`, fifth is `o`.

* Solution code was redacted for readability purposes. Due to time pressure during the competition I was using a lot of one-letter variables and questionable code structure.

* I am using gdb with [pwndbg](https://github.com/pwndbg/pwndbg) plugin

## My struggle



## Epilogue

* Official website: [https://downunderctf.com/](https://downunderctf.com/)
* Official writeups: https://github.com/DownUnderCTF/Challenges_2024_Public
