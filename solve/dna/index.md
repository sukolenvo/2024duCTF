---
id: index
title: DNAdecay writeup
description: Writeup for challenge "DNAdecay" of Down Under CTF 2024
---

## Prologue

Difficulty: easy

Category: reverse engineering

Solved: 148

!!! quote "Description"
    Our flightless birds can run upto 50km/h but we want them to go faster. I've been messing with a mutigen but it seems to have corrupted. Can you help me recover this research?

Input files:

??? info "dna.rb"
    ```ruby
    require "doublehelix"
    
     AT
    A--T
    T- -A
    G----C
     G---- 
         --C
       T---A
        G--C
         AT
         GC
        T-- 
       G- - 
      T----A
     A--- T
    T ---A
    G---C
    C--G
     AT
     CG
      -T
    A---T
    G---  
     A -- T
      G----C
       G   C
         --C
          C
          C
        T--A
       A-- T
      A--  T
     G- --C
    A----T
    G---C
    G--C
     GC
     CG
    G--C
    A--- 
    G----C
     T- --A
      C----G
       T--- 
        G--C
          A
         GC
        T--A
       A-  T
       ----T
     C----G
     -- -T
    G---C
    T--A
     AT
      A
    A -T
     ---A
    T - -A
     G----C
      G----C
       G---C
        T--A
         AT
          C
        G- C
       C --G
      C-- -G
     G----C
     -- -T
    G - C
    T--A
     G 
     AT
     --T
    T--- 
     ----T
     T-- -A
       ---- 
       C---G
        G--C
         AT
         C 
        A - 
           C
      T----A
     T----A
    A---- 
    G  -C
    C- G
     T 
     C 
    G- C
     --  
    G---- 
     C- --G
      G- -  
       C-- G
        A--T
         G 
         GC
        G--C
       C---G
      C-- -G
     G--- C
    A---  
    G- -C
    T--A
     A 
     TA
    T--A
      -- 
     ---- 
     G-- -C
      A- --T
       T- - 
        A--T
         GC
         GC
        T- A
       A---T
      T-- -A
     T----A
     ---- 
    G-- C
    T--A
     GC
      A
    A-  
    A --T
    C----G
     C---- 
      G----C
       G---C
        G -C
         CG
         GC
        T--A
       T--- 
      G----C
     G-- -C
    A---  
    A--  
    G-- 
     GC
     AT
    A--T
    T--- 
    A -- T
     T----A
      G --- 
       T --A
        G--C
          C
         GC
        A- T
       G---C
      C ---G
      --- T
     - - A
    G---C
     --A
      A
     G 
    G--C
    A --T
    C- --G
     A ---T
       ----C
       T -  
        T - 
         CG
          C
        G -C
       G---C
      G -  C
     G --- 
      --- 
     ---T
     - A
     G 
      C
    G-  
    A --T
    G----C
     T ---A
      T--- A
       G --C
        G-  
         TA
          A
        C--G
       G--- 
      C---- 
     G----C
    C----G
    G---C
    T- A
     TA
       
    G--C
    A---T
     -- -C
      ----T
      G---- 
       G--- 
        A--T
         AT
         GC
         - A
       T--- 
      G- --C
     G ---C
    T- --A
    A-- T
    A--T
      C
     TA
    A- T
    T- - 
    A----T
     A----T
      T----A
       A --T
        G--C
         A 
         TA
        A -T
        --- 
      G- --C
     T----A
    T ---A
     - -C
    C-- 
      T
     CG
    A- T
    
    ```

NB:


* Following indices bases system is used to avoid ambiguity. Whenever element of a collection is referenced by **number**, 0-based index implied. 
 
  Ie, element `0` of list `[1, 2, 4, 8, 16]` is `1`, Element `3` is `8`.
  
  When element is reference in explanation with **word** (first, third...), 1-based system is implied.

  Ie, first character of string `Hello World!` is `H`, fifth is `o`.

* Solution code was redacted for readability purposes. Due to time pressure during the competition I was using a lot of one-letter variables and questionable code structure.

* I am using gdb with [pwndbg](https://github.com/pwndbg/pwndbg) plugin

## My struggle

**Disclaimer**: this is the first time I've opened ruby script, therefore technique is primitive and far from optimal.

At this point I can't tell if file we were given is a valid ruby script or first we have to decode the DNA it somehow before running.
There is only one searchable string to start with: `require "doublehelix"` (I don't believe googling all those AT TA can be helpful). Quickly landed at following
library on github https://github.com/mame/doublehelix.

Entire encoding and decoding is implemented in [less than 20 lines](https://github.com/mame/doublehelix/blob/master/lib/doublehelix.rb):
```ruby title="source code of doublehelix.rb"
$code = ""
Object.instance_eval do
  def const_missing(s); $code << s.to_s; 0; end
  remove_const(:GC)  # Holy moly!
end
at_exit do
  dict = { "AT"=>"00", "CG"=>"01", "GC"=>"10", "TA"=>"11" }
  eval([$code.gsub(/../) {|s| dict[s] }].pack("b*"))
end

def doublehelix(src)
  dict = { "00"=>["A","T"], "01"=>["C","G"], "10"=>["G","C"], "11"=>["T","A"] }
  format = [[1,0], [0,2], [0,3], [0,4], [1,4], [2,4], [3,3], [4,2], [5,0]]
  format += format.reverse
  %(require "doublehelix"\n\n) + src.unpack("b*").first.gsub(/../) do |s|
    format << (offset, dist = format.shift)
    " " * offset + dict[s] * ("-" * dist) + "\n"
  end
end
```

I wasn't able to install the package in my machine and run hello world (probably my environment is not properly set up). 
But, replacing `require "doublehelix"` with [contents of the library](https://github.com/mame/doublehelix/blob/2e238ab65fa43abae4f950a580c163c9a5e45e92/lib/doublehelix.rb)
did the trick.

After that I've tried to run source code that we were given in the challenge. Of cause, it was not so easy: task description
mentions _but it seems to have corrupted. Can you help me recover this research?_ So we have to fix the script first.

At lines 7 and 12 of the source code we can see that there are only 4 possible pairs of gens (AT, CG, GC, TA). As a first path
I went through the script and repaired all lines that included 1 letter: 

* lines with A should have T
* lines with T should have A
* liens with C should have G
* lines with G should have C

Its easy to pick a sequence to use (for example AT or TA) visually (fit DNA picture).

Now lets work on empty lines. We will have to guess what it is. For that I've added few modifications:

```ruby title="modied dna.rb"
$code = ""
Object.instance_eval do
  def const_missing(s); $code << s.to_s; 0; end
  remove_const(:GC)  # Holy moly!
end
at_exit do
  # extended dictianary with 4 new gens: V0, V1, V2, V3 that produce same bits as existing ones
  # now I can enter my guesses and still able to distinct given input from my guesses
  dict = { "AT"=>"00", "CG"=>"01", "GC"=>"10", "TA"=>"11", "V0"=>"00", "V1"=>"01", "V2"=>"10", "V3"=>"11"  }
  # print concatenated source code for debug purposes
  puts $code  
  res = [$code.gsub(/../) {|s| dict[s] }]
  # print decoded bits for debug purposes
  puts res
  puts res.pack("b*")
end

def doublehelix(src)
  dict = { "00"=>["A","T"], "01"=>["C","G"], "10"=>["G","C"], "11"=>["T","A"] }
  format = [[1,0], [0,2], [0,3], [0,4], [1,4], [2,4], [3,3], [4,2], [5,0]]
  format += format.reverse
  %(require "doublehelix"\n\n) + src.unpack("b*").first.gsub(/../) do |s|
    format << (offset, dist = format.shift)
    " " * offset + dict[s] * ("-" * dist) + "\n"
  end
end

# removed all spaces and punctuation symbols as it was giving errors and not used in decoding anyway
AT
AT
TA
GC
GC
...
GC
AT
AT
TA
AT
TA
# I've replaced all empty lines with V0 as a starting point
V0
CG
GC
AT
CG
...
```

Now lets run it:
```bash
$ ruby dna_modified.rb
ATATTAGCGCGCTAGCATGCTAGCTAATTAGCCGATCGATATGCATGCGCGCGCGCTAATATGCATGCGCGCCGGCATGCTACGTAGCTAGCTAATATCGATGCTAATTAATTATAGCGCGCTAATGCGCCGCGGCATGCTAGCATATTAATTAV0CGGCATCGATGCTATAATGCCGTACGGCV0GCCGGCCGATGCGCGCCGCGGCATGCTAATTATAV0V0GCATTAATGCGCTAATTATAV0GCTAGCTAATATCGCGGCGCGCCGGCTATAGCGCATATGCGCATATTAATTAGCTAGCGCGCATGCCGATTAGCTATAGCGCATCGATGCTATACGGCGCGCGCGCV0ATTAGCGCGCATGCTATAGCGCTATACGGCCGGCCGGCTATAV0GCATGCATGCGCATATGCTATAGCGCTAATATGCTAATTAATATTAATGCATTAATV0GCTATAGCCGATCGAT
0000111010101110001011101100111001000100001000101010101011000010001010100110001011011110111011000001001011001100111110101011001010010110001011100000110011010110000100101111001001110110011001100100101010010110001011001111010110001100101011001111011011101100000101101010011011111010000010100000110011101110101000100100111011111010000100101111011010101010010011101010001011111010111101100110011011110110001000101000001011111010110000101100110000110010001100011011111001000100
puts"DUCTF{7H3_Mit0kHOnfRi4�15o7he_P0wEr_HoUrE_ofoDA_C3L�}"
```

Looking good, we can even read most of the flag (except for few characters where guess is wrong).

We can continue this in python now:
```py
# source code sequence we recieve from ruby
input="ATATTAGCGCGCTAGCATGCTAGCTAATTAGCCGATCGATATGCATGCGCGCGCGCTAATATGCATGCGCGCCGGCATGCTACGTAGCTAGCTAATATCGATGCTAATTAATTATAGCGCGCTAATGCGCCGCGGCATGCTAGCATATTAATTAV0CGGCATCGATGCTATAATGCCGTACGGCV0GCCGGCCGATGCGCGCCGCGGCATGCTAATTATAV0V0GCATTAATGCGCTAATTATAV0GCTAGCTAATATCGCGGCGCGCCGGCTATAGCGCATATGCGCATATTAATTAGCTAGCGCGCATGCCGATTAGCTATAGCGCATCGATGCTATACGGCGCGCGCGCV0ATTAGCGCGCATGCTATAGCGCTATACGGCCGGCCGGCTATAV0GCATGCATGCGCATATGCTATAGCGCTAATATGCTAATTAATATTAATGCATTAATV0GCTATAGCCGATCGAT"

# same dictinary
dict = { "AT":"00", "CG":"01", "GC":"10", "TA":"11", "V0":"00", "V1":"01", "V2":"10", "V3":"11"  }

# reimplemented deconding logic
for i in range(0, len(input), 8): # iterate 8 character at a time
    # using dictinary convert every 2 characters to binary
    val = (dict[input[i:i+2]] + dict[input[i+2:i+4]] + dict[input[i+4:i+6]] + dict[input[i+6:i+8]])[::-1]
    # print orignal 8 characters, its bynary value and ascii character
    print(input[i: i+8], val, chr(int(val, 2)))
```

Output is convenient to work with and fix guesses: search for V0, check if character makes sense or try V1/V2/V3. Printable characters
in ascii table all starts with 01 so that is a good hint, other bites easy to guess: 

``` hl_lines="20 24 28 31 45 57"
ATATTAGC 01110000 p
GCGCTAGC 01110101 u
ATGCTAGC 01110100 t
TAATTAGC 01110011 s
CGATCGAT 00100010 "
ATGCATGC 01000100 D
GCGCGCGC 01010101 U
TAATATGC 01000011 C
ATGCGCGC 01010100 T
CGGCATGC 01000110 F
TACGTAGC 01111011 {
TAGCTAAT 00110111 7
ATCGATGC 01001000 H
TAATTAAT 00110011 3
TATAGCGC 01011111 _
GCTAATGC 01001101 M
GCCGCGGC 01101001 i
ATGCTAGC 01110100 t
ATATTAAT 00110000 0
TAV0CGGC 01100011 c
ATCGATGC 01001000 H
TATAATGC 01001111 O
CGTACGGC 01101110 n
V0GCCGGC 01100100 d
CGATGCGC 01010010 R
GCCGCGGC 01101001 i
ATGCTAAT 00110100 4
TATAV0V0 00001111 
GCATTAAT 00110001 1
GCGCTAAT 00110101 5
TATAV0GC 01001111 O
TAGCTAAT 00110111 7
ATCGCGGC 01101000 h
GCGCCGGC 01100101 e
TATAGCGC 01011111 _
ATATGCGC 01010000 P
ATATTAAT 00110000 0
TAGCTAGC 01110111 w
GCGCATGC 01000101 E
CGATTAGC 01110010 r
TATAGCGC 01011111 _
ATCGATGC 01001000 H
TATACGGC 01101111 o
GCGCGCGC 01010101 U
V0ATTAGC 01110000 p
GCGCATGC 01000101 E
TATAGCGC 01011111 _
TATACGGC 01101111 o
CGGCCGGC 01100110 f
TATAV0GC 01001111 O
ATGCATGC 01000100 D
GCATATGC 01000001 A
TATAGCGC 01011111 _
TAATATGC 01000011 C
TAATTAAT 00110011 3
ATTAATGC 01001100 L
ATTAATV0 00001100 
GCTATAGC 01111101 }
CGATCGAT 00100010 "
```

After all fixed, print the flag:

??? success "solve.py"
    ```py
    # fixed source code
    input="ATATTAGCGCGCTAGCATGCTAGCTAATTAGCCGATCGATATGCATGCGCGCGCGCTAATATGCATGCGCGCCGGCATGCTACGTAGCTAGCTAATATCGATGCTAATTAATTATAGCGCGCTAATGCGCCGCGGCATGCTAGCATATTAATTAV0CGGCATCGATGCTATAATGCCGTACGGCV0GCCGGCCGATGCGCGCCGCGGCATGCTAATTATAV2V2GCATTAATGCGCTAATTATAV2GCTAGCTAATATCGCGGCGCGCCGGCTATAGCGCATATGCGCATATTAATTAGCTAGCGCGCATGCCGATTAGCTATAGCGCATCGATGCTATACGGCGCGCGCGCV3ATTAGCGCGCATGCTATAGCGCTATACGGCCGGCCGGCTATAV2GCATGCATGCGCATATGCTATAGCGCTAATATGCTAATTAATATTAATGCATTAATV2GCTATAGCCGATCGAT"
    
    dict = { "AT":"00", "CG":"01", "GC":"10", "TA":"11", "V0":"00", "V1":"01", "V2":"10", "V3":"11"  }
    
    for i in range(0, len(input), 8): # iterate 8 characters at a time
        # using dictionary convert every 2 characters to binary
        val = (dict[input[i:i+2]] + dict[input[i+2:i+4]] + dict[input[i+4:i+6]] + dict[input[i+6:i+8]])[::-1]
        # print decoded character
        print(chr(int(val, 2)), end="")
    ```

## Epilogue

* Official website: [https://downunderctf.com/](https://downunderctf.com/)
* Official writeups: https://github.com/DownUnderCTF/Challenges_2024_Public
