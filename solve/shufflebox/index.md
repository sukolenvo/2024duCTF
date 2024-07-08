---
id: index
title: Shufflebox writeup
sidebar_label: Overview
description: Writeup for challenge shufflebox of Down Under CTF 2024
---

## Prologue

CTF Event: Down Under CTF 2024

Website: [https://downunderctf.com/](https://downunderctf.com/)

Challenge: **shufflebox**

Solves: 582

!!! quote "Description"
    I've learned that if you shuffle your text, it's elrlay hrda to tlle htaw eht nioiglra nutpi aws.
  
    Find the text censored with question marks in output_censored.txt and surround it with DUCTF{}.

Input files:

??? info "shufflebox.py"
    ```python
    import random
    
    PERM = list(range(16))
    random.shuffle(PERM)
    
    def apply_perm(s):
    assert len(s) == 16
    return ''.join(s[PERM[p]] for p in range(16))
    
    for line in open(0):
    line = line.strip()
    print(line, '->', apply_perm(line))
    ```

??? info "output_censored.txt"
    ```txt
    aaaabbbbccccdddd -> ccaccdabdbdbbada
    abcdabcdabcdabcd -> bcaadbdcdbcdacab
    ???????????????? -> owuwspdgrtejiiud
    ```
NB:


* Following indices bases system is used to avoid ambiguity. Whenever element of a collection is referenced by **number**, 0-based index implied. 
 
  Ie, element `0` of list `[1, 2, 4, 8, 16]` is `1`, Element `3` is `8`.
  
  When element is reference in explanation with **word** (first, third...), 1-based system is implied.

  Ie, first character of string `Hello World!` is `H`, fifth is `o`.

* Solution code was redacted for readability purposes. Due to time pressure during the competition I was using a lot of one-letter variables and questionable code structure.

## My struggle

First things first - review source code of the script that ciphers data. Explanation for relevant parts of the code added as comments:

```py title="shuffle.py with comments"
PERM = list(range(16)) # create list of 16 elements 0, 1, 2, 3 ... 16
random.shuffle(PERM) # shuffle elements of the list in a random order, so now we have something like 15, 3, 1, 6 ...

# key tranformation logic
# PERM shuffle list is used as array of indices
# For example if PERM was a list of 4 elements [2, 0, 3, 1] 
# then result string will first output charcter 2 then 0 and so on, ie 'abcd' -> 'cadb'
def apply_perm(s): 
	assert len(s) == 16
	return ''.join(s[PERM[p]] for p in range(16))

for line in open(0):   # for each line of input apply transformation and print input and output
	line = line.strip()
	print(line, '->', apply_perm(line))
```
Import note to make is that internal state of the cipher algorithm doesn't change and there is no nonce. In other words
if we can infer PERM list from one line, we can recover all other inputs.

Now that we understand how cipher algorithm works, lets review output file:

```txt title="output_censored.txt"
aaaabbbbccccdddd -> ccaccdabdbdbbada
abcdabcdabcdabcd -> bcaadbdcdbcdacab
???????????????? -> owuwspdgrtejiiud
```
Looking at the first line we immediately spot the problem - there are 4 'a' in the input so we can't immediately tell
where it was.

Based on first line `aaaabbbbccccdddd -> ccaccdabdbdbbada`, first character is moved in one of the following positions: `[0] -> [2, 6, 13, 15]`

Because same transformation is applied to each row, we can use second row to narrow down positions of the first character:
`abcdabcdabcdabcd -> bcaadbdcdbcdacab`: first character is moved into one of the following positions: `[0] -> [2, 3, 12, 14]`

Now we can compare this two lists and see that only value `2` is present in both. Hence, first character of input is third character of output.
Ie our answer will start with `u`.

Although this problem can be solved by hand, I wrote a short stripe to print out all possible positions for each character of the
input (although we were lucky with first character and found exact position, it is possible that for some positions we may have 
several candidates).

```py
in1 = "aaaabbbbccccdddd"
out1 = "ccaccdabdbdbbada"
in2 = "abcdabcdabcdabcd"
out2 = "bcaadbdcdbcdacab"
resolved_positions = [-1] * 16
for i in range(16): # iterate over each position 0..15 and analyze what a resulting possible positions (aka candidates) 
    candidates = []
    for j in range(16):
        # if input character at position i is same as output character at position j for both lines
        # then this position j is one of candidate shuffles
        if out1[j] == in1[i] and out2[j] == in2[i]: 
            candidates.append(j)
    print(i, candidates)
    if len(candidates) == 1: # if number of candidates is 1, then we uniquely identifies transformation and can store it
        resolved_positions[i] = candidates[0]
```
```txt title="output"
0 [2]
1 [15]
2 [13]
3 [6]
4 [12]
5 [9]
6 [7]
7 [11]
8 [3]
9 [0]
10 [1]
11 [4]
12 [14]
13 [5]
14 [10]
15 [8]
```
This means that character `0` of answer is `owuwspdgrtejiiud[2]`, character `1` is `owuwspdgrtejiiud[1]` and so on.

Following short script prints out the answer:
```py
challenge = "owuwspdgrtejiiud"
for i in range(16):
    print(challenge[resolved_positions[i]], end="")
```

??? success "Full solution"
    ```py
    in1 = "aaaabbbbccccdddd"
    out1 = "ccaccdabdbdbbada"
    in2 = "abcdabcdabcdabcd"
    out2 = "bcaadbdcdbcdacab"
    resolved_positions = [-1] * 16
    for i in range(16): # iterate over each position 0..15 and analyze what a resulting possible positions (aka candidates)
        candidates = []
        for j in range(16):
            # if input character at position i is same as output character at position j for both lines
            # then this position j is one of candidate shuffles
            if out1[j] == in1[i] and out2[j] == in2[i]:
                candidates.append(j)
        print(i, candidates)
        if len(candidates) == 1: # if number of candidates is 1, then we uniquely identifies transformation and can store it
            resolved_positions[i] = candidates[0]
    
    print(resolved_positions)
    challenge = "owuwspdgrtejiiud"
    for i in range(16):
        print(challenge[resolved_positions[i]], end="")
    ```

## Epilogue 

Official writeups: https://github.com/DownUnderCTF/Challenges_2024_Public
