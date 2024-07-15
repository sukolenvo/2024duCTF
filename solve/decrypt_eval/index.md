---
id: index
title: Decrypt then eval writeup
description: Writeup for challenge "Decrypt then eval" of Down Under CTF 2024
---

## Prologue

Difficulty: easy

Category: cryptography

Solved: 197

!!! quote "Description"
    This server decrypts user input and evaluates it. Please use your magical malleability mastership to retrieve the flag!

Input files:

??? info "decrypt-then-eval.py"
    ```py
    #!/usr/bin/env python3
    
    from Crypto.Cipher import AES
    import os
    
    KEY = os.urandom(16)
    IV = os.urandom(16)
    FLAG = os.getenv('FLAG', 'DUCTF{testflag}')
    
    def main():
        while True:
            ct = bytes.fromhex(input('ct: '))
            aes = AES.new(KEY, AES.MODE_CFB, IV, segment_size=128)
            try:
                print(eval(aes.decrypt(ct)))
            except Exception:
                print('invalid ct!')
    
    if __name__ == '__main__':
        main()
    ```

NB:


* Following indices bases system is used to avoid ambiguity. Whenever element of a collection is referenced by **number**, 0-based index implied. 
 
  Ie, element `0` of list `[1, 2, 4, 8, 16]` is `1`, Element `3` is `8`.
  
  When element is reference in explanation with **word** (first, third...), 1-based system is implied.

  Ie, first character of string `Hello World!` is `H`, fifth is `o`.

* Solution code was redacted for readability purposes. Due to time pressure during the competition I was using a lot of one-letter variables and questionable code structure.
 
* I am using gdb with [pwndbg](https://github.com/pwndbg/pwndbg) plugin

## My struggle

### Analysis

We got only one file to start with:

```py
KEY = os.urandom(16) # AES params
IV = os.urandom(16)
FLAG = os.getenv('FLAG', 'DUCTF{testflag}') # flag variable this will be our target

def main():
    while True:
        ct = bytes.fromhex(input('ct: '))                      # read input string
        aes = AES.new(KEY, AES.MODE_CFB, IV, segment_size=128) # create AES cipher
        try:
            print(eval(aes.decrypt(ct)))   # decrypt input string, evaluate result value 
        except Exception:
            print('invalid ct!')
```
Our goal is to get `aes.decrypt` return string `FLAG`, then evaluation of it will print value of the 
`FLAG` variable back to us.

AES is considered to be a secure algorithm. If its used correctly - its practically unbreakable. The key part of
this statement is "if used correctly". The key issue of the implementation is that it `AES.new` is created afresh for every
user input. Given IV and KEY are same every time, same cipher keystream is generated for each input. Combined with the fact
that CFB mode is used, we can control result of decryption even though we will never know values of KEY and IV.

Lets review strategy of controlling output of AES description in CFB mode when same keystream is applied to every input
that we provide. Program executes following algorithm:

1. Read used input;
2. Generate same keystream every time for given KEY nad IV
3. XOR input with keystream
4. Evaluate result
5. If expression is evaluated successfully - print result, otherwise print "invalid ct!"

If we know the keystream, we can easily construct input that will give us any desired output. For example if first keystream byte
was 0x67 and we would want it to be 'F' (ascii value 0x46) then input we are lookign for is `0x67 ^ 0x46 = 0x21`. Same calculation
works for any other byte value of the keystream.

### Attempt 1

How would we find the keystream? My first idea was to loop through all possible inputs until I get first and last characters
to be double quotes, then everything is the middle will be considered as string that will be printed back.
Once I have bytes the middle, I can calculate input.

Pseudocode that I used for this:

```py title="attempt_1.py"
input = [0] * 16  # this is our input 16 bytes long (source code mentioned segment size 128)
# when same byte of keystream is XOR-ed with 256 different values in input
# output will also cover 256 possible values
# one of them will be double quote that I am looking for
for i in range(256):          # try all possible first bytes
    for j in range(256):      # try all possible last bytes
        input[0] = i          # set first byte to i, last byte to j, all others will be 0
        input[15] = j
        io.sendline(binascii.hexlify(bytearray(input)))  # send input to the decrypt-eval program
        response = io.recvline().strip()  # read result line
        # if we got something interesting - print it, I expect to double quoted string and single quoted
        # and maybe some other inputs that are randomly valid
        if b'invlaid ct!' not in line:  
            print("We received response that is not error: ", line)
```

I've run the program and to my surprise I got nothing. There must be some other evaluation errors. I've modified source code of the decrypt-eval program
to include more debug information printed while keeping functionality intact and increasing 
performance. With this version I can iterate much quicker:

```py title="modified decrypt-then-eval.py"
aes = AES.new(KEY, AES.MODE_CFB, IV, segment_size=128) # create AES instance at the start of the program 
keysream = aes.decrypt(bytearray(16))                  # by using input [0,0,0,0....0] extract keystream 

def main():
    while True:
        ct = bytes.fromhex(input('ct: '))
        try:
            print(eval(xor_arrays(keysream, ct)))      # xor keystream with provided input
        except Exception as e:
            print('invalid ct!', e)                    # add exception details to the message
```
Once I rerun my enumeration script I found errors of the eval:

1. source code string cannot contain null bytes;
2. invalid utf8 encoding

Looks like there is a bad sequence of bytes somewhere in the middle of the string. So far, all input middle bytes were 0. I think
we should try different value to deal with encoding problems. For nullbyte error we should try both 0 and 1 as input 
(only one may produce null-byte, not both at the same time).

Pair 127,128 should take care of invalid UTF-8 sequence. UTF8 encoded characters are variable length byte sequences.
It means that frequently used characters like latin alphabet, digits will take only 1 byte, and some less frequently used (emoji etc)
assign 2-3 byte sequences. Decoding process is quite straightforward: first bit has a special meaning, its a flag indicating
that current byte is final byte of codepoint. Remaining bits are concatenated to form codepoint value. For example:
```
0XXXXXXX                    -> 1 byte sequence, codepoint is XXXXXXX
1AAAAAAA 0BBBBBBB           -> 2 byte sequence codepoints is AAAAAAABBBBBBB
1AAAAAAA 1BBBBBBB 0CCCCCCC  -> 3 byte sequence codepoint is AAAAAAABBBBBBBCCCCCCC
...
```
1 byte UTF-8 symbols are all defined (matches ascii table for backwards compatibility), 2+ byte sequences have gaps and not 
every codepoint is defined (ie valid). This is where we get encoding errors. If all characters were 1byte sequences, we would
not have undefined codepoints error. Pair `127, 128` should take care of it - flips highes bit, therefore we can
reach a sequence in output where every byte is starting with 0 and is not a null-byte.

The resulting candidate values to try for input bytes 1..14 are `[0, 1, 127, 128]`.

### Attempt 2

Here is script to enumerate through all values 0..255 for bytes 0 and 15, and vocabulary [0, 1, 127, 128]
for bytes 1..14 as discussed earlier to deal with encoding errors.

Feel free to skip implementation of the function `input_generator` as long as you understand the sequence that its producing and 
reasoning why we want this sequence (I think implementation is not too important for understanding the challenge).
Loop in the end of the snippet is mostly the same as before.

```py title="attempt_2.py"
# Generate sequence of states:
# [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
# [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
# ...
# [255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
# [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
# [1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
# ...
# [256, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
# [0, 127, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
# [1, 127, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
# ...
def input_generator():
    state = [0] * 16
    possible_values = [range(256) if i == 0 or i == 15 else [0, 1, 127, 128] for i in range(16)]
    while True:
        yield [possible_values[i][state[i]] for i in range(len(state))]
        for i in range(len(state)):
            if state[i] < len(possible_values[i]) - 1:
                state[i] += 1
                break
            else:
                if i == len(state) - 1:
                    return
                state[i] = 0


for state in input_generator():
    io.sendline(binascii.hexlify(bytearray(state)))  # send input to local bynary
    response = io.recvline().strip()  # read result line
    # if we got something interesting - print it, I expect to double quoted string and single quoted
    # and maybe some other inputs that are randomly unique
    if b'invlaid ct!' not in line:
        print("We received response that is not error: ", line)
```

While the script is running I had some time (actually quite a lot of time) to calculate total number of iterations. The formula
is trivial: `number of possible values for byte 0` * `number of possible values for byte 1` * `number of values for byte 2` * ...

256 * (4 ** 14) * 256 = 17592186044416

No wonder it takes a lot of time! 

Immediate thought was to reduce number of states for bytes 1..14 from `[0, 1, 127, 128]` to `[0, 128]`, unless we are very unlucky
this should also work. Its also easy to update the script.

But it doesn't seem to be enough.

On the second thought, I am running against local application that performs no cryptography, but only XOR of two arrays.
Its magnitudes faster than remote script. Therefore, proper solution should finish locally under few seconds.
Besides that, all heavy lifting of cryptography is done on the server side, its very unlikely author expects all teams to run
thousands of cryptography iterations each, this would be nontrivial question for scalability/costs.

### Attempt 3

My new idea for desired output: first byte is digit, second byte is `#`, other bytes doesn't matter as
they will be treated as comment and hence ignored. Complexity of native implementation of such algorithm would be `256*256`,
but I am sure given all digits are consecutive in ascii table and any of them works for us, there is a smart lookup of first byte
that will reduce algorithm complexity to `25*256` iterations.
Quick prototyping only to got me a disappointing discovery: value for eval should 
be a valid python source file without nullbytes and invalid codepoints, even if its a comment.

At this moment it became clear that I am looking in the wrong direction. Therefore, I went back to the task description and
original source code.

Then it struck me: CFB is a stream cipher, it means I can provide as little as 1 byte and output will also be 1 byte (compared to 
block ciphers that even for 1 byte input are adding padding and produce fixed blocks of output).

### Attempt 4

Algorithm:

1. Iterate through all possible values of byte 0 (0..255) until we receive digit as an output;
2. Calculate keystream byte using formula `k[i] = input[i] ^ ord(output[i])`
3. Calculate input for byte 0 that will produce a space as output using formula `input[0] = k[0] ^ ord(' ')`
4. Use value from step 3 as prefix, repeat step 1-3 to calculate other keystream bytes.
5. Now we can calculate input that will produce `FLAG`: `input[0] = k[i] ^ ord('F')`, `input[1] = k[1] ^ ord('L')`.

Complexity of the algorithm is 4*256 iterations.

??? success "solve.py"
    ```py
    from pwn import *
    
    if args['REMOTE']:
        remote_server = '2024.ductf.dev'
        remote_port = 30020
        io = remote(remote_server, remote_port)
    else:
        io = process(["python", "decrypt-then-eval.py"])
    
    keystream = []                      # store keystream values we idenitified so far
    for j in range(4):                  # we will repeat for 4 bytes
        for i in range(256):            # try all possible values for next byte
            io.recvuntil(b': ')         # wait for decrypt-then-eval.py to init
            # use keystream prefix XORed with space (eval trims spaces) as prefix
            # and append candidate value of next input `i`  
            io.sendline(binascii.hexlify(bytearray([p ^ ord(' ') for p in keystream]) + i.to_bytes()))
            # read result
            line = io.recvline().strip()
            if b'invalid ct!' not in line:  # if not error
                if line == b'0':  # if result is 0, technically we can stop on any digit, but its not a substantial difference
                    keystream.append(i ^ ord('0')) # append keystream value we found
                    break                          # on the the next byte
    
    io.recvuntil(b': ')
    # calculate input that once decrypted produces FLAG
    payload = bytearray([keystream[0] ^ ord('F'), keystream[1] ^ ord('L'), keystream[2] ^ ord('A'), keystream[3] ^ ord('G')])
    io.sendline(binascii.hexlify(payload))
    flag = io.recvline().strip()
    print(f'{flag=}')
    io.close()
    ```

## Epilogue

* Official website: [https://downunderctf.com/](https://downunderctf.com/)
* Official writeups: https://github.com/DownUnderCTF/Challenges_2024_Public

*[IV]: initialization vector
*[AES]: Advanced Encryption Standard
*[CFB]: Cipher Feedback mode: each byte of plaintext is XOR-ed with byte of keystream.
