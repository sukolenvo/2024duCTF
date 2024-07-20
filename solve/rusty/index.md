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

* [rusty_vault binary](https://github.com/DownUnderCTF/Challenges_2024_Public/tree/f2797a33d8f5851508f37e854afceedf85eee8a3/rev/rusty-vault/publish)
    

NB:


* Following indices bases system is used to avoid ambiguity. Whenever element of a collection is referenced by **number**, 0-based index implied. 
 
  Ie, element `0` of list `[1, 2, 4, 8, 16]` is `1`, Element `3` is `8`.
  
  When element is reference in explanation with **word** (first, third...), 1-based system is implied.

  Ie, first character of string `Hello World!` is `H`, fifth is `o`.

* Solution code was redacted for readability purposes. Due to time pressure during the competition I was using a lot of one-letter variables and questionable code structure.

* I am using gdb with [pwndbg](https://github.com/pwndbg/pwndbg) plugin

## My struggle

### Analysis

Running the binary doesn't give us much:
```bash
$ ./rusty_vault
Enter the password to unlock the vault:
```

Its time to open [Ghidra](https://ghidra-sre.org/). The `main` function is a thin wrapper that initializes standard rust runtime and then
calls `_ZN11rusty_vault4main17h33c04fad0008f474E` this is where the magic happens.

The function has very typical structure for security challenge. It consists of 3 key parts:

1. Initialization. Usually includes many constants for key, cypher setup;
2. Key mutation. This section can be recognised by many complicated loops/jmps/branches or cipher;
3. Verification. This section typically has string/byte array comparison and two branches: success and failure.

Lets review each section:

#### Initialization 
```c title="_ZN11rusty_vault4main17h33c04fad0008f474E()"
                        # this are contastants to initialise cipher state
                        # from the first look
                        # it is at least 0xe x 4 byte integers which gives us 15x4 = 60 bytes
  *__s1 = 0x3256a6fa;
  __s1[1] = 0xcd3071c3;
  __s1[2] = 0xf161629;
  __s1[3] = 0x65e74f39;
  __s1[4] = 0xdb05fa2e;
  __s1[5] = 0x1247eacc;
  __s1[6] = 0xed7ff4c8;
  __s1[7] = 0xadf63090;
  __s1[8] = 0xa750b1ab;
  __s1[9] = 0xd1b5cfa2;
  __s1[10] = 0x9ab32e3b;
  __s1[0xb] = 0x8ea036fe;
  *(undefined8 *)(__s1 + 0xc) = 0x6179cbe7049f1890;
  __s1[0xe] = 0x385bd95c;
  if (aes::autodetect::aes_intrinsics::STORAGE == -1) {            # some AES initialization
    aes::autodetect::aes_intrinsics::init_get::cpuid(&local_9b8,1);
    aes::autodetect::aes_intrinsics::init_get::cpuid_count(&local_d78,7,0);
    if ((~(uint)local_9b0 & 0xc000000) == 0) {
      uVar9 = core::core_arch::x86::xsave::_xgetbv();
      uVar9 = (uint)local_9b0 >> 0x19 & (uVar9 & 2) >> 1;
      aes::autodetect::aes_intrinsics::STORAGE = (char)uVar9;
      if (uVar9 != 0) goto LAB_00108dc3;
    }
    else {
      aes::autodetect::aes_intrinsics::STORAGE = '\0';
    }
  }
  else if (aes::autodetect::aes_intrinsics::STORAGE == '\x01') {
LAB_00108dc3:
                           # method annotated by Ghidra  _<aes::ni::Aes256Enc as crypto_common::KeyInit>::new
    _<>::new(&local_d78,&DAT_0014a074);                          
    aes::ni::aes256::inv_expanded_keys(local_508,&local_d78);    
    memcpy(local_5f8,&local_d78,0xf0);
    memcpy(&local_d78,local_5f8,0x1e0);
    goto LAB_00108e2e;
  }
  aes::soft::fixslice::aes256_key_schedule(&local_d78,&DAT_0014a074); 
LAB_00108e2e:
  memcpy(&local_9b8,&local_d78,0x3c0);
                    # method annotated by Ghidra  _<aes_gcm::AesGcm<Aes,NonceSize,TagSize> as core::convert::From<Aes>>::from
  _<>::from(local_418,&local_9b8);
  local_9b8 = 0;
  local_9b0 = &DAT_00000001;
  local_9a8 = 0;
  local_d78 = &PTR_s_Enter_the_password_to_unlock_the_0015a118;      # prompt for password
  local_d70 = 1;
  local_d68 = 8;
  local_d60 = ZEXT816(0);
  std::io::stdio::_print(&local_d78);
  local_d78 = (undefined **)std::io::stdio::stdin();
  auVar12 = std::io::stdio::Stdin::read_line(&local_d78,&local_9b8);  # read line into variable auVar12
```

So we can see a large array initialized. After that AES setup. Then program prompts the password and stores
it in `auVar12`. Key initialization also gives away AES key size - 256 bits (based on calls `aes::soft::fixslice::aes256_key_schedule` and `aes::ni::aes256::inv_expanded_keys`).

From this section important information we are looking for:

1. What algorithm is used;
2. How its initialized.

Annotation `aes_gcm::AesGcm<Aes,NonceSize,TagSize>` tells us its AES 256 GCM, we can now find documentation and all important
params and calls: https://docs.rs/aes-gcm/latest/aes_gcm/.

```rust hl_lines="21-23" title="documentation sample" 
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key // Or `Aes128Gcm`
};

// The encryption key can be generated randomly:
let key = Aes256Gcm::generate_key(OsRng);

// Transformed from a byte array:
let key: &[u8; 32] = &[42; 32];
let key: &Key<Aes256Gcm> = key.into();

// Note that you can get byte array from slice using the `TryInto` trait:
let key: &[u8] = &[42; 32];
let key: [u8; 32] = key.try_into()?;

// Alternatively, the key can be transformed directly from a byte slice
// (panicks on length mismatch):
let key = Key::<Aes256Gcm>::from_slice(key);

let cipher = Aes256Gcm::new(&key);
let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message
let ciphertext = cipher.encrypt(&nonce, b"plaintext message".as_ref())?;
let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref())?;
assert_eq!(&plaintext, b"plaintext message");
```

Key points:

* `Aes256::new(&key)` takes address of key. In our program there is call `_<>::new(&local_d78,&DAT_0014a074);` So `DAT_0014a074` could be the key.
* `cipher.encrypt()` takes nonce (according to docs 12 bytes) and plaintext.

#### Key mutation

Now it time to what is happening to key and password.

??? info "_ZN11rusty_vault4main17h33c04fad0008f474E()"
    ```c hl_lines="80"
      if (auVar12._0_8_ == 0) {
        __dest = &DAT_00000001;
        if (local_9a8 != 0) {
          puVar5 = local_9b0 + local_9a8;
          do {
            bVar7 = puVar5[-1];
            uVar8 = (ulong)bVar7;
            if ((char)bVar7 < '\0') {
              bVar1 = puVar5[-2];
              if ((char)bVar1 < -0x40) {
                bVar2 = puVar5[-3];
                if ((char)bVar2 < -0x40) {
                  puVar6 = puVar5 + -4;
                  uVar9 = bVar2 & 0x3f | ((byte)puVar5[-4] & 7) << 6;
                }
                else {
                  puVar6 = puVar5 + -3;
                  uVar9 = bVar2 & 0xf;
                }
                uVar9 = bVar1 & 0x3f | uVar9 << 6;
              }
              else {
                puVar6 = puVar5 + -2;
                uVar9 = bVar1 & 0x1f;
              }
              uVar9 = bVar7 & 0x3f | uVar9 << 6;
              uVar8 = (ulong)uVar9;
              if (uVar9 == 0x110000) break;
            }
            else {
              puVar6 = puVar5 + -1;
            }
            uVar9 = (uint)uVar8;
            if ((4 < uVar9 - 9) && (uVar9 != 0x20)) {
              if (0x7f < uVar9) {
                uVar3 = (uint)(uVar8 >> 8);
                if (uVar3 < 0x20) {
                  if ((uVar8 & 0xffffff00) == 0) {
                    bVar7 = core::unicode::unicode_data::white_space::WHITESPACE_MAP[uVar8 & 0xff];
    LAB_00108f32:
                    bVar11 = (bool)(bVar7 & 1);
                  }
                  else {
                    if (uVar3 != 0x16) goto LAB_00109025;
                    bVar11 = uVar9 == 0x1680;
                  }
    LAB_00108f35:
                  if (bVar11 != false) goto LAB_00108f40;
                }
                else {
                  if (uVar3 == 0x20) {
                    bVar7 = (byte)core::unicode::unicode_data::white_space::WHITESPACE_MAP[uVar8 & 0xff]
                            >> 1;
                    goto LAB_00108f32;
                  }
                  if (uVar3 == 0x30) {
                    bVar11 = uVar9 == 0x3000;
                    goto LAB_00108f35;
                  }
                }
              }
    LAB_00109025:
              __n = (long)puVar5 - (long)local_9b0;
              if (__n != 0) {
                if ((long)__n < 0) {
                  uVar10 = 0;
                }
                else {
                  uVar10 = 1;
                  __dest = (undefined *)__rust_alloc(__n,1);
                  if (__dest != (undefined *)0x0) goto LAB_00109060;
                }
                alloc::raw_vec::handle_error(uVar10,__n);
                goto LAB_0010922a;
              }
              break;
            }
    LAB_00108f40:
            puVar5 = puVar6;
          } while (puVar6 != local_9b0);
        }
        __n = 0;
        memcpy(__dest,__src,__n);
        local_9b8 = __n;
        local_9b0 = __dest;
        local_9a8 = __n;
        _<>::encrypt(&local_d90,local_418,&DAT_0014a068,__dest,__n);  # call AES encrypt
    ```

It has a lot of going on. The only thing I can tell from initial look thought it there is `while` loop and a lot of branches 
on each iteration. It would take a quite some time to get my head around what is going on here. Probably want to skip this 
part for now to safe time in case its not really needed. After the crazy loop, AES `encrypt()` is called.

Earlier we saw that encrypt is supposed to take 2 params: nonce and plain text to encrypt. Here we can see 5 params. I can guess
that first one is `self` (aka this), and rest of params could be because we invoke some overloaded/internal method. I decided to
run program with gdb debugger to set a breakpoint here and see what this params are.

Instruction that I want to set breakpoint at is at address 0x001090be in Ghidra (we can't set breakpoint at address 0x001090be because
binary has PIE enabled and therefore every launch loaded to different address). Function `_ZN11rusty_vault4main17h33c04fad0008f474E` starts at 0x00108cf0, so
its `0x00108cf0 - 0x001090be = 974` bytes into the function. Therefore gdb command is `br *(_ZN11rusty_vault4main17h33c04fad0008f474E+974)`.

Here I can see params of the call:
4th is password that we entered (probably `plain_text`) and before that is pointer to nonce which we can read from memory:

```bash 
(gdb) x/12bx 0x55555559e068   # read 12 bytes in hex (we know length from docs)
0x55555559e068: 0xff    0x06    0x72    0x45    0xc6    0xae    0x7b    0x9f
0x55555559e070: 0xc1    0x36    0xd4    0x8e
```

#### Verification

Last section of the program is to verify state (ie check that password was correct):

```c title="_ZN11rusty_vault4main17h33c04fad0008f474E()"
    if ((local_d80 == 0x3c) && (iVar4 = bcmp(__s1,local_d88,0x3c), iVar4 == 0)) {  # some check
      local_d78 = &PTR_s_Congratulations,_you_have_opened_0015a150;                # this is what we want to see
      local_d70 = 1;
      local_d68 = 8;
      local_d60 = ZEXT816(0);
      std::io::stdio::_print(&local_d78);
    }
    else {
      local_d78 = &PTR_s_nope_0015a140;                                            # when password is wrong
      local_d70 = 1;
      local_d68 = 8;
      local_d60 = ZEXT816(0);
      std::io::stdio::_print(&local_d78);
    }
    uVar10 = 0;
```

Here we can see comparison of local_d80 to 0x3c which is 60. Looks like expected length as we also see call
bcmp with 3 params: 

1. `__s1` (which we identified is initialized with 60 bytes) - first param to compare;
2. `local_d88` second param to compare;
3. 0x3c (number of bytes to compare).

With debugger we can easily obtain expected value:
```bash
(gdb) x/60bx 0x5555555b2b80
0x5555555b2b80: 0xfa    0xa6    0x56    0x32    0xc3    0x71    0x30    0xcd
0x5555555b2b88: 0x29    0x16    0x16    0x0f    0x39    0x4f    0xe7    0x65
0x5555555b2b90: 0x2e    0xfa    0x05    0xdb    0xcc    0xea    0x47    0x12
0x5555555b2b98: 0xc8    0xf4    0x7f    0xed    0x90    0x30    0xf6    0xad
0x5555555b2ba0: 0xab    0xb1    0x50    0xa7    0xa2    0xcf    0xb5    0xd1
0x5555555b2ba8: 0x3b    0x2e    0xb3    0x9a    0xfe    0x36    0xa0    0x8e
0x5555555b2bb0: 0x90    0x18    0x9f    0x04    0xe7    0xcb    0x79    0x61
0x5555555b2bb8: 0x5c    0xd9    0x5b    0x38
```

### Exploit

Now we understand what program is doing it encrypts password that we enter and expects result to be `0xfaa6...`. Or more formally:
```
AES.encrypt(password) = expected_value

# Because we have expected value, we can caluculate password using formular:
AES.decrypt(expected_value) = password
```

??? success "solve.py"
    ```py
    from Crypto.Cipher import AES
    
    nonce = bytes.fromhex('ff067245c6ae7b9fc136d48e')
    key = bytes.fromhex('9587e8e7dec03c28a28ca1f7352723816c216e10714a620b9e367893389690cf')
    expected_value = bytes.fromhex('faa65632c37130cd2916160f394fe7652efa05dbccea4712c8f47fed9030f6adabb150a7a2cfb5d13b2eb39afe36a08e90189f04e7cb79615cd95b38')
    cipher = AES.new(key, AES.MODE_GCM, nonce)
    res = cipher.decrypt(expected_value)
    print(res)
    ```


## Epilogue

* Official website: [https://downunderctf.com/](https://downunderctf.com/)
* Official writeups: https://github.com/DownUnderCTF/Challenges_2024_Public

*[PIE]: Position Independent Executable
