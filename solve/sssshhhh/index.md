---
id: index
title: sssshhhh writeup
description: Writeup for challenge "sssshhhh" of Down Under CTF 2024
---

## Prologue

Difficulty: beginner

Category: reverse engineering

Solved: 81

!!! quote "Description"
    Great news! We found the Kookaburras!... Bad news.. They're locked up. We've managed to get access to the central terminal and ripped a binary off of it for you to analyse. Maybe you can find a way to free our friends?

Input files:

* [server binary](https://github.com/DownUnderCTF/Challenges_2024_Public/blob/f2797a33d8f5851508f37e854afceedf85eee8a3/beginner/sssshhhh/src/cmd/cmd)

NB:


* Following indices bases system is used to avoid ambiguity. Whenever element of a collection is referenced by **number**, 0-based index implied. 
 
  Ie, element `0` of list `[1, 2, 4, 8, 16]` is `1`, Element `3` is `8`.
  
  When element is reference in explanation with **word** (first, third...), 1-based system is implied.

  Ie, first character of string `Hello World!` is `H`, fifth is `o`.

* Solution code was redacted for readability purposes. Due to time pressure during the competition I was using a lot of one-letter variables and questionable code structure.

* I am using gdb with [pwndbg](https://github.com/pwndbg/pwndbg) plugin

## My struggle

What do we do the first when we have an unknown binary? Lets run it:

```bash
$ ./server
5:29PM INFO Starting SSH Server host=0.0.0.0 port=1337
```

When we try to ssh to it we see that it requires a password. So lets open in [Ghidra](https://ghidra-sre.org/) and see if we can find it.

`main` function has calls `startLogger()` and `RunSSH()`. Second call is interesting - it should initialise user accounts somehow. In code there are a lot of
references to https://github.com/charmbracelet/ssh which is a go package for embeded ssh server. In the documentation and examples of the 
library we can see how usually password authentication is configured https://pkg.go.dev/github.com/gliderlabs/ssh#PasswordAuth, so we know what 
to look for. 

Two interesting lines in `RunSSH()` that caught my eye:

```c
local_b0._8_8_ = &PTR_main.RunSSH.func2_0069c798;
local_b0._0_8_ = main.RunSSH.WithPasswordAuth.PasswordAuth.func10;
```
From docs we know that PasswordAuth take a parameter - PasswordHandler. Address of the `func2` is taken right before PasswordAuth setup. Its worth
to check the code of the func2:
```c hl_lines="8-10"
undefined8 main.RunSSH.func2(long param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)
{
  undefined8 uVar1;
  long unaff_R14;
  undefined8 param_9;
  
  param_9 = param_4;
  if (param_1 == 0x23) {
    uVar1 = runtime.memequal();
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}
```
It compares some number (length?) to 0x23 and then calls `memequal`. Strangely, `memequel` doesn't take any params. Eventually I checked disassembly for this line:
```asm
MOV        RAX,param_4
LEA        RBX,[DAT_0067ec99] 
MOV        RCX,0x23  
CALL       runtime.memequal
```
First it moves param_4 to RAX (password?), then loads value from DAT_0067ec99 to RBX, 0x23 is likely length and calls memequal.

We can see password in plain text at address DAT_0067ec99, now lets try to connect:
```bash
└─$ ssh localhost -p 1337                        
 ____  __.             __          ___.                               
|    |/ _|____   ____ |  | _______ \_ |__  __ _____________________   
|      < /  _ \ /  _ \|  |/ /\__  \ | __ \|  |  \_  __ \_  __ \__  \  
|    |  (  <_> |  <_> )    <  / __ \| \_\ \  |  /|  | \/|  | \// __ \_
|____|__ \____/ \____/|__|_ \(____  /___  /____/ |__|   |__|  (____  /
        \/                 \/     \/    \/                         \/ 
  ___ ___        .__       .___.__                                    
 /   |   \  ____ |  |    __| _/|__| ____    ____                      
/    ~    \/  _ \|  |   / __ | |  |/    \  / ___\                     
\    Y    (  <_> )  |__/ /_/ | |  |   |  \/ /_/  >                    
 \___|_  / \____/|____/\____ | |__|___|  /\___  /                     
       \/                   \/         \//_____/                      
_________        .__  .__                                             
\_   ___ \  ____ |  | |  |   ______                                   
/    \  \/_/ __ \|  | |  |  /  ___/                                   
\     \___\  ___/|  |_|  |__\___ \                                    
 \______  /\___  >____/____/____  >                                   
        \/     \/               \/                                    
kali@localhost's password: 
Welcome, kali!
This is the Kookaburra holding cells.
        Contained: 11912 Kookaburras
        -> No valid command
elapsed time: 552.727µs
Connection to localhost closed.
```

We can see line `-> No valid command`. This looks like a hint of the next obstacle. Our work with Ghidra is not finished yet. There should be handler somewhere with
commands list. We are looking for something that calculates elapsed time or prints kookaburras count. Eventually I restarted
server with gdb and set a breakpoint to printf function found through stack trace that handler for the server is func_8_1.

There we can see following check:
```c hl_lines="1 2"
  if ((((pplVar6[1] == (long *)&DAT_0000000e) && (plVar2 = *pplVar6, *plVar2 == 0x68546b636f6c6e55))
      && (*(int *)(plVar2 + 1) == 0x6c654365)) && (*(short *)((long)plVar2 + 0xc) == 0x736c)) {
    os.Getenv();
    local_28._8_8_ = &PTR_DAT_006df670;
    local_28._0_8_ = &DAT_00625400;
    auVar9 = runtime.convTstring();
    local_18._8_8_ = auVar9._0_8_;
    local_18._0_8_ = &DAT_00625400;
    auVar9 = fmt.Sprintf(2,2,auVar9._8_8_,local_28);
    github.com/charmbracelet/wish.Printf(5,0,auVar9._8_8_,auVar9._0_8_,0,0);
  }
```
This is very common compiler optimisation for comparing short strings with static text. Converting constants `0x68546b636f6c6e55 0x6c654365 0x736c` to ascii 
and reversing order of each number (little endian) gives us the command. Lets try it:

```bash
$ ssh localhost -p 1337  UnlockTheCells  
 ____  __.             __          ___.                               
|    |/ _|____   ____ |  | _______ \_ |__  __ _____________________   
|      < /  _ \ /  _ \|  |/ /\__  \ | __ \|  |  \_  __ \_  __ \__  \  
|    |  (  <_> |  <_> )    <  / __ \| \_\ \  |  /|  | \/|  | \// __ \_
|____|__ \____/ \____/|__|_ \(____  /___  /____/ |__|   |__|  (____  /
        \/                 \/     \/    \/                         \/ 
  ___ ___        .__       .___.__                                    
 /   |   \  ____ |  |    __| _/|__| ____    ____                      
/    ~    \/  _ \|  |   / __ | |  |/    \  / ___\                     
\    Y    (  <_> )  |__/ /_/ | |  |   |  \/ /_/  >                    
 \___|_  / \____/|____/\____ | |__|___|  /\___  /                     
       \/                   \/         \//_____/                      
_________        .__  .__                                             
\_   ___ \  ____ |  | |  |   ______                                   
/    \  \/_/ __ \|  | |  |  /  ___/                                   
\     \___\  ___/|  |_|  |__\___ \                                    
 \______  /\___  >____/____/____  >                                   
        \/     \/               \/                                    
kali@localhost's password: 
Welcome Warden, running command
Welcome, kali!
This is the Kookaburra holding cells.
        Contained: 11912 Kookaburras
        -> No valid command
elapsed time: 666.382µs
```

And it did nothing - I still see `no valid command`. Well actually now there is one more line `Welcome Warden, running command`, but then it says command is still invalid.
In code inside the `if` block there is `os.GetEnv()`, so likely this is where flag comes from. Restarting server with following command:

```bash
WARDEN=myflag ./server 
```

Connecting to server now gave the flag. 

## Epilogue

* Official website: [https://downunderctf.com/](https://downunderctf.com/)
* Official writeups: https://github.com/DownUnderCTF/Challenges_2024_Public
