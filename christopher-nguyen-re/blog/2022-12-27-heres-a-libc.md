---
slug: heres_a_libc
title: Here's a LIBC
authors: [nguyen]
tags: [Pico CTF, Binary Exploitation]
---

<!--truncate-->

## The Challenge

The challenge can be found [here](https://play.picoctf.org/practice).

## The Solve

Checksec
NX No PIE

Ghidra

scanf

Library provided

Leak puts

Find base address of library

Get address of system

Create Rop

## Script

c
