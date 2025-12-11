---
title: rainfall - level8 breakdown
author: Romain GARRIGOU
date: 09/12/25
---

## level8

### Theme
Allocation visualisation?

### Exploit
Typing "login\n" with \*(int \*)(a + 32) != 0 gives us a shell.

We just have to do the following:
- Allocate a (4 bytes).
- Allocate b of size 32.
- Filling b with non-zero values.
(a + 32) will be an address in the buffer b, therefore non-zero.
- Typing "login"

Translation to './level8' commands:
- Typing "auth \<dummy-name\>"
- Typing "service\<32 non-zero characters\>"
- Typing "login"

This gives a shell, thus the flag.
