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
So looking at the disassembled code we see that we need to run ./level 423 to escape the condition that prints "No !"
Therefore the program runs a shell with level1 right, so:
```console
level0@RainFall:~$ ./level0 423
$ cat /home/user/level1/.pass
1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
```
