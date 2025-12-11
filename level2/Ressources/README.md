---
title: rainfall - level2 breakdown
author: Romain GARRIGOU
date: 09/12/25
---

## level2

### Theme
Shellcode on the heap.

### Documentation

#### Shellcode
We can write custom machine code to a buffer then jump to this buffer to execute this custom code.
This custom code is usually just a call to 'execve("/bin/sh", 0, 0)'.
Thus the name: shellcode.

#### ELF Program header table and memory pages permissions
An ELF file specify several segments, that will be loaded in memory.
A segment consist of an adress, a size and read/write/execution permissions.

The ELF program header describes all the memory segments available during the execution.
It can be shown using 'readelf -l':
```bash
$> readelf -l ./level2 

Elf file type is EXEC (Executable file)
Entry point 0x8048420
There are 8 program headers, starting at offset 52

Program Headers:
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  PHDR           0x000034 0x08048034 0x08048034 0x00100 0x00100 R E 0x4
  INTERP         0x000134 0x08048134 0x08048134 0x00013 0x00013 R   0x1
      [Requesting program interpreter: /lib/ld-linux.so.2]
  LOAD           0x000000 0x08048000 0x08048000 0x00748 0x00748 R E 0x1000
  LOAD           0x000748 0x08049748 0x08049748 0x00114 0x00124 RW  0x1000
  DYNAMIC        0x00075c 0x0804975c 0x0804975c 0x000c8 0x000c8 RW  0x4
  NOTE           0x000148 0x08048148 0x08048148 0x00044 0x00044 R   0x4
  GNU_EH_FRAME   0x000628 0x08048628 0x08048628 0x0003c 0x0003c R   0x4
  GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RWE 0x4

 Section to Segment mapping:
  Segment Sections...
   00     
   01     .interp 
   02     .interp .note.ABI-tag .note.gnu.build-id .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_r .rel.dyn .rel.plt .init .plt .text .fini .rodata .eh_frame_hdr .eh_frame 
   03     .ctors .dtors .jcr .dynamic .got .got.plt .data .bss 
   04     .dynamic 
   05     .note.ABI-tag .note.gnu.build-id 
   06     .eh_frame_hdr 
   07
```
Here we can see that './level2' has a writable and executable stack.

A shellcode needs to be written in memory, then executed.
Therefore, to exploit an executable with a shellcode, it is necessary to write it to a segment with write and execution permissions.

### Exploit
'./level2' calls a function called 'p' during its execution.
We can use a stack buffer overflow with the 'gets' function in 'p' to overwrite the return address of the 'p' function.
```C
char    *p(void)
{
    int     n;
    char    buffer[64];
[...]
    gets(buffer);
[...]
}
```

We write a shellcode in the buffer, with the idea to jump to this shellcode using the overwritten return address of 'p'.

However, there is a check present that prevent us to overwrite the return address with an address on stack:
```C
[...]
    n = *(int *)(buffer + 112) & 0xb0000000;
    if (n != 0xb0000000)
    {
        printf("(%p)\n", buffer);
        exit(1);
    }
[...]
```
The check works because:
- (buffer + 112) corresponds to the address of the overwritten return address
- For the execution of './level2', all the address of the stack begins with 0xb

To counter this check, we use the fact the buffer is copied on the heap after the call to 'strdup':
```C
[...]
    return (strdup(buffer));
[...]
```

The shellcode is copied on the heap at the address 0x0804a008.
This OS set the memory permissions of the heap as the memory permissions of the stack.
The shellcode copied on the heap is therefore executable.

We launch this way a shellcode that executes '/bin/sh' with permissions of 'level3'.
We use this shell to retrieve the password of 'level3'.
