## bonus0

```console
(gdb) disas pp
Dump of assembler code for function pp:
   0x0804851e <+0>:     push   ebp
   0x0804851f <+1>:     mov    ebp,esp
   0x08048521 <+3>:     push   edi
   0x08048522 <+4>:     push   ebx
   0x08048523 <+5>:     sub    esp,0x50
   0x08048526 <+8>:     mov    DWORD PTR [esp+0x4],0x80486a0
   0x0804852e <+16>:    lea    eax,[ebp-0x30]
   0x08048531 <+19>:    mov    DWORD PTR [esp],eax
   0x08048534 <+22>:    call   0x80484b4 <p>
   0x08048539 <+27>:    mov    DWORD PTR [esp+0x4],0x80486a0
   0x08048541 <+35>:    lea    eax,[ebp-0x1c]
   0x08048544 <+38>:    mov    DWORD PTR [esp],eax
   0x08048547 <+41>:    call   0x80484b4 <p>
   0x0804854c <+46>:    lea    eax,[ebp-0x30]
   0x0804854f <+49>:    mov    DWORD PTR [esp+0x4],eax
   0x08048553 <+53>:    mov    eax,DWORD PTR [ebp+0x8]
   0x08048556 <+56>:    mov    DWORD PTR [esp],eax
   0x08048559 <+59>:    call   0x80483a0 <strcpy@plt>
   0x0804855e <+64>:    mov    ebx,0x80486a4
   0x08048563 <+69>:    mov    eax,DWORD PTR [ebp+0x8]
   0x08048566 <+72>:    mov    DWORD PTR [ebp-0x3c],0xffffffff
   0x0804856d <+79>:    mov    edx,eax
   0x0804856f <+81>:    mov    eax,0x0
   0x08048574 <+86>:    mov    ecx,DWORD PTR [ebp-0x3c]
   0x08048577 <+89>:    mov    edi,edx
   0x08048579 <+91>:    repnz scas al,BYTE PTR es:[edi]
   0x0804857b <+93>:    mov    eax,ecx
   0x0804857d <+95>:    not    eax
   0x0804857f <+97>:    sub    eax,0x1
   0x08048582 <+100>:   add    eax,DWORD PTR [ebp+0x8]
   0x08048585 <+103>:   movzx  edx,WORD PTR [ebx]
   0x08048588 <+106>:   mov    WORD PTR [eax],dx
   0x0804858b <+109>:   lea    eax,[ebp-0x1c]
   0x0804858e <+112>:   mov    DWORD PTR [esp+0x4],eax
   0x08048592 <+116>:   mov    eax,DWORD PTR [ebp+0x8]
   0x08048595 <+119>:   mov    DWORD PTR [esp],eax
   0x08048598 <+122>:   call   0x8048390 <strcat@plt>
   0x0804859d <+127>:   add    esp,0x50
   0x080485a0 <+130>:   pop    ebx
   0x080485a1 <+131>:   pop    edi
   0x080485a2 <+132>:   pop    ebp
   0x080485a3 <+133>:   ret    
End of assembler dump.
```

We can do 20 then 19.

```console
bonus0@RainFall:~$ ./bonus0 
 - 
abcdefghijklmnopqrst
 - 
abcdefghijklmnopqrs 
abcdefghijklmnopqrstabcdefghijklmnopqrs abcdefghijklmnopqrs
Segmentation fault (core dumped)
```

TODO clean

cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9
