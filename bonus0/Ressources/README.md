---
title: rainfall - bonus0 breakdown
author: Romain GARRIGOU
date: 09/12/25
---

## bonus0

### Theme
Non-null terminating strings.

### Exploit
We want to get a stack buffer overflow to overwrite the return address of 'main' and jump to a shellcode.
```C
int main(void)
{
    char    buffer[42];

    pp(buffer);
    puts(buffer);
    return (0);
}
```

We thus wants to puts more than 42 characters in the buffer, let's look at the 'pp' function:
```C
void    pp(char *dest)
{
    char    pp_buffer2[20];
    char    pp_buffer1[20];
    int     a;
    int     b;
    int     i;

    p(pp_buffer1, " - ");
    p(pp_buffer2, " - ");
    strcpy(dest, pp_buffer1);
    dest[strlen(dest)] = ' ';
    strcat(dest, pp_buffer2);
}
```

We see that a function calls 'p' is used to set the buffers 'pp_buffer1' and 'pp_buffer2'.
Let's look at it.
```C
void    p(char *dest, const char *str)
{
    char    p_buffer[4096];

    puts(str);
    read(0, p_buffer, 4096);
    *strchr(p_buffer, '\n') = 0;
    strncpy(dest, p_buffer, 20);
}
```

We see that we can put 20 arbitrary bytes into 'p_buffer'.
Meaning we can have a non-null terminated 'pp_buffer1' or 'pp_buffer2', by setting them to 20 non-null bytes.

By having a non-null terminated 'pp_buffer1':
- The call to 'strcpy' will copy 'pp_buffer1' to dest, then 'pp_buffer2' to dest ('pp_buffer1' and 'pp_buffer2' are continous on the stack)
- Then, dest will be concatenated with 'pp_buffer2'

dest will therefore looks like this at the end of 'pp':
```
[pp_buffer1 (20 bytes)][pp_buffer2 (at most 19 bytes)][pp_buffer2 (at most 19 bytes)]
```

By putting a 23 bytes shellcode in ('pp_buffer1' + 'pp_buffer2'), and the address of the 'dest' buffer somewhere in 'pp_buffer2', we can overwrite the return address of 'main' to jump to our shellcode.

With the shell given by our shellcode, we then retrieve the flag.
