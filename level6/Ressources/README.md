---
title: rainfall - level6 breakdown
author: Romain GARRIGOU
date: 09/12/25
---

## level6

### Theme
Heap buffer overflow.

### Documentation

#### Heap allocation
Differents implementations of malloc exists.
For the implementation used by './level6', each allocation is done continously, with an header of 8 bytes before each allocation.

### Exploit
There is buffer overflow vulnerability in './level6':
```C
[...]
strcpy(buffer, argv[1]);
[...]
```
argv[1] can be as big as we want, where buffer has a fixed size of 64 bytes.

Here is the allocation part of './level6':
```C
[...]
buffer = malloc(64);
f = malloc(sizeof(t_f));
[...]
```
The allocations is therefore of the form:
```
[buffer (64 bytes)][malloc header (8 bytes)][f (4 bytes)]
```

We can thus use the buffer overflow to overwrite the value of 'f'.

There is a function in the executable that gives us the flag, at the address 0x08048454:
```C
int n(void)
{
    return (system("/bin/cat /home/user/level7/.pass"));
}
```

'f' is called at the end of the execution:
```C
int main(int argc, char *argv[])
{
    [...]
    return ((*f)());
}
```
Using the buffer overflow to overwrite 'f' with the address 'n', we can call the function 'n'.

We define PAYLOAD := 64 bytes (to fill buffer) + 8 bytes (to fill malloc header) + 0x08048454.
Combining all those parts, './level6 $PAYLOAD' gives us the flag.
