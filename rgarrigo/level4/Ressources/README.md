---
title: rainfall - level4 breakdown
author: Romain GARRIGOU
date: 09/12/25
---

## level4

### Theme
Advanced format string bug.

### Documentation

#### printf length modifiers
On each printf integer conversion, we can add a length modifier.

The length modifier 'hh' corresponds to a byte.
Example:
```C
// Print the char 'n' to stdout.
printf("%hhd", n);
```

#### printf field width
On each printf conversion, we can add a field width.
With a field width of 'n', the conversion will be printed with at least 'n' characters.

Example:
```C
// Print '   2' to stdout.
printf("%4d", 2);
```

#### printf argument specifier
On each printf conversion, we can add 'm$' after the '%'. 
It specifies that the m-th argument has to be taken for the conversion instead of the next argument.

Example:
```C
// Print the int 'm' to stdout.
printf("%2$d", n, m);
```

### Exploit
Using a format string bug, we have to write 0x01025544 at the address 0x08049810.

We split this task into four:
- Writing 0x01 at the address 0x08049813
- Writing 0x02 at the address 0x08049812
- Writing 0x55 at the address 0x08049811
- Writing 0x44 at the address 0x08049810

Here is a technique to write 'n' at the address 'A', then 'm' at the address 'B' with a single call to printf:
-  We print 'n' characters then use the '%n' conversion with 'A'.
-  We print 'm - n' characters then use the '%n' conversion with 'B'.

By extending this technique to four differents writes, we can executes our tasks with a single call to printf.

The tasks will therefore be executed as follows:
- Writing 0x01 at the address 0x08049813
- Writing 0x02 at the address 0x08049812
- Writing 0x44 at the address 0x08049810
- Writing 0x55 at the address 0x08049811

Using the format string bug:
- We print '0x01' characters, then use the %n conversion with the address 0x08049813
- We print '0x02 - 0x01' characters, then use the %n conversion with the address 0x08049812
- We print '0x44 - 0x02' characters, then use the %n conversion with the address 0x08049810
- We print '0x55 - 0x44' characters, then use the %n conversion with the address 0x08049811

This bypass the check and executes the following:
```C
return (system("/bin/cat /home/user/level5/.pass"));
```
Which gives us the flag.
