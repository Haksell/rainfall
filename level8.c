#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* auth;
char* service;

int main() {
    char s[5];
    char v5[2];
    char v6[129];

    while (1) {
        printf("%p, %p \n", auth, (const void*)service);
        if (!fgets(s, 128, stdin)) break;
        if (!memcmp(s, "auth ", 5)) {
            auth = malloc(4);
            auth[0] = 0;
            if (strlen(v5) <= 0x1E) strcpy(auth, v5);
        }
        if (!memcmp(s, "reset", 5)) free(auth);
        if (!memcmp(s, "service", 6)) service = strdup(v6);
        if (!memcmp(s, "login", 5)) {
            if (auth[32]) {
                system("/bin/sh");
            } else {
                fwrite("Password:\n", 1u, 0xAu, stdout);
            }
        }
    }
    return 0;
}
