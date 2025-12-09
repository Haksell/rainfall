#include <stdio.h>
#include <string.h>
#include <unistd.h>

char* p(char* dest, char* s) {
    char buf[4096];

    puts(s);
    read(STDIN_FILENO, buf, 4096);
    *strchr(buf, '\n') = '\0';
    return strncpy(dest, buf, 20);
}

char* pp(char* dest) {
    char s1[20];
    char s2[20];

    p(s1, " - ");
    p(s2, " - ");
    strcpy(dest, s1);

    size_t len = strlen(dest);
    dest[len] = ' ';
    dest[len + 1] = '\0';
    return strcat(dest, s2);
}

int main() {
    char s[42];

    pp(s);
    puts(s);
    return 0;
}
