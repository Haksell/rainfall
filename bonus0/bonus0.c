#include <stdio.h>
#include <string.h>
#include <unistd.h>

void p(char* dest, char* s) {
    char buf[4096];

    puts(s);
    read(STDIN_FILENO, buf, 4096);
    *strchr(buf, '\n') = '\0';
    strncpy(dest, buf, 20);
}

void pp(char* dest) {
    char s1[20];
    char s2[20];

    p(s1, " - ");
    p(s2, " - ");
    strcpy(dest, s1);

    size_t len = strlen(dest);
    dest[len] = ' ';
    dest[len + 1] = '\0';
    strcat(dest, s2);
}

int main() {
    char buf[42];

    pp(buf);
    puts(buf);
    return 0;
}
