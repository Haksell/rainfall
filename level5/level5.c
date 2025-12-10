#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void shell() {
    system("/bin/sh");
    _exit(1);
}

void cat() {
    char buf[520];

    fgets(buf, 512, stdin);
    printf(buf);
    exit(1);
}

int main() { cat(); }
