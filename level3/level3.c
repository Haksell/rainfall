#include <stdio.h>
#include <stdlib.h>

int m;

void v() {
    char buf[520];

    fgets(buf, 512, stdin);
    printf(buf);  // NOLINT
    if (m == 64) {
        fwrite("Wait what?!\n", 1, 12, stdout);
        system("/bin/sh");
    }
}

int main() { v(); }
