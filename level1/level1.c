#include <stdio.h>
#include <stdlib.h>

char* gets(char* s);

void run() {
    fwrite("Good... Wait what?\n", 1, 19, stdout);
    system("/bin/sh");
}

int main() {
    char buf[64];
    gets(buf);
}
