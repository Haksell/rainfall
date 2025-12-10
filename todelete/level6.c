#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void n() { system("/bin/cat /home/user/level7/.pass"); }

void m() {
    puts("Nope");
    return;
}

int main(int argc, char** argv) {
    char* dst = malloc(64);
    void (**fn_ptr)() = malloc(4);

    *fn_ptr = m;
    strcpy(dst, argv[1]);
    (*fn_ptr)();
}
