#include <stdio.h>
#include <string.h>
#include <unistd.h>

char* gets(char* s);

void p() {
    char buf[64];
    unsigned int ret_addr;

    fflush(stdout);
    gets(buf);

    ret_addr = (unsigned int)__builtin_return_address(0);

    if ((ret_addr & 0xb0000000) == 0xb0000000) {
        printf("(%p)\n", (const void*)ret_addr);
        _exit(1);
    }

    puts(buf);
    strdup(buf);
}

int main() { p(); }
