#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char** argv) {
    char buf[40];
    int n = atoi(argv[1]);

    if (n < 10) {
        memcpy(buf, argv[2], n * 4);
        if (n == 0x574f4c46) { execl("/bin/sh", "sh", 0); }
        return EXIT_SUCCESS;
    } else {
        return EXIT_FAILURE;
    }
}
