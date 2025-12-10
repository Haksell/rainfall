#include <stdio.h>  //
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, const char** argv, const char** envp) {
    char dest[40];
    int n = atoi(argv[1]);
    if (n > 9) return EXIT_FAILURE;
    memcpy(dest, argv[2], 4 * n);
    printf("%d\n", n);  //
    if (n == 0x574f4c46) execl("/bin/sh", "sh", NULL);
    return EXIT_SUCCESS;
}
