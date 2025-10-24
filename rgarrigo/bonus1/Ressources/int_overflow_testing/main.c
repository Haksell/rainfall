#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
    int n;

    if (argc != 2)
        return (fprintf(stderr, "Usage: %s <n>\n", argv[0]), 2);
    n = atoi(argv[1]);
    printf("n: %d\n", n);
    printf("4 * n: %d\n", 4 * n);
    return (0);
}
