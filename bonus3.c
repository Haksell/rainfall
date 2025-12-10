#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, const char** argv, const char** envp) {
    char buf[132];
    FILE* file = fopen("/home/user/end/.pass", "r");
    memset(buf, 0, sizeof(buf));
    if (!file || argc != 2) return -1;

    fread(buf, 1, 66, file);
    buf[65] = 0;
    buf[atoi(argv[1])] = 0;
    fread(&buf[66], 1, 65, file);
    fclose(file);
    if (!strcmp(buf, argv[1]))
        execl("/bin/sh", "sh", 0);
    else
        puts(&buf[66]);
    return 0;
}
