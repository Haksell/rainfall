#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

int setresuid(uid_t ruid, uid_t euid, uid_t suid);
int setresgid(gid_t rgid, gid_t egid, gid_t sgid);

int main(int argc, char** argv) {
    if (atoi(argv[1]) == 423) {
        char* exec_argv[2] = {strdup("/bin/sh"), NULL};

        gid_t egid = getegid();
        uid_t euid = geteuid();

        setresgid(egid, egid, egid);
        setresuid(euid, euid, euid);

        execv("/bin/sh", exec_argv);
    } else {
        fwrite("No !\n", 1, 5, stdout);
    }

    return 0;
}
