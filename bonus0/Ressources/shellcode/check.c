// gcc -z execstack check.c -o check
// ./check "$(cat shellcode.dump)"

int main(int argc, char *argv[])
{
    int     i;
    char    buffer[128];
    void    (*f)(void);

    i = 0;
    while (argv[1][i])
    {
        buffer[i] = argv[1][i];
        ++i;
    }
    f = buffer;
    f();
    return (0);
}
