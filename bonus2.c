#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

uint32_t language;

int greetuser(char src) {
    int128_t dest;  // [esp+10h] [ebp-48h] BYREF
    int16_t v3;  // [esp+20h] [ebp-38h]
    char v4;  // [esp+22h] [ebp-36h]

    switch (language) {
    case 1:
        *(_QWORD*)&dest = 0x20A4C3A4C3767948LL;
        *((_QWORD*)&dest + 1) = 0xC3A4C37669A4C370LL;
        v3 = unk_8048727;
        v4 = unk_8048729;
        break;
    case 2: strcpy((char*)&dest, "Goedemiddag! "); break;
    case 0: strcpy((char*)&dest, "Hello "); break;
    }
    strcat((char*)&dest, &src);
    return puts((const char*)&dest);
}

int32_t main(int32_t argc, char** argv, char** envp) {
    if (argc != 3) return 1;

    void var_60;
    memset(&var_60, 0, 0x4c);
    size_t var_a8_1 = 0x28;
    char* var_ac = argv[1];
    char* name = &var_60;
    strncpy(name, var_ac, var_a8_1);
    size_t var_a8_2 = 0x20;
    var_ac = argv[2];
    void var_38;
    name = &var_38;
    strncpy(name, var_ac, var_a8_2);
    name = "LANG";
    char* name_1 = getenv(name);

    if (name_1) {
        size_t var_a8_3 = 2;
        var_ac = &data_804873d;
        name = name_1;

        if (memcmp(name, var_ac, var_a8_3)) {
            size_t var_a8_4 = 2;
            var_ac = &data_8048740;
            name = name_1;

            if (!memcmp(name, var_ac, var_a8_4)) language = 2;
        } else
            language = 1;
    }

    memcpy(&name, &var_60, 0x4c);
    return greetuser();
}
