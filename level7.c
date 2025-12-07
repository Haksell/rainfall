#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

char c[68];

typedef struct item_t {
    int id;
    char* buf;
} item_t;

void m() {
    printf("%s - %d\n", c, (int)time(NULL));
    return;
}

int main(int argc, char** argv) {
    item_t* item1 = malloc(sizeof(item_t));
    item1->id = 1;
    item1->buf = malloc(8);

    item_t* item2 = malloc(sizeof(item_t));
    item2->id = 2;
    item2->buf = malloc(8);

    strcpy(item1->buf, argv[1]);
    strcpy(item2->buf, argv[2]);

    FILE* stream = fopen("/home/user/level8/.pass", "r");
    fgets(c, 68, stream);

    puts("~~");
    return 0;
}
