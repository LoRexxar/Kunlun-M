#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc > 1) {
        int size = atoi(argv[1]);
        char *buf = (char *)malloc(size);
        if (buf) {
            memcpy(buf, argv[1], strlen(argv[1]));
            printf("Allocated %d bytes\n", size);
            free(buf);
        }
    }
    return 0;
}
