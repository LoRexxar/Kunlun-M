#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    char filepath[256];
    FILE *fp;
    if (argc > 1) {
        snprintf(filepath, sizeof(filepath), "/var/data/%s", argv[1]);
        fp = fopen(filepath, "r");
        if (fp) {
            printf("File opened\n");
            fclose(fp);
        }
    }
    return 0;
}
