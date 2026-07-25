#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    char cmd[256];
    if (argc > 1) {
        snprintf(cmd, sizeof(cmd), "ping %s", argv[1]);
        system(cmd);
    }
    return 0;
}
