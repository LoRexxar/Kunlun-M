#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    char cmd[256];
    strcpy(cmd, argv[1]);
    system(cmd);
    return 0;
}
