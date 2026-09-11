#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    if (argc > 1) {
        putenv(argv[1]);
        printf("Environment updated\n");
    }
    return 0;
}
