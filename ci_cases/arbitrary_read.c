#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    char buf[512];
    int fd;
    ssize_t n;
    if (argc > 1) {
        fd = open(argv[1], O_RDONLY);
        if (fd >= 0) {
            n = read(fd, buf, sizeof(buf));
            if (n > 0) {
                write(STDOUT_FILENO, buf, n);
            }
            close(fd);
        }
    }
    return 0;
}
