#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

// Just ftruncate(2) a file

int main(int argc, char **argv) {
    if (argc < 3) {
        return 1;
    }

    char *path = argv[1];
    int size = atoi(argv[2]);

    int fd = open(path, O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    int ret = ftruncate(fd, size);
    if (ret < 0) {
        perror("ftruncate");
        return 1;
    }
    printf("OK\n");
}
