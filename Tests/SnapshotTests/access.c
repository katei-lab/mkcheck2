#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

// Just access(2) a file

int main(int argc, char **argv) {
    if (argc < 2) {
        return 1;
    }

    char *path = argv[1];

    int ret = access(path, F_OK);
    if (ret < 0) {
        perror("access");
        return 1;
    }

    printf("OK\n");
}
