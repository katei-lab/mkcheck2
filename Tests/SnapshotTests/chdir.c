#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

// fchdir(2), then access(2) a file

int main(int argc, char **argv) {
    if (argc < 3) {
        return 1;
    }

    char *chdir_to = argv[1];
    char *path = argv[2];

    int ret = chdir(chdir_to);
    if (ret < 0) {
        perror("chdir");
        return 1;
    }

    ret = access(path, F_OK);
    if (ret < 0) {
        perror("access");
        return 1;
    }

    printf("OK\n");
}
