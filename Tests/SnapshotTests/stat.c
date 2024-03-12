#define _GNU_SOURCE
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

// Just stat a file

int main(int argc, char **argv) {
    if (argc < 3) {
        return 1;
    }

    char *type = argv[1];
    char *path = argv[2];

    if (strcmp(type, "lstat") == 0) {
        struct stat st;
        int ret = lstat(path, &st);
        if (ret < 0) {
            perror("lstat");
            return 1;
        }
    } else {
        printf("Unknown type: %s\n", type);
        return 1;
    }

    printf("OK\n");
}
