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
    char *base_path = argv[2];
    char *path = argv[3];

    int dfd = open(base_path, O_RDONLY);
    if (dfd < 0) {
        perror("open base");
        return 1;
    }

    if (strcmp(type, "statx") == 0) {
        struct statx st;
        int ret = statx(dfd, path, AT_SYMLINK_NOFOLLOW, STATX_ALL, &st);
        if (ret < 0) {
            perror("statx");
            return 1;
        }
    } else if (strcmp(type, "lstat") == 0) {
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
