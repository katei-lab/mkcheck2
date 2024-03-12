#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

// Just link(2) a file

int main(int argc, char **argv) {
    if (argc < 3) {
        return 1;
    }

    char *type = argv[1];
    char *src = argv[2];
    char *dst = argv[3];

    if (strcmp(type, "link") == 0) {
        int ret = link(src, dst);
        if (ret < 0) {
            perror("link");
            return 1;
        }
    } else if (strcmp(type, "symlink") == 0) {
        int ret = symlink(src, dst);
        if (ret < 0) {
            perror("symlink");
            return 1;
        }
    } else {
        printf("Unknown type: %s\n", type);
        return 1;
    
    }

    printf("OK\n");
}
