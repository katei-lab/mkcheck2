#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

// Just open a file with openat
int main(int argc, char **argv) {
    if (argc < 3) {
        return 1;
    }

    int base_fd, fd;
    base_fd = open(argv[1], O_RDONLY);
    if (base_fd < 0) {
        perror("open base");
        return 1;
    }

    fd = openat(base_fd, argv[2], O_RDONLY);

    if (fd < 0) {
        perror("openat");
        return 1;
    }
    close(base_fd);

    // Read the file
    char buf[1024];
    ssize_t n = read(fd, buf, sizeof(buf));
    if (n < 0) {
        perror("read");
        return 1;
    }
    buf[n] = '\0';
    printf("Read %ld bytes\n", n);

    int ret = close(fd);
    if (ret < 0) {
        perror("close");
        return 1;
    }
    printf("OK\n");
    return 0;
}
