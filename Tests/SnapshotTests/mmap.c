#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>

static void *mmap_file(const char *path, int prot, int flags, off_t *len) {
    int fd;
    fd = open(path, O_RDWR);
    if (fd < 0) {
        perror("open");
        return NULL;
    }
    struct stat st;
    int ret = fstat(fd, &st);
    if (ret < 0) {
        perror("fstat");
        return NULL;
    }
    *len = st.st_size;
    void *addr = mmap(NULL, st.st_size, prot, flags, fd, 0);
    if (addr == MAP_FAILED) {
        perror("mmap");
        return NULL;
    }
    return addr;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        return 1;
    }

    char *type = argv[1];
    off_t len = 0;

    if (strcmp(type, "write") == 0) {
        if (argc < 3) return 1;
        char *path = argv[2];
        void *addr = mmap_file(path, PROT_WRITE, MAP_SHARED, &len);
        if (addr == NULL) return 1;
        memset(addr, 42, len);
    } else if (strcmp(type, "read") == 0) {
        if (argc < 3) return 1;
        char *path = argv[2];
        void *addr = mmap_file(path, PROT_READ, MAP_SHARED, &len);
        if (addr == NULL) return 1;
        int chunk_size = 1024;
        for (int line = 0; line < len / chunk_size; line++) {
            for (int i = 0; i < chunk_size; i++) {
                printf("%02x ", ((unsigned char *)addr)[line * chunk_size + i]);
            }
            printf("\n");
        }

        for (int i = 0; i < len % chunk_size; i++) {
            printf("%02x ", ((unsigned char *)addr)[(len / chunk_size) * chunk_size + i]);
        }
        printf("\n");
    } else {
        printf("Unknown type: %s\n", type);
        return 1;
    }
    
}
