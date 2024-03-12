#include <pthread.h>
#include <stdio.h>

void *my_thread(void *arg) {
    // Write a message to a file
    FILE *f = fopen("thread.txt", "w");
    fprintf(f, "Hello from a thread\n");
    fclose(f);
    return 0;
}

int main() {
    pthread_t thread;
    int err = pthread_create(&thread, NULL, my_thread, NULL);
    if (err) {
        printf("Error creating thread\n");
        return 1;
    }

    FILE *f = fopen("main.txt", "w");
    fprintf(f, "Hello from main\n");
    fclose(f);

    err = pthread_join(thread, NULL);
    if (err) {
        printf("Error joining thread\n");
        return 1;
    }
    printf("Thread finished\n");
    return 0;
}
