#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int model_malloc_min(int size)
{
    int* res = malloc(size);
    memset((void *)res, 0, size);
    return res[0];
}

int model_malloc_max(int size)
{
    int* res = malloc(size);
    memset((void *)res, 0, size);
    printf("size: %d\n", size);
    return res[127];
}

int model_realloc_min(int size)
{
    void* res = realloc(malloc(8), size);
    return size == 0;
}

int model_realloc_max(int size)
{
    void* res = realloc(malloc(8), size);
    return size > 128;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Error\n");
        return 1;
    }
    FILE *file = fopen(argv[1], "r");
    if (!file) {
        printf("Error\n");
        return 1;
    }
    int data[2];
    fread(data, 4, 2, file);
    int *size = (int*)data;
    model_malloc_min(size[0]);
    model_malloc_max(size[1]);
    fclose(file);
}
