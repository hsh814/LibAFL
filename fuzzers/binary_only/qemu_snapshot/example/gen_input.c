#include <stdio.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        return 1;
    }
    char *filename = argv[1];
    FILE *file = fopen(filename, "w");
    int data[2] = {4, 128 * 4};
    fwrite(data, sizeof(int), 2, file);
    fclose(file);
    return 0;
}
