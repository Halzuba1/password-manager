#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Security/Security.h>

#define DEFAULT_LENGTH 24

static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;':\",./<>?"; 

int get_secure_random_bytes(unsigned char *buf, size_t len) {
    if (SecRandomCopyBytes(kSecRandomDefault, len, buf) != errSecSuccess) {
        fprintf(stderr, "Error: unable to generate secure random bytes\n");
        return -1;
    }
    return 0;
}

void generate_password(size_t length) {
    size_t charset_size = strlen(charset);
    unsigned char *random_bytes = malloc(length);
    if (!random_bytes) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    if (get_secure_random_bytes(random_bytes, length) != 0) {
        free(random_bytes);
        exit(EXIT_FAILURE);
    }

    for (size_t i = 0; i < length; i++) {
        putchar(charset[random_bytes[i] % charset_size]);
    }
    putchar('\n');

    free(random_bytes);
}

int main(int argc, char *argv[]) {
    size_t length = DEFAULT_LENGTH;
    if (argc == 2) {
        length = strtoul(argv[1], NULL, 10);
        if (length == 0) {
            fprintf(stderr, "Invalid length\n");
            return EXIT_FAILURE;
        }
    }

    generate_password(length);
    return EXIT_SUCCESS;
}
