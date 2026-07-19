#include "generator.h"
#include "crypto.h"

#include <string.h>

static const char charset[] =
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    "!@#$%^&*()_+-=[]{}|;':\",./<>?";

int generate_password(char *out, size_t length) {
    const size_t charset_size = sizeof(charset) - 1;
    /* Largest multiple of charset_size that fits in a byte. Bytes at or
     * above this limit are rejected: mapping them through the modulo would
     * make the first (256 % charset_size) characters more likely than the
     * rest. */
    const unsigned char limit = (unsigned char)(256 - (256 % charset_size));
    uint8_t buf[128];
    size_t filled = 0;

    while (filled < length) {
        if (crypto_random(buf, sizeof(buf)) != 0) {
            secure_zero(buf, sizeof(buf));
            return -1;
        }
        for (size_t i = 0; i < sizeof(buf) && filled < length; i++) {
            if (buf[i] < limit)
                out[filled++] = charset[buf[i] % charset_size];
        }
    }

    out[length] = '\0';
    secure_zero(buf, sizeof(buf));
    return 0;
}
