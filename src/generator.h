#ifndef GENERATOR_H
#define GENERATOR_H

#include <stddef.h>

#define GEN_MIN_LENGTH 1
#define GEN_MAX_LENGTH 256
#define GEN_DEFAULT_LENGTH 24

/* Generate a random password of exactly `length` characters into `out`,
 * which must have room for length + 1 bytes (NUL-terminated). Uses rejection
 * sampling so every charset character is equally likely. Returns 0 on
 * success. */
int generate_password(char *out, size_t length);

#endif
