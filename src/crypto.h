#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define SALT_LEN 16
#define IV_LEN 16
#define KEY_LEN 32
#define HMAC_LEN 32
#define PBKDF2_ITERATIONS 600000

/* Fill buf with cryptographically secure random bytes. Returns 0 on success. */
int crypto_random(uint8_t *buf, size_t len);

/* Derive an encryption key and a MAC key from a master password via
 * PBKDF2-HMAC-SHA256. Returns 0 on success. */
int crypto_derive_keys(const char *password, const uint8_t salt[SALT_LEN],
                       uint8_t enc_key[KEY_LEN], uint8_t mac_key[KEY_LEN]);

/* AES-256-CBC with PKCS#7 padding. out must have room for in_len + 16 bytes
 * when encrypting, or in_len bytes when decrypting. Returns 0 on success. */
int crypto_encrypt(const uint8_t key[KEY_LEN], const uint8_t iv[IV_LEN],
                   const uint8_t *in, size_t in_len,
                   uint8_t *out, size_t *out_len);
int crypto_decrypt(const uint8_t key[KEY_LEN], const uint8_t iv[IV_LEN],
                   const uint8_t *in, size_t in_len,
                   uint8_t *out, size_t *out_len);

/* HMAC-SHA256 over two concatenated regions (header, then ciphertext). */
void crypto_hmac2(const uint8_t key[KEY_LEN],
                  const uint8_t *a, size_t a_len,
                  const uint8_t *b, size_t b_len,
                  uint8_t out[HMAC_LEN]);

/* Constant-time comparison. Returns 1 if equal, 0 otherwise. */
int crypto_memeq(const uint8_t *a, const uint8_t *b, size_t len);

/* Zero memory in a way the compiler may not optimize away. */
void secure_zero(void *p, size_t len);

#endif
