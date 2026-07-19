#define __STDC_WANT_LIB_EXT1__ 1
#include "crypto.h"

#include <string.h>
#include <Security/Security.h>
#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonKeyDerivation.h>
#include <CommonCrypto/CommonHMAC.h>

int crypto_random(uint8_t *buf, size_t len) {
    return SecRandomCopyBytes(kSecRandomDefault, len, buf) == errSecSuccess ? 0 : -1;
}

int crypto_derive_keys(const char *password, const uint8_t salt[SALT_LEN],
                       uint8_t enc_key[KEY_LEN], uint8_t mac_key[KEY_LEN]) {
    uint8_t okm[KEY_LEN * 2];
    if (CCKeyDerivationPBKDF(kCCPBKDF2, password, strlen(password),
                             salt, SALT_LEN, kCCPRFHmacAlgSHA256,
                             PBKDF2_ITERATIONS, okm, sizeof(okm)) != kCCSuccess)
        return -1;
    memcpy(enc_key, okm, KEY_LEN);
    memcpy(mac_key, okm + KEY_LEN, KEY_LEN);
    secure_zero(okm, sizeof(okm));
    return 0;
}

static int aes_cbc(CCOperation op, const uint8_t key[KEY_LEN],
                   const uint8_t iv[IV_LEN], const uint8_t *in, size_t in_len,
                   uint8_t *out, size_t out_cap, size_t *out_len) {
    CCCryptorStatus st = CCCrypt(op, kCCAlgorithmAES, kCCOptionPKCS7Padding,
                                 key, KEY_LEN, iv, in, in_len,
                                 out, out_cap, out_len);
    return st == kCCSuccess ? 0 : -1;
}

int crypto_encrypt(const uint8_t key[KEY_LEN], const uint8_t iv[IV_LEN],
                   const uint8_t *in, size_t in_len,
                   uint8_t *out, size_t *out_len) {
    return aes_cbc(kCCEncrypt, key, iv, in, in_len, out, in_len + 16, out_len);
}

int crypto_decrypt(const uint8_t key[KEY_LEN], const uint8_t iv[IV_LEN],
                   const uint8_t *in, size_t in_len,
                   uint8_t *out, size_t *out_len) {
    return aes_cbc(kCCDecrypt, key, iv, in, in_len, out, in_len, out_len);
}

void crypto_hmac2(const uint8_t key[KEY_LEN],
                  const uint8_t *a, size_t a_len,
                  const uint8_t *b, size_t b_len,
                  uint8_t out[HMAC_LEN]) {
    CCHmacContext ctx;
    CCHmacInit(&ctx, kCCHmacAlgSHA256, key, KEY_LEN);
    CCHmacUpdate(&ctx, a, a_len);
    CCHmacUpdate(&ctx, b, b_len);
    CCHmacFinal(&ctx, out);
    secure_zero(&ctx, sizeof(ctx));
}

int crypto_memeq(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++)
        diff |= a[i] ^ b[i];
    return diff == 0;
}

void secure_zero(void *p, size_t len) {
    memset_s(p, len, 0, len);
}
