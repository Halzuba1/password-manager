#include "vault.h"
#include "crypto.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* File layout:
 *   magic  4 bytes  "PMV1"
 *   salt   16 bytes
 *   iv     16 bytes
 *   hmac   32 bytes  HMAC-SHA256(mac_key, magic || salt || iv || ciphertext)
 *   ct     N bytes   AES-256-CBC(enc_key, iv, serialized entries)
 *
 * Serialized plaintext:
 *   u32 count, then per entry: u32 len + bytes for name, username, password.
 * All integers are little-endian.
 */

#define MAGIC "PMV1"
#define MAGIC_LEN 4
#define HDR_LEN (MAGIC_LEN + SALT_LEN + IV_LEN)
#define FILE_MIN (HDR_LEN + HMAC_LEN + 16)
#define FILE_MAX (16u * 1024 * 1024)

static void put_u32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static uint32_t get_u32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
           (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static size_t serialized_size(const Vault *v) {
    size_t total = 4;
    for (size_t i = 0; i < v->count; i++) {
        total += 12 + strlen(v->entries[i].name) +
                 strlen(v->entries[i].username) +
                 strlen(v->entries[i].password);
    }
    return total;
}

static void serialize_field(uint8_t **p, const char *s) {
    size_t len = strlen(s);
    put_u32(*p, (uint32_t)len);
    memcpy(*p + 4, s, len);
    *p += 4 + len;
}

static int parse_field(const uint8_t **p, size_t *remaining, char **out) {
    if (*remaining < 4)
        return VAULT_ERR_FORMAT;
    uint32_t len = get_u32(*p);
    *p += 4;
    *remaining -= 4;
    if (len > VAULT_FIELD_MAX || len > *remaining)
        return VAULT_ERR_FORMAT;
    char *s = malloc(len + 1);
    if (!s)
        return VAULT_ERR_MEM;
    memcpy(s, *p, len);
    s[len] = '\0';
    *p += len;
    *remaining -= len;
    *out = s;
    return VAULT_OK;
}

static int parse_entries(const uint8_t *p, size_t len, Vault *v) {
    if (len < 4)
        return VAULT_ERR_FORMAT;
    uint32_t count = get_u32(p);
    p += 4;
    len -= 4;
    if (count > len / 12)
        return VAULT_ERR_FORMAT;

    v->entries = NULL;
    v->count = 0;
    if (count > 0) {
        v->entries = calloc(count, sizeof(VaultEntry));
        if (!v->entries)
            return VAULT_ERR_MEM;
    }

    for (uint32_t i = 0; i < count; i++) {
        VaultEntry *e = &v->entries[i];
        int rc;
        if ((rc = parse_field(&p, &len, &e->name)) != VAULT_OK ||
            (rc = parse_field(&p, &len, &e->username)) != VAULT_OK ||
            (rc = parse_field(&p, &len, &e->password)) != VAULT_OK) {
            v->count = i + 1; /* free whatever was parsed so far */
            vault_free(v);
            return rc;
        }
        v->count = i + 1;
    }

    if (len != 0) {
        vault_free(v);
        return VAULT_ERR_FORMAT;
    }
    return VAULT_OK;
}

int vault_load(const char *path, const char *master, Vault *v) {
    v->entries = NULL;
    v->count = 0;

    FILE *f = fopen(path, "rb");
    if (!f)
        return errno == ENOENT ? VAULT_ERR_NOT_FOUND : VAULT_ERR_IO;

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    rewind(f);
    if (fsize < FILE_MIN || fsize > (long)FILE_MAX) {
        fclose(f);
        return VAULT_ERR_FORMAT;
    }

    uint8_t *buf = malloc((size_t)fsize);
    if (!buf) {
        fclose(f);
        return VAULT_ERR_MEM;
    }
    if (fread(buf, 1, (size_t)fsize, f) != (size_t)fsize) {
        free(buf);
        fclose(f);
        return VAULT_ERR_IO;
    }
    fclose(f);

    if (memcmp(buf, MAGIC, MAGIC_LEN) != 0) {
        free(buf);
        return VAULT_ERR_FORMAT;
    }

    const uint8_t *salt = buf + MAGIC_LEN;
    const uint8_t *iv = buf + MAGIC_LEN + SALT_LEN;
    const uint8_t *stored_hmac = buf + HDR_LEN;
    const uint8_t *ct = buf + HDR_LEN + HMAC_LEN;
    size_t ct_len = (size_t)fsize - HDR_LEN - HMAC_LEN;

    uint8_t enc_key[KEY_LEN], mac_key[KEY_LEN];
    if (crypto_derive_keys(master, salt, enc_key, mac_key) != 0) {
        free(buf);
        return VAULT_ERR_CRYPTO;
    }

    /* Verify authenticity before touching the ciphertext (encrypt-then-MAC),
     * with a constant-time comparison. */
    uint8_t hmac[HMAC_LEN];
    crypto_hmac2(mac_key, buf, HDR_LEN, ct, ct_len, hmac);
    if (!crypto_memeq(hmac, stored_hmac, HMAC_LEN)) {
        secure_zero(enc_key, sizeof(enc_key));
        secure_zero(mac_key, sizeof(mac_key));
        free(buf);
        return VAULT_ERR_AUTH;
    }

    uint8_t *pt = malloc(ct_len);
    int rc = VAULT_ERR_MEM;
    if (pt) {
        size_t pt_len = 0;
        if (crypto_decrypt(enc_key, iv, ct, ct_len, pt, &pt_len) != 0)
            rc = VAULT_ERR_CRYPTO;
        else
            rc = parse_entries(pt, pt_len, v);
        secure_zero(pt, ct_len);
        free(pt);
    }

    secure_zero(enc_key, sizeof(enc_key));
    secure_zero(mac_key, sizeof(mac_key));
    free(buf);
    return rc;
}

int vault_save(const char *path, const char *master, const Vault *v) {
    size_t pt_len = serialized_size(v);
    /* Refuse to write anything vault_load would reject. CBC with PKCS#7
     * always adds 1-16 bytes of padding. */
    if (v->count > UINT32_MAX ||
        HDR_LEN + HMAC_LEN + (pt_len / 16 + 1) * 16 > FILE_MAX)
        return VAULT_ERR_TOO_LARGE;

    uint8_t *pt = malloc(pt_len);
    if (!pt)
        return VAULT_ERR_MEM;

    uint8_t *p = pt;
    put_u32(p, (uint32_t)v->count);
    p += 4;
    for (size_t i = 0; i < v->count; i++) {
        serialize_field(&p, v->entries[i].name);
        serialize_field(&p, v->entries[i].username);
        serialize_field(&p, v->entries[i].password);
    }

    size_t file_cap = HDR_LEN + HMAC_LEN + pt_len + 16;
    uint8_t *out = malloc(file_cap);
    if (!out) {
        secure_zero(pt, pt_len);
        free(pt);
        return VAULT_ERR_MEM;
    }

    memcpy(out, MAGIC, MAGIC_LEN);
    uint8_t *salt = out + MAGIC_LEN;
    uint8_t *iv = out + MAGIC_LEN + SALT_LEN;
    uint8_t *hmac = out + HDR_LEN;
    uint8_t *ct = out + HDR_LEN + HMAC_LEN;

    uint8_t enc_key[KEY_LEN], mac_key[KEY_LEN];
    int rc = VAULT_ERR_CRYPTO;
    size_t ct_len = 0;

    if (crypto_random(salt, SALT_LEN) == 0 &&
        crypto_random(iv, IV_LEN) == 0 &&
        crypto_derive_keys(master, salt, enc_key, mac_key) == 0 &&
        crypto_encrypt(enc_key, iv, pt, pt_len, ct, &ct_len) == 0) {
        crypto_hmac2(mac_key, out, HDR_LEN, ct, ct_len, hmac);
        rc = VAULT_OK;
    }

    secure_zero(pt, pt_len);
    free(pt);

    if (rc == VAULT_OK) {
        char tmp[1024];
        snprintf(tmp, sizeof(tmp), "%s.tmp", path);
        int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        size_t file_len = HDR_LEN + HMAC_LEN + ct_len;
        if (fd < 0 ||
            write(fd, out, file_len) != (ssize_t)file_len ||
            close(fd) != 0 ||
            rename(tmp, path) != 0) {
            if (fd >= 0)
                unlink(tmp);
            rc = VAULT_ERR_IO;
        }
    }

    secure_zero(enc_key, sizeof(enc_key));
    secure_zero(mac_key, sizeof(mac_key));
    free(out);
    return rc;
}

VaultEntry *vault_find(Vault *v, const char *name) {
    for (size_t i = 0; i < v->count; i++) {
        if (strcmp(v->entries[i].name, name) == 0)
            return &v->entries[i];
    }
    return NULL;
}

int vault_add(Vault *v, const char *name, const char *username,
              const char *password) {
    if (strlen(name) > VAULT_FIELD_MAX || strlen(username) > VAULT_FIELD_MAX ||
        strlen(password) > VAULT_FIELD_MAX)
        return VAULT_ERR_TOO_LARGE;

    VaultEntry *grown = realloc(v->entries, (v->count + 1) * sizeof(VaultEntry));
    if (!grown)
        return VAULT_ERR_MEM;
    v->entries = grown;

    VaultEntry *e = &v->entries[v->count];
    e->name = strdup(name);
    e->username = strdup(username);
    e->password = strdup(password);
    if (!e->name || !e->username || !e->password) {
        free(e->name);
        free(e->username);
        free(e->password);
        return VAULT_ERR_MEM;
    }
    v->count++;
    return VAULT_OK;
}

int vault_remove(Vault *v, const char *name) {
    VaultEntry *e = vault_find(v, name);
    if (!e)
        return VAULT_ERR_NOT_FOUND;

    secure_zero(e->password, strlen(e->password));
    free(e->name);
    free(e->username);
    free(e->password);

    size_t idx = (size_t)(e - v->entries);
    memmove(&v->entries[idx], &v->entries[idx + 1],
            (v->count - idx - 1) * sizeof(VaultEntry));
    v->count--;
    return VAULT_OK;
}

void vault_free(Vault *v) {
    for (size_t i = 0; i < v->count; i++) {
        VaultEntry *e = &v->entries[i];
        if (e->password)
            secure_zero(e->password, strlen(e->password));
        free(e->name);
        free(e->username);
        free(e->password);
    }
    free(v->entries);
    v->entries = NULL;
    v->count = 0;
}

const char *vault_strerror(int code) {
    switch (code) {
    case VAULT_OK:            return "success";
    case VAULT_ERR_NOT_FOUND: return "vault not found (run 'passman init' first)";
    case VAULT_ERR_IO:        return "unable to read or write the vault file";
    case VAULT_ERR_FORMAT:    return "vault file is corrupt or not a vault";
    case VAULT_ERR_AUTH:      return "authentication failed: wrong master password or vault was tampered with";
    case VAULT_ERR_CRYPTO:    return "cryptographic operation failed";
    case VAULT_ERR_MEM:       return "out of memory";
    case VAULT_ERR_TOO_LARGE: return "entry or vault exceeds the maximum supported size";
    default:                  return "unknown error";
    }
}
