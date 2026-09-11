#ifndef VAULT_H
#define VAULT_H

#include <stddef.h>

/* Longest name, username, or password an entry may hold, in bytes. */
#define VAULT_FIELD_MAX 4096

enum {
    VAULT_OK = 0,
    VAULT_ERR_NOT_FOUND = -1, /* vault file does not exist */
    VAULT_ERR_IO = -2,        /* read/write failure */
    VAULT_ERR_FORMAT = -3,    /* not a vault file / corrupt structure */
    VAULT_ERR_AUTH = -4,      /* HMAC mismatch: wrong password or tampering */
    VAULT_ERR_CRYPTO = -5,    /* underlying crypto call failed */
    VAULT_ERR_MEM = -6,       /* allocation failure */
    VAULT_ERR_TOO_LARGE = -7, /* field or vault exceeds the format's limits */
    VAULT_ERR_EXISTS = -8,    /* vault_create target already exists */
};

typedef struct {
    char *name;
    char *username;
    char *password;
} VaultEntry;

typedef struct {
    VaultEntry *entries;
    size_t count;
} Vault;

/* Load and decrypt the vault at path with the master password. On success
 * fills *v (caller frees with vault_free). Returns a VAULT_* code. */
int vault_load(const char *path, const char *master, Vault *v);

/* Encrypt and atomically write the vault. A fresh salt and IV are generated
 * on every save. Returns a VAULT_* code. */
int vault_save(const char *path, const char *master, const Vault *v);

/* Write a new empty vault. Fails with VAULT_ERR_EXISTS rather than replacing
 * anything already at path, even if it was created after the caller last
 * checked. */
int vault_create(const char *path, const char *master);

VaultEntry *vault_find(Vault *v, const char *name);
int vault_add(Vault *v, const char *name, const char *username,
              const char *password);
int vault_remove(Vault *v, const char *name);

/* Zero all secrets and release memory. */
void vault_free(Vault *v);

const char *vault_strerror(int code);

#endif
