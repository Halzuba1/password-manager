/* Regression tests for vault.c: format size limits, creating and replacing
 * the vault file safely, locking, and symlinked vault paths.
 *
 * Every save and load runs the full key derivation, so the suite takes a few
 * seconds. Run with `make test`. */
#include "vault.h"

#include <dirent.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define MASTER "correct horse battery staple"

/* vault_load rejects files over 16 MiB. A file is a 68-byte header followed by
 * the AES-CBC ciphertext, which pads the plaintext up to the next multiple of
 * 16 and always adds at least one byte. */
#define FILE_MAX (16u * 1024 * 1024)
#define HEADER_LEN 68
#define LARGEST_PLAINTEXT (((FILE_MAX - HEADER_LEN) / 16 - 1) * 16 + 15)

/* Serialized plaintext: a 4-byte entry count, then for each entry three 4-byte
 * lengths followed by the field bytes. */
#define COUNT_LEN 4
#define ENTRY_OVERHEAD 12

static int failures;

#define CHECK(cond, ...)                       \
    do {                                       \
        int ok_ = (cond);                      \
        printf("%s  ", ok_ ? "PASS" : "FAIL"); \
        printf(__VA_ARGS__);                   \
        printf("\n");                          \
        if (!ok_)                              \
            failures++;                        \
    } while (0)

static void die(const char *what) {
    perror(what);
    exit(EXIT_FAILURE);
}

static char *repeat(char c, size_t n) {
    char *s = malloc(n + 1);
    if (!s)
        die("malloc");
    memset(s, c, n);
    s[n] = '\0';
    return s;
}

static void add_or_die(Vault *v, const char *name, const char *username,
                       const char *password) {
    int rc = vault_add(v, name, username, password);
    if (rc != VAULT_OK) {
        fprintf(stderr, "vault_add: %s\n", vault_strerror(rc));
        exit(EXIT_FAILURE);
    }
}

static ino_t inode_of(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 ? st.st_ino : 0;
}

/* Temp files are named "<vault>.XXXXXX"; none should outlive a save. */
static int count_temp_files(void) {
    DIR *d = opendir(".");
    if (!d)
        die("opendir");
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        const char *dot = strstr(e->d_name, ".vault.");
        if (dot && strlen(dot) == strlen(".vault.XXXXXX"))
            n++;
    }
    closedir(d);
    return n;
}

/* Run fn in a child process and report whether it exited with status 0. */
static int in_child(int (*fn)(void)) {
    pid_t pid = fork();
    if (pid < 0)
        die("fork");
    if (pid == 0)
        _exit(fn() ? 0 : 1);
    int status;
    return waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
           WEXITSTATUS(status) == 0;
}

static void test_round_trip(void) {
    const char *path = "basic.vault";
    Vault v = {0};
    add_or_die(&v, "github", "octocat", "hunter2");
    CHECK(vault_create(path, MASTER) == VAULT_OK, "create a new vault");
    CHECK(vault_save(path, MASTER, &v) == VAULT_OK, "save an entry");
    vault_free(&v);

    Vault loaded;
    int rc = vault_load(path, MASTER, &loaded);
    VaultEntry *e = rc == VAULT_OK ? vault_find(&loaded, "github") : NULL;
    CHECK(e && strcmp(e->username, "octocat") == 0 &&
              strcmp(e->password, "hunter2") == 0,
          "entry loads back unchanged");
    vault_free(&loaded);

    CHECK(vault_load(path, "wrong password", &loaded) == VAULT_ERR_AUTH,
          "wrong master password is rejected");

    /* Flip one bit in the ciphertext, just past the header. */
    int fd = open(path, O_RDWR);
    unsigned char byte = 0;
    int flipped = fd >= 0 && pread(fd, &byte, 1, HEADER_LEN) == 1;
    byte ^= 1;
    flipped = flipped && pwrite(fd, &byte, 1, HEADER_LEN) == 1;
    if (fd >= 0)
        close(fd);
    CHECK(flipped && vault_load(path, MASTER, &loaded) == VAULT_ERR_AUTH,
          "modified vault file is rejected");
}

/* vault_load rejects fields over VAULT_FIELD_MAX, so vault_add must too, or a
 * single long entry makes the whole vault unloadable. */
static void test_field_limits(void) {
    const char *path = "fields.vault";
    char *max = repeat('m', VAULT_FIELD_MAX);
    char *over = repeat('o', VAULT_FIELD_MAX + 1);
    Vault v = {0};

    CHECK(vault_add(&v, over, "user", "pass") == VAULT_ERR_TOO_LARGE,
          "add rejects a name longer than VAULT_FIELD_MAX");
    CHECK(vault_add(&v, "name", over, "pass") == VAULT_ERR_TOO_LARGE,
          "add rejects a username longer than VAULT_FIELD_MAX");
    CHECK(vault_add(&v, "name", "user", over) == VAULT_ERR_TOO_LARGE,
          "add rejects a password longer than VAULT_FIELD_MAX");
    CHECK(v.count == 0, "rejected adds leave the vault unchanged");

    CHECK(vault_add(&v, max, max, max) == VAULT_OK,
          "add accepts fields of exactly VAULT_FIELD_MAX");
    CHECK(vault_save(path, MASTER, &v) == VAULT_OK,
          "save succeeds with maximum-length fields");
    Vault loaded;
    int rc = vault_load(path, MASTER, &loaded);
    CHECK(rc == VAULT_OK && loaded.count == 1 &&
              strcmp(loaded.entries[0].name, max) == 0 &&
              strcmp(loaded.entries[0].username, max) == 0 &&
              strcmp(loaded.entries[0].password, max) == 0,
          "maximum-length fields load back unchanged");

    vault_free(&loaded);
    vault_free(&v);
    free(max);
    free(over);
}

/* A save that would produce a file larger than vault_load accepts must be
 * refused, and must leave the existing vault untouched. */
static void test_file_size_limit(void) {
    const char *path = "large.vault";
    const size_t full_entry = ENTRY_OVERHEAD + 3 * VAULT_FIELD_MAX;
    const size_t budget = LARGEST_PLAINTEXT - COUNT_LEN - ENTRY_OVERHEAD;
    size_t full_entries = budget / full_entry;
    /* The last entry gets a full-size name and username and whatever is left
     * for its password. That has to fit in one field, with room to grow by a
     * byte below; it does for the current limits. */
    size_t last_password = budget - full_entries * full_entry -
                           2 * VAULT_FIELD_MAX;
    if (budget - full_entries * full_entry < 2 * VAULT_FIELD_MAX ||
        last_password >= VAULT_FIELD_MAX) {
        fprintf(stderr, "test_file_size_limit: limits changed, update test\n");
        exit(EXIT_FAILURE);
    }

    Vault v = {0};
    char *field = repeat('f', VAULT_FIELD_MAX);
    for (size_t i = 0; i < full_entries; i++) {
        char prefix[16];
        snprintf(prefix, sizeof(prefix), "%015zu", i);
        memcpy(field, prefix, 15); /* keep names unique and full length */
        add_or_die(&v, field, field, field);
    }
    char *last_name = repeat('L', VAULT_FIELD_MAX);
    char *password = repeat('p', last_password);
    add_or_die(&v, last_name, field, password);

    CHECK(vault_save(path, MASTER, &v) == VAULT_OK,
          "save succeeds at exactly the largest loadable size");
    Vault loaded;
    int rc = vault_load(path, MASTER, &loaded);
    CHECK(rc == VAULT_OK && loaded.count == v.count,
          "vault at the size limit loads back");
    vault_free(&loaded);

    ino_t before = inode_of(path);
    free(password);
    password = repeat('p', last_password + 1);
    vault_remove(&v, last_name);
    add_or_die(&v, last_name, field, password);
    CHECK(vault_save(path, MASTER, &v) == VAULT_ERR_TOO_LARGE,
          "save one byte over the size limit is refused");
    CHECK(inode_of(path) == before, "refused save leaves the old vault in place");

    vault_free(&v);
    free(field);
    free(last_name);
    free(password);
}

static int create_race_vault(void) {
    return vault_create("race.vault", MASTER) == VAULT_OK;
}

/* init must never replace an existing vault, even one it can't read, and
 * even if another process creates one at the same moment. */
static void test_create_never_replaces(void) {
    const char *path = "existing.vault";
    vault_create(path, MASTER);
    ino_t before = inode_of(path);
    chmod(path, 0);
    CHECK(vault_create(path, MASTER) == VAULT_ERR_EXISTS,
          "create refuses a path holding an unreadable vault");
    CHECK(inode_of(path) == before, "unreadable vault is not replaced");
    chmod(path, 0600);

    enum { RACERS = 8 };
    pid_t pids[RACERS];
    for (int i = 0; i < RACERS; i++) {
        if ((pids[i] = fork()) < 0)
            die("fork");
        if (pids[i] == 0)
            _exit(create_race_vault() ? 0 : 1);
    }
    int winners = 0;
    for (int i = 0; i < RACERS; i++) {
        int status;
        if (waitpid(pids[i], &status, 0) == pids[i] && WIFEXITED(status) &&
            WEXITSTATUS(status) == 0)
            winners++;
    }
    CHECK(winners == 1, "exactly one of %d concurrent creates succeeds (%d did)",
          RACERS, winners);
}

static int save_repeatedly(const char *path, size_t entries, size_t field_len) {
    Vault v = {0};
    char *field = repeat('c', field_len);
    for (size_t i = 0; i < entries; i++) {
        char name[32];
        snprintf(name, sizeof(name), "entry%zu", i);
        add_or_die(&v, name, field, field);
    }
    int ok = 1;
    for (int i = 0; i < 5; i++)
        ok &= vault_save(path, MASTER, &v) == VAULT_OK;
    vault_free(&v);
    free(field);
    return ok;
}

/* Saves used to write through a fixed "<vault>.tmp" opened with O_TRUNC,
 * which kept a stale file's permissions, followed symlinks, and let
 * concurrent saves splice their output together. */
static void test_save_temp_file(void) {
    const char *path = "temp.vault";
    const char *old_temp = "temp.vault.tmp";
    const char *victim = "victim.txt";
    Vault empty = {0};

    vault_create(path, MASTER);
    chmod(path, 0644);
    int fd = open(old_temp, O_WRONLY | O_CREAT, 0644);
    if (fd < 0)
        die(old_temp);
    fchmod(fd, 0644);
    close(fd);
    CHECK(vault_save(path, MASTER, &empty) == VAULT_OK,
          "save succeeds with world-readable files already in place");
    struct stat st = {0};
    CHECK(stat(path, &st) == 0 && (st.st_mode & 0777) == 0600,
          "saved vault is mode 0600 (got %o)", st.st_mode & 0777);
    unlink(old_temp);

    FILE *f = fopen(victim, "w");
    if (!f)
        die(victim);
    fputs("unrelated file", f);
    fclose(f);
    if (symlink(victim, old_temp) != 0)
        die("symlink");
    vault_save(path, MASTER, &empty);
    char contents[32] = {0};
    f = fopen(victim, "r");
    size_t n = f ? fread(contents, 1, sizeof(contents) - 1, f) : 0;
    if (f)
        fclose(f);
    CHECK(n > 0 && strcmp(contents, "unrelated file") == 0,
          "save does not write through a symlink next to the vault");
    unlink(old_temp);

    /* The temp path is the vault path plus a suffix; if that doesn't fit in
     * PATH_MAX, save must fail rather than use a truncated name. The path runs
     * through real directories so that a truncated name would be creatable. */
    char long_path[PATH_MAX] = "";
    char component[251];
    memset(component, 'd', sizeof(component) - 1);
    component[sizeof(component) - 1] = '\0';
    for (int i = 0; i < 4; i++) {
        strcat(long_path, component);
        if (mkdir(long_path, 0700) != 0)
            die("mkdir");
        strcat(long_path, "/");
    }
    /* Pad the file name so the vault path fits with 3 bytes to spare. */
    size_t dir_len = strlen(long_path);
    size_t pad = PATH_MAX - 4 - dir_len - strlen(".vault");
    memset(long_path + dir_len, 'f', pad);
    strcpy(long_path + dir_len + pad, ".vault");
    CHECK(vault_save(long_path, MASTER, &empty) == VAULT_ERR_IO,
          "save fails when the temp file path would be truncated");
    /* With the test directory in front, these paths are longer than nftw in
     * main can handle, so remove them now while a relative path reaches. */
    char *slash;
    while ((slash = strrchr(long_path, '/')) != NULL) {
        *slash = '\0';
        rmdir(long_path);
    }

    /* Two processes save vaults of different sizes while this one loads. */
    const char *shared = "shared.vault";
    vault_save(shared, MASTER, &empty);
    pid_t small = fork();
    if (small == 0)
        _exit(save_repeatedly(shared, 5, 8) ? 0 : 1);
    pid_t large = fork();
    if (large == 0)
        _exit(save_repeatedly(shared, 40, 2000) ? 0 : 1);
    if (small < 0 || large < 0)
        die("fork");
    int bad_loads = 0;
    for (int i = 0; i < 10; i++) {
        Vault loaded;
        if (vault_load(shared, MASTER, &loaded) != VAULT_OK)
            bad_loads++;
        vault_free(&loaded);
    }
    int status, children_ok = 1;
    for (int i = 0; i < 2; i++)
        children_ok &= wait(&status) > 0 && WIFEXITED(status) &&
                       WEXITSTATUS(status) == 0;
    Vault loaded;
    CHECK(children_ok && bad_loads == 0 &&
              vault_load(shared, MASTER, &loaded) == VAULT_OK,
          "concurrent saves never leave a corrupt vault (%d failed loads)",
          bad_loads);
    vault_free(&loaded);

    CHECK(count_temp_files() == 0, "no temp files are left behind");
}

static int lock_is_busy(void) {
    int fd;
    return vault_lock("lock.vault", &fd) == VAULT_ERR_LOCKED;
}

static int lock_is_on_current_file(void) {
    int fd;
    if (vault_lock("lock.vault", &fd) != VAULT_OK)
        return 0;
    struct stat held;
    return fstat(fd, &held) == 0 && held.st_ino == inode_of("lock.vault");
}

/* A load/modify/save must not interleave with another process doing the
 * same, or the first save's changes are silently lost. */
static void test_lock(void) {
    const char *path = "lock.vault";
    Vault empty = {0};
    vault_create(path, MASTER);

    int fd;
    CHECK(vault_lock(path, &fd) == VAULT_OK, "lock an unlocked vault");
    CHECK(in_child(lock_is_busy),
          "another process gets VAULT_ERR_LOCKED while it is held");

    /* The save renames a new file over the locked one. */
    vault_save(path, MASTER, &empty);
    vault_unlock(fd);
    CHECK(in_child(lock_is_on_current_file),
          "after a save and unlock, the next lock is on the new file");
}

/* A vault symlinked into a synced folder must stay a symlink, or later saves
 * silently stop reaching the synced copy. */
static void test_symlinked_vault(void) {
    const char *target = "target.vault";
    const char *link = "link.vault";
    vault_create(target, MASTER);
    if (symlink(target, link) != 0)
        die("symlink");

    Vault v = {0};
    add_or_die(&v, "synced", "user", "pass");
    CHECK(vault_save(link, MASTER, &v) == VAULT_OK, "save through a symlink");
    vault_free(&v);

    struct stat st;
    CHECK(lstat(link, &st) == 0 && S_ISLNK(st.st_mode),
          "vault symlink is still a symlink");
    Vault loaded;
    CHECK(vault_load(target, MASTER, &loaded) == VAULT_OK && loaded.count == 1,
          "saved change is in the symlink's target");
    vault_free(&loaded);
}

static int remove_entry(const char *path, const struct stat *st, int type,
                        struct FTW *ftw) {
    (void)st, (void)type, (void)ftw;
    return remove(path);
}

int main(void) {
    const char *tmpdir = getenv("TMPDIR");
    char dir[PATH_MAX];
    snprintf(dir, sizeof(dir), "%s/passman-test.XXXXXX",
             tmpdir ? tmpdir : "/tmp");
    if (!mkdtemp(dir) || chdir(dir) != 0)
        die(dir);

    test_round_trip();
    test_field_limits();
    test_file_size_limit();
    test_create_never_replaces();
    test_save_temp_file();
    test_lock();
    test_symlinked_vault();

    if (failures == 0) {
        printf("\nall tests passed\n");
        if (nftw(dir, remove_entry, 16, FTW_DEPTH | FTW_PHYS) != 0)
            fprintf(stderr, "warning: could not remove %s\n", dir);
        return EXIT_SUCCESS;
    }
    printf("\n%d failed; test files kept in %s\n", failures, dir);
    return EXIT_FAILURE;
}
