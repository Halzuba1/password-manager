#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <readpassphrase.h>
#include <unistd.h>

#include "crypto.h"
#include "generator.h"
#include "vault.h"

#define MASTER_MAX 1024
#define FIELD_INPUT_MAX 1024

static const char *vault_path(void) {
    static char path[1024];
    const char *env = getenv("PASSMAN_VAULT");
    if (env)
        return env;
    const char *home = getenv("HOME");
    if (!home) {
        fprintf(stderr, "Error: HOME is not set\n");
        exit(EXIT_FAILURE);
    }
    snprintf(path, sizeof(path), "%s/.passman.vault", home);
    return path;
}

static int read_secret(const char *prompt, char *buf, size_t cap) {
    if (readpassphrase(prompt, buf, cap, RPP_ECHO_OFF) == NULL) {
        fprintf(stderr, "Error: unable to read passphrase\n");
        return -1;
    }
    /* readpassphrase silently truncates long input; a full buffer means the
     * stored secret might not be what was typed. */
    if (strlen(buf) == cap - 1) {
        fprintf(stderr, "Error: passphrase must be shorter than %zu characters\n",
                cap - 1);
        secure_zero(buf, cap);
        return -1;
    }
    if (buf[0] == '\0') {
        fprintf(stderr, "Error: passphrase must not be empty\n");
        return -1;
    }
    return 0;
}

static int read_secret_confirmed(const char *prompt, char *buf, size_t cap) {
    char confirm[MASTER_MAX];
    if (read_secret(prompt, buf, cap) != 0)
        return -1;
    if (read_secret("Confirm: ", confirm, sizeof(confirm)) != 0) {
        secure_zero(buf, cap);
        return -1;
    }
    int match = strcmp(buf, confirm) == 0;
    secure_zero(confirm, sizeof(confirm));
    if (!match) {
        fprintf(stderr, "Error: passphrases do not match\n");
        secure_zero(buf, cap);
        return -1;
    }
    return 0;
}

static int read_line(const char *prompt, char *buf, size_t cap) {
    /* readpassphrase with echo keeps input unbuffered, so it interleaves
     * cleanly with the hidden prompts (stdio's fgets would read ahead). */
    if (readpassphrase(prompt, buf, cap, RPP_ECHO_ON) == NULL) {
        fprintf(stderr, "Error: unable to read input\n");
        return -1;
    }
    if (strlen(buf) == cap - 1) {
        fprintf(stderr, "Error: input must be shorter than %zu characters\n",
                cap - 1);
        return -1;
    }
    return 0;
}

static int parse_length(const char *arg, size_t *out) {
    char *end;
    unsigned long n = strtoul(arg, &end, 10);
    if (*end != '\0' || n < GEN_MIN_LENGTH || n > GEN_MAX_LENGTH) {
        fprintf(stderr, "Error: length must be between %d and %d\n",
                GEN_MIN_LENGTH, GEN_MAX_LENGTH);
        return -1;
    }
    *out = (size_t)n;
    return 0;
}

/* Load the vault after prompting for the master password. On success the
 * master password is left in `master` for a follow-up save. */
static int open_vault(Vault *v, char *master, size_t master_cap) {
    if (read_secret("Master password: ", master, master_cap) != 0)
        return -1;
    int rc = vault_load(vault_path(), master, v);
    if (rc != VAULT_OK) {
        fprintf(stderr, "Error: %s\n", vault_strerror(rc));
        secure_zero(master, master_cap);
        return -1;
    }
    return 0;
}

static int cmd_init(void) {
    /* Only a courtesy check to skip the password prompt. vault_create is what
     * actually guarantees an existing vault is never replaced. */
    if (access(vault_path(), F_OK) == 0) {
        fprintf(stderr, "Error: vault already exists at %s\n", vault_path());
        return EXIT_FAILURE;
    }

    char master[MASTER_MAX];
    if (read_secret_confirmed("New master password: ", master, sizeof(master)) != 0)
        return EXIT_FAILURE;

    int rc = vault_create(vault_path(), master);
    secure_zero(master, sizeof(master));
    if (rc != VAULT_OK) {
        fprintf(stderr, "Error: %s\n", vault_strerror(rc));
        return EXIT_FAILURE;
    }
    printf("Created empty vault at %s\n", vault_path());
    return EXIT_SUCCESS;
}

static int cmd_add(int argc, char *argv[]) {
    if (argc < 1) {
        fprintf(stderr, "usage: passman add <name> [-g [length]]\n");
        return EXIT_FAILURE;
    }
    const char *name = argv[0];
    if (strlen(name) > VAULT_FIELD_MAX) {
        fprintf(stderr, "Error: entry name is longer than %d bytes\n",
                VAULT_FIELD_MAX);
        return EXIT_FAILURE;
    }
    int gen = 0;
    size_t gen_len = GEN_DEFAULT_LENGTH;
    if (argc >= 2) {
        if (strcmp(argv[1], "-g") != 0) {
            fprintf(stderr, "usage: passman add <name> [-g [length]]\n");
            return EXIT_FAILURE;
        }
        gen = 1;
        if (argc >= 3 && parse_length(argv[2], &gen_len) != 0)
            return EXIT_FAILURE;
    }

    char master[MASTER_MAX];
    Vault v;
    if (open_vault(&v, master, sizeof(master)) != 0)
        return EXIT_FAILURE;

    int status = EXIT_FAILURE;
    char username[FIELD_INPUT_MAX];
    char password[FIELD_INPUT_MAX];

    if (vault_find(&v, name)) {
        fprintf(stderr, "Error: an entry named '%s' already exists\n", name);
        goto out;
    }
    if (read_line("Username: ", username, sizeof(username)) != 0)
        goto out;

    if (gen) {
        if (generate_password(password, gen_len) != 0) {
            fprintf(stderr, "Error: unable to generate password\n");
            goto out;
        }
        printf("Generated password: %s\n", password);
    } else {
        if (read_secret_confirmed("Password: ", password, sizeof(password)) != 0)
            goto out;
    }

    int rc = vault_add(&v, name, username, password);
    if (rc == VAULT_OK)
        rc = vault_save(vault_path(), master, &v);
    secure_zero(password, sizeof(password));
    if (rc != VAULT_OK) {
        fprintf(stderr, "Error: %s\n", vault_strerror(rc));
        goto out;
    }
    printf("Added entry '%s'\n", name);
    status = EXIT_SUCCESS;

out:
    secure_zero(master, sizeof(master));
    vault_free(&v);
    return status;
}

static int cmd_get(int argc, char *argv[]) {
    if (argc != 1) {
        fprintf(stderr, "usage: passman get <name>\n");
        return EXIT_FAILURE;
    }

    char master[MASTER_MAX];
    Vault v;
    if (open_vault(&v, master, sizeof(master)) != 0)
        return EXIT_FAILURE;
    secure_zero(master, sizeof(master));

    int status = EXIT_FAILURE;
    VaultEntry *e = vault_find(&v, argv[0]);
    if (!e) {
        fprintf(stderr, "Error: no entry named '%s'\n", argv[0]);
    } else {
        printf("username: %s\npassword: %s\n", e->username, e->password);
        status = EXIT_SUCCESS;
    }
    vault_free(&v);
    return status;
}

static int cmd_list(void) {
    char master[MASTER_MAX];
    Vault v;
    if (open_vault(&v, master, sizeof(master)) != 0)
        return EXIT_FAILURE;
    secure_zero(master, sizeof(master));

    if (v.count == 0)
        printf("(vault is empty)\n");
    for (size_t i = 0; i < v.count; i++)
        printf("%s\n", v.entries[i].name);
    vault_free(&v);
    return EXIT_SUCCESS;
}

static int cmd_rm(int argc, char *argv[]) {
    if (argc != 1) {
        fprintf(stderr, "usage: passman rm <name>\n");
        return EXIT_FAILURE;
    }

    char master[MASTER_MAX];
    Vault v;
    if (open_vault(&v, master, sizeof(master)) != 0)
        return EXIT_FAILURE;

    int status = EXIT_FAILURE;
    int rc = vault_remove(&v, argv[0]);
    if (rc != VAULT_OK) {
        fprintf(stderr, "Error: no entry named '%s'\n", argv[0]);
    } else if ((rc = vault_save(vault_path(), master, &v)) != VAULT_OK) {
        fprintf(stderr, "Error: %s\n", vault_strerror(rc));
    } else {
        printf("Removed entry '%s'\n", argv[0]);
        status = EXIT_SUCCESS;
    }

    secure_zero(master, sizeof(master));
    vault_free(&v);
    return status;
}

static int cmd_generate(int argc, char *argv[]) {
    size_t length = GEN_DEFAULT_LENGTH;
    if (argc >= 1 && parse_length(argv[0], &length) != 0)
        return EXIT_FAILURE;

    char password[GEN_MAX_LENGTH + 1];
    if (generate_password(password, length) != 0) {
        fprintf(stderr, "Error: unable to generate password\n");
        return EXIT_FAILURE;
    }
    printf("%s\n", password);
    secure_zero(password, sizeof(password));
    return EXIT_SUCCESS;
}

static int cmd_change_master(void) {
    char master[MASTER_MAX];
    Vault v;
    if (open_vault(&v, master, sizeof(master)) != 0)
        return EXIT_FAILURE;
    secure_zero(master, sizeof(master));

    int status = EXIT_FAILURE;
    char new_master[MASTER_MAX];
    if (read_secret_confirmed("New master password: ", new_master,
                              sizeof(new_master)) == 0) {
        int rc = vault_save(vault_path(), new_master, &v);
        secure_zero(new_master, sizeof(new_master));
        if (rc != VAULT_OK) {
            fprintf(stderr, "Error: %s\n", vault_strerror(rc));
        } else {
            printf("Master password changed\n");
            status = EXIT_SUCCESS;
        }
    }
    vault_free(&v);
    return status;
}

static void usage(void) {
    fprintf(stderr,
            "usage: passman <command> [args]\n"
            "\n"
            "  init                   create a new vault\n"
            "  add <name> [-g [len]]  add an entry (-g generates the password)\n"
            "  get <name>             show an entry's username and password\n"
            "  list                   list entry names\n"
            "  rm <name>              delete an entry\n"
            "  generate [len]         print a random password (no vault needed)\n"
            "  change-master          change the vault's master password\n"
            "\n"
            "The vault lives at ~/.passman.vault (override with PASSMAN_VAULT).\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        usage();
        return EXIT_FAILURE;
    }

    const char *cmd = argv[1];
    if (strcmp(cmd, "init") == 0)
        return cmd_init();
    if (strcmp(cmd, "add") == 0)
        return cmd_add(argc - 2, argv + 2);
    if (strcmp(cmd, "get") == 0)
        return cmd_get(argc - 2, argv + 2);
    if (strcmp(cmd, "list") == 0)
        return cmd_list();
    if (strcmp(cmd, "rm") == 0)
        return cmd_rm(argc - 2, argv + 2);
    if (strcmp(cmd, "generate") == 0)
        return cmd_generate(argc - 2, argv + 2);
    if (strcmp(cmd, "change-master") == 0)
        return cmd_change_master();

    usage();
    return EXIT_FAILURE;
}
