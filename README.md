# passman — a CLI password manager for macOS

A password manager written in C with no dependencies beyond the macOS system
SDK. Credentials are stored in a single encrypted vault file protected by a
master password.

## Security design

- **Key derivation** — PBKDF2-HMAC-SHA256 with 600,000 iterations and a
  random 16-byte salt derives two independent 256-bit keys (one for
  encryption, one for authentication) from the master password.
- **Authenticated encryption** — the vault is encrypted with AES-256-CBC and
  authenticated with HMAC-SHA256 in an encrypt-then-MAC construction. The
  MAC covers the file header (magic, salt, IV) as well as the ciphertext,
  and is verified with a constant-time comparison *before* any decryption is
  attempted, so wrong passwords and tampered files are rejected without ever
  touching the ciphertext.
- **Randomness** — all random material (salts, IVs, generated passwords)
  comes from `SecRandomCopyBytes`, the macOS CSPRNG.
- **Unbiased password generation** — random bytes are mapped onto the
  91-character set using rejection sampling: bytes that would wrap around
  the charset unevenly are discarded, so every character is exactly equally
  likely (a plain `byte % charset_size` would bias toward the first
  characters of the set).
- **Fresh salt and IV on every save** — the vault never reuses an IV, and a
  key derived for one write is never reused for another.
- **Memory hygiene** — master passwords, derived keys, and decrypted
  plaintext are zeroed with `memset_s` (which the compiler may not optimize
  away) as soon as they are no longer needed. Hidden input is read with
  `readpassphrase(3)`, so secrets never echo to the terminal.
- **Atomic, durable writes** — saves go to a uniquely named temp file
  (created exclusively with mode `0600` by `mkstemp(3)`), are flushed to
  disk with `F_FULLFSYNC`, and are then `rename(2)`d into place, so a crash
  or power loss mid-write cannot corrupt the existing vault. If the vault
  path is a symlink, the file it points to is updated and the link is kept.
- **Locking** — commands that modify the vault (`add`, `rm`,
  `change-master`) hold an exclusive `flock(2)` from load to save. A second
  one started meanwhile exits with an error instead of silently discarding
  the first one's changes.

### Vault file format

```
offset  size  field
0       4     magic "PMV1"
4       16    PBKDF2 salt
20      16    AES-CBC IV
36      32    HMAC-SHA256(mac_key, magic || salt || iv || ciphertext)
68      N     AES-256-CBC ciphertext of the serialized entries
```

The plaintext is a count followed by length-prefixed name/username/password
records, all little-endian, with strict bounds checking on parse.

## Build

Requires macOS with the Xcode Command Line Tools installed.

```sh
make
```

## Usage

```sh
passman init                   # create a new vault
passman add github             # add an entry (prompts for the password)
passman add aws -g 32          # add an entry with a generated 32-char password
passman get github             # show an entry's username and password
passman list                   # list entry names
passman rm github              # delete an entry
passman generate 24            # print a random password (no vault needed)
passman change-master          # re-encrypt the vault under a new master password
```

The vault lives at `~/.passman.vault` by default; set `PASSMAN_VAULT` to use
a different path.

## Project structure

```
src/
  main.c       CLI parsing, prompts, and command dispatch
  vault.c/.h   vault file format, serialization, load/save, entry management
  crypto.c/.h  key derivation, AES, HMAC, CSPRNG, constant-time compare
  generator.c  rejection-sampled password generation
```

## Limitations

This is a portfolio project, not a replacement for an audited password
manager. Known limitations: secrets are printed to stdout (by design, for
piping) and can end up in terminal scrollback; memory is not locked against
swapping (`mlock`); and there is no protection against a compromised local
machine, which no password manager can provide.
