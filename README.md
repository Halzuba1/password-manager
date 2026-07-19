# Secure Password Generator

A command-line password generator written in C for macOS. Passwords are built
from cryptographically secure random bytes provided by Apple's Security
framework (`SecRandomCopyBytes`), rather than `rand()` or other predictable
sources.

## Features

- Cryptographically secure randomness via the macOS Security framework
- Configurable password length (defaults to 24 characters)
- Character set covering lowercase, uppercase, digits, and symbols
- No dependencies beyond the system SDK

## Build

Requires macOS with the Xcode Command Line Tools installed.

```sh
make
```

This produces a `passgen` binary. To compile manually:

```sh
clang -Wall -Wextra -O2 -o passgen main.c -framework Security
```

## Usage

```sh
# Generate a 24-character password (default)
./passgen

# Generate a password of a specific length
./passgen 32
```

Example output:

```
tR9!kQ{2x&Vm]pZ7@dLc#4Wn
```

## How it works

1. The requested number of random bytes is filled by
   `SecRandomCopyBytes(kSecRandomDefault, ...)`, the same CSPRNG interface
   used by system security features.
2. Each byte is mapped onto a 92-character set of letters, digits, and
   symbols.
3. The buffer is freed and the password is printed to stdout, making it easy
   to pipe into other tools (e.g. `./passgen | pbcopy`).
