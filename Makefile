CC = clang
CFLAGS = -Wall -Wextra -O2 -std=c11
LDFLAGS = -framework Security

SRC = src/main.c src/crypto.c src/generator.c src/vault.c
HDR = src/crypto.h src/generator.h src/vault.h

TEST_SRC = tests/vault_test.c src/crypto.c src/vault.c

passman: $(SRC) $(HDR)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LDFLAGS)

tests/vault_test: $(TEST_SRC) $(HDR)
	$(CC) $(CFLAGS) -Isrc -o $@ $(TEST_SRC) $(LDFLAGS)

test: tests/vault_test
	./tests/vault_test

clean:
	rm -f passman tests/vault_test

.PHONY: clean test
