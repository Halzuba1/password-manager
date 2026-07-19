CC = clang
CFLAGS = -Wall -Wextra -O2 -std=c11
LDFLAGS = -framework Security

SRC = src/main.c src/crypto.c src/generator.c src/vault.c
HDR = src/crypto.h src/generator.h src/vault.h

passman: $(SRC) $(HDR)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LDFLAGS)

clean:
	rm -f passman

.PHONY: clean
