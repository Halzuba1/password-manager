CC = clang
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -framework Security

passgen: main.c
	$(CC) $(CFLAGS) -o passgen main.c $(LDFLAGS)

clean:
	rm -f passgen

.PHONY: clean
