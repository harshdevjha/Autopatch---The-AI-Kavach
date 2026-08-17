CC ?= gcc
# -fno-stack-protector + no _FORTIFY_SOURCE so the classic overflow actually
# crashes instead of being caught by glibc's own hardening (keeps the demo
# honest about what the *fuzzer* found vs. what libc silently blocked).
CFLAGS ?= -g -O0 -fno-stack-protector -D_FORTIFY_SOURCE=0 -Wall

TARGET ?= buggy
SRC ?= buggy.c

all:
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f buggy buggy_patched
