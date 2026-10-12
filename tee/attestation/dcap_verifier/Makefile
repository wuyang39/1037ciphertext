#
# A1-22 DCAP quote verifier (KAS_DCAP_VERIFY_BIN).
#
CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -std=c99
DCAP_LIB_DIR ?= /usr/lib/x86_64-linux-gnu
LDLIBS ?= -lsgx_dcap_quoteverify

BIN := a122_dcap_verify

.PHONY: all clean

all: $(BIN)

$(BIN): a122_dcap_verify.c
	$(CC) $(CFLAGS) $< -o $@ -L$(DCAP_LIB_DIR) $(LDLIBS)

clean:
	rm -f $(BIN)
