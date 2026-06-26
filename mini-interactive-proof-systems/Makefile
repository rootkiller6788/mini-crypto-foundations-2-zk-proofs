# Makefile for mini-interactive-proof-systems

CC       = gcc
CFLAGS   = -Wall -Wextra -std=c11 -O2 -g -I./include
LDFLAGS  = -lm
AR       = ar
ARFLAGS  = rcs

SRCS     = src/ip_system.c src/ip_protocols.c src/ip_sumcheck.c src/ip_arithmetization.c src/ip_gkr.c src/ip_polynomial_commitment.c src/ip_zkp.c
OBJS     = $(patsubst src/%.c,bin/%.o,$(SRCS))
LIB      = lib/libip.a

.PHONY: all clean test examples lib

all: lib test examples

lib: $(LIB)

bin:
	mkdir -p bin

$(LIB): $(OBJS)
	@mkdir -p lib
	$(AR) $(ARFLAGS) $@ $(OBJS)

bin/%.o: src/%.c | bin
	$(CC) $(CFLAGS) -c $< -o $@

bin/test_ip_systems: tests/test_ip_systems.c $(LIB)
	$(CC) $(CFLAGS) $< -Llib -lip $(LDFLAGS) -o $@

bin/example_gni: examples/example_gni.c $(LIB)
	$(CC) $(CFLAGS) $< -Llib -lip $(LDFLAGS) -o $@

bin/example_sumcheck: examples/example_sumcheck.c $(LIB)
	$(CC) $(CFLAGS) $< -Llib -lip $(LDFLAGS) -o $@

bin/example_qr: examples/example_qr.c $(LIB)
	$(CC) $(CFLAGS) $< -Llib -lip $(LDFLAGS) -o $@

bin/example_zk_gni: examples/example_zk_gni.c $(LIB)
	$(CC) $(CFLAGS) $< -Llib -lip $(LDFLAGS) -o $@

test: bin/test_ip_systems
	@echo "Running tests..."
	./bin/test_ip_systems && echo "  ALL TESTS PASSED" || echo "  TESTS FAILED"

examples: bin/example_gni bin/example_sumcheck bin/example_qr bin/example_zk_gni
	@echo "Running examples..."
	./bin/example_gni
	./bin/example_sumcheck
	./bin/example_qr
	./bin/example_zk_gni

clean:
	rm -rf bin lib
