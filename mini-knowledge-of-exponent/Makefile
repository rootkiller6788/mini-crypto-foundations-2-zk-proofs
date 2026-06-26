# Makefile — mini-knowledge-of-exponent
# Knowledge of Exponent Assumption & Groth16 SNARK
# (C) Mini-Theory-of-Computation

CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2 -Iinclude
LDFLAGS = -lm

SRC = src/group.c src/discrete_log.c src/kea.c src/pairing.c src/snark_kea.c
OBJ = $(SRC:.c=.o)

EXAMPLES = examples/example_kea examples/example_dlp examples/example_snark
BENCHES = benches/bench_group benches/bench_dlp benches/bench_kea

.PHONY: all test clean examples benches lib

all: lib examples benches test

lib: $(OBJ)
	ar rcs build/libkea.a $(OBJ)

src/%.o: src/%.c include/*.h
	$(CC) $(CFLAGS) -c $< -o $@

# ── Test ──────────────────────────────────────────────────────

test: tests/test_all
	./tests/test_all

tests/test_all: tests/test_all.c $(SRC)
	$(CC) $(CFLAGS) -o $@ tests/test_all.c $(SRC) $(LDFLAGS)

# ── Examples ──────────────────────────────────────────────────

examples: $(EXAMPLES)

examples/example_kea: examples/example_kea.c $(SRC)
	$(CC) $(CFLAGS) -o $@ examples/example_kea.c $(SRC) $(LDFLAGS)

examples/example_dlp: examples/example_dlp.c $(SRC)
	$(CC) $(CFLAGS) -o $@ examples/example_dlp.c $(SRC) $(LDFLAGS)

examples/example_snark: examples/example_snark.c $(SRC)
	$(CC) $(CFLAGS) -o $@ examples/example_snark.c $(SRC) $(LDFLAGS)

# ── Benchmarks ────────────────────────────────────────────────

benches: $(BENCHES)

benches/%: benches/%.c $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(SRC) $(LDFLAGS)

# ── Clean ─────────────────────────────────────────────────────

clean:
	rm -f $(OBJ) build/libkea.a
	rm -f tests/test_all
	rm -f $(EXAMPLES)
	rm -f $(addsuffix .exe,$(EXAMPLES))
	rm -f $(BENCHES)
