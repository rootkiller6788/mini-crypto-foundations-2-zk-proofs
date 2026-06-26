# Makefile for mini-commitment-schemes
CC       = gcc
CFLAGS   = -std=c11 -Wall -Wextra -O2 -g
CPPFLAGS = -Iinclude
LDFLAGS  =

CORE_SRC = src/bigint.c src/modarith.c src/commitment.c \
           src/pedersen.c src/hash_commit.c src/vector_commit.c
CORE_OBJ = $(CORE_SRC:.c=.o)
TEST_SRC = tests/test_commitment.c
TEST_OBJ = $(TEST_SRC:.c=.o)
TEST_BIN = build/test_commitment
EXAMPLE_SRC = examples/example_pedersen.c examples/example_vector.c \
              examples/example_coin_flip.c examples/example_sigma_protocol.c \
              examples/example_post_quantum.c
EXAMPLE_BINS = $(EXAMPLE_SRC:examples/%.c=build/%)
DEMO_SRC = demos/demo_commitment_lifecycle.c
DEMO_BIN = build/demo_commitment_lifecycle
BENCH_SRC = benches/bench_commitment.c
BENCH_BIN = build/bench_commitment
BUILD_DIR = build

.PHONY: all
all: $(BUILD_DIR) $(EXAMPLE_BINS)
	@echo "=== All examples built ==="

.PHONY: demo
demo: $(BUILD_DIR) $(DEMO_BIN)
	$(DEMO_BIN)

.PHONY: bench
bench: $(BUILD_DIR) $(BENCH_BIN)
	$(BENCH_BIN)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

$(TEST_BIN): $(CORE_OBJ) $(TEST_OBJ) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^ $(LDFLAGS)

build/%: examples/%.c $(CORE_SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $< $(CORE_SRC) $(LDFLAGS)

$(DEMO_BIN): $(CORE_SRC) $(DEMO_SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $(DEMO_SRC) $(CORE_SRC) $(LDFLAGS)

$(BENCH_BIN): $(CORE_SRC) $(BENCH_SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $(BENCH_SRC) $(CORE_SRC) $(LDFLAGS)

.PHONY: test
test: $(TEST_BIN)
	$(TEST_BIN)

.PHONY: examples
examples: $(EXAMPLE_BINS)

.PHONY: run-examples
run-examples: $(EXAMPLE_BINS)
	for bin in $(EXAMPLE_BINS); do echo "=== $$bin ==="; $$bin; done

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
	rm -f src/*.o tests/*.o examples/*.o

.PHONY: help
help:
	@echo "Targets: all test examples run-examples clean help"
