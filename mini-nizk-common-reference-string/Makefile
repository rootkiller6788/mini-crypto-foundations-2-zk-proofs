# Makefile for mini-nizk-common-reference-string
# Non-Interactive Zero-Knowledge Proofs with Common Reference String

CC       = gcc
CFLAGS   = -Wall -Wextra -std=c11 -O2 -I include -Wno-unused-parameter -Wno-unused-function -Wno-unused-variable
LDFLAGS  = -lm

SRC = src/nizk_group.c \
      src/nizk_crs.c \
      src/nizk_commitment.c \
      src/nizk_sigma.c \
      src/nizk_proof.c \
      src/nizk_simulator.c

OBJ = $(SRC:.c=.o)

TEST_SRC = tests/test_nizk.c
TEST_BIN = test_nizk

EXAMPLES = examples/example_dlog \
           examples/example_commitment \
           examples/example_or_proof

BENCHES = benches/bench_nizk
DEMOS   = demos/demo_nizk_interactive

.PHONY: all clean test examples benches demos

all: libnizk.a

libnizk.a: $(OBJ)
	ar rcs $@ $(OBJ)

src/%.o: src/%.c include/*.h
	$(CC) $(CFLAGS) -c $< -o $@

test: libnizk.a $(TEST_SRC)
	$(CC) $(CFLAGS) $(TEST_SRC) -L. -lnizk $(LDFLAGS) -o $(TEST_BIN)
	./$(TEST_BIN)

examples: libnizk.a $(EXAMPLES)

examples/example_dlog: examples/example_dlog.c libnizk.a
	$(CC) $(CFLAGS) $< -L. -lnizk $(LDFLAGS) -o $@

examples/example_commitment: examples/example_commitment.c libnizk.a
	$(CC) $(CFLAGS) $< -L. -lnizk $(LDFLAGS) -o $@

examples/example_or_proof: examples/example_or_proof.c libnizk.a
	$(CC) $(CFLAGS) $< -L. -lnizk $(LDFLAGS) -o $@

benches: libnizk.a $(BENCHES)

benches/bench_nizk: benches/bench_nizk.c libnizk.a
	$(CC) $(CFLAGS) $< -L. -lnizk $(LDFLAGS) -o $@

demos: libnizk.a $(DEMOS)

demos/demo_nizk_interactive: demos/demo_nizk_interactive.c libnizk.a
	$(CC) $(CFLAGS) $< -L. -lnizk $(LDFLAGS) -o $@

clean:
	rm -f src/*.o libnizk.a $(TEST_BIN) $(EXAMPLES) $(BENCHES) $(DEMOS)
