CC = gcc
CFLAGS = -Wall -Wextra -O2 -I./include
AR = ar
LDFLAGS = -lm

SRC = $(wildcard src/*.c)
OBJ = $(patsubst src/%.c,build/%.o,$(SRC))
LIB = build/libzksim.a

TESTS_SRC = $(wildcard tests/*.c)
TESTS_BIN = $(patsubst tests/%.c,tests/%,$(TESTS_SRC))

EXAMPLES_SRC = $(wildcard examples/*.c)
EXAMPLES_BIN = $(patsubst examples/%.c,build/example_%,$(EXAMPLES_SRC))

BENCH_SRC = $(wildcard benches/*.c)
BENCH_BIN = $(patsubst benches/%.c,build/bench_%,$(BENCH_SRC))

DEMOS_SRC = $(wildcard demos/*.c)
DEMOS_BIN = $(patsubst demos/%.c,build/demo_%,$(DEMOS_SRC))

.PHONY: all test clean distclean examples benches demos run-examples run-benches run-demos

all: $(LIB) test examples benches demos

$(LIB): $(OBJ)
	@mkdir -p build
	$(AR) rcs $@ $^

build/%.o: src/%.c
	@mkdir -p build
	$(CC) $(CFLAGS) -c $< -o $@

tests/%: tests/%.c $(LIB)
	@mkdir -p tests 2>/dev/null || true
	$(CC) $(CFLAGS) -o $@ $< -Lbuild -lzksim $(LDFLAGS)

test: $(TESTS_BIN)
	@for t in $(TESTS_BIN); do echo "=== $$t ===" && ./$$t && echo ""; done
	@echo "All tests passed."

# Examples
examples: $(EXAMPLES_BIN)

build/example_%: examples/%.c $(LIB)
	@mkdir -p build
	$(CC) $(CFLAGS) -o $@ $< -Lbuild -lzksim $(LDFLAGS)

run-examples: examples
	@for e in $(EXAMPLES_BIN); do echo "=== $$e ===" && ./$$e && echo ""; done

# Benchmarks
benches: $(BENCH_BIN)

build/bench_%: benches/%.c $(LIB)
	@mkdir -p build
	$(CC) $(CFLAGS) -o $@ $< -Lbuild -lzksim $(LDFLAGS)

run-benches: benches
	@for b in $(BENCH_BIN); do echo "=== $$b ===" && ./$$b && echo ""; done

# Demos
demos: $(DEMOS_BIN)

build/demo_%: demos/%.c $(LIB)
	@mkdir -p build
	$(CC) $(CFLAGS) -o $@ $< -Lbuild -lzksim $(LDFLAGS)

run-demos: demos
	@for d in $(DEMOS_BIN); do echo "=== $$d ===" && ./$$d && echo ""; done

clean:
	rm -rf build/ tests/run_tests tests/run_tests.exe examples/*.exe benches/*.exe demos/*.exe

distclean: clean
	rm -f tests/*.exe
