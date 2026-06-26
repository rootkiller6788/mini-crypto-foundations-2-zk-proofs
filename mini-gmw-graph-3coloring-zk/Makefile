# Makefile for mini-gmw-graph-3coloring-zk
# GMW Graph 3-Coloring Zero-Knowledge Proof Implementation
# Courses: MIT 6.876, Stanford CS255, Berkeley CS276, Princeton COS 551

CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2 -g
INCLUDES = -Iinclude
LDFLAGS = -lm

SRCDIR = src
INCDIR = include
TESTDIR = tests
EXAMPLEDIR = examples

SRCS = $(SRCDIR)/graph_3coloring.c        $(SRCDIR)/commitment.c        $(SRCDIR)/gmw_protocol.c        $(SRCDIR)/simulator.c        $(SRCDIR)/interactive_proof.c        $(SRCDIR)/zk_applications.c

OBJS = $(SRCS:.c=.o)
TARGETS = $(TESTDIR)/test_all           $(EXAMPLEDIR)/example_gmw_3coloring           $(EXAMPLEDIR)/example_zk_auth           $(EXAMPLEDIR)/example_simulator

.PHONY: all test examples clean

all: test examples

$(SRCDIR)/%.o: $(SRCDIR)/%.c $(INCDIR)/%.h
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(TESTDIR)/test_all: $(TESTDIR)/test_all.c $(OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) $< $(OBJS) -o $@ $(LDFLAGS)

$(EXAMPLEDIR)/example_gmw_3coloring: $(EXAMPLEDIR)/example_gmw_3coloring.c $(OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) $< $(OBJS) -o $@ $(LDFLAGS)

$(EXAMPLEDIR)/example_zk_auth: $(EXAMPLEDIR)/example_zk_auth.c $(OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) $< $(OBJS) -o $@ $(LDFLAGS)

$(EXAMPLEDIR)/example_simulator: $(EXAMPLEDIR)/example_simulator.c $(OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) $< $(OBJS) -o $@ $(LDFLAGS)

test: $(TESTDIR)/test_all
	@echo "Running tests..."
	$(TESTDIR)/test_all
	@echo "All tests passed."

examples: $(TARGETS)

clean:
	rm -f $(SRCDIR)/*.o
	rm -f $(TESTDIR)/test_all
	rm -f $(EXAMPLEDIR)/example_gmw_3coloring $(EXAMPLEDIR)/example_zk_auth $(EXAMPLEDIR)/example_simulator
