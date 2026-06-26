# Makefile -- mini-sigma-protocols-fiat-shamir
# Sigma Protocols and Fiat-Shamir Transform

CC      = gcc
CFLAGS  = -Wall -Wextra -std=c11 -O2 -g -Wno-unused-parameter -Wno-unused-variable
INCDIR  = include
SRCDIR  = src
TSTDIR  = tests
EXDIR   = examples

SRCS    = $(SRCDIR)/sigma_math.c $(SRCDIR)/sigma_core.c \
          $(SRCDIR)/sigma_schnorr.c $(SRCDIR)/sigma_fiat_shamir.c \
          $(SRCDIR)/sigma_chaum_pedersen.c $(SRCDIR)/sigma_composition.c \
          $(SRCDIR)/sigma_gq.c

TESTS   = $(TSTDIR)/test_schnorr $(TSTDIR)/test_chaum_pedersen \
          $(TSTDIR)/test_fiat_shamir $(TSTDIR)/test_composition

EXAMPLES = $(EXDIR)/example_schnorr_id $(EXDIR)/example_fs_signature \
           $(EXDIR)/example_ring_signature

.PHONY: all test examples clean

all: test examples

$(TSTDIR)/test_schnorr: $(TSTDIR)/test_schnorr.c $(SRCS)
	$(CC) $(CFLAGS) -I$(INCDIR) $^ -o $@

$(TSTDIR)/test_chaum_pedersen: $(TSTDIR)/test_chaum_pedersen.c $(SRCS)
	$(CC) $(CFLAGS) -I$(INCDIR) $^ -o $@

$(TSTDIR)/test_fiat_shamir: $(TSTDIR)/test_fiat_shamir.c $(SRCS)
	$(CC) $(CFLAGS) -I$(INCDIR) $^ -o $@

$(TSTDIR)/test_composition: $(TSTDIR)/test_composition.c $(SRCS)
	$(CC) $(CFLAGS) -I$(INCDIR) $^ -o $@

test: $(TESTS)
	@echo "=== Schnorr Tests ==="
	@$(TSTDIR)/test_schnorr
	@echo "=== Chaum-Pedersen Tests ==="
	@$(TSTDIR)/test_chaum_pedersen
	@echo "=== Fiat-Shamir Tests ==="
	@$(TSTDIR)/test_fiat_shamir
	@echo "=== Composition Tests ==="
	@$(TSTDIR)/test_composition
	@echo "=== ALL TESTS PASSED ==="

$(EXDIR)/example_schnorr_id: $(EXDIR)/example_schnorr_id.c $(SRCS)
	$(CC) $(CFLAGS) -I$(INCDIR) $^ -o $@

$(EXDIR)/example_fs_signature: $(EXDIR)/example_fs_signature.c $(SRCS)
	$(CC) $(CFLAGS) -I$(INCDIR) $^ -o $@

$(EXDIR)/example_ring_signature: $(EXDIR)/example_ring_signature.c $(SRCS)
	$(CC) $(CFLAGS) -I$(INCDIR) $^ -o $@

examples: $(EXAMPLES)

clean:
	rm -f $(TESTS) $(EXAMPLES) obj/*.o
