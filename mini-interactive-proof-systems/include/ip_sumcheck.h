#ifndef MINI_IP_SUMCHECK_H
#define MINI_IP_SUMCHECK_H
#include "ip_system.h"

/* Sumcheck protocol for verifying sum_{x in {0,1}^n} g(x) = H.
 * Core building block of IP=PSPACE and the GKR protocol.
 * Theorem (LFKN 1990, Shamir 1992): sumcheck has soundness error n*d/|F|. */

typedef struct {
    uint64_t *work_array;
    size_t    n;
    uint64_t  prime;
} SumcheckProver;

typedef struct {
    uint64_t *claims;
    uint64_t *challenges;
    size_t    n;
    uint64_t  prime;
} SumcheckTranscript;

int sumcheck_prover_init(SumcheckProver *prover, const uint64_t *hypercube_vals,
                          size_t n, uint64_t prime);
void sumcheck_prover_free(SumcheckProver *prover);
int sumcheck_prover_round(SumcheckProver *prover, size_t round_i,
                           uint64_t r_i, uint64_t *c0, uint64_t *c1);
int ip_sumcheck_verify(const void *protocol, uint64_t claimed_H,
                       size_t n, uint64_t prime, IPRandomTape *tape,
                       int *accepted, uint64_t *final_r);
int ip_sumcheck_full(const IPMultilinearExtension *mex,
                     uint64_t claimed_sum, IPRandomTape *tape, int *accepted);
uint64_t ip_sumcheck_compute_sum(const IPMultilinearExtension *mex);
double ip_sumcheck_soundness_error(size_t n, uint64_t field_size, size_t repetitions);
int ip_multilinear_product(const IPMultilinearExtension *A,
                            const IPMultilinearExtension *B,
                            IPMultilinearExtension *out);

#endif /* MINI_IP_SUMCHECK_H */