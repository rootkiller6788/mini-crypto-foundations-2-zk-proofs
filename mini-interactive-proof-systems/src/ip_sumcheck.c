/*======================================================================
 * ip_sumcheck.c -- Sumcheck Protocol Implementation
 *
 * Implements the Lund-Fortnow-Karloff-Nisan (LFKN) sumcheck protocol,
 * the central building block of IP = PSPACE and the GKR protocol.
 *
 * Knowledge mapping:
 *   L1: Sumcheck protocol definition, completeness, soundness
 *   L2: interactive reduction, polynomial identity testing
 *   L3: multilinear polynomials over GF(p), low-degree extensions
 *   L4: Sumcheck soundness theorem (Lund et al. 1990, Shamir 1992)
 *   L5: Sumcheck prover algorithm (recursive polynomial construction)
 *   L6: #SAT via sumcheck, TQBF arithmetization
 *   L8: GKR protocol uses sumcheck as a subroutine
 *
 * The sumcheck protocol solves:
 *   Given a multilinear polynomial g(X1,...,Xn) over field F,
 *   and a claimed value H, verify that:
 *     sum_{x1 in {0,1}} ... sum_{xn in {0,1}} g(x1,...,xn) = H
 *
 * Protocol has n rounds, each reducing the number of variables by 1.
 *
 * Reference:
 *   Lund, Fortnow, Karloff, Nisan. "Algebraic methods for
 *   interactive proof systems." J. ACM 39(4), 1992.
 *   Arora & Barak. Computational Complexity, Sec. 8.3, 8.4.
 *======================================================================*/

#include "ip_system.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>

/*======================================================================
 * Sumcheck Types and Constants (L3: Mathematical Structures)
 *======================================================================*/

#define SUMCHECK_MAX_VARS  32
#define SUMCHECK_MAX_DEGREE 256

/* Sumcheck instance: the multilinear polynomial g and claim H */
typedef struct {
    IPMultilinearExtension *g;   /* The multilinear polynomial g */
    uint64_t                H;   /* Claimed sum over hypercube */
    size_t                  n;   /* Number of variables */
    uint64_t                prime;
} SumcheckInstance;

/* Sumcheck prover state across rounds */
typedef struct {
    IPMultilinearExtension *current_poly;  /* Restricted polynomial */
    size_t                  current_n;     /* Variables remaining */
    uint64_t               *partial_sums;  /* Precomputed partial sums */
    uint64_t                prime;
    int                     initialized;
} SumcheckProverState;

/* per-round claim: V holds H_i after i rounds */
typedef struct {
    uint64_t *claims;     /* H_0, H_1, ..., H_n */
    uint64_t *challenges; /* r_1, r_2, ..., r_n */
    size_t    n;
    uint64_t  prime;
} SumcheckTranscript;

/*======================================================================
 * Univariate polynomial from multilinear restriction (L5: Algorithm)
 *
 * In round i (1-indexed), given previous challenges r_1,...,r_{i-1},
 * the prover computes the univariate polynomial:
 *   q_i(X) = sum over b_{i+1},...,b_n in {0,1} of
 *     g(r_1, ..., r_{i-1}, X, b_{i+1}, ..., b_n)
 *
 * This is a degree-1 polynomial (since g is multilinear in each
 * variable). The prover sends coefficients of q_i to V.
 *
 * V checks: q_i(0) + q_i(1) = H_{i-1} (where H_0 = H, the claim).
 * Then V picks random r_i, sets H_i = q_i(r_i), and continues.
 *======================================================================*/

/* Compute the univariate polynomial q_i(X) for round i.
 *
 * Inputs:
 *   evaluations - the 2^k evaluations of g restricted to first i-1 vars
 *   k - number of remaining variables (n - i + 1)
 *   var_idx - index of the variable being summed out (0 = first remaining)
 *
 * Output:
 *   coeff0, coeff1 - coefficients of the degree-1 polynomial q(X)=c0+c1*X
 *
 * q(X) = sum_{b in {0,1}^{k-1}} g(r_1,...,r_{i-1}, X, b_1,...,b_{k-1})
 *
 * Since g is multilinear, q is degree-1 (affine).
 */
static int __attribute__((unused)) compute_univariate(const uint64_t *evaluations, size_t k,
                               size_t var_idx, uint64_t prime,
                               uint64_t *coeff0, uint64_t *coeff1) {
    if (!evaluations || !coeff0 || !coeff1 || k == 0) return -1;

    size_t half = 1ULL << (k - 1);
    uint64_t sum0 = 0, sum1 = 0;

    /* q(0) = sum over b of g(..., 0, b_1, ..., b_{k-1})
     * q(1) = sum over b of g(..., 1, b_1, ..., b_{k-1}) */
    for (size_t b = 0; b < half; b++) {
        /* Index for X=0: var_idx is 0 in the bitvector */
        size_t idx0 = 0;
        size_t idx1 = 0;
        size_t bit_pos = 0;
        for (size_t i = 0; i < k; i++) {
            if (i == var_idx) {
                /* idx0: X=0, don't set bit */
                /* idx1: X=1, set bit */
                idx1 |= (1ULL << bit_pos);
            } else {
                size_t b_bit = (b >> bit_pos) & 1;
                if (b_bit) {
                    idx0 |= (1ULL << (i > var_idx ? i : i));
                }
            }
            if (i != var_idx) bit_pos++;
        }
        /* Simpler approach: pair entries that differ only at var_idx */
        /* Entries are paired such that index pairs (j, j+stride) differ
           only at var_idx bit. stride = 2^var_idx. */
        size_t stride = 1ULL << var_idx;
        size_t total = 1ULL << k;
        for (size_t j = 0; j < total; j += 2 * stride) {
            for (size_t off = 0; off < stride; off++) {
                size_t idx_lo = j + off;
                size_t idx_hi = j + off + stride;
                uint64_t v_lo = evaluations[idx_lo] % prime;
                uint64_t v_hi = evaluations[idx_hi] % prime;
                /* q(0): X=0, use v_lo. q(1): X=1, use v_hi */
                sum0 = (sum0 + v_lo) % prime;
                sum1 = (sum1 + v_hi) % prime;
            }
        }
        break; /* single iteration covers everything; loop body above sums all */
    }

    /* Correct implementation: iterate over all pairs */
    sum0 = 0; sum1 = 0;
    size_t stride = 1ULL << var_idx;
    size_t total = 1ULL << k;
    for (size_t j = 0; j < total; j += 2 * stride) {
        for (size_t off = 0; off < stride; off++) {
            size_t idx0_v = j + off;
            size_t idx1_v = j + off + stride;
            sum0 = (sum0 + evaluations[idx0_v]) % prime;
            sum1 = (sum1 + evaluations[idx1_v]) % prime;
        }
    }

    *coeff0 = sum0;
    *coeff1 = (sum1 + prime - sum0) % prime; /* c1 = q(1) - q(0) = sum1 - sum0 */
    return 0;
}

/*======================================================================
 * Sumcheck Verifier (L5: Algorithm)
 *
 * The verifier's job in each round i:
 *   1. Receive q_i(X) = c_0 + c_1*X from prover
 *   2. Check: q_i(0) + q_i(1) == H_{i-1} (consistency check)
 *   3. Pick random r_i in F
 *   4. Set H_i = q_i(r_i) for the next round
 *
 * After n rounds, V needs to evaluate g(r_1,...,r_n) directly
 * and check that H_n == g(r_1,...,r_n). This requires oracle
 * access to g. In the LFKN/GKR frameworks, this final check
 * is delegated to another layer.
 *
 * Complexity: O(2^n) time for prover, O(n) field ops for verifier.
 * The verifier's advantage: verifier time is linear in n, while
 * direct sum computation would be exponential.
 *======================================================================*/

/* Sumcheck verifier: given the multilinear extension of a function
 * and a claimed sum H, run the sumcheck protocol.
 *
 * Returns 1 if proof is accepted, 0 if rejected.
 *
 * prover_oracle: function pointer that the verifier calls to get
 *   q_i coefficients in each round, simulating the prover.
 * final_eval: function to evaluate g(r_1,...,r_n) for final check.
 */
typedef int (*SumcheckProverFn)(size_t round, const uint64_t *prev_challenges,
                                 size_t n, uint64_t prime, void *prover_data,
                                 uint64_t *c0, uint64_t *c1);

typedef uint64_t (*FinalEvalFn)(const uint64_t *point, size_t n,
                                 uint64_t prime, void *eval_data);

typedef struct {
    SumcheckProverFn  get_univariate;
    FinalEvalFn       evaluate_final;
    void             *prover_data;
    void             *eval_data;
} SumcheckProtocol;

int ip_sumcheck_verify(const SumcheckProtocol *protocol,
                       uint64_t claimed_H, size_t n, uint64_t prime,
                       IPRandomTape *tape, int *accepted,
                       uint64_t *final_r) {
    if (!protocol || !tape || !accepted || !final_r || n == 0) return -1;

    uint64_t *challenges = (uint64_t *)calloc(n, sizeof(uint64_t));
    if (!challenges) return -1;

    uint64_t H_current = claimed_H % prime;
    int ok = 1;

    for (size_t round = 0; round < n; round++) {
        /* 1. Get univariate q_i from prover */
        uint64_t c0, c1;
        int pret = protocol->get_univariate(round, challenges,
                                              n, prime,
                                              protocol->prover_data,
                                              &c0, &c1);
        if (pret != 0) { ok = 0; break; }

        c0 = c0 % prime;
        c1 = c1 % prime;

        /* 2. Consistency check: q_i(0) + q_i(1) == H_{i-1}
         * q(0) + q(1) = c0 + (c0 + c1) = 2*c0 + c1 */
        /* Wait: q(X) = c0 + c1*X
         * q(0) = c0
         * q(1) = c0 + c1
         * q(0) + q(1) = 2*c0 + c1 */
        uint64_t consistency = (2 * c0 + c1) % prime;
        if (consistency != H_current) {
            ok = 0; break;
        }

        /* 3. Pick random challenge r_i */
        uint64_t r_i = ip_tape_consume(tape, 32) % prime;
        challenges[round] = r_i;

        /* 4. Set H_i = q_i(r_i) */
        H_current = (c0 + (c1 * r_i) % prime) % prime;
    }

    /* After n rounds: final check H_n == g(r_1,...,r_n) */
    if (ok) {
        uint64_t g_val = protocol->evaluate_final(challenges, n,
                                                    prime,
                                                    protocol->eval_data);
        ok = (H_current == (g_val % prime));
    }

    /* Copy final challenges for caller */
    memcpy(final_r, challenges, n * sizeof(uint64_t));

    *accepted = ok;
    free(challenges);
    return 0;
}

/*======================================================================
 * Sumcheck Prover (L5: Algorithm)
 *
 * The prover must compute q_i(X) in each round by summing over
 * exponentially many assignments to remaining variables. The
 * straightforward approach is O(2^{n}) per round, leading to
 * O(n * 2^n) total prover time.
 *
 * Optimization: precompute partial sums so that each round can
 * be computed in O(2^{n-i}) time. The total prover time is still
 * O(n * 2^n) but with better constants.
 *======================================================================*/

/* Sumcheck prover data structure for efficient round computation.
 *
 * Maintains an array A of size 2^k representing the sum of g over
 * the first n-k variables restricted to their challenge values.
 * Initially A[b] = g(b) for all b in {0,1}^n.
 *
 * In round i (first variable = variable 0):
 *   A_new[b] = A_old[0,b] + A_old[1,b]  (for all b in {0,1}^{n-1})
 *   q_i(0) = sum_b A_new[b]? No...
 *
 * Actually the prover needs to compute:
 *   q_i(X) = sum_{b in {0,1}^{n-i-1}} g(r_1,...,r_{i-1}, X, b)
 *
 * So q_i is a degree-1 polynomial: q_i(X) = a + b*X
 * where a = sum over b of g(..., 0, b) (X=0 case)
 *       b = sum over b of g(..., 1, b) - g(..., 0, b) (coefficient of X)
 *
 * In the DP approach: after i rounds, we have an array of size
 * 2^{n-i} where entry k is g(r_1,...,r_i, k interpreted as bits).
 * To compute q_{i+1}: sum entries pairwise.
 */

typedef struct {
    uint64_t *work_array;  /* Size 2^n, evolves over rounds */
    size_t    n;
    uint64_t  prime;
} SumcheckProver;

int sumcheck_prover_init(SumcheckProver *prover,
                          const uint64_t *hypercube_vals,
                          size_t n, uint64_t prime) {
    if (!prover || !hypercube_vals || n == 0 || n > SUMCHECK_MAX_VARS)
        return -1;

    size_t total = 1ULL << n;
    prover->work_array = (uint64_t *)malloc(total * sizeof(uint64_t));
    if (!prover->work_array) return -1;
    memcpy(prover->work_array, hypercube_vals, total * sizeof(uint64_t));
    prover->n = n;
    prover->prime = prime;
    return 0;
}

void sumcheck_prover_free(SumcheckProver *prover) {
    if (prover && prover->work_array) {
        free(prover->work_array);
        prover->work_array = NULL;
        prover->n = 0;
    }
}

/* Compute q_i(X) for round i (0-indexed: i = 0 is first variable).
 * Work array currently has size 2^{n-i} representing
 * g(r_0,...,r_{i-1}, b_i, ..., b_{n-1}) for b in {0,1}^{n-i}.
 *
 * After this call, work_array is reduced to size 2^{n-i-1} and
 * the prover obtains q_i coefficients.
 */
int sumcheck_prover_round(SumcheckProver *prover, size_t round_i,
                           uint64_t r_i, uint64_t *c0, uint64_t *c1) {
    if (!prover || !c0 || !c1) return -1;

    size_t current_n = prover->n - round_i;
    if (current_n == 0) return -1;

    size_t current_size = 1ULL << current_n;
    size_t half = current_size / 2;
    uint64_t p = prover->prime;

    /* q(X) = sum_{b in {0,1}^{current_n-1}} work[X, b_1,...,b_{n-i-1}]
     * q(0) = sum over b of work[0, b]
     * q(1) = sum over b of work[1, b]
     */
    uint64_t sum0 = 0, sum1 = 0;
    for (size_t b = 0; b < half; b++) {
        sum0 = (sum0 + prover->work_array[b]) % p;
        sum1 = (sum1 + prover->work_array[half + b]) % p;
    }

    *c0 = sum0;
    *c1 = (sum1 + p - sum0) % p; /* c1 = q(1) - q(0) */

    /* Reduce work array: work_new[b] = (1-r_i)*work[0,b] + r_i*work[1,b]
     * This is the restriction: g(r_0,...,r_{i-1}, r_i, b_1,...,)
     */
    uint64_t one_minus_r = (r_i == 0) ? 1 : (1 + p - r_i) % p;
    for (size_t b = 0; b < half; b++) {
        uint64_t term0 = (one_minus_r * prover->work_array[b]) % p;
        uint64_t term1 = (r_i * prover->work_array[half + b]) % p;
        prover->work_array[b] = (term0 + term1) % p;
    }

    return 0;
}

/*======================================================================
 * Sumcheck for counting satisfying assignments (L6: #SAT via sumcheck)
 *
 * Given a Boolean formula phi over n variables, the number of
 * satisfying assignments is:
 *   #phi = sum_{x in {0,1}^n} phi(x)
 *
 * Arithmetization produces a polynomial P_phi(x_1,...,x_n) such
 * that P_phi(x) = 1 if phi(x) is true, 0 otherwise, for x in {0,1}^n.
 *
 * The sumcheck protocol can then verify #phi = H interactively.
 *
 * This is the basis for IP = PSPACE: TQBF reduces to evaluating
 * a polynomial over the Boolean hypercube, which sumcheck verifies.
 *======================================================================*/

/* Compute the sum of a multilinear extension over the Boolean hypercube.
 * This is the ground truth that the prover claims.
 *
 * sum = sum_{x in {0,1}^n} f_tilde(x)
 *     = sum_{x in {0,1}^n} f(x) for the original Boolean function.
 */
uint64_t ip_sumcheck_compute_sum(const IPMultilinearExtension *mex) {
    if (!mex || !mex->is_valid) return 0;
    size_t n = mex->num_vars;
    size_t total = 1ULL << n;
    uint64_t sum = 0;
    for (size_t i = 0; i < total; i++) {
        sum = (sum + mex->evaluations[i]) % mex->prime;
    }
    return sum;
}

/* Full sumcheck protocol execution: prover and verifier interact.
 *
 * This function simulates a complete sumcheck execution with
 * the prover computing univariate polynomials on-the-fly and
 * the verifier checking consistency and finally evaluating g.
 *
 * Returns 1 if proof is accepted (sum is correct), 0 otherwise.
 */
int ip_sumcheck_full(const IPMultilinearExtension *mex,
                     uint64_t claimed_sum, IPRandomTape *tape,
                     int *accepted) {
    if (!mex || !mex->is_valid || !tape || !accepted) return -1;

    size_t n = mex->num_vars;
    uint64_t p = mex->prime;
    uint64_t H = claimed_sum % p;

    /* Initialize prover with full hypercube */
    SumcheckProver prover;
    if (sumcheck_prover_init(&prover, mex->evaluations, n, p) != 0) {
        return -1;
    }

    uint64_t *challenges = (uint64_t *)calloc(n, sizeof(uint64_t));
    if (!challenges) { sumcheck_prover_free(&prover); return -1; }

    int ok = 1;

    for (size_t round = 0; round < n; round++) {
        /* Prover computes q_i(X) */
        uint64_t c0, c1;
        if (sumcheck_prover_round(&prover, round, 0, &c0, &c1) != 0) {
            ok = 0; break;
        }

        /* Verifier checks: q_i(0) + q_i(1) == H */
        uint64_t consistency = (2 * c0 + c1) % p;
        if (consistency != H) {
            ok = 0; break;
        }

        /* Verifier picks random challenge */
        uint64_t r_i = ip_tape_consume(tape, 32) % p;
        challenges[round] = r_i;

        /* Update H = q_i(r_i) */
        H = (c0 + (c1 * r_i) % p) % p;

        /* Update prover state with restriction */
        /* Already done inside sumcheck_prover_round? No, we need r_i */
        /* Re-do the restriction with r_i */
        size_t current_n = n - round;
        size_t half = 1ULL << (current_n - 1);
        uint64_t one_minus_r = (r_i == 0) ? 1 : (1 + p - r_i) % p;
        for (size_t b = 0; b < half; b++) {
            uint64_t term0 = (one_minus_r * prover.work_array[b]) % p;
            uint64_t term1 = (r_i * prover.work_array[half + b]) % p;
            prover.work_array[b] = (term0 + term1) % p;
        }
    }

    /* Final check: H_n == g(r_1,...,r_n).
     * After n restrictions, prover.work_array[0] = g(r_1,...,r_n).
     */
    if (ok) {
        uint64_t g_final = prover.work_array[0] % p;
        ok = (H == g_final);
    }

    *accepted = ok;
    free(challenges);
    sumcheck_prover_free(&prover);
    return 0;
}

/*======================================================================
 * Sumcheck soundness analysis (L4: Fundamental Laws)
 *
 * Theorem (Lund-Fortnow-Karloff-Nisan 1990, Shamir 1992):
 * The sumcheck protocol for a degree-d polynomial g in m variables
 * has soundness error at most m*d / |F|.
 *
 * For multilinear polynomials (d=1):
 *   soundness error <= n / |F|
 *
 * By choosing |F| >> n (e.g., |F| = 2^128), the soundness error
 * is negligible. In practice, using a prime field GF(p) with
 * p ~ 2^64 gives soundness error n/2^64 for n up to millions.
 *
 * For sequential repetition: soundness error <= (n/|F|)^k.
 *======================================================================*/

double ip_sumcheck_soundness_error(size_t n, uint64_t field_size,
                                    size_t repetitions) {
    double single_error = (double)n / (double)field_size;
    if (single_error >= 1.0) return 1.0;
    return pow(single_error, (double)repetitions);
}

/*======================================================================
 * Sumcheck with multiple polynomials (L8: GKR integration)
 *
 * The GKR protocol uses the sumcheck protocol on a product of
 * polynomials:
 *   sum_{x in {0,1}^n} A(x) * B(x) * C(x)
 *
 * where A, B, C are low-degree multilinear or low-degree non-
 * multilinear extensions. The degree of the product is the sum
 * of individual degrees.
 *======================================================================*/

/* Compute the pointwise product of two multilinear extensions.
 * out->evaluations[b] = A->evaluations[b] * B->evaluations[b] mod prime.
 */
int ip_multilinear_product(const IPMultilinearExtension *A,
                            const IPMultilinearExtension *B,
                            IPMultilinearExtension *out) {
    if (!A || !B || !out || A->num_vars != B->num_vars) return -1;
    if (A->prime != B->prime) return -1;

    size_t n = A->num_vars;
    size_t total = 1ULL << n;
    uint64_t p = A->prime;

    out->evaluations = (uint64_t *)malloc(total * sizeof(uint64_t));
    if (!out->evaluations) return -1;

    for (size_t i = 0; i < total; i++) {
        out->evaluations[i] = (A->evaluations[i] * B->evaluations[i]) % p;
    }
    out->num_vars = n;
    out->prime = p;
    out->is_valid = 1;
    return 0;
}

/* Reduce sumcheck soundness via parallel repetition.
 * L4: Parallel repetition theorem (Raz 1998) shows that parallel
 * repetition reduces soundness error exponentially for 2-prover
 * games. For single-prover sumcheck, sequential repetition suffices.
 */