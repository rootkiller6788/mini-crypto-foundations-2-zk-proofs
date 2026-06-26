/**
 * nizk_commitment.h ！ Cryptographic Commitment Schemes
 *
 * L1 Definition: A commitment scheme allows a sender to commit to a value v
 * by publishing a commitment C = Commit(v, r) where r is random. Later, the
 * sender can open the commitment by revealing (v, r). The verifier checks
 * C == Commit(v, r).
 *
 * Properties:
 *   - Hiding: C reveals no information about v (computationally or perfectly)
 *   - Binding: The sender cannot open C to two different values
 *
 * Pedersen Commitment Scheme:
 *   Setup: Group G of prime order q with generators g, h where log_g(h) unknown
 *   Commit(m, r): C = g^m * h^r  (mod p)
 *   Verify(C, m, r): Check C == g^m * h^r
 *
 * Properties of Pedersen:
 *   - Perfectly hiding: For any m, there exists r' such that C = g^m * h^r'
 *     (because h is a generator, h^r covers all group elements)
 *   - Computationally binding: Opening to two values requires computing log_g(h),
 *     which is the discrete log problem
 *
 * Homomorphic property: Pedersen commitments are additively homomorphic:
 *   Commit(m1, r1) * Commit(m2, r2) = g^{m1+m2} * h^{r1+r2} = Commit(m1+m2, r1+r2)
 *
 * Reference: Pedersen, T.P. "Non-Interactive and Information-Theoretic
 *            Secure Verifiable Secret Sharing." CRYPTO 1991.
 *
 * Course Mapping:
 *   Stanford CS355: Commitment schemes
 *   MIT 6.875: Cryptographic commitments
 *   Princeton COS 551: Pedersen commitments in NIZK
 *   Berkeley CS278: Homomorphic commitments
 */

#ifndef NIZK_COMMITMENT_H
#define NIZK_COMMITMENT_H

#include "nizk_group.h"
#include "nizk_crs.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------------
 * L1: Commitment Data Structures
 * ------------------------------------------------------------------------- */

/**
 * nizk_commitment ！ A Pedersen commitment value.
 *
 * The commitment is a single group element C = g^m * h^r.
 * The message m and randomness r are scalars in Z_q.
 */
typedef struct {
    nizk_group_elem_t C;  /* commitment value (group element) */
} nizk_commitment_t;

/**
 * nizk_commitment_opening ！ The opening information for a commitment.
 *
 * Contains the message and randomness used to create the commitment.
 * This must be kept secret until opening time (for the message).
 */
typedef struct {
    nizk_scalar_t m;  /* committed message (scalar in Z_q) */
    nizk_scalar_t r;  /* randomness / blinding factor */
} nizk_commitment_opening_t;

/* ---------------------------------------------------------------------------
 * L1: Pedersen Commitment ！ Core Algorithm
 * ------------------------------------------------------------------------- */

/**
 * nizk_pedersen_commit ！ Create a Pedersen commitment to message m.
 *
 * Computes: C = g^m * h^r
 *
 * Parameters:
 *   com    ！ output commitment
 *   open   ！ output opening (message + randomness)
 *   m      ！ message to commit to (scalar in Z_q)
 *   r      ！ randomness; if NULL, random r is generated
 *   crs    ！ CRS providing generators g, h
 *   params ！ group parameters
 *
 * Complexity: O(log q) group operations (one multi-exp)
 */
void nizk_pedersen_commit(nizk_commitment_t *com,
                           nizk_commitment_opening_t *open,
                           const nizk_scalar_t *m,
                           const nizk_scalar_t *r,
                           const nizk_crs_t *crs,
                           const nizk_group_params_t *params);

/**
 * nizk_pedersen_verify ！ Verify a Pedersen commitment opening.
 *
 * Checks: C == g^m * h^r
 *
 * Returns 1 if valid, 0 otherwise.
 */
int  nizk_pedersen_verify(const nizk_commitment_t *com,
                           const nizk_commitment_opening_t *open,
                           const nizk_crs_t *crs,
                           const nizk_group_params_t *params);

/* ---------------------------------------------------------------------------
 * L5: Homomorphic Operations on Commitments
 * ------------------------------------------------------------------------- */

/**
 * nizk_commitment_add ！ Homomorphic addition of two commitments.
 *
 * Computes: C_sum = C_a * C_b = g^{ma+mb} * h^{ra+rb}
 * This is a commitment to (ma + mb) with randomness (ra + rb).
 *
 * Theorem: The sum of two Pedersen commitments is a valid Pedersen
 * commitment to the sum of the messages.
 */
void nizk_commitment_add(nizk_commitment_t *result,
                          const nizk_commitment_t *a,
                          const nizk_commitment_t *b,
                          const nizk_group_params_t *params);

/**
 * nizk_commitment_sub ！ Homomorphic subtraction of two commitments.
 *
 * Computes: C_diff = C_a * C_b^{-1} = g^{ma-mb} * h^{ra-rb}
 * This is a commitment to (ma - mb) with randomness (ra - rb).
 */
void nizk_commitment_sub(nizk_commitment_t *result,
                          const nizk_commitment_t *a,
                          const nizk_commitment_t *b,
                          const nizk_group_params_t *params);

/**
 * nizk_commitment_scalar_mul ！ Multiply commitment by scalar.
 *
 * Computes: C_scaled = C^s = g^{m*s} * h^{r*s}
 * This is a commitment to (m * s) with randomness (r * s).
 *
 * Note: This operation does NOT preserve perfect hiding in the same way
 * because the scalar multiplication changes the distribution.
 */
void nizk_commitment_scalar_mul(nizk_commitment_t *result,
                                 const nizk_commitment_t *com,
                                 const nizk_scalar_t *s,
                                 const nizk_group_params_t *params);

/* ---------------------------------------------------------------------------
 * L5: Advanced Commitment Operations
 * ------------------------------------------------------------------------- */

/**
 * nizk_vector_commit ！ Commit to a vector of messages with a single value.
 *
 * Uses multiple generators h_1, ..., h_n from the CRS.
 * Computes: C = g^r * prod_{i=1}^{n} h_i^{m_i}
 *
 * This is a generalized Pedersen commitment to n values with a single
 * group element. The randomness r ensures hiding.
 *
 * Parameters:
 *   com    ！ output commitment
 *   msgs   ！ array of n message scalars
 *   n      ！ number of messages in the vector
 *   r      ！ randomness (if NULL, random r is generated)
 *   crs    ！ CRS with h1, h2, ... bases
 *   params ！ group parameters
 *
 * L8 Application: Vector commitments are used in zk-SNARK constructions
 * for committing to witness vectors in R1CS satisfiability proofs.
 */
void nizk_vector_commit(nizk_commitment_t *com,
                         const nizk_scalar_t *msgs, size_t n,
                         const nizk_scalar_t *r,
                         const nizk_crs_t *crs,
                         const nizk_group_params_t *params);

/**
 * nizk_vector_verify ！ Verify a vector commitment opening.
 *
 * Checks: C == g^r * prod_{i=1}^{n} h_{i+1}^{m_i}
 * where h_1 = g of the CRS, h_2 = crs->h1, h_3 = crs->h2, etc.
 */
int  nizk_vector_verify(const nizk_commitment_t *com,
                         const nizk_scalar_t *msgs, size_t n,
                         const nizk_scalar_t *r,
                         const nizk_crs_t *crs,
                         const nizk_group_params_t *params);

/* ---------------------------------------------------------------------------
 * L2: Commitment Utilities
 * ------------------------------------------------------------------------- */

/** Copy a commitment. */
void nizk_commitment_copy(nizk_commitment_t *dst,
                           const nizk_commitment_t *src);

/** Check if two commitments are equal. */
int  nizk_commitment_eq(const nizk_commitment_t *a,
                         const nizk_commitment_t *b);

/** Print commitment for debugging. */
void nizk_commitment_print(const nizk_commitment_t *com,
                            const nizk_group_params_t *params);

/** Clear commitment opening (zeroize secret data). */
void nizk_commitment_opening_clear(nizk_commitment_opening_t *open);

#ifdef __cplusplus
}
#endif

#endif /* NIZK_COMMITMENT_H */
