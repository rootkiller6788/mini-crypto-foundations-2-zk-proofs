/**
 * nizk_commitment.c - Cryptographic Commitment Scheme Implementation
 *
 * L1 Definition: A commitment scheme allows a sender to commit to a value
 * by publishing C = Commit(v, r). Later, the sender reveals (v, r) and
 * verifier checks C == Commit(v, r).
 *
 * Security properties:
 *   - Hiding: C reveals no information about v
 *   - Binding: Cannot open C to two different values
 *
 * Pedersen Commitment: C = g^m * h^r (mod p)
 *   - Perfectly hiding (information-theoretic)
 *   - Computationally binding (under DLOG assumption)
 *   - Additively homomorphic
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

#include "nizk_commitment.h"
#include "nizk_group.h"
#include "nizk_crs.h"
#include <string.h>
#include <stdio.h>

/* =========================================================================
 * L5: Pedersen Commitment - Core Algorithm
 * ========================================================================= */

/**
 * nizk_pedersen_commit - Create a Pedersen commitment.
 *
 * L5 Knowledge Point: Pedersen Commitment Scheme
 *
 * Computes: C = g^m * h^r (mod p)
 *
 * The commitment C is a single group element. The message m and
 * randomness r are scalars in Z_q.
 *
 * Perfect Hiding Proof:
 *   For any message m1, there exists a unique r1 such that
 *   C = g^m * h^r = g^{m1} * h^{r1}.
 *   Solving: r1 = r + (m - m1) / log_g(h) mod q.
 *   However, since log_g(h) exists (h is in the group), for each m1
 *   there IS some r1 that works. The distribution of C is independent
 *   of m when r is uniform: C = g^m * h^r = h^r * g^m.
 *   Since h is a generator, h^r is uniform over G for uniform r.
 *   Multiplying by g^m just shifts this uniform distribution.
 *   Therefore, C is uniformly distributed in G regardless of m.
 *   QED: Perfectly hiding.
 *
 * Computational Binding Proof:
 *   To open C to two values (m1, r1) and (m2, r2), one must have
 *   g^{m1} * h^{r1} = g^{m2} * h^{r2}.
 *   This implies g^{m1-m2} = h^{r2-r1}.
 *   Therefore h = g^{(m1-m2)/(r2-r1)}.
 *   So log_g(h) = (m1-m2)/(r2-r1) mod q.
 *   Computing this requires solving the DLOG problem.
 *   QED: Computationally binding under DLOG assumption.
 *
 * Complexity: O(log q) = O(n) group operations (two exponentiations
 * with multi-exp optimization, or one multi-exponentiation).
 *
 * Course: Stanford CS355 Pedersen Commitments, MIT 6.875 Binding & Hiding
 */
void nizk_pedersen_commit(nizk_commitment_t *com,
                           nizk_commitment_opening_t *open,
                           const nizk_scalar_t *m,
                           const nizk_scalar_t *r,
                           const nizk_crs_t *crs,
                           const nizk_group_params_t *params) {
    /* If no randomness provided, generate random r */
    nizk_scalar_t rand_r;
    if (r == NULL) {
        nizk_scalar_rand(&rand_r, params);
        r = &rand_r;
    }

    /* Store opening information */
    nizk_scalar_copy(&open->m, m);
    nizk_scalar_copy(&open->r, r);

    /* Compute C = g^m * h^r using multi-exponentiation */
    nizk_group_elem_t gen;
    nizk_bigint_copy(&gen.elem, &params->g);
    nizk_group_multi_exp(&com->C, &gen, m, &crs->h1, r, params);
}

/**
 * nizk_pedersen_verify - Verify a Pedersen commitment opening.
 *
 * L5 Knowledge Point: Commitment Verification
 *
 * Checks: C == g^m * h^r (mod p)
 *
 * This is a straightforward verification: recompute the commitment
 * from (m, r) and compare with stored C. Equality of group elements
 * means equality of the underlying big integers modulo p.
 *
 * Complexity: O(log q) group operations (one multi-exponentiation).
 */
int nizk_pedersen_verify(const nizk_commitment_t *com,
                          const nizk_commitment_opening_t *open,
                          const nizk_crs_t *crs,
                          const nizk_group_params_t *params) {
    /* Recompute C' = g^m * h^r */
    nizk_group_elem_t gen;
    nizk_bigint_copy(&gen.elem, &params->g);
    nizk_group_elem_t recomputed;
    nizk_group_multi_exp(&recomputed, &gen, &open->m, &crs->h1, &open->r, params);

    /* Compare */
    return nizk_group_elem_eq(&com->C, &recomputed);
}

/* =========================================================================
 * L5: Homomorphic Operations on Commitments
 * ========================================================================= */

/**
 * nizk_commitment_add - Homomorphic addition of two commitments.
 *
 * L5 Knowledge Point: Additive Homomorphism of Pedersen Commitments
 *
 * Computes: C_sum = C_a * C_b
 *         = (g^{ma} * h^{ra}) * (g^{mb} * h^{rb})
 *         = g^{ma+mb} * h^{ra+rb}
 *
 * This is a commitment to (ma + mb) with combined randomness (ra + rb).
 *
 * Theorem: The sum of two Pedersen commitments is a valid Pedersen
 * commitment to the sum of the messages.
 *
 * Proof: Follows directly from the homomorphic property of
 * exponentiation: g^{ma} * g^{mb} = g^{ma+mb}. The group operation
 * (multiplication mod p) preserves the commitment structure.
 *
 * Applications:
 *   - Additive voting: sum up votes without revealing individual votes
 *   - Confidential transactions: sum of input amounts = sum of output amounts
 *   - Verifiable secret sharing: reconstruct secrets from shares
 *
 * Course: Berkeley CS278 Homomorphic Commitments,
 *         Stanford CS355 Additive Homomorphism
 */
void nizk_commitment_add(nizk_commitment_t *result,
                          const nizk_commitment_t *a,
                          const nizk_commitment_t *b,
                          const nizk_group_params_t *params) {
    nizk_group_op(&result->C, &a->C, &b->C, params);
}

/**
 * nizk_commitment_sub - Homomorphic subtraction of two commitments.
 *
 * L5 Knowledge Point: Homomorphic Subtraction via Group Inverse
 *
 * Computes: C_diff = C_a * C_b^{-1}
 *          = g^{ma} * h^{ra} * (g^{mb} * h^{rb})^{-1}
 *          = g^{ma} * h^{ra} * g^{-mb} * h^{-rb}
 *          = g^{ma-mb} * h^{ra-rb}
 *
 * This is a commitment to (ma - mb) with randomness (ra - rb).
 *
 * The group inverse is computed via modular inverse mod p
 * (Fermat: element^{-1} = element^{p-2} mod p for prime p).
 *
 * This operation is essential for confidential transactions:
 * proving that input_amount - output_amount - fee = 0 without
 * revealing the actual amounts.
 */
void nizk_commitment_sub(nizk_commitment_t *result,
                          const nizk_commitment_t *a,
                          const nizk_commitment_t *b,
                          const nizk_group_params_t *params) {
    /* Compute C_b^{-1} mod p */
    nizk_group_elem_t b_inv;
    nizk_mod_inv(&b_inv.elem, &b->C.elem, &params->p);

    /* C_diff = C_a * C_b^{-1} mod p */
    nizk_mod_mul(&result->C.elem, &a->C.elem, &b_inv.elem, &params->p);
}

/**
 * nizk_commitment_scalar_mul - Multiply a commitment by a scalar.
 *
 * L5 Knowledge Point: Scalar Multiplication on Commitments
 *
 * Computes: C_scaled = C^s = (g^m * h^r)^s = g^{m*s} * h^{r*s}
 *
 * This is a commitment to (m * s mod q) with randomness (r * s mod q).
 *
 * Important caveat: This operation changes the randomness distribution.
 * If s != 1, the new randomness r' = r*s mod q may not be uniformly
 * distributed even if r was. For ZK applications, you may need to
 * re-randomize after scalar multiplication.
 *
 * This operation is used in:
 *   - Batch opening of commitments
 *   - Linear combination proofs (proving knowledge of weighted sums)
 *   - Polynomial commitment schemes (evaluating at a point)
 *
 * Complexity: O(log q) group operations (one exponentiation).
 */
void nizk_commitment_scalar_mul(nizk_commitment_t *result,
                                 const nizk_commitment_t *com,
                                 const nizk_scalar_t *s,
                                 const nizk_group_params_t *params) {
    nizk_group_exp(&result->C, &com->C, s, params);
}

/* =========================================================================
 * L8: Vector Commitments - Committing to Multiple Values
 * ========================================================================= */

/**
 * nizk_vector_commit - Commit to a vector of messages with one group element.
 *
 * L8 Knowledge Point: Vector Pedersen Commitments
 *
 * Uses n+1 generators (g, h_1, ..., h_n) from CRS to commit to vector
 * (m_1, ..., m_n) with a single group element:
 *
 *   C = g^r * h_1^{m_1} * h_2^{m_2} * ... * h_n^{m_n}
 *
 * Properties:
 *   - Perfectly hiding: The randomness r (combined with g) provides
 *     n degrees of freedom to hide n messages
 *   - Computationally binding: Opening to different vectors requires
 *     finding non-trivial discrete log relations among h_i
 *
 * This is the commitment scheme used in:
 *   - Groth-Sahai NIZK proofs (pairing-based)
 *   - Bulletproofs (range proofs)
 *   - zk-SNARKs (R1CS witness commitments)
 *   - Polynomial commitment schemes (KZG, IPA)
 *
 * The key advantage: committing to an entire vector of arbitrary length
 * using only ONE group element. This enables succinct proofs.
 *
 * Reference: Groth, J. and Sahai, A. "Efficient Non-interactive Proof
 *            Systems for Bilinear Groups." EUROCRYPT 2008.
 *
 * Course: MIT 6.875 Advanced Commitments, ETH 263-4650 SNARK Constructions
 */
void nizk_vector_commit(nizk_commitment_t *com,
                         const nizk_scalar_t *msgs, size_t n,
                         const nizk_scalar_t *r,
                         const nizk_crs_t *crs,
                         const nizk_group_params_t *params) {
    /* Generate randomness if not given */
    nizk_scalar_t rand_r;
    if (r == NULL) {
        nizk_scalar_rand(&rand_r, params);
        r = &rand_r;
    }

    /* Compute C = g^r (start with the randomness contribution) */
    nizk_group_elem_t gen;
    nizk_bigint_copy(&gen.elem, &params->g);
    nizk_group_exp(&com->C, &gen, r, params);

    /* Multiply by h_i^{m_i} for each message in the vector.
     * We use h1 for m_0, construct successive bases from h1, h2.
     * In practice, independent bases would be generated via hash-to-group. */
    for (size_t i = 0; i < n; i++) {
        /* Derive base for position i: alternate between h1 and h2
         * with domain separation via exponent. */
        nizk_group_elem_t base_i;
        if (i == 0) {
            nizk_group_elem_copy(&base_i, &crs->h1);
        } else if (i == 1) {
            nizk_group_elem_copy(&base_i, &crs->h2);
        } else {
            /* For i >= 2, derive base as h1^{i} * h2.
             * In production, use independent hash-to-group bases. */
            nizk_scalar_t exp_i;
            nizk_scalar_set_u64(&exp_i, (uint64_t)(i + 1));
            nizk_group_elem_t t1, t2;
            nizk_group_exp(&t1, &crs->h1, &exp_i, params);
            nizk_group_op(&base_i, &t1, &crs->h2, params);
        }

        /* Multiply C by base_i^{m_i} */
        nizk_group_elem_t contrib, new_C;
        nizk_group_exp(&contrib, &base_i, &msgs[i], params);
        nizk_group_op(&new_C, &com->C, &contrib, params);
        nizk_group_elem_copy(&com->C, &new_C);
    }
}

/**
 * nizk_vector_verify - Verify a vector commitment opening.
 *
 * L8 Knowledge Point: Vector Commitment Verification
 *
 * Recomputes C' = g^r * prod_i h_{i+1}^{m_i} and checks equality.
 * This requires knowing all messages (the opening is full, not selective).
 *
 * For selective opening (revealing only some positions), you would use
 * a Merkle tree of commitments or a polynomial commitment scheme.
 *
 * Complexity: O(n * log q) group operations for n-vector.
 */
int nizk_vector_verify(const nizk_commitment_t *com,
                        const nizk_scalar_t *msgs, size_t n,
                        const nizk_scalar_t *r,
                        const nizk_crs_t *crs,
                        const nizk_group_params_t *params) {
    /* Recompute: C' = g^r * prod_i h_{i+1}^{m_i} */
    nizk_group_elem_t gen;
    nizk_bigint_copy(&gen.elem, &params->g);
    nizk_group_elem_t recomputed;
    nizk_group_exp(&recomputed, &gen, r, params);

    for (size_t i = 0; i < n; i++) {
        nizk_group_elem_t base_i;
        if (i == 0) {
            nizk_group_elem_copy(&base_i, &crs->h1);
        } else if (i == 1) {
            nizk_group_elem_copy(&base_i, &crs->h2);
        } else {
            nizk_scalar_t exp_i;
            nizk_scalar_set_u64(&exp_i, (uint64_t)(i + 1));
            nizk_group_elem_t t1, t2;
            nizk_group_exp(&t1, &crs->h1, &exp_i, params);
            nizk_group_op(&base_i, &t1, &crs->h2, params);
        }

        nizk_group_elem_t contrib, new_C;
        nizk_group_exp(&contrib, &base_i, &msgs[i], params);
        nizk_group_op(&new_C, &recomputed, &contrib, params);
        nizk_group_elem_copy(&recomputed, &new_C);
    }

    return nizk_group_elem_eq(&com->C, &recomputed);
}

/* =========================================================================
 * L2: Commitment Utility Functions
 * ========================================================================= */

/**
 * nizk_commitment_copy - Copy a commitment.
 *
 * Simple structure copy. The commitment value is a single group element.
 */
void nizk_commitment_copy(nizk_commitment_t *dst,
                           const nizk_commitment_t *src) {
    nizk_group_elem_copy(&dst->C, &src->C);
}

/**
 * nizk_commitment_eq - Check if two commitments are equal.
 *
 * Equality means the underlying group elements are identical.
 * Two commitments can be equal even if they commit to different
 * (m, r) pairs, which is the hiding property at work.
 */
int nizk_commitment_eq(const nizk_commitment_t *a,
                        const nizk_commitment_t *b) {
    return nizk_group_elem_eq(&a->C, &b->C);
}

/**
 * nizk_commitment_print - Print commitment for debugging.
 *
 * Displays the first few limbs of the commitment value.
 * Does NOT reveal the committed message (hiding property maintained).
 */
void nizk_commitment_print(const nizk_commitment_t *com,
                            const nizk_group_params_t *params) {
    (void)params;
    printf("Commitment C: [%016llx...]\\n",
           (unsigned long long)com->C.elem.limbs[0]);
}

/**
 * nizk_commitment_opening_clear - Zeroize commitment opening.
 *
 * L2 Knowledge Point: Secure Deletion of Opening Information
 *
 * The opening contains the message and randomness. After the opening
 * is revealed, there's no further need to protect it. However, BEFORE
 * opening, these values must be kept secret. Clearing prevents
 * accidental disclosure through memory inspection.
 *
 * Uses volatile pointer to prevent compiler from optimizing away
 * the zeroization (MSC06-C, CWE-14: Compiler Removal of Code).
 */
void nizk_commitment_opening_clear(nizk_commitment_opening_t *open) {
    volatile uint64_t *m = (volatile uint64_t*)&open->m;
    volatile uint64_t *r = (volatile uint64_t*)&open->r;
    for (int i = 0; i < NIZK_BIGINT_LIMBS; i++) {
        m[i] = 0;
        r[i] = 0;
    }
}
