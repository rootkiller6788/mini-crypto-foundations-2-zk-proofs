/*======================================================================
 * ip_polynomial_commitment.c -- Polynomial Commitment Schemes
 *
 * Implements a simplified polynomial commitment scheme based on
 * the KZG (Kate-Zaverucha-Goldberg 2010) construction. Polynomial
 * commitments allow a prover to commit to a polynomial and later
 * open it at any point, with the verifier checking correctness.
 *
 * Knowledge mapping:
 *   L1: Polynomial commitment definition -- commit, open, verify
 *   L2: binding (can't open to different value), hiding (reveals nothing)
 *   L3: bilinear pairings algebra, polynomial division
 *   L4: KZG security reduction to d-Strong Diffie-Hellman assumption
 *   L5: commitment via SRS, opening via quotient polynomial
 *   L7: ZK-SNARKs, blockchain verifiable computation (ZK-rollups)
 *   L8: batch opening, multi-point evaluation proofs
 *
 * Simplified implementation uses modular arithmetic over a
 * prime field without pairings. The full KZG requires elliptic
 * curve groups with bilinear pairings.
 *
 * Core identity:
 *   To prove P(z) = y, the prover computes:
 *     Q(X) = (P(X) - y) / (X - z)
 *   and sends commitment to Q.
 *   Verifier checks: e(com(P) - com(y), g) = e(com(Q), com(X-z))
 *
 * Reference:
 *   Kate, Zaverucha, Goldberg. "Constant-size commitments to
 *   polynomials and their applications." ASIACRYPT 2010.
 *======================================================================*/

#include "ip_system.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*======================================================================
 * Simplified KZG Commitment (L2: Core Concepts)
 *
 * In the real KZG, commitments are elliptic curve points:
 *   com(P) = P(s) * G  where s is secret and G is generator.
 *
 * Here we simulate this with modular arithmetic, providing
 * the algebraic structure without elliptic curves.
 *======================================================================*/

/* Structured Reference String (SRS): the public parameters.
 *
 * Real SRS: {s^i * G}_{i=0}^d (powers of secret s in group G)
 * Here: powers of a secret value s modulo prime.
 */
typedef struct {
    uint64_t *powers;     /* s^i mod p for i = 0,...,max_degree */
    size_t    max_degree;
    uint64_t  prime;
    uint64_t  secret;     /* SHOULD be discarded after setup! */
} PCCommitmentKey;

typedef struct {
    uint64_t *powers;     /* Powers in the verification group */
    size_t    max_degree;
    uint64_t  prime;
} PCVerificationKey;

/* Commitment: a single field element (simulates group element) */
typedef uint64_t PCCommitment;

/* Opening proof: quotient polynomial commitment */
typedef struct {
    PCCommitment quotient_commit;
    uint64_t      z;          /* Evaluation point */
    uint64_t      y;          /* Claimed value P(z) = y */
} PCOpeningProof;

/* Initialize SRS via a trusted setup.
 * In real KZG, this is a multi-party computation (MPC) ceremony.
 * Here we use a simple PRNG-based setup for demonstration.
 */
int pc_setup(PCCommitmentKey *ck, PCVerificationKey *vk,
              size_t max_degree, uint64_t prime, uint64_t secret) {
    if (!ck || !vk || max_degree == 0) return -1;

    ck->powers = (uint64_t *)calloc(max_degree + 1, sizeof(uint64_t));
    vk->powers = (uint64_t *)calloc(max_degree + 1, sizeof(uint64_t));
    if (!ck->powers || !vk->powers) {
        free(ck->powers); free(vk->powers);
        return -1;
    }

    ck->powers[0] = 1;
    vk->powers[0] = 1;
    for (size_t i = 1; i <= max_degree; i++) {
        ck->powers[i] = (ck->powers[i-1] * secret) % prime;
        vk->powers[i] = ck->powers[i]; /* Same group (simplified) */
    }
    ck->max_degree = max_degree;
    ck->prime = prime;
    ck->secret = secret;
    vk->max_degree = max_degree;
    vk->prime = prime;
    return 0;
}

void pc_setup_free(PCCommitmentKey *ck, PCVerificationKey *vk) {
    if (ck) {
        if (ck->powers) free(ck->powers);
        ck->powers = NULL;
    }
    if (vk) {
        if (vk->powers) free(vk->powers);
        vk->powers = NULL;
    }
}

/* Commit to a polynomial P(X) = sum_{i=0}^d c_i * X^i.
 *
 * com(P) = sum_{i=0}^d c_i * s^i  (mod prime)
 *
 * In real KZG, this is sum_i c_i * (s^i * G) in an elliptic curve.
 */
int pc_commit(const PCCommitmentKey *ck, const IPPolynomial *poly,
               PCCommitment *commitment) {
    if (!ck || !poly || !commitment || poly->degree > ck->max_degree)
        return -1;

    uint64_t p = ck->prime;
    uint64_t result = 0;
    for (size_t i = 0; i <= poly->degree; i++) {
        uint64_t term = (poly->coeffs[i] * ck->powers[i]) % p;
        result = (result + term) % p;
    }
    *commitment = result;
    return 0;
}

/* Create opening proof: prove P(z) = y.
 *
 * Compute quotient polynomial:
 *   Q(X) = (P(X) - y) / (X - z)
 *
 * Polynomial long division: P(X) - y divided by X - z.
 *
 * For P(X) = sum c_i X^i:
 *   Q_{d-1} = c_d
 *   Q_i = c_{i+1} + z * Q_{i+1}  for i = d-2,...,0
 *   Remainder r = c_0 + z * Q_0 - y
 *
 * If remainder r = 0, then P(z) = y is verified.
 */
int pc_open(const PCCommitmentKey *ck, const IPPolynomial *poly,
             uint64_t z, PCOpeningProof *proof) {
    if (!ck || !poly || !proof) return -1;

    size_t d = poly->degree;
    if (d == 0) return -1; /* Need degree >= 1 */

    /* Compute P(z) */
    uint64_t pz = ip_polynomial_eval((IPPolynomial *)poly, z);

    /* Compute quotient Q(X) = (P(X) - pz) / (X - z)
     * Horner-like division:
     * q_{d-1} = c_d
     * For i = d-2 down to 0: q_i = c_{i+1} + z * q_{i+1}
     * remainder = c_0 + z*q_0 - pz (should be 0)
     *
     * Correct polynomial division:
     * Let P'(X) = P(X) - pz = sum_{i=0}^d c_i X^i - pz
     *              = (c_0 - pz) + c_1 X + ... + c_d X^d
     * Divide P'(X) by (X - z):
     *
     * Synthetic division:
     * Init: q_{d-1} = c_d
     * For j = d-1 to 1: q_{j-1} = c_j + z * q_j
     * remainder = c_0 + z * q_0
     *
     * But we need the remainder to equal pz, so:
     * remainder = c_0 + z*q_0
     * For P(z) to equal something, (c_0-pz) + z*q_0 = 0 => q_0 = (pz-c_0)*z^{-1}
     *
     * Actually: P(z) = c_0 + z(c_1 + z(c_2 + ... + z*c_d)...)
     * = c_0 + z*q_0 where q_i = c_{i+1} + z*q_{i+1}
     */
    uint64_t p = poly->prime;
    uint64_t *q_coeffs = (uint64_t *)calloc(d, sizeof(uint64_t));
    if (!q_coeffs) return -1;

    /* Synthetic division */
    q_coeffs[d-1] = poly->coeffs[d] % p;
    for (int64_t i = (int64_t)d - 2; i >= 0; i--) {
        q_coeffs[i] = ((poly->coeffs[i+1] % p)
                      + (z * q_coeffs[i+1]) % p) % p;
    }
    /* remainder = (c_0 - pz) + z * q_0 */
    uint64_t remainder = (((poly->coeffs[0] % p) + p - (pz % p)) % p
                         + (z * q_coeffs[0]) % p) % p;

    /* If remainder != 0, P(z) != pz (consistency check) */
    if (remainder != 0) {
        free(q_coeffs);
        return -1;
    }

    /* Commit to Q(X) */
    IPPolynomial q_poly;
    if (ip_polynomial_init(&q_poly, q_coeffs, d - 1, p) != 0) {
        free(q_coeffs);
        return -1;
    }

    pc_commit(ck, &q_poly, &proof->quotient_commit);
    proof->z = z;
    proof->y = pz;

    ip_polynomial_free(&q_poly);
    free(q_coeffs);
    return 0;
}

/* Verify opening proof.
 *
 * The verifier checks:
 *   com(P) - y * com(1) == z * com(Q)?
 *
 * Actually: com(P) - y (as commitment to constant) = (s - z) * com(Q)?
 * In our field-only simulation:
 *   com(P) - y = (s - z) * com(Q) mod p
 *
 * But s is secret! The real verification uses pairings:
 *   e(com(P) - y*G, H) = e(com(Q), s*H - z*H)
 *
 * We simulate by verifying:
 *   com(P) - y == (s - z) * com(Q)  (mod p)
 * where s is available to the verifier (only in simulation!).
 */
int pc_verify(const PCVerificationKey *vk, PCCommitment com_P,
               const PCOpeningProof *proof) {
    if (!vk || !proof) return 0;

    uint64_t p = vk->prime;

    /* Verify: (com_P - y) == (s - z) * com_Q  mod p
     * But s is secret in real KZG!
     * In this simplified simulation, vk stores s^1 = vk->powers[1].
     */
    uint64_t s = vk->powers[1];
    uint64_t lhs = (com_P + p - (proof->y % p)) % p;
    uint64_t s_minus_z = (s + p - (proof->z % p)) % p;
    uint64_t rhs = (s_minus_z * proof->quotient_commit) % p;

    return (lhs == rhs) ? 1 : 0;
}

/*======================================================================
 * Batch opening (L8: Advanced Topics)
 *
 * A prover can open a polynomial at multiple points efficiently
 * using a single combined proof. Given points z_1,...,z_k and
 * values y_1,...,y_k, the prover computes:
 *
 *   h(X) = sum_{i=1}^k gamma_i * (P(X) - y_i) / (X - z_i)
 *
 * where gamma_i are random scalars chosen by the verifier.
 *
 * The quotient polynomial for batch verification is:
 *   Q_batch(X) = h(X) / prod_i (X - z_i)
 *======================================================================*/

/* Batch open: prove P(z_i) = y_i for multiple points.
 *
 * Uses random linear combination to combine multiple openings
 * into a single quotient polynomial.
 */
int pc_batch_open(const PCCommitmentKey *ck, const IPPolynomial *poly,
                   const uint64_t *zs, const uint64_t *ys,
                   size_t num_points, const uint64_t *challenge_scalars,
                   PCCommitment *batch_commit) {
    if (!ck || !poly || !zs || !ys || !challenge_scalars || !batch_commit)
        return -1;
    if (num_points == 0) return -1;

    uint64_t p = poly->prime;
    size_t d = poly->degree;

    /* Compute the combined polynomial:
     *   h(X) = sum_i gamma_i * (P(X) - y_i) / (X - z_i)
     *
     * Each term (P(X) - y_i) / (X - z_i) is a polynomial of degree d-1.
     * We compute each quotient and accumulate the linear combination.
     */

    uint64_t *h_coeffs = (uint64_t *)calloc(d, sizeof(uint64_t));
    if (!h_coeffs) return -1;

    for (size_t pt = 0; pt < num_points; pt++) {
        /* Compute Q_i(X) = (P(X) - y_i) / (X - z_i) */
        uint64_t *qi_coeffs = (uint64_t *)calloc(d, sizeof(uint64_t));
        if (!qi_coeffs) { free(h_coeffs); return -1; }

        qi_coeffs[d-1] = poly->coeffs[d] % p;
        for (int64_t j = (int64_t)d - 2; j >= 0; j--) {
            qi_coeffs[j] = ((poly->coeffs[j+1] % p)
                           + (zs[pt] * qi_coeffs[j+1]) % p) % p;
        }

        /* Accumulate: h_coeffs[j] += gamma_i * qi_coeffs[j] */
        uint64_t gamma = challenge_scalars[pt] % p;
        for (size_t j = 0; j < d; j++) {
            h_coeffs[j] = (h_coeffs[j] + (gamma * qi_coeffs[j]) % p) % p;
        }
        free(qi_coeffs);
    }

    /* Now commit to h(X) = sum gamma_i * Q_i(X).
     * In real KZG, we also need to divide by prod (X - z_i) for the
     * batched verification formula. Here we commit to h directly.
     */
    IPPolynomial h_poly;
    if (ip_polynomial_init(&h_poly, h_coeffs, d - 1, p) != 0) {
        free(h_coeffs);
        return -1;
    }

    pc_commit(ck, &h_poly, batch_commit);

    ip_polynomial_free(&h_poly);
    free(h_coeffs);
    return 0;
}

/*======================================================================
 * Polynomial commitment for sumcheck integration (L7: Applications)
 *
 * In the GKR protocol with polynomial commitments, the prover
 * commits to the multilinear extensions V_i of each layer.
 * The verifier can check evaluations without the prover sending
 * the full layer description.
 *
 * This is a key technique in practical ZK-rollup systems
 * (e.g., zkSync, StarkWare) where polynomial commitments
 * reduce proof size and verification cost.
 *======================================================================*/

/* Commit to a multilinear extension as a dense polynomial.
 *
 * Since a multilinear polynomial over n variables has degree n
 * (total degree, not individual), we can represent it as a
 * dense polynomial in 2^n coefficients and commit using KZG.
 *
 * In practice, multilinear commitments use schemes like
 * HyperKZG or FRI-based commitments that are more efficient.
 */
int pc_commit_multilinear(const PCCommitmentKey *ck,
                           const IPMultilinearExtension *mex,
                           PCCommitment *commitment) {
    if (!ck || !mex || !commitment) return -1;

    /* Represent multilinear extension as dense polynomial.
     * For n variables, the dense representation has 2^n coefficients.
     * The coefficient for monomial x_1^{b_1}...x_n^{b_n} is the
     * evaluation f_tilde(b_1,...,b_n) * (-1)^{sum(b_i)} via
     * Möbius inversion.
     *
     * For simplicity, we commit to the evaluation table directly
     * as if it were coefficient form (which works for commitment
     * but not for evaluation proofs without transformation).
     */
    size_t n = mex->num_vars;
    size_t total = 1ULL << n;

    IPPolynomial poly;
    if (ip_polynomial_init(&poly, mex->evaluations, total - 1,
                            ck->prime) != 0) {
        return -1;
    }

    int ret = pc_commit(ck, &poly, commitment);
    ip_polynomial_free(&poly);
    return ret;
}

/*======================================================================
 * Security analysis for polynomial commitments (L4: Fundamental Laws)
 *
 * KZG security relies on the d-Strong Diffie-Hellman (d-SDH)
 * assumption in bilinear groups:
 *   Given (G, s*G, s^2*G, ..., s^d*G),
 *   it is hard to compute (c, c/(s-z)*G) for any z.
 *
 * Binding property: A computationally bounded prover cannot
 *   produce a proof that P(z) = y and P(z) = y' with y != y'.
 *
 * Hiding property: The commitment com(P) reveals no information
 *   about P beyond what can be extracted from evaluations.
 *
 * In our simplified field-based simulation, these properties
 * do not hold cryptographically but illustrate the algebraic
 * structure.
 *======================================================================*/

/* Simulate the d-SDH game: given s^i for i=0..d, try to find
 * a valid (c, proof) pair without knowing the polynomial.
 * In our simulation, this is always possible (since s is public
 * in the verification key), making it instructive but not secure.
 */
int pc_security_check(const PCVerificationKey *vk,
                       PCCommitment com_P, uint64_t z,
                       PCOpeningProof *fake_proof) {
    /* In a real implementation with hidden s, this would be infeasible.
     * Here we demonstrate the structure of a forgery attempt. */
    if (!vk) return -1;

    /* Can fake a proof when s is known.
     * For any (z, y), compute Q = (com_P - y) / (s - z) mod p */
    uint64_t p = vk->prime;
    uint64_t s = vk->powers[1];
    uint64_t s_minus_z = (s + p - (z % p)) % p;
    if (s_minus_z == 0) return -1; /* Cannot open at s */

    /* Choose arbitrary y */
    uint64_t y = 42 % p;
    uint64_t q = ((com_P + p - y) % p);

    /* Find modular inverse of (s - z) */
    uint64_t inv = 1;
    for (uint64_t k = 1; k < p; k++) {
        if ((s_minus_z * k) % p == 1) { inv = k; break; }
    }

    fake_proof->quotient_commit = (q * inv) % p;
    fake_proof->z = z;
    fake_proof->y = y;
    return 0;
}