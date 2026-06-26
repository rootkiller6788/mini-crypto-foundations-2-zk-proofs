/*
 * pairing.h — Bilinear Pairings for Pairing-Based KEA
 *
 * L1 Definitions:
 *   - Bilinear pairing: e: G1 x G2 -> GT such that:
 *     e(aP, bQ) = e(P, Q)^{ab} for all a, b in Z, P in G1, Q in G2
 *   - Non-degenerate: e(P, Q) != 1 for generators P, Q
 *   - Computable: e() is efficiently computable
 *
 *   - Type 1 (symmetric): G1 = G2
 *   - Type 2: G1 != G2, efficiently computable homomorphism G2 -> G1
 *   - Type 3 (asymmetric): G1 != G2, no efficient homomorphism
 *
 * L2 Core Concepts:
 *   - Pairing-friendly curve: BN, BLS12, BLS24, KSS families
 *   - Miller's algorithm: computes the Weil/Tate pairing
 *   - Final exponentiation: raises to (p^k-1)/r for Tate pairing
 *   - Pairing-based SNARKs use KEA in bilinear groups (KEA3)
 *
 * L3 Mathematical Structures:
 *   - G1: base field group (e.g., E(F_p)[r])
 *   - G2: extension field group (e.g., E(F_{p^k})[r])
 *   - GT: target group (multiplicative subgroup of F_{p^k}*)
 *   - Miller function: f_{n,P} with divisor n(P) - ([n]P) - (n-1)(O)
 *
 * This module provides a simplified/simulated bilinear pairing
 * for pedagogical purposes. Real pairings require elliptic curves
 * and extension field arithmetic.
 *
 * References:
 *   - Menezes, Okamoto, Vanstone (1993) — Weil pairing, MOV attack
 *   - Boneh & Franklin (2001) — Identity-based encryption with pairings
 *   - Barreto & Naehrig (2005) — BN curves, pairing-friendly
 *   - Costello (2012) "Pairings for Beginners"
 *
 * Courses: Stanford CS255 (Cryptography), EPFL COM-401 (Cryptography & Security)
 */

#ifndef KEA_PAIRING_H
#define KEA_PAIRING_H

#include "group.h"
#include <stdlib.h>
#include <stdint.h>

/* ── Pairing Group Types ──────────────────────────────────── */

/*
 * A simplified pairing group structure.
 * In real systems: G1, G2 are elliptic curve groups; GT is a finite field.
 * Here we use the multiplicative group Z_p* for all three,
 * and simulate the pairing via a bilinear map.
 */
typedef enum {
    PAIRING_TYPE_SYMMETRIC = 1,
    PAIRING_TYPE_ASYM_BN   = 2,
    PAIRING_TYPE_ASYM_BLS12 = 3,
    PAIRING_TYPE_SIMULATED  = 4
} PairingType;

/*
 * Bilinear pairing parameters.
 * For simulation: e(g1^a, g2^b) = gt^{a*b}
 */
typedef struct {
    PairingType type;
    CyclicGroup* G1;    /* Source group 1 */
    CyclicGroup* G2;    /* Source group 2 (same as G1 for symmetric) */
    CyclicGroup* GT;    /* Target group */
    /* Generators */
    GroupElement* g1;  /* Generator of G1 */
    GroupElement* g2;  /* Generator of G2 */
    GroupElement* gt;  /* Generator of GT */
    /* Group orders (all equal for prime-order pairing groups) */
    uint64_t     r;    /* Prime order of all three groups */
    char*        name; /* e.g., "BN256", "BLS12-381" */
} BilinearPairing;

/* ── Pairing Result ──────────────────────────────────────── */

/*
 * The result of a pairing computation: e(P, Q) in GT.
 */
typedef struct {
    GroupElement*    result;   /* element in GT */
    BilinearPairing* pairing;  /* the pairing used */
} PairingResult;

/* ── Pairing Construction ─────────────────────────────────── */

/* Create a simulated bilinear pairing for testing/education */
BilinearPairing* pairing_create_simulated(void);

/* Create a pairing with explicit groups */
BilinearPairing* pairing_create(PairingType type,
                                 CyclicGroup* G1, CyclicGroup* G2, CyclicGroup* GT,
                                 GroupElement* g1, GroupElement* g2, GroupElement* gt);

/* Free pairing structure */
void pairing_free(BilinearPairing* bp);

/* ── Pairing Computation ──────────────────────────────────── */

/*
 * Compute e(P, Q).
 * For simulated pairing: output = gt^{dlog(P) * dlog(Q) mod r}
 *
 * L5: In real systems this calls Miller's algorithm.
 * Complexity: O(log r) group operations, using Miller loop + final exp.
 *
 * Reference: Miller (1986) "Short Programs for Functions on Curves"
 */
PairingResult* pairing_compute(const BilinearPairing* bp,
                                const GroupElement* P, const GroupElement* Q);

/*
 * Compute e(P, Q) for symmetric pairings (G1 = G2).
 */
PairingResult* pairing_compute_symmetric(const BilinearPairing* bp,
                                          const GroupElement* P, const GroupElement* Q);

/*
 * Product pairing: e(P1, Q1) * e(P2, Q2) * ... * e(Pn, Qn)
 * More efficient than computing individually and multiplying
 * (using the distributive property of pairings).
 *
 * e(P1, Q1) * e(P2, Q2) = e(P1, Q1) * e(P2, Q2)
 *
 * L5: Used in Groth16 verification for batch pairing checks.
 * Complexity: O(n * log r) using optimal ate pairing.
 */
PairingResult* pairing_product(const BilinearPairing* bp,
                                const GroupElement** Ps,
                                const GroupElement** Qs,
                                int n);

/* ── Pairing Verification ─────────────────────────────────── */

/*
 * Verify a pairing equation of the form:
 *   e(A, B) = e(C, D)
 *
 * Returns 1 if equality holds, 0 otherwise.
 */
int pairing_verify_equation(const BilinearPairing* bp,
                             const GroupElement* A, const GroupElement* B,
                             const GroupElement* C, const GroupElement* D);

/*
 * Verify a multi-pairing equation:
 *   Prod e(A_i, B_i) = Prod e(C_i, D_i)
 *
 * Used in Groth16 verification (single pairing check instead of 4).
 */
int pairing_verify_multi_equation(const BilinearPairing* bp,
                                   const GroupElement** As,
                                   const GroupElement** Bs,
                                   const GroupElement** Cs,
                                   const GroupElement** Ds,
                                   int n_pairs);

/* ── Pairing Properties ───────────────────────────────────── */

/*
 * Verify bilinearity:
 *   e(a*P, b*Q) = e(P, Q)^{ab}
 *
 * Returns 1 if the property holds for the given random exponents.
 */
int pairing_check_bilinearity(const BilinearPairing* bp,
                               const GroupElement* P, const GroupElement* Q);

/*
 * Verify non-degeneracy:
 *   e(P, Q) != 1 for generators P, Q
 */
int pairing_check_nondegenerate(const BilinearPairing* bp);

/*
 * Run self-test: check bilinearity, non-degeneracy, symmetry if applicable.
 */
int pairing_self_test(const BilinearPairing* bp);

/* ── Pairing Result Operations ────────────────────────────── */

PairingResult* pr_create(GroupElement* result, BilinearPairing* bp);
void pr_free(PairingResult* pr);
int pr_equal(const PairingResult* a, const PairingResult* b);
void pr_print(const PairingResult* pr, const char* label);

/* ── Miller's Algorithm (Simplified) ──────────────────────── */

/*
 * Compute f_{n,P}(Q) — the Miller function value.
 * For the simulated pairing, this is a scalar exponentiation.
 *
 * Reference: Miller (1986) "Short Programs for Functions on Curves"
 * Reference: Silverman "The Arithmetic of Elliptic Curves" §XI.8
 */
GroupElement* miller_function(uint64_t n, const GroupElement* P,
                               const GroupElement* Q, const BilinearPairing* bp);

/*
 * Final exponentiation for Tate pairing.
 * Raises Miller result to (p^k - 1)/r.
 */
GroupElement* final_exponentiation(const GroupElement* miller_result,
                                    const BilinearPairing* bp);

/* ── Application: KEA in Bilinear Groups (KEA3) ──────────── */

/*
 * KEA3 (Bilinear Knowledge of Exponent):
 *
 * Given [a]_1 = a * g1 and [a]_2 = a * g2 (in G1 and G2),
 * any adversary outputting (C, a*C) in G1 and G2 must know c = dlog(C).
 *
 * This is the core assumption used in Groth16 SNARK.
 */

/* Create a KEA3 challenge pair */
typedef struct {
    BilinearPairing* bp;
    GroupElement*    alpha_g1;   /* [a]_1 = a * g1 in G1 */
    GroupElement*    alpha_g2;   /* [a]_2 = a * g2 in G2 */
    uint64_t         secret_alpha;
} KEA3Challenge;

KEA3Challenge* kea3_challenge_create(BilinearPairing* bp);
void kea3_challenge_free(KEA3Challenge* ch);

/*
 * KEA3 Response: (C1, C1' = a*C1) in G1, (C2, C2' = a*C2) in G2
 */
typedef struct {
    GroupElement* c1;       /* C1 in G1 */
    GroupElement* c1_prime; /* a*C1 in G1 */
    GroupElement* c2;       /* C2 in G2 */
    GroupElement* c2_prime; /* a*C2 in G2 */
    uint64_t      witness;
    int           is_valid;
} KEA3Response;

KEA3Response* kea3_response_create(const KEA3Challenge* ch, uint64_t r);
int kea3_response_verify(const KEA3Challenge* ch, const KEA3Response* resp);
void kea3_response_free(KEA3Response* resp);

#endif /* KEA_PAIRING_H */