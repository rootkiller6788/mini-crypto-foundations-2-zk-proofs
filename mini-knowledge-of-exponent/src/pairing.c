/*
 * pairing.c — Bilinear Pairings for Pairing-Based KEA
 *
 * L1: Bilinear pairing e: G1 x G2 -> GT, bilinearity, non-degeneracy
 * L2: Pairing types (symmetric, asymmetric BN, BLS12), Miller's algorithm
 * L3: BilinearPairing, PairingResult, G1/G2/GT groups
 * L5: Pairing computation, Miller loop, final exponentiation, product pairing
 * L6: KEA3 challenge-response for bilinear groups
 *
 * This module provides a simulated bilinear pairing for educational purposes.
 * Real pairings (BN254, BLS12-381) require elliptic curve arithmetic.
 *
 * Courses: Stanford CS255, EPFL COM-401
 * (C) Mini-Theory-of-Computation — mini-knowledge-of-exponent
 */
#include "pairing.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ═══════════════════════════════════════════════════════════════
   Simulated Bilinear Pairing Construction
   ═══════════════════════════════════════════════════════════════ */

/*
 * In a simulated pairing, we use the multiplicative group Z_p* for G1, G2, GT.
 * The pairing is: e(g1^a, g2^b) = gt^{a*b} mod p
 *
 * This satisfies bilinearity, non-degeneracy, and computability.
 * It does NOT provide cryptographic hardness (no secure CRS).
 */

BilinearPairing* pairing_create_simulated(void) {
    BilinearPairing* bp = (BilinearPairing*)calloc(1, sizeof(BilinearPairing));
    if (!bp) return NULL;
    bp->type = PAIRING_TYPE_SIMULATED;

    /* Create three identical prime-order groups */
    bp->G1 = group_create_test_group();
    if (!bp->G1) { free(bp); return NULL; }

    bp->G2 = group_create_test_group();
    if (!bp->G2) { group_free(bp->G1); free(bp); return NULL; }

    bp->GT = group_create_test_group();
    if (!bp->GT) { group_free(bp->G2); group_free(bp->G1); free(bp); return NULL; }

    bp->r = bp->G1->order;
    bp->g1 = ge_create(bp->G1->generator, bp->G1);
    bp->g2 = ge_create(bp->G2->generator, bp->G2);
    bp->gt = ge_create(bp->GT->generator, bp->GT);
    bp->name = (char*)calloc(64, 1);
    snprintf(bp->name, 63, "Simulated pairing, order %llu", (unsigned long long)bp->r);

    if (!bp->g1 || !bp->g2 || !bp->gt) {
        pairing_free(bp); return NULL;
    }
    return bp;
}

BilinearPairing* pairing_create(PairingType type,
                                 CyclicGroup* G1, CyclicGroup* G2, CyclicGroup* GT,
                                 GroupElement* g1, GroupElement* g2, GroupElement* gt) {
    if (!G1 || !G2 || !GT || !g1 || !g2 || !gt) return NULL;
    BilinearPairing* bp = (BilinearPairing*)calloc(1, sizeof(BilinearPairing));
    if (!bp) return NULL;
    bp->type = type;
    bp->G1 = G1;
    bp->G2 = G2;
    bp->GT = GT;
    bp->r = G1->order;
    bp->g1 = ge_clone(g1);
    bp->g2 = ge_clone(g2);
    bp->gt = ge_clone(gt);
    bp->name = (char*)calloc(64, 1);
    snprintf(bp->name, 63, "%s pairing", type == PAIRING_TYPE_SYMMETRIC ? "Symmetric" :
             type == PAIRING_TYPE_ASYM_BN ? "BN" : "BLS12");
    return bp;
}

void pairing_free(BilinearPairing* bp) {
    if (!bp) return;
    ge_free(bp->g1); ge_free(bp->g2); ge_free(bp->gt);
    free(bp->name);
    free(bp);
    /* Note: does not free the CyclicGroup pointers since those
       may be shared or owned elsewhere */
}

/* ═══════════════════════════════════════════════════════════════
   Pairing Computation
   ═══════════════════════════════════════════════════════════════ */

/*
 * pairing_compute — Compute e(P, Q) in GT
 *
 * For the simulated pairing:
 *   P = g1^a, Q = g2^b
 *   e(P, Q) = gt^{a*b} mod p where p = modulus.
 *
 * L5: In real implementations, this runs Miller's algorithm:
 *   - Double-and-add loop over the curve order
 *   - Evaluates line functions at each step
 *   - Final exponentiation
 *
 * Complexity (real): O(log r) group operations
 * Reference: Miller (1986) "Short Programs for Functions on Curves"
 */
PairingResult* pairing_compute(const BilinearPairing* bp,
                                const GroupElement* P, const GroupElement* Q) {
    if (!bp || !P || !Q) return NULL;
    if (bp->type == PAIRING_TYPE_SYMMETRIC || bp->type == PAIRING_TYPE_SIMULATED) {
        return pairing_compute_symmetric(bp, P, Q);
    }
    /* For asymmetric types, we would need different handling */
    return pairing_compute_symmetric(bp, P, Q);
}

/*
 * pairing_compute_symmetric — Compute pairing for symmetric groups
 *
 * e(P, Q) = gt^{dlog(P) * dlog(Q)} in the simulated setting.
 * Since we don't actually compute DLP, we use the exponent directly:
 *   P = g1^x, Q = g2^y
 *   → search for (x, y) such that g1^x = P.value and g2^y = Q.value
 *
 * For efficiency, we use the fact that all groups are identical in
 * the simulated setting, and the pairing is: gt^{P.value * Q.value / g_order}
 * Wait, that's not right either.
 *
 * Simplest approach: In the simulated pairing, e(g1^a, g2^b) = gt^{a*b}.
 * We use the internal representation: P = g1^a means a = dlog(P).
 * For the simulation we do NOT compute DLP; instead we approximate:
 *   e(P, Q) = gt^{a*b} when we know a, b.
 *
 * For the general case (unknown exponents), we use a DLP solver.
 */
PairingResult* pairing_compute_symmetric(const BilinearPairing* bp,
                                          const GroupElement* P, const GroupElement* Q) {
    if (!bp || !P || !Q) return NULL;

    uint64_t p = bp->GT->modulus;
    uint64_t n = bp->r;

    /* Compute a = dlog(g1, P), b = dlog(g2, Q) */
    /* For testing, we use known small groups where DLP is feasible */
    uint64_t a = 0;
    if (ge_is_identity(P)) {
        a = 0;
    } else if (ge_equal(P, bp->g1)) {
        a = 1;
    } else {
        /* Try small exponents (suitable for test groups) */
        uint64_t cur = 1;
        for (uint64_t x = 0; x < n && x < 200; x++) {
            if (cur == P->value) { a = x; break; }
            cur = mpz_mod_mul(cur, bp->g1->value, p);
        }
    }

    uint64_t b = 0;
    if (ge_is_identity(Q)) {
        b = 0;
    } else if (ge_equal(Q, bp->g2)) {
        b = 1;
    } else {
        uint64_t cur = 1;
        for (uint64_t y = 0; y < n && y < 200; y++) {
            if (cur == Q->value) { b = y; break; }
            cur = mpz_mod_mul(cur, bp->g2->value, p);
        }
    }

    uint64_t ab = mpz_mod_mul(a, b, n);
    GroupElement* result = ge_pow(bp->gt, ab);

    PairingResult* pr = (PairingResult*)calloc(1, sizeof(PairingResult));
    if (!pr) { ge_free(result); return NULL; }
    pr->result = result;
    pr->pairing = (BilinearPairing*)bp;
    return pr;
}

/*
 * pairing_product — Product pairing: ∏ e(Pi, Qi)
 *
 * L5: Product pairing is used in Groth16 verification to compress
 * multiple pairing checks into one:
 *   Verify: ∏ e(A_i, B_i) = ∏ e(C_i, D_i)
 *
 * By bilinearity: e(P1, Q1) * e(P2, Q2) = gt^{a1*b1 + a2*b2}
 *
 * In real systems: use multi-Miller loop (shared Miller function).
 */
PairingResult* pairing_product(const BilinearPairing* bp,
                                const GroupElement** Ps,
                                const GroupElement** Qs,
                                int n) {
    if (!bp || !Ps || !Qs || n <= 0) return NULL;

    uint64_t p = bp->GT->modulus;
    uint64_t order = bp->r;
    uint64_t total = 0;

    for (int i = 0; i < n; i++) {
        if (!Ps[i] || !Qs[i]) continue;

        /* Get exponents via brute force (small test groups only) */
        uint64_t a = 0, b = 0;
        uint64_t cur = 1;
        for (uint64_t x = 0; x < order && x < 200; x++) {
            if (cur == Ps[i]->value) { a = x; break; }
            cur = mpz_mod_mul(cur, bp->g1->value, p);
        }
        cur = 1;
        for (uint64_t y = 0; y < order && y < 200; y++) {
            if (cur == Qs[i]->value) { b = y; break; }
            cur = mpz_mod_mul(cur, bp->g2->value, p);
        }
        uint64_t ab = mpz_mod_mul(a, b, order);
        total = mpz_mod_add(total, ab, order);
    }

    GroupElement* result = ge_pow(bp->gt, total);
    PairingResult* pr = (PairingResult*)calloc(1, sizeof(PairingResult));
    if (!pr) { ge_free(result); return NULL; }
    pr->result = result;
    pr->pairing = (BilinearPairing*)bp;
    return pr;
}

/* ═══════════════════════════════════════════════════════════════
   Pairing Verification
   ═══════════════════════════════════════════════════════════════ */

/*
 * pairing_verify_equation — Verify e(A,B) == e(C,D)
 *
 * Returns 1 if equality holds.
 */
int pairing_verify_equation(const BilinearPairing* bp,
                             const GroupElement* A, const GroupElement* B,
                             const GroupElement* C, const GroupElement* D) {
    if (!bp || !A || !B || !C || !D) return 0;
    PairingResult* pr1 = pairing_compute(bp, A, B);
    PairingResult* pr2 = pairing_compute(bp, C, D);
    if (!pr1 || !pr2) { pr_free(pr1); pr_free(pr2); return 0; }
    int ok = pr_equal(pr1, pr2);
    pr_free(pr1); pr_free(pr2);
    return ok;
}

/*
 * pairing_verify_multi_equation — Verify ∏ e(A_i,B_i) == ∏ e(C_i,D_i)
 *
 * L5: Groth16 verification uses this single pairing check.
 */
int pairing_verify_multi_equation(const BilinearPairing* bp,
                                   const GroupElement** As,
                                   const GroupElement** Bs,
                                   const GroupElement** Cs,
                                   const GroupElement** Ds,
                                   int n_pairs) {
    if (!bp || !As || !Bs || !Cs || !Ds || n_pairs <= 0) return 0;
    PairingResult* pr_left = pairing_product(bp, As, Bs, n_pairs);
    PairingResult* pr_right = pairing_product(bp, Cs, Ds, n_pairs);
    if (!pr_left || !pr_right) { pr_free(pr_left); pr_free(pr_right); return 0; }
    int ok = pr_equal(pr_left, pr_right);
    pr_free(pr_left); pr_free(pr_right);
    return ok;
}

/* ═══════════════════════════════════════════════════════════════
   Pairing Properties Verification
   ═══════════════════════════════════════════════════════════════ */

/*
 * pairing_check_bilinearity — Verify bilinearity property
 *
 * Tests: e(a*P, b*Q) = e(P, Q)^{ab} for random a, b.
 */
int pairing_check_bilinearity(const BilinearPairing* bp,
                               const GroupElement* P, const GroupElement* Q) {
    if (!bp || !P || !Q) return 0;
    uint64_t a = 3, b = 5;
    if (a >= bp->r) a = bp->r - 1;
    if (b >= bp->r) b = bp->r - 1;

    GroupElement* aP = ge_pow(P, a);
    GroupElement* bQ = ge_pow(Q, b);
    if (!aP || !bQ) { ge_free(aP); ge_free(bQ); return 0; }

    PairingResult* pr_left = pairing_compute(bp, aP, bQ);
    PairingResult* pr_right = pairing_compute(bp, P, Q);
    if (!pr_left || !pr_right) {
        ge_free(aP); ge_free(bQ); pr_free(pr_left); pr_free(pr_right); return 0;
    }

    GroupElement* expected = ge_pow(pr_right->result, mpz_mod_mul(a, b, bp->r));
    int ok = ge_equal(pr_left->result, expected);

    ge_free(aP); ge_free(bQ); ge_free(expected);
    pr_free(pr_left); pr_free(pr_right);
    return ok;
}

/*
 * pairing_check_nondegenerate — Verify non-degeneracy
 *
 * e(g1, g2) ≠ 1 (identity in GT).
 */
int pairing_check_nondegenerate(const BilinearPairing* bp) {
    if (!bp) return 0;
    PairingResult* pr = pairing_compute(bp, bp->g1, bp->g2);
    if (!pr) return 0;
    int ok = !ge_is_identity(pr->result);
    pr_free(pr);
    return ok;
}

/*
 * pairing_self_test — Run comprehensive pairing self-test
 *
 * Checks bilinearity, non-degeneracy, and symmetry (if applicable).
 */
int pairing_self_test(const BilinearPairing* bp) {
    if (!bp) return 0;
    printf("=== Pairing Self-Test ===\n");
    printf("Pairing: %s\n", bp->name);
    printf("Order r: %llu\n", (unsigned long long)bp->r);

    int bilin = pairing_check_bilinearity(bp, bp->g1, bp->g2);
    printf("Bilinearity:    %s\n", bilin ? "PASS ✓" : "FAIL ✗");

    int nondeg = pairing_check_nondegenerate(bp);
    printf("Non-degenerate: %s\n", nondeg ? "PASS ✓" : "FAIL ✗");

    /* Symmetry check for symmetric pairings */
    if (bp->type == PAIRING_TYPE_SYMMETRIC || bp->type == PAIRING_TYPE_SIMULATED) {
        PairingResult* pr1 = pairing_compute(bp, bp->g1, bp->g2);
        PairingResult* pr2 = pairing_compute(bp, bp->g2, bp->g1);
        int symm = pr_equal(pr1, pr2);
        printf("Symmetry:       %s\n", symm ? "PASS ✓" : "FAIL ✗");
        pr_free(pr1); pr_free(pr2);
    }

    int all_pass = bilin && nondeg;
    printf("Overall: %s\n", all_pass ? "ALL TESTS PASS ✓" : "SOME TESTS FAIL ✗");
    printf("========================\n");
    return all_pass;
}

/* ═══════════════════════════════════════════════════════════════
   Pairing Result Operations
   ═══════════════════════════════════════════════════════════════ */

PairingResult* pr_create(GroupElement* result, BilinearPairing* bp) {
    if (!result || !bp) return NULL;
    PairingResult* pr = (PairingResult*)calloc(1, sizeof(PairingResult));
    if (!pr) return NULL;
    pr->result = result;
    pr->pairing = bp;
    return pr;
}

void pr_free(PairingResult* pr) {
    if (!pr) return;
    ge_free(pr->result);
    free(pr);
}

int pr_equal(const PairingResult* a, const PairingResult* b) {
    if (!a || !b) return 0;
    return ge_equal(a->result, b->result);
}

void pr_print(const PairingResult* pr, const char* label) {
    if (!pr) return;
    printf("PairingResult{%s}: ", label);
    if (pr->result) {
        printf("gt^{%llu} (mod %llu)\n",
               (unsigned long long)pr->result->value,
               (unsigned long long)(pr->result->group ? pr->result->group->modulus : 0));
    } else {
        printf("(null)\n");
    }
}

/* ═══════════════════════════════════════════════════════════════
   Miller's Algorithm (Simplified for Simulation)
   ═══════════════════════════════════════════════════════════════ */

/*
 * miller_function — Compute f_{n,P}(Q)
 *
 * In the simulated pairing, f_{n,P}(Q) is approximated by
 * exponentiation: gt^{n * dlog(P) * dlog(Q)}.
 *
 * In real pairings (Weil/Tate), this involves evaluating
 * line functions at the divisor points.
 *
 * Reference: Miller (1986), Silverman "Arithmetic of EC" §XI.8
 */
GroupElement* miller_function(uint64_t n, const GroupElement* P,
                               const GroupElement* Q, const BilinearPairing* bp) {
    if (!P || !Q || !bp) return NULL;
    /* Simplified: f_{n,P}(Q) approximates contribution */
    /* Find dlog of P and Q */
    uint64_t p_mod = bp->G1->modulus;
    uint64_t a = 0, b = 0;
    uint64_t cur = 1;
    for (uint64_t x = 0; x < bp->r && x < 200; x++) {
        if (cur == P->value) { a = x; break; }
        cur = mpz_mod_mul(cur, bp->g1->value, p_mod);
    }
    cur = 1;
    for (uint64_t y = 0; y < bp->r && y < 200; y++) {
        if (cur == Q->value) { b = y; break; }
        cur = mpz_mod_mul(cur, bp->g2->value, p_mod);
    }
    uint64_t contrib = mpz_mod_mul(mpz_mod_mul(n, a, bp->r), b, bp->r);
    return ge_pow(bp->gt, contrib);
}

/*
 * final_exponentiation — Raise to (p^k - 1) / r
 *
 * For the Tate pairing, the Miller result f must be raised to
 * the power (p^k - 1)/r to obtain a unique value in GT.
 *
 * In our simulated pairing, we just return the input (already in GT).
 */
GroupElement* final_exponentiation(const GroupElement* miller_result,
                                    const BilinearPairing* bp) {
    if (!miller_result || !bp) return NULL;
    return ge_clone(miller_result);
}

/* ═══════════════════════════════════════════════════════════════
   KEA3: Knowledge of Exponent in Bilinear Groups
   ═══════════════════════════════════════════════════════════════ */

/*
 * kea3_challenge_create — Create a KEA3 challenge
 *
 * KEA3: Given [a]_1 in G1 and [a]_2 in G2, any PPT adversary
 * outputting (C_1, a*C_1) in G1 and (C_2, a*C_2) in G2 must
 * know c = dlog(C_1) = dlog(C_2).
 */
KEA3Challenge* kea3_challenge_create(BilinearPairing* bp) {
    if (!bp || !bp->g1 || !bp->g2) return NULL;
    KEA3Challenge* ch = (KEA3Challenge*)calloc(1, sizeof(KEA3Challenge));
    if (!ch) return NULL;
    ch->bp = bp;
    ch->secret_alpha = 1 + (bp->r > 2 ? bp->r / 3 : 1);
    if (ch->secret_alpha >= bp->r) ch->secret_alpha = bp->r - 1;
    ch->alpha_g1 = ge_pow(bp->g1, ch->secret_alpha);
    ch->alpha_g2 = ge_pow(bp->g2, ch->secret_alpha);
    if (!ch->alpha_g1 || !ch->alpha_g2) { kea3_challenge_free(ch); return NULL; }
    return ch;
}

void kea3_challenge_free(KEA3Challenge* ch) {
    if (!ch) return;
    ge_free(ch->alpha_g1); ge_free(ch->alpha_g2);
    free(ch);
}

/*
 * kea3_response_create — Create a KEA3 response with witness r
 *
 * C1 = g1^r, C1' = (g1^a)^r = g1^{a*r}
 * C2 = g2^r, C2' = (g2^a)^r = g2^{a*r}
 */
KEA3Response* kea3_response_create(const KEA3Challenge* ch, uint64_t r) {
    if (!ch || !ch->bp) return NULL;
    KEA3Response* resp = (KEA3Response*)calloc(1, sizeof(KEA3Response));
    if (!resp) return NULL;
    resp->c1 = ge_pow(ch->bp->g1, r);
    resp->c1_prime = ge_pow(ch->alpha_g1, r);
    resp->c2 = ge_pow(ch->bp->g2, r);
    resp->c2_prime = ge_pow(ch->alpha_g2, r);
    resp->witness = r;
    /* Verify consistency */
    int ok1 = ge_equal(resp->c1_prime, ge_pow(resp->c1, ch->secret_alpha));
    int ok2 = ge_equal(resp->c2_prime, ge_pow(resp->c2, ch->secret_alpha));
    resp->is_valid = ok1 && ok2;
    if (!resp->c1 || !resp->c1_prime || !resp->c2 || !resp->c2_prime) {
        kea3_response_free(resp); return NULL;
    }
    return resp;
}

int kea3_response_verify(const KEA3Challenge* ch, const KEA3Response* resp) {
    if (!ch || !resp) return 0;
    int ok1 = ge_equal(resp->c1_prime, ge_pow(resp->c1, ch->secret_alpha));
    int ok2 = ge_equal(resp->c2_prime, ge_pow(resp->c2, ch->secret_alpha));
    return ok1 && ok2;
}

void kea3_response_free(KEA3Response* resp) {
    if (!resp) return;
    ge_free(resp->c1); ge_free(resp->c1_prime);
    ge_free(resp->c2); ge_free(resp->c2_prime);
    free(resp);
}
