/*
 * discrete_log.h — Discrete Logarithm and Diffie-Hellman Problems
 *
 * L1 Definitions:
 *   - Discrete Logarithm Problem (DLP):
 *     Given g and h = g^x in group G, find x.
 *     WARNING: The KEA assumption implies that DLP is feasible
 *     FOR THE EXTRACTOR (non-black-box), but hard for ordinary
 *     polynomial-time adversaries.
 *
 *   - Computational Diffie-Hellman (CDH):
 *     Given g, g^a, g^b, compute g^{ab}.
 *
 *   - Decisional Diffie-Hellman (DDH):
 *     Distinguish (g^a, g^b, g^{ab}) from (g^a, g^b, g^c)
 *     for random a, b, c.
 *
 *   - Square DLP: Given g, g^{x^2}, find x.
 *
 * L2 Core Concepts:
 *   - Hardness assumptions hierarchy: DLP >= CDH >= DDH
 *   - Generic group model: lower bound Omega(sqrt(p)) for DLP
 *   - Knowledge assumptions: circumvent generic lower bounds
 *
 * L5 Algorithms:
 *   - Baby-step Giant-step (Shanks): O(sqrt(n)) time, O(sqrt(n)) space
 *   - Pollard's Rho: O(sqrt(n)) time, O(1) space
 *   - Pohlig-Hellman: reduces DLP in composite order groups to prime subgroups
 *   - Index Calculus: subexponential for Z_p* (not generic)
 *
 * Relationship to KEA:
 *   The KEA assumption says that if an adversary can produce
 *   (g^r, g^{ar}) from (g, g^a), then it MUST have known r.
 *   The extractor, by definition, can recover r.
 *   This extraction step essentially "breaks DLP" for the
 *   specific response elements, using non-black-box access.
 *
 * References:
 *   - Diffie & Hellman (1976) "New Directions in Cryptography"
 *   - Shanks (1971) — Baby-step Giant-step
 *   - Pollard (1978) — Rho algorithm
 *   - Pohlig & Hellman (1978) — Subgroup reduction
 *   - Maurer & Wolf (1999) — Relationship between Diffie-Hellman problems
 *
 * Courses: Stanford CS255, MIT 6.875, Berkeley CS276, ETH 263-4600
 */

#ifndef KEA_DISCRETE_LOG_H
#define KEA_DISCRETE_LOG_H

#include "group.h"
#include <stdlib.h>
#include <stdint.h>

/* ── DLP Instance ─────────────────────────────────────────── */

typedef struct {
    GroupElement* generator;   /* g */
    GroupElement* target;      /* h = g^x */
    CyclicGroup* group;       /* the group */
    int           solved;      /* 1 if x has been found */
    uint64_t      solution;    /* x (if solved) */
} DLPInstance;

/* ── CDH Instance ────────────────────────────────────────── */

typedef struct {
    GroupElement* g;           /* generator */
    GroupElement* g_a;         /* g^a */
    GroupElement* g_b;         /* g^b */
    GroupElement* answer;      /* g^{ab} (set by solver) */
    CyclicGroup* group;
    int           solved;
} CDHInstance;

/* ── DDH Instance ────────────────────────────────────────── */

typedef struct {
    GroupElement* g;
    GroupElement* g_a;
    GroupElement* g_b;
    GroupElement* g_c;        /* either g^{ab} or g^{random} */
    int           is_dh_tuple; /* 1 if c = ab, 0 otherwise */
    CyclicGroup* group;
} DDHInstance;

/* ── DLP Construction ─────────────────────────────────────── */

DLPInstance* dlp_instance_create(CyclicGroup* g, uint64_t secret);
DLPInstance* dlp_instance_random(CyclicGroup* g);
void dlp_instance_free(DLPInstance* inst);
void dlp_print(const DLPInstance* inst);

/* ── CDH Construction ─────────────────────────────────────── */

CDHInstance* cdh_instance_create(CyclicGroup* g, uint64_t a, uint64_t b);
CDHInstance* cdh_instance_random(CyclicGroup* g);
void cdh_instance_free(CDHInstance* inst);
int cdh_verify(const CDHInstance* inst);
void cdh_print(const CDHInstance* inst);

/* ── DDH Construction ─────────────────────────────────────── */

DDHInstance* ddh_instance_create(CyclicGroup* g, uint64_t a, uint64_t b, int is_dh);
DDHInstance* ddh_instance_random(CyclicGroup* g);
void ddh_instance_free(DDHInstance* inst);
void ddh_print(const DDHInstance* inst);

/* ── Baby-step Giant-step ─────────────────────────────────── */

/*
 * Baby-step Giant-step algorithm for DLP.
 * Complexity: O(sqrt(n)) time, O(sqrt(n)) space.
 *
 * Algorithm (L5):
 *   1. Let m = ceil(sqrt(n))
 *   2. Baby steps: compute g^{j} for j = 0..m-1, store in hash table
 *   3. Compute gamma = g^{-m}
 *   4. Giant steps: for i = 0..m-1, compute h * gamma^i,
 *      look up in hash table.
 *   5. If match found at (i, j): x = i*m + j
 *
 * Reference: Shanks (1971) "Class Number ..."
 */
uint64_t dlp_baby_giant_step(const GroupElement* g, const GroupElement* h,
                              const CyclicGroup* group);

/* ── Pollard's Rho ────────────────────────────────────────── */

/*
 * Pollard's Rho algorithm for DLP.
 * Complexity: O(sqrt(n)) time, O(1) space (expected).
 *
 * Uses a pseudorandom walk f: G -> G that behaves like a random function.
 * By birthday paradox, two walk points x_i ≡ x_j (mod p) will be found
 * in O(sqrt(n)) steps.
 *
 * Reference: Pollard (1978) "Monte Carlo Methods for Index Computation (mod p)"
 * Courses: MIT 6.875, Stanford CS255
 */
uint64_t dlp_pollard_rho(const GroupElement* g, const GroupElement* h,
                          const CyclicGroup* group);

/* ── Pohlig-Hellman ───────────────────────────────────────── */

/*
 * Pohlig-Hellman reduction for DLP.
 * If |G| = Prod p_i^{e_i}, solves DLP in each subgroup and
 * combines using CRT.
 *
 * Complexity: O(Sum e_i * (log |G| + sqrt(p_i)))
 *
 * Reference: Pohlig & Hellman (1978)
 */
uint64_t dlp_pohlig_hellman(const GroupElement* g, const GroupElement* h,
                             const CyclicGroup* group,
                             const uint64_t* prime_factors, int n_factors);

/* ── Index Calculus ───────────────────────────────────────── */

/*
 * Index Calculus for DLP in Z_p*.
 * Subexponential complexity: exp(O(sqrt(log p * log log p)))
 *
 * Unlike BSGS and Pollard Rho, this is NOT a generic algorithm.
 * It exploits the structure of Z_p* as a multiplicative group
 * of a finite field.
 *
 * Three phases:
 *   1. Factor base selection (small primes)
 *   2. Relation collection (linear equations)
 *   3. Linear algebra (solve for logs of factor base)
 *   4. Individual logarithm computation
 *
 * For educational purposes, this implementation uses a small
 * factor base and Gaussian elimination.
 */
uint64_t dlp_index_calculus(const GroupElement* g, const GroupElement* h,
                             const CyclicGroup* group);

/* ── DLP Solver (Auto-Select) ─────────────────────────────── */

/*
 * Automatically select the best DLP algorithm based on group size.
 * For small groups (< 2^20): brute force
 * For medium groups (< 2^32): BSGS or Pollard Rho
 * For large groups (< 2^48): Index Calculus
 * For larger groups: infeasible (return 0)
 */
uint64_t dlp_solve(const GroupElement* g, const GroupElement* h,
                    const CyclicGroup* group);

/* ── CDH Solver ───────────────────────────────────────────── */

/*
 * Solve CDH using DLP:
 *   1. Compute a = dlog(g, g^a)
 *   2. Compute g^{ab} = (g^b)^a
 *
 * This shows that CDH reduces to DLP.
 */
int cdh_solve_via_dlp(CDHInstance* inst);

/* ── DDH Solver ───────────────────────────────────────────── */

/*
 * Solve DDH using DLP (for groups where DDH is easy, e.g., Z_p*):
 *   - DDH is easy in Z_p* (quadratic residuosity check)
 *   - DDH is hard in elliptic curve groups of prime order
 *
 * Returns 1 if (g, g^a, g^b, g^c) is a DH tuple, 0 otherwise.
 */
int ddh_solve_legendre(const DDHInstance* inst);

/* ── Hardness Reduction Proofs ────────────────────────────── */

/*
 * Prove: DLP solvable => CDH solvable.
 * Given DLP oracle, solve CDH: a = DLP(g, g^a), then (g^b)^a = g^{ab}.
 */
void proof_dlp_implies_cdh(CyclicGroup* g);

/*
 * Prove: DDH solvable => CDH solvable (for some groups).
 * Using a DDH oracle to test candidate CDH solutions.
 * This is a gap-DH reduction.
 */
void proof_ddh_implies_cdh(CyclicGroup* g);

/*
 * Self-reducibility of DLP:
 * If we can solve DLP with probability epsilon, we can amplify to
 * probability 1 - negl(n) by randomizing the instance.
 */
void proof_dlp_self_reducibility(CyclicGroup* g, int trials);

/* ── DLP vs KEA Comparison ────────────────────────────────── */

/*
 * Compare DLP hardness with KEA extraction:
 *   - DLP: black-box, generic algorithms need Omega(sqrt(n))
 *   - KEA extractor: non-black-box, can extract exponent from valid response
 *
 * This function demonstrates that KEA is a strictly stronger assumption
 * than DLP hardness.
 */
void kea_vs_dlp_comparison(CyclicGroup* g);

/* ── DLP Benchmarking ─────────────────────────────────────── */

/* Measure average runtime of each DLP algorithm for a given group size */
void dlp_benchmark_algorithms(CyclicGroup* g);

/* Compare the performance of BSGS vs Pollard Rho vs Index Calculus */
void dlp_compare_methods(CyclicGroup* g);

#endif /* KEA_DISCRETE_LOG_H */