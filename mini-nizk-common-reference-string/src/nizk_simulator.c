/**
 * nizk_simulator.c - Zero-Knowledge Simulator for NIZK Proofs
 *
 * L2 Definition: A simulator is an algorithm that produces proofs
 * indistinguishable from real proofs WITHOUT knowing the witness.
 *
 * The existence of a simulator formally defines zero-knowledge:
 *   For every verifier V*, there exists a PPT simulator Sim s.t.
 *   for all (x,w) in R, {Prove(x,w)} ≈_c {Sim(x)}.
 *
 * In the CRS model with trapdoor tau (h = g^tau), the simulator:
 *   1. Picks random s, c <- Z_q
 *   2. Computes t = g^s * h^{-c} = g^{s - tau*c}
 *   3. Programs random oracle: H(stmt || t) := c
 *   4. Outputs proof pi = (t, s)
 *
 * The simulated transcript is PERFECTLY indistinguishable from real
 * when the trapdoor is uniformly random.
 *
 * Reference: Goldreich, Micali, Wigderson. "Proofs that Yield Nothing
 *            But Their Validity." JACM 1991.
 *            Blum, Feldman, Micali. "Non-Interactive Zero-Knowledge."
 *            STOC 1988.
 *
 * Course Mapping:
 *   MIT 6.875: Zero-knowledge simulation
 *   Stanford CS355: Simulator construction
 *   Princeton COS 551: Simulation in CRS model
 *   Berkeley CS278: Zero-knowledge definitions
 */

#include "nizk_simulator.h"
#include "nizk_group.h"
#include "nizk_crs.h"
#include "nizk_proof.h"
#include "nizk_sigma.h"
#include "nizk_commitment.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

/* =========================================================================
 * L2: Simulator Initialization
 * ========================================================================= */

/**
 * nizk_simulator_init - Initialize simulator with CRS trapdoor.
 *
 * L2 Knowledge Point: Simulator Setup in CRS Model
 *
 * The simulator REQUIRES the CRS trapdoor tau where h = g^tau.
 * Without this trapdoor, the simulator cannot generate valid-looking
 * proofs without witnesses (the CRS is in "soundness mode").
 *
 * This models the real-world constraint: zero-knowledge only holds
 * if the CRS was set up in "ZK mode" with a known trapdoor. If the
 * CRS was set up in soundness mode (h has unknown DL), then proofs
 * are only sound but not necessarily zero-knowledge (or they achieve
 * ZK through different means, e.g., bilinear pairings in Groth-Sahai).
 *
 * The trapdoor tau is the "simulation trapdoor" - a secret value
 * that allows simulation but cannot be computed from the CRS alone
 * (assuming DLOG is hard).
 *
 * Course: MIT 6.875 NIZK with CRS, Stanford CS355 Simulation Trapdoor
 */
int nizk_simulator_init(nizk_simulator_state_t *sim,
                         const nizk_crs_t *crs) {
    if (!crs->has_trapdoor) {
        /* Cannot simulate without trapdoor */
        return 0;
    }

    nizk_scalar_copy(&sim->trapdoor, &crs->trapdoor);
    sim->is_active = 1;
    sim->proof_count = 0;
    return 1;
}

/* =========================================================================
 * L5: Simulation Techniques - Generating Proofs Without Witness
 * ========================================================================= */

/**
 * nizk_simulate_dlog - Simulate a NIZK proof of discrete log knowledge.
 *
 * L5 Knowledge Point: DLOG Proof Simulation
 *
 * Simulates a proof that "I know w such that h = g^w" without knowing w.
 *
 * Algorithm (with trapdoor tau):
 *   1. Pick random s, c <- Z_q
 *   2. Compute t = g^s * h^{-c}
 *      = g^s * (g^tau)^{-c}
 *      = g^{s - tau*c}
 *   3. The Fiat-Shamir challenge would be c = H(h || t || label),
 *      but we've already chosen c. In the ROM, we "program" the
 *      oracle so that H(h || t || label) = c.
 *
 * Convention: In this implementation, we directly set the challenge
 * to c and the response to s, bypassing the hash. The verifier will
 * recompute c = H(h || t || label) and check g^s == t * h^c.
 *
 * Wait - if the verifier recomputes the challenge, it won't match our
 * pre-chosen c! This is the "programmability" issue in the ROM.
 *
 * Solution: Instead, we use a simulation technique that works WITHOUT
 * programming the RO: pick s randomly, compute t = g^s * h^{-c}
 * where c is ANY value (e.g., 0). Then the transcript (t, c=0, s)
 * satisfies the verification equation but has the wrong challenge
 * distribution (c is not uniformly random).
 *
 * For PERFECT simulation (identical distribution):
 *   1. Pick random s, random c
 *   2. Compute t = g^s * h^{-c}
 *   3. Verify that c == H(h || t || label). If not, this pair (s,c)
 *      doesn't work with the real hash function.
 *
 * In our implementation, the simulation is done by constructing
 * (t, s) and setting the challenge appropriately so that the
 * verifier's recomputation matches. This requires trapdoor knowledge.
 *
 * A simpler correct approach used here:
 *   Pick random s, compute t = g^s * h^{-H(h||t||label)}
 *   But this is circular (t depends on H(t)).
 *
 * The practical approach (Bellare-Shoup 2006):
 *   The simulator with trapdoor can always produce valid proofs
 *   because for ANY s, there exists a t that makes it verify.
 *   Specifically, for any s, compute c = H(...t...) but this still
 *   has the circular dependency.
 *
 * In THIS implementation, we use a direct approach:
 *   1. Pick random s, c
 *   2. Compute t = g^s * h^{-c}
 *   3. Return (t, s) — the verifier will recompute c' = H(...)
 *      which will generally NOT equal c.
 *
 * For a proper simulation, we need the ROM programming capability.
 * Here we provide two simulation modes:
 *   MODE 1 (Direct): Return (t, s) with a pre-chosen c.
 *     Verifier must use this c instead of recomputing.
 *   MODE 2 (ZK Weak): Pick s, compute c = 0, t = g^s.
 *     This satisfies the equation but c distribution is wrong.
 *
 * For our educational implementation, we use MODE 1 and document
 * that the verifier must accept the embedded challenge.
 * This models the "programmable random oracle" idealization.
 *
 * Theorem (Perfect ZK in ROM): If the trapdoor is uniform, the
 * simulated proof distribution is IDENTICAL to the real distribution.
 *
 * Course: MIT 6.875 NIZK Simulation Techniques,
 *         Stanford CS355 Zero-Knowledge Proofs
 */
void nizk_simulate_dlog(nizk_proof_t *proof,
                         const nizk_simulator_state_t *sim,
                         const nizk_crs_t *crs,
                         const nizk_group_elem_t *pubkey,
                         const uint8_t *label, size_t label_len,
                         const nizk_group_params_t *params) {
    (void)crs;
    if (!sim->is_active) return;

    proof->type = NIZK_PROOF_DLOG_KNOWLEDGE;

    /* Pick random response s and challenge c */
    nizk_scalar_t s, c;
    nizk_scalar_rand(&s, params);
    nizk_scalar_rand(&c, params);

    /* Compute t = g^s * h^{-c} */
    nizk_group_elem_t gen;
    nizk_bigint_copy(&gen.elem, &params->g);

    /* h^{-c} = h^{q-c} mod p */
    nizk_scalar_t neg_c;
    nizk_scalar_neg(&neg_c, &c, params);
    nizk_group_elem_t h_neg_c;
    nizk_group_exp(&h_neg_c, pubkey, &neg_c, params);

    /* t = g^s * h^{-c} */
    nizk_group_elem_t g_s;
    nizk_group_exp(&g_s, &gen, &s, params);
    nizk_group_op(&proof->commitment.t, &g_s, &h_neg_c, params);
    proof->commitment.has_aux = 0;

    /* Set response = s */
    nizk_scalar_copy(&proof->response.s, &s);
    proof->response.has_aux = 0;

    /* Store the challenge in response.s_aux for verification bypass.
     * This is a ROM programming simulation: the verifier must use
     * this challenge instead of recomputing from the hash.
     *
     * In a real ROM security proof, this is equivalent to the
     * simulator programming H(stmt || t) = c. */
    proof->response.has_aux = 1;
    nizk_scalar_copy(&proof->response.s_aux, &c);

    memset(proof->statement_hash, 0, 32);
    (void)label; (void)label_len;
}

/**
 * nizk_simulate_dlog_eq - Simulate proof of equal discrete logs.
 *
 * L5 Knowledge Point: DLOG Equality Proof Simulation
 *
 * Simulates proof that log_g(u) = log_h(v) without knowing w.
 *
 * Technique:
 *   1. Pick random s, c <- Z_q
 *   2. Compute t1 = g^s * u^{-c}
 *   3. Compute t2 = h^s * v^{-c}
 *   4. Output proof with (t1, t2, s, c)
 *
 * Both equations verify:
 *   Check 1: g^s == t1 * u^c  ✓ (by construction of t1)
 *   Check 2: h^s == t2 * v^c  ✓ (by construction of t2)
 *
 * The simulated distribution is identical to real when (s, c) are
 * uniformly random, because in real transcripts:
 *   t1 = g^r, c = H(...), s = r + c*w
 *   (r uniform => t1 uniform in G, s uniform in Z_q)
 * In simulated:
 *   s uniform, c uniform, t1 = g^s * u^{-c}
 *   Both produce uniformly distributed (t1, s) ✓
 */
void nizk_simulate_dlog_eq(nizk_proof_t *proof,
                            const nizk_simulator_state_t *sim,
                            const nizk_crs_t *crs,
                            const nizk_group_elem_t *u,
                            const nizk_group_elem_t *v,
                            const nizk_group_elem_t *base_h,
                            const uint8_t *label, size_t label_len,
                            const nizk_group_params_t *params) {
    (void)crs;
    if (!sim->is_active) return;

    proof->type = NIZK_PROOF_DLOG_EQUALITY;

    nizk_scalar_t s, c;
    nizk_scalar_rand(&s, params);
    nizk_scalar_rand(&c, params);

    nizk_group_elem_t gen;
    nizk_bigint_copy(&gen.elem, &params->g);

    /* t1 = g^s * u^{-c} */
    nizk_scalar_t neg_c;
    nizk_scalar_neg(&neg_c, &c, params);
    nizk_group_elem_t u_neg_c, g_s;
    nizk_group_exp(&u_neg_c, u, &neg_c, params);
    nizk_group_exp(&g_s, &gen, &s, params);
    nizk_group_op(&proof->commitment.t, &g_s, &u_neg_c, params);

    /* t2 = h^s * v^{-c} */
    nizk_group_elem_t h_s, v_neg_c;
    nizk_group_exp(&h_s, base_h, &s, params);
    nizk_group_exp(&v_neg_c, v, &neg_c, params);
    nizk_group_op(&proof->commitment.t_aux, &h_s, &v_neg_c, params);
    proof->commitment.has_aux = 1;

    nizk_scalar_copy(&proof->response.s, &s);
    proof->response.has_aux = 1;
    nizk_scalar_copy(&proof->response.s_aux, &c);

    memset(proof->statement_hash, 0, 32);
    (void)label; (void)label_len;
}

/**
 * nizk_simulate_commitment - Simulate proof of commitment opening.
 *
 * L5 Knowledge Point: Representation Proof Simulation
 *
 * Simulates proof that C = g^m * h^r without knowing (m, r).
 *
 * Technique:
 *   1. Pick random s1, s2, c <- Z_q
 *   2. Compute t = g^{s1} * h^{s2} * C^{-c}
 *   3. Verification: g^{s1} * h^{s2} == t * C^c  ✓
 *
 * This works because:
 *   t * C^c = (g^{s1} * h^{s2} * C^{-c}) * C^c = g^{s1} * h^{s2}
 *   QED.
 *
 * The simulation is perfect because (s1, s2, c) are uniform in the
 * simulated distribution, just as (s1 = u + c*m, s2 = v + c*r, c)
 * are in the real distribution (where u, v, m, r are all uniform
 * in their respective domains).
 */
void nizk_simulate_commitment(nizk_proof_t *proof,
                               const nizk_simulator_state_t *sim,
                               const nizk_crs_t *crs,
                               const nizk_commitment_t *com,
                               const uint8_t *label, size_t label_len,
                               const nizk_group_params_t *params) {
    (void)crs;
    if (!sim->is_active) return;

    proof->type = NIZK_PROOF_COMMITMENT;

    nizk_scalar_t s1, s2, c;
    nizk_scalar_rand(&s1, params);
    nizk_scalar_rand(&s2, params);
    nizk_scalar_rand(&c, params);

    /* Compute t = g^{s1} * h1^{s2} * C^{-c} */
    nizk_group_elem_t gen;
    nizk_bigint_copy(&gen.elem, &params->g);

    /* C^{-c} = C^{q-c} */
    nizk_scalar_t neg_c;
    nizk_scalar_neg(&neg_c, &c, params);
    nizk_group_elem_t C_neg_c;
    nizk_group_exp(&C_neg_c, (nizk_group_elem_t*)&com->C, &neg_c, params);

    /* g^{s1} * h1^{s2} */
    nizk_group_elem_t gs1_h1s2;
    nizk_group_multi_exp(&gs1_h1s2, &gen, &s1, &crs->h1, &s2, params);

    /* t = g^{s1} * h1^{s2} * C^{-c} */
    nizk_group_op(&proof->commitment.t, &gs1_h1s2, &C_neg_c, params);
    proof->commitment.has_aux = 0;

    nizk_scalar_copy(&proof->response.s, &s1);
    nizk_scalar_copy(&proof->response.s_aux, &s2);
    proof->response.has_aux = 1;

    /* Store challenge for verification */
    /* We use an additional storage mechanism - s_aux holds s2,
     * but we also need c. Store c in the or_challenges[0] field. */
    nizk_scalar_copy(&proof->or_challenges[0].c, &c);
    proof->or_num_branches = 1;  /* signal: challenge in or_challenges[0] */

    memset(proof->statement_hash, 0, 32);
    (void)label; (void)label_len;
}

/**
 * nizk_simulate_or - Simulate an OR proof (both branches simulated).
 *
 * L5 Knowledge Point: OR-Proof Simulation
 *
 * Simulates knowledge of one of two secrets without knowing EITHER.
 * This is simpler than real OR proving because we can simulate
 * BOTH branches (no real witness needed for either).
 *
 * Technique:
 *   1. Pick random s0, s1, c0, c1 <- Z_q
 *   2. Compute t0 = g^{s0} * pk0^{-c0}
 *   3. Compute t1 = g^{s1} * pk1^{-c1}
 *   4. Set total challenge c = c0 + c1 mod q
 *   5. Output proof with (t0, t1, s0, s1, c0, c1)
 *
 * This simulates an OR proof where the simulator "knows" neither
 * witness. It's indistinguishable from a real OR proof because
 * the real proof also has one simulated branch!
 *
 * In the real OR proof:
 *   - Branch known: (t_real, s_real, c_real) from Schnorr
 *   - Branch unknown: (t_sim, s_sim, c_sim) simulated
 *   - c_real + c_sim = c_total
 *
 * In the fully simulated OR proof:
 *   - Both branches: (t_sim_i, s_sim_i, c_sim_i) simulated
 *   - c_sim_0 + c_sim_1 = c_total
 *
 * An outsider cannot distinguish because the distributions are
 * identical: each branch is individually HVZK, and the challenge
 * split is uniformly random in both cases.
 */
void nizk_simulate_or(nizk_proof_t *proof,
                       const nizk_simulator_state_t *sim,
                       const nizk_crs_t *crs,
                       const nizk_group_elem_t *pubkey1,
                       const nizk_group_elem_t *pubkey2,
                       const uint8_t *label, size_t label_len,
                       const nizk_group_params_t *params) {
    (void)crs;
    if (!sim->is_active) return;

    proof->type = NIZK_PROOF_OR;
    proof->or_num_branches = 2;

    nizk_group_elem_t gen;
    nizk_bigint_copy(&gen.elem, &params->g);

    nizk_group_elem_t *pks[2];
    pks[0] = (nizk_group_elem_t*)pubkey1;
    pks[1] = (nizk_group_elem_t*)pubkey2;

    nizk_scalar_t c_total;
    nizk_scalar_zero(&c_total);

    for (int i = 0; i < 2; i++) {
        /* Pick random response and challenge for this branch */
        nizk_scalar_t s_i, c_i;
        nizk_scalar_rand(&s_i, params);
        nizk_scalar_rand(&c_i, params);

        /* t_i = g^{s_i} * pk_i^{-c_i} */
        nizk_scalar_t neg_c;
        nizk_scalar_neg(&neg_c, &c_i, params);
        nizk_group_elem_t pk_neg_c, g_s;
        nizk_group_exp(&pk_neg_c, pks[i], &neg_c, params);
        nizk_group_exp(&g_s, &gen, &s_i, params);
        nizk_group_op(&proof->or_commitments[i].t, &g_s, &pk_neg_c, params);
        proof->or_commitments[i].has_aux = 0;

        nizk_scalar_copy(&proof->or_challenges[i].c, &c_i);
        nizk_scalar_copy(&proof->or_responses[i].s, &s_i);
        proof->or_responses[i].has_aux = 0;

        /* c_total += c_i */
        nizk_scalar_t new_total;
        nizk_scalar_add(&new_total, &c_total, &c_i, params);
        c_total = new_total;
    }

    /* Store total challenge */
    proof->response.s = c_total;
    proof->response.has_aux = 0;

    /* Store first commitment as main commitment for compatibility */
    nizk_group_elem_copy(&proof->commitment.t, &proof->or_commitments[0].t);

    memset(proof->statement_hash, 0, 32);
    (void)label; (void)label_len;
}

/* =========================================================================
 * L8: Distinguisher Test - Checking Indistinguishability
 * ========================================================================= */

/**
 * nizk_distinguisher_test - Generate real and simulated proofs for comparison.
 *
 * L8 Knowledge Point: Computational Indistinguishability and ZK Testing
 *
 * Zero-knowledge is formally defined as: for every PPT distinguisher D,
 * |Pr[D(real_proof) = 1] - Pr[D(simulated_proof) = 1]| ≤ negl(lambda)
 *
 * This function generates both real and simulated proofs so that an
 * empirical (not provable!) comparison can be made. This is for
 * educational and debugging purposes only.
 *
 * In practice, you CANNOT verify ZK empirically:
 *   - ZK is a computational property (based on hardness assumptions)
 *   - Statistical tests may fail to detect subtle differences
 *   - The distinguisher could use any polynomial-time strategy
 *
 * However, comparing distributions can catch IMPLEMENTATION BUGS:
 *   - If simulated proofs look obviously different (e.g., different size)
 *   - If the simulator accidentally leaks information
 *   - If the trapdoor derivation is wrong
 *
 * This is analogous to the "sanity check" approach in security
 * evaluation: if two distributions that should be identical look
 * obviously different, there's a bug.
 *
 * Algorithm:
 *   1. Generate N real proofs using the witness
 *   2. Generate N simulated proofs using the trapdoor
 *   3. Both sets are returned for external comparison
 *
 * Course: MIT 6.875 ZK Definitions, Stanford CS355 Indistinguishability
 */
void nizk_distinguisher_test(nizk_proof_t *real_proofs,
                              nizk_proof_t *simulated_proofs,
                              int N,
                              const nizk_crs_t *crs_zk,
                              const nizk_crs_t *crs_sound,
                              const nizk_group_elem_t *pubkey,
                              const nizk_scalar_t *witness,
                              const nizk_group_params_t *params) {
    nizk_simulator_state_t sim;
    nizk_simulator_init(&sim, crs_zk);

    const uint8_t label[] = "distinguisher_test";
    size_t label_len = 17;

    for (int i = 0; i < N; i++) {
        /* Generate real proof (with witness, using soundness CRS) */
        nizk_proof_init(&real_proofs[i], NIZK_PROOF_DLOG_KNOWLEDGE);
        nizk_prove_dlog(&real_proofs[i], crs_sound, pubkey, witness,
                         label, label_len, params);

        /* Generate simulated proof (without witness, using ZK CRS) */
        nizk_proof_init(&simulated_proofs[i], NIZK_PROOF_DLOG_KNOWLEDGE);
        nizk_simulate_dlog(&simulated_proofs[i], &sim, crs_zk, pubkey,
                            label, label_len, params);
    }

    sim.proof_count += N;
}

/**
 * nizk_compare_proofs - Compute a similarity heuristic between proof sets.
 *
 * L8 Knowledge Point: Statistical Comparison of Proof Distributions
 *
 * Compares two sets of proofs using a simple heuristic: variance of
 * the first limb of the response scalar. If the variances are similar,
 * the proof sets are "structurally similar" (not a formal guarantee).
 *
 * This is NOT a proper statistical ZK test. It's an educational tool
 * to demonstrate the concept of distribution comparison.
 *
 * In formal ZK, indistinguishability means: NO polynomial-time
 * algorithm can tell the difference better than random guessing.
 * This is fundamentally different from statistical comparison.
 *
 * Returns a similarity score in [0.0, 1.0]:
 *   - 1.0: distributions appear identical by this heuristic
 *   - 0.0: distributions appear completely different
 *
 * Course: MIT 6.875 Advanced ZK, Berkeley CS278 ZK Definitions
 */
double nizk_compare_proofs(const nizk_proof_t *proofs_a,
                            const nizk_proof_t *proofs_b,
                            int count,
                            const nizk_group_params_t *params) {
    (void)params;
    if (count <= 0) return 1.0;

    /* Compute mean response first-limb for set A */
    double mean_a = 0.0, mean_b = 0.0;
    for (int i = 0; i < count; i++) {
        mean_a += (double)proofs_a[i].response.s.val.limbs[0];
        mean_b += (double)proofs_b[i].response.s.val.limbs[0];
    }
    mean_a /= count;
    mean_b /= count;

    /* Compute variance */
    double var_a = 0.0, var_b = 0.0;
    for (int i = 0; i < count; i++) {
        double da = (double)proofs_a[i].response.s.val.limbs[0] - mean_a;
        double db = (double)proofs_b[i].response.s.val.limbs[0] - mean_b;
        var_a += da * da;
        var_b += db * db;
    }
    var_a /= count;
    var_b /= count;

    /* Similarity: 1 - normalized difference */
    double max_var = (var_a > var_b) ? var_a : var_b;
    if (max_var < 1.0) return 1.0;

    double diff = (var_a > var_b) ? (var_a - var_b) : (var_b - var_a);
    double similarity = 1.0 - (diff / max_var);
    if (similarity < 0.0) similarity = 0.0;
    if (similarity > 1.0) similarity = 1.0;

    return similarity;
}

/* =========================================================================
 * L2: Simulator Utilities
 * ========================================================================= */

/**
 * nizk_simulator_clear - Clean up simulator state.
 *
 * Zeroizes the trapdoor for security. The simulator holds sensitive
 * state (the CRS trapdoor) that should be cleared when done.
 */
void nizk_simulator_clear(nizk_simulator_state_t *sim) {
    volatile uint64_t *t = (volatile uint64_t*)&sim->trapdoor;
    for (int i = 0; i < NIZK_BIGINT_LIMBS; i++) {
        t[i] = 0;
    }
    sim->is_active = 0;
    sim->proof_count = 0;
}

/**
 * nizk_simulator_print - Print simulator state for debugging.
 *
 * Does NOT print the trapdoor (security).
 */
void nizk_simulator_print(const nizk_simulator_state_t *sim) {
    printf("=== NIZK Simulator State ===\n");
    printf("  Active:      %s\n", sim->is_active ? "yes" : "no");
    printf("  Proof count: %llu\n", (unsigned long long)sim->proof_count);
    printf("  Trapdoor:    [REDACTED]\n");
}
