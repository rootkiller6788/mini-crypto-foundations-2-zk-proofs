/**
 * nizk_sigma.c - Sigma Protocol Implementation
 *
 * L1 Definition: A Sigma Protocol is a 3-move interactive proof between
 * Prover and Verifier for an NP relation R(x, w):
 *   Prover -> Verifier: commitment t
 *   Prover <- Verifier: challenge c (random)
 *   Prover -> Verifier: response s
 *
 * Properties:
 *   - Completeness: If (x,w) in R, honest prover always convinces verifier
 *   - Special Soundness: Given (t,c,s) and (t,c',s') with c != c',
 *     witness w can be extracted
 *   - Honest-Verifier Zero-Knowledge (HVZK): Simulator can generate
 *     indistinguishable transcripts without witness
 *
 * Reference: Damgard, I. "On Sigma Protocols." 2002.
 *            Cramer, R. "Modular Design of Secure yet Practical
 *            Cryptographic Protocols." PhD Thesis, 1996.
 *
 * Course Mapping:
 *   MIT 6.875: Sigma protocols, special soundness
 *   Stanford CS355: Interactive proof systems
 *   ETH 263-4650: Sigma protocol theory
 */

#include "nizk_sigma.h"
#include "nizk_group.h"
#include "nizk_crs.h"
#include <string.h>
#include <stdio.h>

/* =========================================================================
 * L5: Schnorr Protocol - Proving Knowledge of Discrete Logarithm
 * ========================================================================= */

/**
 * nizk_schnorr_commit - Generate commitment for Schnorr protocol.
 *
 * L5 Knowledge Point: Schnorr Identification Protocol Commit Phase
 *
 * Proves knowledge of w such that h = g^w (discrete log).
 *
 * Commit phase:
 *   1. Prover picks random ephemeral v <- Z_q
 *   2. Prover computes commitment t = g^v
 *   3. Sends t to verifier, keeps v secret
 *
 * The ephemeral v MUST be:
 *   - Uniformly random (otherwise leaks information about w)
 *   - Never reused (if reused with two challenges c1,c2, then:
 *     w = (s1 - s2) / (c1 - c2) mod q)
 *   - Kept secret until challenge is received
 *
 * Reference: Schnorr, C.P. "Efficient Identification and Signatures
 *            for Smart Cards." CRYPTO 1989.
 *
 * Course: Stanford CS355 Schnorr Protocol, MIT 6.875 Sigma Protocols
 */
void nizk_schnorr_commit(nizk_sigma_commitment_t *commitment,
                          nizk_scalar_t *ephemeral,
                          const nizk_group_params_t *params) {
    /* Generate random ephemeral secret v <- Z_q */
    nizk_scalar_rand(ephemeral, params);

    /* Compute t = g^v */
    nizk_group_elem_t gen;
    nizk_bigint_copy(&gen.elem, &params->g);
    nizk_group_exp(&commitment->t, &gen, ephemeral, params);

    commitment->has_aux = 0;
    nizk_bigint_one(&commitment->t_aux.elem);
}

/**
 * nizk_schnorr_respond - Generate response for Schnorr protocol.
 *
 * L5 Knowledge Point: Challenge-Response Mechanism
 *
 * Response: s = v + c * w (mod q)
 *
 * Where v = ephemeral secret, c = challenge, w = witness (sk).
 *
 * Verification equation: g^s == t * h^c
 * Proof:
 *   g^s = g^{v + c*w} = g^v * g^{c*w} = t * (g^w)^c = t * h^c
 *
 * Security: If the same v is reused with challenges c1,c2:
 *   s1 = v + c1*w, s2 = v + c2*w
 *   => w = (s1 - s2) / (c1 - c2) mod q
 * This is why nonce reuse in Schnorr/ECDSA/EdDSA is catastrophic.
 *
 * The response s is a single scalar that encodes the prover's knowledge
 * of w, masked by the ephemeral secret v.
 */
void nizk_schnorr_respond(nizk_sigma_response_t *response,
                           const nizk_scalar_t *witness,
                           const nizk_scalar_t *ephemeral,
                           const nizk_sigma_challenge_t *challenge,
                           const nizk_group_params_t *params) {
    /* s = v + c * w (mod q) */
    nizk_scalar_t cw;
    nizk_scalar_mul(&cw, &challenge->c, witness, params);
    nizk_scalar_add(&response->s, ephemeral, &cw, params);

    response->has_aux = 0;
    nizk_scalar_zero(&response->s_aux);
}

/**
 * nizk_schnorr_verify - Verify a Schnorr protocol transcript.
 *
 * L5 Knowledge Point: Sigma Protocol Verification Equation
 *
 * Checks: g^s == t * h^c
 *
 * Completeness proof:
 *   Given t = g^v, s = v + c*w, h = g^w:
 *   LHS: g^s = g^{v + c*w}
 *   RHS: t * h^c = g^v * (g^w)^c = g^{v + c*w}
 *   LHS == RHS. QED.
 *
 * Complexity: O(log q) group operations (two exponentiations or
 * one multi-exponentiation).
 */
int nizk_schnorr_verify(const nizk_sigma_statement_t *stmt,
                         const nizk_sigma_commitment_t *commitment,
                         const nizk_sigma_challenge_t *challenge,
                         const nizk_sigma_response_t *response,
                         const nizk_group_params_t *params) {
    /* Compute LHS: g^s */
    nizk_group_elem_t gen, lhs;
    nizk_bigint_copy(&gen.elem, &params->g);
    nizk_group_exp(&lhs, &gen, &response->s, params);

    /* Compute RHS: t^1 * h^c */
    nizk_group_elem_t rhs;
    nizk_scalar_t one;
    nizk_scalar_set_u64(&one, 1);
    nizk_group_multi_exp(&rhs, &commitment->t, &one,
                          &stmt->public_key, &challenge->c, params);

    return nizk_group_elem_eq(&lhs, &rhs);
}

/* =========================================================================
 * L5: Special Soundness Extractor - Witness Extraction from Two Transcripts
 * ========================================================================= */

/**
 * nizk_schnorr_extract - Extract witness from two accepting transcripts.
 *
 * L4 Theorem: Special Soundness of Schnorr Protocol
 *
 * Given two accepting transcripts (t, c1, s1) and (t, c2, s2) with
 * c1 != c2 and the SAME commitment t, the witness w can be extracted:
 *
 *   w = (s1 - s2) * (c1 - c2)^{-1} mod q
 *
 * Proof:
 *   From verification: g^{s1} = t * h^{c1} and g^{s2} = t * h^{c2}
 *   Divide: g^{s1-s2} = h^{c1-c2}
 *   Since h = g^w: g^{s1-s2} = g^{w*(c1-c2)}
 *   Therefore: s1 - s2 = w * (c1 - c2) mod q (since g has order q)
 *   And: w = (s1 - s2) * (c1 - c2)^{-1} mod q
 *   QED.
 *
 * This extractor is the Knowledge-of-Exponent Assumption (KEA) in action
 * and is the foundation for proving that Schnorr is a "proof of knowledge."
 *
 * Applications of the extractor in security proofs:
 *   - Schnorr signatures: unforgeability reduction to DLOG
 *   - Fiat-Shamir NIZK: soundness proof in ROM via forking lemma
 *   - Threshold signatures: security against rogue key attacks
 *
 * Course: MIT 6.875 Knowledge Extractors, ETH 263-4650 Special Soundness
 */
int nizk_schnorr_extract(nizk_scalar_t *witness,
                          const nizk_sigma_transcript_t *t1,
                          const nizk_sigma_transcript_t *t2,
                          const nizk_group_params_t *params) {
    /* Verify same commitment */
    if (!nizk_group_elem_eq(&t1->commitment.t, &t2->commitment.t)) {
        return 0;  /* Different commitments: cannot extract */
    }

    /* Verify different challenges */
    if (nizk_scalar_cmp(&t1->challenge.c, &t2->challenge.c) == 0) {
        return 0;  /* Same challenge: cannot extract */
    }

    /* Compute s_diff = s1 - s2 mod q */
    nizk_scalar_t s_diff;
    nizk_scalar_sub(&s_diff, &t1->response.s, &t2->response.s, params);

    /* Compute c_diff = c1 - c2 mod q */
    nizk_scalar_t c_diff;
    nizk_scalar_sub(&c_diff, &t1->challenge.c, &t2->challenge.c, params);

    /* c_diff non-zero guaranteed since c1 != c2 */
    if (nizk_scalar_is_zero(&c_diff)) return 0;

    /* Compute c_diff^{-1} mod q */
    nizk_scalar_t c_diff_inv;
    nizk_scalar_inv(&c_diff_inv, &c_diff, params);

    /* w = s_diff * c_diff^{-1} mod q */
    nizk_scalar_mul(witness, &s_diff, &c_diff_inv, params);

    return 1;
}

/* =========================================================================
 * L5: Chaum-Pedersen Protocol - Equality of Discrete Logarithms
 * ========================================================================= */

/**
 * nizk_chaum_pedersen_commit - Generate commitment for Chaum-Pedersen.
 *
 * L5 Knowledge Point: Chaum-Pedersen DLOG Equality Protocol
 *
 * Proves: log_g(u) = log_h(v) without revealing the value.
 * i.e., "I know w such that u = g^w AND v = h^w"
 *
 * Commit phase:
 *   1. Prover picks random ephemeral r <- Z_q
 *   2. Computes t1 = g^r, t2 = h^r
 *
 * Applications:
 *   - Verifiable encryption: u = g^w (public key), v = h^w (encrypted key)
 *     Proving equality proves v encrypts the secret key for u
 *   - Threshold cryptography: proving shares correspond to same secret
 *   - Mix-nets: proving correct shuffling (Neff 2001)
 *
 * Reference: Chaum, D. and Pedersen, T.P. "Wallet Databases with
 *            Observers." CRYPTO 1992.
 *
 * Course: Princeton COS 551 Verifiable Encryption, MIT 6.875 DLOG Proofs
 */
void nizk_chaum_pedersen_commit(nizk_sigma_commitment_t *commitment,
                                 nizk_scalar_t *ephemeral,
                                 const nizk_group_elem_t *base1,
                                 const nizk_group_elem_t *base2,
                                 const nizk_group_params_t *params) {
    /* Generate random ephemeral r <- Z_q */
    nizk_scalar_rand(ephemeral, params);

    /* Compute t1 = base1^r, t2 = base2^r */
    nizk_group_exp(&commitment->t, base1, ephemeral, params);
    nizk_group_exp(&commitment->t_aux, base2, ephemeral, params);
    commitment->has_aux = 1;
}

/**
 * nizk_chaum_pedersen_respond - Generate response for Chaum-Pedersen.
 *
 * Response: s = r + c * w (mod q)
 * Single response because both equations share the same witness w.
 */
void nizk_chaum_pedersen_respond(nizk_sigma_response_t *response,
                                  const nizk_scalar_t *witness,
                                  const nizk_scalar_t *ephemeral,
                                  const nizk_sigma_challenge_t *challenge,
                                  const nizk_group_params_t *params) {
    nizk_scalar_t cw;
    nizk_scalar_mul(&cw, &challenge->c, witness, params);
    nizk_scalar_add(&response->s, ephemeral, &cw, params);

    response->has_aux = 0;
    nizk_scalar_zero(&response->s_aux);
}

/**
 * nizk_chaum_pedersen_verify - Verify Chaum-Pedersen transcript.
 *
 * Checks BOTH equations simultaneously:
 *   g^s == t1 * u^c
 *   h^s == t2 * v^c
 *
 * Both must hold. If either fails, proof is rejected.
 * This ensures w is the same for both discrete log relationships.
 */
int nizk_chaum_pedersen_verify(const nizk_sigma_statement_t *stmt,
                                const nizk_sigma_commitment_t *commitment,
                                const nizk_sigma_challenge_t *challenge,
                                const nizk_sigma_response_t *response,
                                const nizk_group_params_t *params) {
    nizk_scalar_t one;
    nizk_scalar_set_u64(&one, 1);

    /* Check 1: g^s == t * u^c */
    nizk_group_elem_t gen, lhs1;
    nizk_bigint_copy(&gen.elem, &params->g);
    nizk_group_exp(&lhs1, &gen, &response->s, params);
    nizk_group_elem_t rhs1;
    nizk_group_multi_exp(&rhs1, &commitment->t, &one,
                          &stmt->public_key, &challenge->c, params);
    if (!nizk_group_elem_eq(&lhs1, &rhs1)) return 0;

    /* Check 2: h^s == t_aux * v^c */
    nizk_group_elem_t lhs2;
    nizk_group_exp(&lhs2, &stmt->base_h, &response->s, params);
    nizk_group_elem_t rhs2;
    nizk_group_multi_exp(&rhs2, &commitment->t_aux, &one,
                          &stmt->aux_element, &challenge->c, params);
    if (!nizk_group_elem_eq(&lhs2, &rhs2)) return 0;

    return 1;
}

/* =========================================================================
 * L5: OR-Proof - Proving Knowledge of One of Two Secrets
 * ========================================================================= */

/**
 * nizk_or_prove_commit - Generate commitments for OR proof.
 *
 * L5 Knowledge Point: OR-Composition of Sigma Protocols
 *
 * Proves knowledge of w1 OR w2 without revealing which one is known.
 *
 * Algorithm (Cramer-Damgard-Schoenmakers):
 *   Let b = known_branch (0 or 1), u = unknown branch = 1-b.
 *
 *   For UNKNOWN branch (simulated via HVZK):
 *     1. Pick random challenge c_sim and response s_sim
 *     2. Compute t_sim = g^{s_sim} * pk_u^{-c_sim}
 *        (This uses the HVZK simulator)
 *
 *   For KNOWN branch (real protocol):
 *     1. Pick random ephemeral v, compute t_real = g^v
 *
 *   Later: c_real = c_total - c_sim (mod q)
 *
 * The key insight: the prover can simulate one side because HVZK
 * produces valid-looking transcripts without the witness. For the
 * real side, the prover uses the actual witness.
 *
 * Reference: Cramer, Damgard, Schoenmakers. "Proofs of Partial Knowledge
 *            and Simplified Design of Witness Hiding Protocols." CRYPTO 1994.
 *
 * Course: MIT 6.875 OR-Proofs, ETH 263-4650 Protocol Composition
 */
void nizk_or_prove_commit(nizk_sigma_commitment_t *commitments,
                           nizk_scalar_t *ephemerals,
                           nizk_scalar_t *sim_challenges,
                           const nizk_or_statement_t *stmt,
                           const nizk_or_witness_t *witness,
                           const nizk_group_params_t *params) {
    int known = witness->known_branch;
    int unknown = 1 - known;

    nizk_group_elem_t gen;
    nizk_bigint_copy(&gen.elem, &params->g);

    /* UNKNOWN branch: simulate using HVZK */
    nizk_scalar_rand(&sim_challenges[unknown], params);
    nizk_scalar_rand(&ephemerals[unknown], params);

    /* t_sim = g^{s_sim} * pk_u^{-c_sim}
     * pk_u^{-c_sim} = pk_u^{q - c_sim} */
    nizk_scalar_t neg_c;
    nizk_scalar_neg(&neg_c, &sim_challenges[unknown], params);
    nizk_group_elem_t pk_neg_c;
    nizk_group_exp(&pk_neg_c, &stmt->stmt[unknown].public_key,
                    &neg_c, params);
    nizk_group_elem_t g_s;
    nizk_group_exp(&g_s, &gen, &ephemerals[unknown], params);
    nizk_group_op(&commitments[unknown].t, &g_s, &pk_neg_c, params);
    commitments[unknown].has_aux = 0;

    /* KNOWN branch: real Schnorr commit */
    nizk_scalar_rand(&ephemerals[known], params);
    nizk_group_exp(&commitments[known].t, &gen, &ephemerals[known], params);
    commitments[known].has_aux = 0;
}

/**
 * nizk_or_prove_respond - Generate responses for OR proof.
 *
 * Challenge splitting:
 *   c_total from Fiat-Shamir hash
 *   c_real = c_total - c_sim (mod q)
 *
 * This ensures c_0 + c_1 = c_total, which the verifier will check.
 */
void nizk_or_prove_respond(nizk_sigma_response_t *responses,
                            nizk_sigma_challenge_t *challenges,
                            const nizk_scalar_t *witness,
                            const nizk_scalar_t *ephemeral,
                            const nizk_scalar_t *sim_challenge,
                            const nizk_sigma_challenge_t *real_challenge,
                            int known_branch,
                            const nizk_group_params_t *params) {
    int unknown = 1 - known_branch;

    /* Simulated branch: use pre-computed values */
    nizk_scalar_copy(&challenges[unknown].c, sim_challenge);
    nizk_scalar_copy(&responses[unknown].s, ephemeral);
    responses[unknown].has_aux = 0;

    /* Real branch: respond to the real challenge */
    nizk_scalar_copy(&challenges[known_branch].c, &real_challenge->c);
    nizk_scalar_t cw;
    nizk_scalar_mul(&cw, &real_challenge->c, witness, params);
    nizk_scalar_add(&responses[known_branch].s, ephemeral, &cw, params);
    responses[known_branch].has_aux = 0;
}

/**
 * nizk_or_verify - Verify an OR proof.
 *
 * Checks: c_0 + c_1 == combined_challenge (mod q)
 * AND both individual Schnorr verifications pass.
 *
 * Soundness argument:
 * A cheating prover who knows NEITHER witness would need to guess
 * one challenge before seeing c_total. In the ROM, c_total = H(stmt||t)
 * cannot be predicted, so the prover can only satisfy one branch
 * (which requires knowing the corresponding witness).
 */
int nizk_or_verify(const nizk_or_statement_t *stmt,
                    const nizk_sigma_commitment_t *commitments,
                    const nizk_sigma_challenge_t *challenges,
                    const nizk_sigma_response_t *responses,
                    const nizk_sigma_challenge_t *combined_challenge,
                    const nizk_group_params_t *params) {
    /* Check c_0 + c_1 == combined_challenge (mod q) */
    nizk_scalar_t sum;
    nizk_scalar_add(&sum, &challenges[0].c, &challenges[1].c, params);
    if (nizk_scalar_cmp(&sum, &combined_challenge->c) != 0) {
        return 0;
    }

    /* Verify both branches */
    nizk_scalar_t one;
    nizk_scalar_set_u64(&one, 1);
    nizk_group_elem_t gen;
    nizk_bigint_copy(&gen.elem, &params->g);

    for (int i = 0; i < 2; i++) {
        nizk_group_elem_t lhs;
        nizk_group_exp(&lhs, &gen, &responses[i].s, params);

        nizk_group_elem_t rhs;
        nizk_group_multi_exp(&rhs, &commitments[i].t, &one,
                              &stmt->stmt[i].public_key,
                              &challenges[i].c, params);

        if (!nizk_group_elem_eq(&lhs, &rhs)) return 0;
    }

    return 1;
}

/* =========================================================================
 * L5: AND-Proof - Proving Knowledge of Two Secrets
 * ========================================================================= */

/**
 * nizk_and_prove_commit - Generate commitments for AND proof.
 *
 * L5 Knowledge Point: AND-Composition of Sigma Protocols
 *
 * Proves knowledge of w1 AND w2 simultaneously.
 * Uses the SAME challenge for both sub-protocols.
 *
 * This is the basis for representation proofs:
 *   "I know (m, r) such that C = g^m * h^r"
 * interpreted as: I know m = log_g(C/h^r) AND r = log_h(C/g^m)
 *
 * The AND composition is straightforward: parallel execution with
 * a single verifier challenge.
 */
void nizk_and_prove_commit(nizk_sigma_commitment_t *commitments,
                            nizk_scalar_t *ephemerals,
                            const nizk_group_params_t *params) {
    nizk_group_elem_t gen;
    nizk_bigint_copy(&gen.elem, &params->g);

    nizk_scalar_rand(&ephemerals[0], params);
    nizk_scalar_rand(&ephemerals[1], params);
    nizk_group_exp(&commitments[0].t, &gen, &ephemerals[0], params);
    nizk_group_exp(&commitments[1].t, &gen, &ephemerals[1], params);
    commitments[0].has_aux = 0;
    commitments[1].has_aux = 0;
}

/**
 * nizk_and_prove_respond - Generate responses for AND proof.
 *
 * All sub-protocols use the SAME challenge c.
 * s_i = v_i + c * w_i (mod q) for each i.
 */
void nizk_and_prove_respond(nizk_sigma_response_t *responses,
                             const nizk_scalar_t *witnesses,
                             const nizk_scalar_t *ephemerals,
                             const nizk_sigma_challenge_t *challenge,
                             int num_witnesses,
                             const nizk_group_params_t *params) {
    for (int i = 0; i < num_witnesses; i++) {
        nizk_scalar_t cw;
        nizk_scalar_mul(&cw, &challenge->c, &witnesses[i], params);
        nizk_scalar_add(&responses[i].s, &ephemerals[i], &cw, params);
        responses[i].has_aux = 0;
    }
}

/**
 * nizk_and_verify - Verify an AND proof.
 *
 * All sub-protocol verifications must pass.
 * ALL verifications use the SAME challenge.
 */
int nizk_and_verify(const nizk_sigma_statement_t *stmts,
                     const nizk_sigma_commitment_t *commitments,
                     const nizk_sigma_challenge_t *challenge,
                     const nizk_sigma_response_t *responses,
                     int num_statements,
                     const nizk_group_params_t *params) {
    nizk_scalar_t one;
    nizk_scalar_set_u64(&one, 1);
    nizk_group_elem_t gen;
    nizk_bigint_copy(&gen.elem, &params->g);

    for (int i = 0; i < num_statements; i++) {
        nizk_group_elem_t lhs;
        nizk_group_exp(&lhs, &gen, &responses[i].s, params);

        nizk_group_elem_t rhs;
        nizk_group_multi_exp(&rhs, &commitments[i].t, &one,
                              &stmts[i].public_key, &challenge->c, params);

        if (!nizk_group_elem_eq(&lhs, &rhs)) return 0;
    }

    return 1;
}

/* =========================================================================
 * L2: HVZK Simulator - Generating Transcripts Without Witness
 * ========================================================================= */

/**
 * nizk_sigma_simulate_transcript - Simulate a complete sigma transcript.
 *
 * L2 Knowledge Point: HVZK Simulation
 *
 * The HVZK simulator produces (t, c, s) indistinguishable from a real
 * transcript WITHOUT knowing the witness w.
 *
 * Schnorr simulator:
 *   1. Pick random c <- Z_q
 *   2. Pick random s <- Z_q
 *   3. Compute t = g^s * h^{-c}
 *
 * This satisfies: g^s = t * h^c
 * (by construction: t = g^s * h^{-c} => g^s = t * h^c)
 *
 * Distribution analysis:
 *   Real:  v uniform, t = g^v, c = H(stmt||t), s = v + c*w
 *   Sim:   s uniform, c uniform, t = g^s * h^{-c}
 *
 * Both produce (t, c, s) where:
 *   - s is uniform in Z_q (in real: v is uniform, c*w shifts it)
 *   - c is uniform (in real: random oracle output)
 *   - t satisfies the verification equation
 *
 * In the ROM, these distributions are IDENTICAL, giving perfect ZK.
 *
 * This simulator is used in:
 *   - OR-proof construction (simulating the unknown branch)
 *   - NIZK simulation (via Fiat-Shamir + trapdoor)
 *   - Security proofs (showing the protocol reveals nothing)
 *
 * Course: Stanford CS355 HVZK, MIT 6.875 Simulation in ROM
 */
void nizk_sigma_simulate_transcript(nizk_sigma_transcript_t *transcript,
                                     const nizk_sigma_statement_t *stmt,
                                     const nizk_group_params_t *params) {
    /* Pick random challenge and response */
    nizk_scalar_rand(&transcript->challenge.c, params);
    nizk_scalar_rand(&transcript->response.s, params);
    transcript->response.has_aux = 0;

    /* Compute t = g^s * h^{-c} */
    nizk_group_elem_t gen;
    nizk_bigint_copy(&gen.elem, &params->g);

    /* h^{-c} = h^{q-c} */
    nizk_scalar_t neg_c;
    nizk_scalar_neg(&neg_c, &transcript->challenge.c, params);
    nizk_group_elem_t h_neg_c;
    nizk_group_exp(&h_neg_c, &stmt->public_key, &neg_c, params);

    /* t = g^s * h^{-c} */
    nizk_group_elem_t g_s;
    nizk_group_exp(&g_s, &gen, &transcript->response.s, params);
    nizk_group_op(&transcript->commitment.t, &g_s, &h_neg_c, params);
    transcript->commitment.has_aux = 0;
}

/* =========================================================================
 * L1: Statement Initialization
 * ========================================================================= */

/**
 * nizk_sigma_statement_init - Initialize a sigma protocol statement.
 *
 * The statement is the "public input x" in NP relation R(x,w).
 * For Schnorr: x = h (public key), w = sk (secret key).
 */
void nizk_sigma_statement_init(nizk_sigma_statement_t *stmt,
                                const nizk_group_elem_t *pubkey,
                                const nizk_group_elem_t *g,
                                const nizk_group_params_t *params) {
    (void)params;
    nizk_group_elem_copy(&stmt->public_key, pubkey);
    nizk_group_elem_copy(&stmt->base_g, g);
    nizk_bigint_one(&stmt->base_h.elem);
    nizk_bigint_one(&stmt->aux_element.elem);
    stmt->is_equality = 0;
}
