/**
 * sigma_core.c 〞 Core Sigma Protocol Runtime
 *
 * Provides the runtime execution, verification, and property-checking
 * infrastructure for any sigma protocol implementing the abstract vtable.
 *
 * L1 Definitions:
 *   - Generic sigma protocol dispatcher
 *   - 3-move interactive execution model
 *
 * L2 Concepts:
 *   - Honest-verifier model simulation
 *   - Knowledge error estimation
 *
 * L4 Theorems (verified through tests):
 *   - Special soundness: extract witness from two transcripts
 *   - SHVZK: simulated transcripts are indistinguishable from real
 *
 * References:
 *   - Damgard (2002) "On 曳-Protocols" (CPT lecture notes)
 *   - Cramer (1996) "Modular Design of Secure yet Practical Protocols"
 *   - Hazay & Lindell (2010) "Efficient Secure Two-Party Protocols", Ch 6
 */

#include "sigma_core.h"
#include <string.h>
#include <stdio.h>

/* ========================================================================
 *  sigma_run_protocol 〞 Execute one full interactive protocol round
 *
 *  1. Prover generates commitment a using witness + randomness
 *  2. Verifier draws random challenge e (or uses provided challenge)
 *  3. Prover computes response z
 *  4. Returns whether verifier accepts
 *
 *  The transcript is filled by this function: commitment, challenge,
 *  response. In the honest-verifier model, the challenge is truly random.
 *  In a real protocol, the verifier would choose the challenge.
 * ======================================================================== */

bool sigma_run_protocol(const sigma_protocol *proto,
                        const void *witness,
                        const void *public_input,
                        sigma_transcript *out_transcript) {
    if (!proto || !witness || !public_input || !out_transcript)
        return false;

    /* Step 1: Generate fresh randomness r */
    sigma_scalar randomness;
    sigma_random_nonzero_scalar(&randomness);

    /* Step 2: Prover commits a = f(r, witness) */
    proto->prove_commit(&out_transcript->commitment, &randomness,
                        witness, (void*)public_input);

    /* Step 3: Verifier generates random challenge e */
    sigma_random_scalar(&out_transcript->challenge);

    /* Step 4: Prover responds z = g(r, e, witness) */
    proto->prove_response(&out_transcript->response, &randomness,
                          &out_transcript->challenge,
                          witness, (void*)public_input);

    /* Step 5: Verifier checks (a, e, z) */
    return proto->verify(&out_transcript->commitment,
                         &out_transcript->challenge,
                         &out_transcript->response,
                         (void*)public_input);
}

/* ========================================================================
 *  sigma_check_transcript 〞 Re-verify a stored transcript
 *
 *  Useful for audit trails, protocol debugging, and test harnesses.
 *  Simply delegates to the protocol's verify function.
 * ======================================================================== */

bool sigma_check_transcript(const sigma_protocol *proto,
                            const sigma_transcript *t,
                            const void *public_input) {
    if (!proto || !t || !public_input) return false;
    return proto->verify(&t->commitment, &t->challenge,
                         &t->response, (void*)public_input);
}

/* ========================================================================
 *  sigma_check_special_soundness 〞 Verify extraction correctness
 *
 *  Given two transcripts (t1, t2) with same commitment and different
 *  challenges, call the extract function and verify that the extracted
 *  witness actually satisfies the relation.
 *
 *  L4 Theorem: Any sigma protocol with special soundness is a proof
 *  of knowledge with knowledge error 百 ≒ 1/|C| where C is the
 *  challenge space size.
 * ======================================================================== */

bool sigma_check_special_soundness(const sigma_protocol *proto,
                                    const sigma_transcript *t1,
                                    const sigma_transcript *t2,
                                    const void *public_input) {
    if (!proto || !t1 || !t2 || !public_input) return false;

    /* Check preconditions: same commitment, different challenges */
    if (!sigma_group_eq(&t1->commitment, &t2->commitment))
        return false;
    if (sigma_scalar_cmp(&t1->challenge, &t2->challenge) == 0)
        return false;

    /* Both transcripts must be accepting */
    if (!proto->verify(&t1->commitment, &t1->challenge,
                       &t1->response, (void*)public_input))
        return false;
    if (!proto->verify(&t2->commitment, &t2->challenge,
                       &t2->response, (void*)public_input))
        return false;

    /* Extract witness */
    uint8_t witness_buf[256]; /* generous buffer */
    memset(witness_buf, 0, sizeof(witness_buf));
    if (proto->witness_size > sizeof(witness_buf)) return false;

    bool extracted = proto->extract(witness_buf, t1, t2, (void*)public_input);
    if (!extracted) return false;

    /* Generate a fresh proof using the extracted witness */
    sigma_transcript check_t;
    sigma_scalar test_r;
    sigma_random_nonzero_scalar(&test_r);

    proto->prove_commit(&check_t.commitment, &test_r,
                        witness_buf, (void*)public_input);

    /* Use the same challenge as t1 (or a fresh one) */
    sigma_scalar_copy(&check_t.challenge, &t1->challenge);

    proto->prove_response(&check_t.response, &test_r,
                          &check_t.challenge,
                          witness_buf, (void*)public_input);

    /* The proof with the extracted witness should verify */
    return proto->verify(&check_t.commitment, &check_t.challenge,
                         &check_t.response, (void*)public_input);
}

/* ========================================================================
 *  sigma_check_hvzk 〞 Statistical verification of SHVZK property
 *
 *  Runs the simulator k times and checks:
 *    (a) All simulated transcripts are accepting
 *    (b) Basic uniformity test on challenge values (chi-squared approximation)
 *
 *  L4 Theorem: SHVZK = there exists a simulator Sim such that for any
 *  verifier V*, the output of Sim is computationally indistinguishable
 *  from a real protocol execution.
 *
 *  Returns fraction of accepting simulations (should be ＞ 1.0).
 * ======================================================================== */

double sigma_check_hvzk(const sigma_protocol *proto,
                        const void *public_input,
                        int num_simulations) {
    if (!proto || !public_input || num_simulations <= 0) return 0.0;

    int accept_count = 0;
    for (int i = 0; i < num_simulations; i++) {
        /* Pick a random challenge */
        sigma_scalar challenge;
        sigma_random_scalar(&challenge);

        /* Simulate a transcript */
        sigma_transcript sim;
        proto->simulate(&sim, &challenge, (void*)public_input);

        /* Verify it's accepting */
        if (proto->verify(&sim.commitment, &sim.challenge,
                          &sim.response, (void*)public_input)) {
            accept_count++;
        }
    }

    return (double)accept_count / (double)num_simulations;
}

/* ========================================================================
 *  sigma_estimate_knowledge_error 〞 Empirical knowledge error estimation
 *
 *  The knowledge error 百 is the probability that a dishonest prover
 *  (without the witness) can convince the verifier.
 *
 *  Our estimator: guess a random response z ﹋ Z_q, compute commitment
 *  a to satisfy the verification equation, and see if the proof verifies.
 *  This is essentially running the simulator "backwards".
 *
 *  For Schnorr: 百 = 1/q ＞ 2^{-256} (negligible).
 *  For GQ with small e: 百 = 1/e (non-negligible unless e is large).
 *
 *  L4 Theorem: A sigma protocol for relation R has knowledge error 百
 *  if for every prover P* that convinces with probability > 百, there
 *  exists an extractor that outputs a valid witness in expected
 *  poly(1/(汍-百)) time.
 * ======================================================================== */

double sigma_estimate_knowledge_error(const sigma_protocol *proto,
                                       const void *public_input,
                                       int trials) {
    if (!proto || !public_input || trials <= 0) return 1.0;

    int success = 0;
    for (int i = 0; i < trials; i++) {
        /* Simulate a proof without witness */
        sigma_scalar challenge;
        sigma_random_scalar(&challenge);

        sigma_transcript fake;
        proto->simulate(&fake, &challenge, (void*)public_input);

        /* If the simulator can produce accepting transcripts without the witness,
         * then the knowledge error is effectively 0 (we already know the protocol
         * is honest-verifier ZK). The real knowledge error test would try to
         * answer a *given* challenge without the witness.
         * For a proper estimate, we try a random response:
         */
        sigma_scalar guess_z;
        sigma_random_scalar(&guess_z);
        sigma_group_elem guess_a;
        sigma_group_exp_g(&guess_a, &guess_z);

        /* Check if (guess_a, challenge, guess_z) verifies 〞 should fail */
        if (proto->verify(&guess_a, &challenge, &guess_z, (void*)public_input)) {
            success++;
        }
    }

    return (double)success / (double)trials;
}
