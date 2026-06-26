#ifndef SIGMA_CORE_H
#define SIGMA_CORE_H

/**
 * sigma_core.h ? Abstract Sigma Protocol Interface
 *
 * Defines the 3-move sigma protocol structure (commit, challenge, response)
 * and the transcript data type. Every concrete sigma protocol implements
 * this interface.
 *
 * L1 Definitions:
 *   - Sigma protocol: 3-move public-coin interactive proof
 *   - (a, e, z) transcript: commitment a, challenge e, response z
 *   - Special soundness: from two accepting transcripts (a,e,z), (a,e',z')
 *     with same commitment a and e ? e', can extract witness
 *   - Special honest-verifier zero-knowledge (SHVZK):
 *     simulator can generate (a,e,z) without witness, given e in advance
 *
 * L2 Core Concepts:
 *   - Proof of knowledge: prover proves knowledge of witness w s.t. R(x,w)=1
 *   - Honest-verifier model: verifier chooses challenge uniformly at random
 *   - Knowledge error ?: probability verifier accepts without witness ? ?
 *
 * References:
 *   - Damgard (2002) "On ?-Protocols" (CPT lecture notes)
 *   - Cramer (1996) "Modular Design of Secure yet Practical Protocols"
 *   - Hazay & Lindell (2010) Efficient Secure Two-Party Protocols, Ch 6
 *   - Goldreich (2004) Foundations of Cryptography I, ?4.7
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "sigma_math.h"

/* ??? Sigma Protocol Transcript ????????????????????????????????????? */

/**
 * sigma_transcript ? A complete (a, e, z) transcript.
 *
 * - commitment: group element (prover's first message)
 * - challenge:  scalar in Z_q (verifier's random challenge)
 * - response:   scalar in Z_q (prover's answer)
 *
 * Theorem (Special Soundness): If a sigma protocol has special
 * soundness, then given two accepting transcripts (a, e, z) and
 * (a, e', z') with same commitment a and e ? e', a witness w can
 * be extracted in polynomial time.
 */
typedef struct {
    sigma_group_elem commitment;  /* a = g^r (or protocol-specific) */
    sigma_scalar     challenge;   /* e ? Z_q, verifier's random challenge */
    sigma_scalar     response;    /* z = r + e?x mod q (for Schnorr) */
} sigma_transcript;

/**
 * sigma_proof ? A non-interactive proof (Fiat-Shamir transform).
 *
 * Contains the commitment and response; the challenge is derived
 * via hash function (random oracle).
 */
typedef struct {
    sigma_group_elem commitment;  /* a */
    sigma_scalar     response;    /* z */
    sigma_scalar     challenge;   /* e = H(a || msg) for verification */
} sigma_proof;

/* ??? Sigma Protocol VTable ????????????????????????????????????????? */

/**
 * sigma_protocol ? Abstract interface for any sigma protocol.
 *
 * Each concrete sigma protocol (Schnorr, Chaum-Pedersen, GQ, etc.)
 * provides these function pointers. The knowledge extractor and
 * zero-knowledge simulator are protocol-specific.
 */
typedef struct sigma_protocol sigma_protocol;

struct sigma_protocol {
    const char *name;

    /**
     * prove_commit ? First phase: generate commitment a from randomness r.
     * Returns commitment a = g^r (or protocol-specific).
     * Called by prover.
     */
    void (*prove_commit)(sigma_group_elem *commitment,
                         const sigma_scalar *randomness,
                         const void *witness,
                         const void *public_input);

    /**
     * prove_response ? Third phase: compute response z given challenge e.
     * z = r + e?w mod q (or protocol-specific).
     * Called by prover after receiving challenge.
     */
    void (*prove_response)(sigma_scalar *response,
                           const sigma_scalar *randomness,
                           const sigma_scalar *challenge,
                           const void *witness,
                           const void *public_input);

    /**
     * verify ? Verifier checks: does (a, e, z) accept?
     * For Schnorr: g^z ? a ? y^e (mod p) where y = g^x.
     * Returns true iff the proof is valid.
     */
    bool (*verify)(const sigma_group_elem *commitment,
                   const sigma_scalar *challenge,
                   const sigma_scalar *response,
                   const void *public_input);

    /**
     * extract ? Knowledge extractor (special soundness).
     * Given two accepting transcripts with same a and e ? e',
     * extract the witness w. Implements the forking lemma.
     * Returns true on success.
     */
    bool (*extract)(void *witness_out,
                    const sigma_transcript *t1,
                    const sigma_transcript *t2,
                    const void *public_input);

    /**
     * simulate ? SHVZK simulator.
     * Given challenge e (in advance), produces accepting transcript
     * (a, e, z) without knowing witness.
     */
    void (*simulate)(sigma_transcript *transcript,
                     const sigma_scalar *challenge,
                     const void *public_input);

    /**
     * public_input_size ? Size of public input structure in bytes.
     */
    size_t public_input_size;

    /**
     * witness_size ? Size of witness structure in bytes.
     */
    size_t witness_size;
};

/* ??? Concrete Protocol Types ??????????????????????????????????????? */

/**
 * sigma_schnorr_public ? Public input for Schnorr protocol.
 * Statement: "I know x such that y = g^x mod p."
 * - y: public key / group element derived from witness
 * - generator: the group generator g
 */
typedef struct {
    sigma_group_elem y;          /* y = g^x mod p (public key) */
    sigma_group_elem generator;  /* g (group generator) */
} sigma_schnorr_public;

/**
 * sigma_schnorr_witness ? Witness for Schnorr protocol.
 * x ? Z_q is the discrete logarithm: y = g^x mod p.
 */
typedef struct {
    sigma_scalar x;  /* secret key / discrete log */
} sigma_schnorr_witness;

/**
 * sigma_chaum_pedersen_public ? Public input for Chaum-Pedersen.
 * Statement: "I know x such that y1 = g1^x ? y2 = g2^x."
 * Proves equality of discrete logarithms across bases.
 */
typedef struct {
    sigma_group_elem y1;  /* y1 = g1^x */
    sigma_group_elem y2;  /* y2 = g2^x */
    sigma_group_elem g1;  /* base 1 */
    sigma_group_elem g2;  /* base 2 */
} sigma_chaum_pedersen_public;

/**
 * sigma_chaum_pedersen_witness ? Witness for CP.
 */
typedef struct {
    sigma_scalar x;  /* the exponent: log_{g1}(y1) = log_{g2}(y2) = x */
} sigma_chaum_pedersen_witness;

/* ??? Core Protocol Functions ??????????????????????????????????????? */

/**
 * sigma_run_protocol ? Execute one full interactive run of a sigma protocol.
 *
 * Prover (has witness) and verifier complete a 3-move round.
 * Returns true iff verifier accepts.
 *
 * L2 Core Concept: This is the interactive honest-verifier model.
 * In the real protocol, challenge is random from verifier.
 * In Fiat-Shamir, challenge = H(commitment).
 */
bool sigma_run_protocol(const sigma_protocol *proto,
                        const void *witness,
                        const void *public_input,
                        sigma_transcript *out_transcript);

/**
 * sigma_check_transcript ? Re-verify a stored transcript.
 * Useful for audit and debugging.
 */
bool sigma_check_transcript(const sigma_protocol *proto,
                            const sigma_transcript *t,
                            const void *public_input);

/**
 * sigma_check_special_soundness ? Verify that extraction works.
 * Given two transcripts with same a, e?e', verify that the extracted
 * witness satisfies the relation R(public, witness) = 1.
 *
 * L4 Theorem: Special soundness ? proof of knowledge.
 */
bool sigma_check_special_soundness(const sigma_protocol *proto,
                                   const sigma_transcript *t1,
                                   const sigma_transcript *t2,
                                   const void *public_input);

/**
 * sigma_check_hvzk ? Verify SHVZK property.
 * Run simulator k times; verify all transcripts are accepting AND
 * distribution is uniform (basic statistical test).
 * Returns fraction of successful simulations.
 *
 * L4 Theorem: SHVZK ? honest-verifier zero-knowledge.
 */
double sigma_check_hvzk(const sigma_protocol *proto,
                        const void *public_input,
                        int num_simulations);

/* ??? Knowledge Error Estimation ???????????????????????????????????? */

/**
 * sigma_estimate_knowledge_error ? Empirically estimate knowledge error.
 * Runs prover without witness (just random guessing) and counts
 * acceptance rate. Theoretical: ? = 1/q for Schnorr (negligible).
 */
double sigma_estimate_knowledge_error(const sigma_protocol *proto,
                                      const void *public_input,
                                      int trials);

#endif /* SIGMA_CORE_H */
