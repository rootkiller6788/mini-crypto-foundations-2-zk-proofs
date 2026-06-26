/*
 * kea.h — Knowledge of Exponent Assumption (KEA)
 *
 * L1 Definitions:
 *   - Knowledge of Exponent Assumption (KEA1):
 *     For any polynomial-time adversary A that on input (g, g^a)
 *     outputs a pair (C, C') such that C' = C^a, there exists an
 *     extractor E that can recover c = dlog_g(C) from A's internal state.
 *
 *   - KEA2 (Stronger variant):
 *     Given (g, g^a, g^b, g^{ab}), any adversary outputting (C, C^a, C^b, C^{ab})
 *     must "know" c = dlog_g(C).
 *
 *   - KEA3 (Bilinear variant):
 *     In bilinear groups: given [a]_1, [a]_2, any adversary outputting
 *     (C, a*C) in G1 and G2 must know c = dlog(C).
 *
 * L2 Core Concepts:
 *   - Non-black-box extraction: The extractor can inspect the adversary's code.
 *   - Falsifiability: KEA is non-falsifiable (Nao03 classification).
 *   - Generic group model: KEA holds in the generic group model.
 *   - Algebraic group model (AGM): KEA is "trivially" true by definition.
 *
 * L3 Mathematical Structures:
 *   - KEA Instance: (g, g^a) pair with secret exponent a
 *   - KEA Response: (C, C') pair claimed to satisfy C' = C^a
 *   - Extractor: algorithm that recovers the discrete logarithm
 *   - Adversary state: internal randomness and code of the adversary
 *   - Bilinear KEA: G1 × G2 → GT with asymmetric pairing
 *
 * References:
 *   - Damgard (1991) — Original KEA in the context of chosen-ciphertext security
 *   - Hada & Tanaka (1998) — KEA-based 3-round ZK
 *   - Bellare & Palacio (2004) — Formal analysis of KEA, non-falsifiability
 *   - Abe & Fehr (2007) — NIZK from KEA
 *   - Groth (2010) — SNARKs using pairing-based KEA
 *   - Bitansky et al. (2012) — SNARKs and extractable collision-resistant hashing
 *
 * Courses: Stanford CS255 (Cryptography), Berkeley CS276 (Graduate Cryptography),
 *          MIT 6.875 (Cryptography & Cryptanalysis)
 */

#ifndef KEA_H
#define KEA_H

#include "group.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/* ── KEA Instance ─────────────────────────────────────────── */

/*
 * A KEA1 challenge: (g, h = g^a) where a is a secret exponent.
 * The adversary must produce (C, C') with C' = C^a.
 */
typedef struct {
    GroupElement* base;         /* g — generator */
    GroupElement* challenge;    /* h = g^a — the challenge element */
    uint64_t      secret_exp;  /* a — secret exponent (unknown to adversary) */
    CyclicGroup*  group;       /* the underlying group */
    int           variant;     /* 1=KEA1, 2=KEA2, 3=KEA3 (bilinear) */
} KEAInstance;

/*
 * KEA2 extends the challenge with a second pair.
 * Input: (g, h1=g^a, h2=g^b, h3=g^{ab})
 * Adversary must output (C, C^a, C^b, C^{ab})
 */
typedef struct {
    GroupElement* base;         /* g */
    GroupElement* challenge_a;  /* g^a */
    GroupElement* challenge_b;  /* g^b */
    GroupElement* challenge_ab; /* g^{ab} */
    uint64_t      secret_a;     /* a */
    uint64_t      secret_b;     /* b */
    CyclicGroup*  group;
} KEA2Instance;

/* ── KEA Response ─────────────────────────────────────────── */

/*
 * Response to a KEA challenge.
 * (C, C') where allegedly C' = C^a.
 */
typedef struct {
    GroupElement* c;            /* C = g^r for some r */
    GroupElement* c_prime;      /* C' = h^r = g^{ar} */
    uint64_t      witness;      /* r — known to adversary, extracted */
    int           is_valid;     /* 1 if C' == C^a, 0 otherwise */
} KEAResponse;

/*
 * KEA2 response: (C, C_a, C_b, C_ab)
 * where allegedly C_a = C^a, C_b = C^b, C_ab = C^{ab}
 */
typedef struct {
    GroupElement* c;
    GroupElement* c_a;
    GroupElement* c_b;
    GroupElement* c_ab;
    uint64_t      witness;
    int           is_valid;
} KEA2Response;

/* ── Extractor ─────────────────────────────────────────────── */

/*
 * KEA Extractor: Given the adversary's code and randomness,
 * recovers the discrete logarithm (witness) r.
 *
 * In the generic/idealized setting, the extractor simply reads
 * the group element representations and extracts r.
 *
 * In practice (ROM), the extractor can rewind the adversary.
 */
typedef struct {
    int       num_queries;     /* number of extraction attempts */
    uint64_t* extracted_values;/* successfully extracted witnesses */
    int       success_count;   /* number of successful extractions */
    double    success_rate;    /* success_count / num_queries */
} KEAExtractor;

/*
 * Extract the exponent from an adversary's response.
 * Returns the extracted witness r, or 0 if extraction failed.
 *
 * L5: In the real world, extraction requires non-black-box access.
 * This implementation simulates extraction in the generic group model.
 */
typedef struct {
    /* Internal state of the simulated adversary */
    uint64_t    random_tape[32];   /* fixed randomness */
    int         tape_index;
    uint64_t    last_witness;      /* witness from most recent computation */
    CyclicGroup* group;
    /* Trace of group operations for extraction */
    uint64_t    op_count;
} KEAAdversaryState;

/* ── KEA Instance Management ─────────────────────────────── */

/* Create a KEA1 instance with a random secret exponent a */
KEAInstance* kea_instance_create(CyclicGroup* g);

/* Create a KEA2 instance with two random secret exponents */
KEA2Instance* kea2_instance_create(CyclicGroup* g);

/* Free KEA instance */
void kea_instance_free(KEAInstance* inst);

/* Free KEA2 instance */
void kea2_instance_free(KEA2Instance* inst);

/* Print a KEA instance */
void kea_instance_print(const KEAInstance* inst);

/* ── KEA Response Operations ──────────────────────────────── */

/* Create a KEA1 response with a given witness r */
KEAResponse* kea_response_create(const KEAInstance* inst, uint64_t r);

/* Create a KEA2 response with a given witness r */
KEA2Response* kea2_response_create(const KEA2Instance* inst, uint64_t r);

/* Verify a KEA1 response: check that C' = C^a */
int kea_response_verify(const KEAInstance* inst, const KEAResponse* resp);

/* Verify a KEA2 response: check all four pairings */
int kea2_response_verify(const KEA2Instance* inst, const KEA2Response* resp);

/* Free a KEA response */
void kea_response_free(KEAResponse* resp);

/* Free a KEA2 response */
void kea2_response_free(KEA2Response* resp);

/* Print a response */
void kea_response_print(const KEAResponse* resp);

/* ── Extractor Operations ─────────────────────────────────── */

/* Create an extractor */
KEAExtractor* kea_extractor_create(void);

/* Attempt to extract the witness from an adversary state */
int kea_extractor_extract(KEAExtractor* ext, const KEAAdversaryState* adv,
                           const KEAInstance* inst, uint64_t* witness_out);

/* Free the extractor */
void kea_extractor_free(KEAExtractor* ext);

/* ── Adversary Simulation ─────────────────────────────────── */

/* Create an adversary state with given randomness */
KEAAdversaryState* kea_adversary_create(CyclicGroup* g, uint64_t seed);

/* The adversary computes: picks r, outputs (g^r, (g^a)^r) */
KEAResponse* kea_adversary_compute(KEAAdversaryState* adv,
                                    const KEAInstance* inst);

/* A "malicious" adversary that tries to fool KEA (outputs random junk) */
KEAResponse* kea_malicious_adversary(KEAAdversaryState* adv,
                                      const KEAInstance* inst);

/* A KEA2 adversary */
KEA2Response* kea2_adversary_compute(KEAAdversaryState* adv,
                                      const KEA2Instance* inst);

/* Free adversary state */
void kea_adversary_free(KEAAdversaryState* adv);

/* ── KEA Security Game ────────────────────────────────────── */

/*
 * Run the full KEA1 security game:
 * 1. Setup: generate (g, g^a)
 * 2. Challenge: send to adversary
 * 3. Response: adversary outputs (C, C')
 * 4. Verify: check C' = C^a
 * 5. Extract: try to extract r
 *
 * Returns 1 if the adversary won the game (valid response + extraction failed).
 */
int kea_security_game(CyclicGroup* g, int verbose);

/*
 * Run the KEA2 security game with two exponents.
 */
int kea2_security_game(CyclicGroup* g, int verbose);

/* ── KEA Variants ─────────────────────────────────────────── */

/* KEA with auxiliary input: adversary gets z = f(a) as extra input */
KEAInstance* kea_auxiliary_input_create(CyclicGroup* g, uint64_t* aux, int aux_len);

/* "q-KEA": adversary gets (g, g^a, g^{a^2}, ..., g^{a^q}) */
typedef struct {
    KEAInstance*   base;
    GroupElement** powers;    /* g^{a^i} for i=1..q */
    int            q;         /* number of powers */
} QKEAInstance;

QKEAInstance* qkea_instance_create(CyclicGroup* g, int q);
void qkea_instance_free(QKEAInstance* inst);

/* ── Statistical Analysis ─────────────────────────────────── */

/* Measure extraction success rate over multiple trials */
double kea_extraction_rate(CyclicGroup* g, int trials);

/* Compare honest vs malicious adversary extraction rates */
void kea_compare_adversaries(CyclicGroup* g, int trials);

#endif /* KEA_H */