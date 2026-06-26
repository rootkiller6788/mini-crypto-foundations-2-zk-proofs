#ifndef ZK_SIMULATOR_H
#define ZK_SIMULATOR_H

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <assert.h>

/*
 * mini-zero-knowledge-simulators -- zk_simulator.h
 * Core definitions for the ZK proof simulator framework.
 * Covers L1 (Definitions) and L2 (Core Concepts).
 *
 * Reference: Goldreich (2004) Foundations of Cryptography, Vol. 1
 *            Goldwasser, Micali & Rackoff (1989)
 *            Arora & Barak (2009) Ch. 18
 * Courses: MIT 6.875, Stanford CS355, Berkeley CS276, CMU 15-859
 */

/* ZK flavour */
typedef enum {
    ZK_PERFECT       = 0,
    ZK_STATISTICAL   = 1,
    ZK_COMPUTATIONAL = 2,
} zk_flavour_t;

/* Verdict */
typedef enum {
    VERDICT_ACCEPT = 1,
    VERDICT_REJECT = 0,
} verdict_t;

/*
 * L1.1 -- Transcript
 * Records all messages exchanged between prover and verifier.
 */
#define MAX_TRANSCRIPT_LEN 4096
#define MAX_ROUNDS         256

typedef struct {
    uint8_t  data[MAX_TRANSCRIPT_LEN];
    size_t   len;
    uint32_t num_rounds;
    size_t   round_start[MAX_ROUNDS];
} transcript_t;

/*
 * L1.2 -- The Simulator
 *
 * A simulator S is a PPT algorithm that, given only the public input x,
 * produces transcripts indistinguishable from real protocol executions.
 * This is THE defining property of ZK.
 *
 * Black-box simulator: rewinds V* as subroutine.
 * Non-black-box simulator: uses the code of V* directly (Barak 2001).
 */
typedef int (*simulator_fn)(const uint8_t *x, size_t xlen,
                            const uint8_t *rng, size_t rng_len,
                            transcript_t *out);

/*
 * L1.3 -- Verifier View
 * View_{V*(z)}(x) = (r, m1, m2, ..., mk)
 */
#define MAX_RANDOM_TAPE 512

typedef struct {
    uint8_t  coins[MAX_RANDOM_TAPE];
    size_t   coin_len;
    uint64_t seed;
} random_tape_t;

typedef struct {
    random_tape_t r;
    transcript_t  messages;
} verifier_view_t;

/*
 * L2.1 -- Honest-Verifier Zero-Knowledge (HVZK)
 * ZK holds only against the honest verifier V.
 * Schnorr, Guillou-Quisquater achieve HVZK.
 * For sigma protocols, HVZK is trivial: pick random c,s, compute a.
 */
/* L2.2 -- Witness Indistinguishability (WI)
 * Weaker than ZK: cannot tell which witness was used.
 * WI is closed under parallel composition (unlike ZK).
 */
typedef enum {
    WI_STATISTICAL   = 0,
    WI_COMPUTATIONAL = 1,
} wi_level_t;

/*
 * L2.3 -- Proof of Knowledge (PoK)
 * Exists extractor E: from convincing prover, extracts witness.
 * Soundness: existential. PoK: constructive.
 */
typedef int (*extractor_fn)(const uint8_t *x, size_t xlen,
                             void *prover_oracle,
                             uint8_t *witness_out, size_t *witness_len);

/*
 * L2.4 -- Statistical Distance and Negligible Functions
 */
double statistical_distance(const double *d1, const double *d2, size_t n);
int    is_negligible(double eps, double n);

/*
 * L2.5 -- Simulation Modes
 */
typedef enum {
    SIM_BLACK_BOX     = 0,
    SIM_NON_BLACK_BOX = 1,
    SIM_STRAIGHT_LINE = 2,
} simulation_mode_t;

/*
 * L2.6 -- Rewinding: The Fundamental ZK Technique
 * Black-box simulation rewinds V* and retries.
 * Expected rewinds = O(q) for challenge space size q.
 */
typedef struct {
    random_tape_t saved_tape;
    size_t        rewind_position;
    uint32_t      round;
} rewind_state_t;

/*
 * L2.7 -- Commitment Schemes in ZK
 * Hiding + Binding = digital envelope for ZK.
 */

/*
 * L3.1 -- Group Parameters for DLog-based ZK
 */
typedef struct {
    uint64_t p;   /* modulus */
    uint64_t g;   /* generator */
    uint64_t q;   /* order */
    uint64_t h;   /* second generator for Pedersen */
} group_params_t;

/* Modular arithmetic */
uint64_t mod_add(uint64_t a, uint64_t b, uint64_t m);
uint64_t mod_sub(uint64_t a, uint64_t b, uint64_t m);
uint64_t mod_mul(uint64_t a, uint64_t b, uint64_t m);
uint64_t mod_pow(uint64_t base, uint64_t exp, uint64_t m);
uint64_t mod_inv(uint64_t a, uint64_t m);
uint64_t mod_neg(uint64_t a, uint64_t m);
int64_t extended_gcd(int64_t a, int64_t b, int64_t *x, int64_t *y);

/* PRNG (linear congruential, didactic use) */
void     init_random_tape(random_tape_t *tape, uint64_t seed);
uint64_t next_random_u64(random_tape_t *tape);
uint64_t pull_random_mod_q(random_tape_t *tape, uint64_t q);

/* Transcript management */
void transcript_init(transcript_t *t);
void transcript_append(transcript_t *t, const uint8_t *data, size_t len);
void transcript_append_u64(transcript_t *t, uint64_t val);
void transcript_start_round(transcript_t *t);
int  transcript_verify(const transcript_t *t);
void transcript_copy(const transcript_t *src, transcript_t *dst);

/*
 * L4.1 -- Schnorr Protocol Verification
 * THEOREM (Schnorr 1991): g^s == a * y^c mod p
 */
int schnorr_verify(uint64_t a, uint64_t c, uint64_t s,
                   uint64_t y, const group_params_t *gp);

/*
 * L4.2 -- HVZK Simulator for Schnorr
 * Pick c,s random; a = g^s * y^{-c}; return (a,c,s).
 * PERFECT simulation: distribution identical to real transcripts.
 */
int hvzk_simulate_schnorr(uint64_t y, const group_params_t *gp,
                          const random_tape_t *rng,
                          uint64_t *a_out, uint64_t *c_out, uint64_t *s_out);

/*
 * L4.3 -- Knowledge Extraction (Special Soundness)
 * w = (s1-s2)*(c1-c2)^{-1} mod q
 */
int schnorr_extract_witness(uint64_t a,
                            uint64_t c1, uint64_t s1,
                            uint64_t c2, uint64_t s2,
                            const group_params_t *gp,
                            uint64_t *witness_out);

/*
 * L4.4 -- OR-Composition Theorem (Cramer-Damgard-Schoenmakers 1994)
 * Sigma protocols closed under OR.
 * L4.5 -- Fiat-Shamir Transform (1986)
 * Sigma protocol -> NIZK in ROM.
 * L4.6 -- GMW Theorem: ZK for all of NP (1991)
 * Commitments => every L in NP has comp. ZK proof.
 */

#endif /* ZK_SIMULATOR_H */

