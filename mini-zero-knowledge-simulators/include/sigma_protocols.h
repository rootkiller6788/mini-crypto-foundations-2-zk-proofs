#ifndef SIGMA_PROTOCOLS_H
#define SIGMA_PROTOCOLS_H

#include "zk_simulator.h"

/*
 * mini-zero-knowledge-simulators -- sigma_protocols.h
 * Sigma protocols: 3-move public-coin protocols, the workhorse of ZK.
 * Covers L3 (Mathematical Structures), L5 (Algorithms/Methods).
 *
 * A sigma protocol is:
 *   P -> V:  commitment a
 *   V -> P:  challenge c (uniform random from challenge space)
 *   P -> V:  response s
 *
 * Properties:
 *  1. Completeness: honest P always convinces V.
 *  2. Special Soundness: from (a,c1,s1),(a,c2,s2) with c1!=c2, extract witness.
 *  3. HVZK: exists simulator S producing indisting. transcripts WITHOUT witness.
 *
 * Reference: Damgard (2010) "On Sigma Protocols"
 *            Cramer (1997) "Modular Design of Secure Protocols"
 * Courses: MIT 6.875, Stanford CS355, ETH 263-4660
 */

/* ================================================================
 * L3 -- Mathematical Structures
 * ================================================================ */

/*
 * L3.1 -- Challenge Space
 * For a sigma protocol over group of order q, the challenge space
 * is typically Z_q. Soundness error = 1/|challenge space|.
 */

/*
 * L3.2 -- Schnorr Identification Protocol (Schnorr 1991)
 *
 * The canonical sigma protocol. Proves knowledge of discrete log.
 * Public:  (p,q,g,y) where y = g^x mod p
 * Private: x (the discrete log of y)
 *
 * Protocol:
 *   P -> V: a = g^r mod p        (r random in Z_q)
 *   V -> P: c                     (c random in Z_q)
 *   P -> V: s = r + c*x mod q
 *   V:      accept iff g^s == a * y^c mod p
 *
 * Completeness: g^{r+cx} = g^r * (g^x)^c = a * y^c
 * HVZK: pick c,s random, compute a = g^s * y^{-c}. Perfect!
 * Special soundness: from (a,c1,s1),(a,c2,s2) -> x = (s1-s2)/(c1-c2) mod q
 */
typedef struct {
    uint64_t r;          /* random nonce */
    uint64_t a;          /* commitment a = g^r mod p */
    uint64_t x;          /* secret key (witness) */
    const group_params_t *gp;
} schnorr_prover_t;

typedef struct {
    uint64_t y;          /* public key y = g^x */
    uint64_t a;          /* received commitment */
    uint64_t c;          /* challenge */
    uint64_t s;          /* received response */
    const group_params_t *gp;
} schnorr_verifier_t;

typedef struct {
    uint64_t a, c, s;
} schnorr_transcript_t;

/* Schnorr prover operations */
void schnorr_prover_init(schnorr_prover_t *sp, uint64_t x,
                         const group_params_t *gp);
uint64_t schnorr_prover_commit(schnorr_prover_t *sp,
                                const random_tape_t *rng);
uint64_t schnorr_prover_respond(schnorr_prover_t *sp, uint64_t challenge);

/* Schnorr verifier operations */
void schnorr_verifier_init(schnorr_verifier_t *sv, uint64_t y,
                            const group_params_t *gp);
void schnorr_verifier_set_commitment(schnorr_verifier_t *sv, uint64_t a);
uint64_t schnorr_verifier_pick_challenge(schnorr_verifier_t *sv,
                                          const random_tape_t *rng);
int schnorr_verifier_verify(schnorr_verifier_t *sv, uint64_t s);

/* Serialize Schnorr transcript */
void schnorr_transcript_to_transcript(const schnorr_transcript_t *st,
                                       transcript_t *out);

/*
 * L3.3 -- Chaum-Pedersen Protocol: Equality of Discrete Logs
 *
 * Proves that log_g(A) = log_h(B) without revealing the value.
 * Fundamental building block for verifiable secret sharing,
 * mix-nets, and anonymous credentials.
 *
 * Public: (g, h, A, B) with A = g^x, B = h^x
 * Private: x
 *
 * Protocol:
 *   P -> V: a1 = g^r, a2 = h^r       (same r!)
 *   V -> P: c
 *   P -> V: s = r + c*x mod q
 *   V:      g^s ==? a1 * A^c  AND  h^s ==? a2 * B^c
 *
 * Key property: using the SAME r for both bases ties them together.
 * The verifier is convinced that the same x is used in both equations.
 */
typedef struct {
    uint64_t x;          /* secret witness (same for both bases) */
    uint64_t r;          /* random nonce (same for both bases) */
    uint64_t a1, a2;     /* commitments under g and h */
    uint64_t A, B;       /* public keys: A = g^x, B = h^x */
    const group_params_t *gp;
} chaum_pedersen_prover_t;

void chaum_pedersen_prover_init(chaum_pedersen_prover_t *cp, uint64_t x,
                                 uint64_t A, uint64_t B,
                                 const group_params_t *gp);
void chaum_pedersen_prover_commit(chaum_pedersen_prover_t *cp,
                                   const random_tape_t *rng,
                                   uint64_t *a1_out, uint64_t *a2_out);
uint64_t chaum_pedersen_prover_respond(chaum_pedersen_prover_t *cp,
                                        uint64_t challenge);

/* Verify a Chaum-Pedersen transcript */
int chaum_pedersen_verify(uint64_t a1, uint64_t a2,
                           uint64_t c, uint64_t s,
                           uint64_t A, uint64_t B,
                           const group_params_t *gp);

/*
 * L3.4 -- Guillou-Quisquater Protocol (RSA-based Sigma Protocol)
 *
 * Proves knowledge of an RSA secret key.
 * Public: (N, e, y) where N = p*q, y = x^{-e} mod N
 * Private: x
 *
 * Protocol:
 *   P -> V: a = r^e mod N       (r random in Z_N^*)
 *   V -> P: c                    (c random)
 *   P -> V: s = r * x^c mod N
 *   V:      s^e ==? a * y^c mod N
 *
 * Demonstrates that sigma protocols work over RSA groups too,
 * not just discrete-log groups. Completeness follows from
 * s^e = (r*x^c)^e = r^e * (x^{-e})^{-c} = a * y^{-c}^{-1} ... wait.
 * Actually: r^e * (x^{-e})^c = a * y^c. Yes.
 */
typedef struct {
    uint64_t N;         /* RSA modulus */
    uint64_t e;         /* public exponent */
    uint64_t x;         /* secret key */
    uint64_t y;         /* public key y = x^{-e} mod N */
    uint64_t r;         /* random nonce */
    uint64_t a;         /* commitment a = r^e mod N */
} gq_prover_t;

void gq_prover_init(gq_prover_t *gq, uint64_t x, uint64_t y,
                     uint64_t N, uint64_t e);
uint64_t gq_prover_commit(gq_prover_t *gq, const random_tape_t *rng);
uint64_t gq_prover_respond(gq_prover_t *gq, uint64_t challenge);
int gq_verify(uint64_t a, uint64_t c, uint64_t s,
               uint64_t y, uint64_t N, uint64_t e);

/* ================================================================
 * L5 -- Sigma Protocol Algorithms/Methods
 * ================================================================ */

/*
 * L5.1 -- AND-Composition
 * Given sigma protocols for L1 and L2, construct one for L1 AND L2.
 * Prover must know witnesses for BOTH.
 *
 * Protocol:
 *   P -> V: (a1, a2)
 *   V -> P: c                      (same challenge for both)
 *   P -> V: (s1, s2)
 *   V:      verify1(a1,c,s1) AND verify2(a2,c,s2)
 *
 * Soundness error additive: at most 1/|C1| + 1/|C2|.
 */
typedef struct {
    uint64_t a1, a2;
    uint64_t c;
    uint64_t s1, s2;
} and_composition_transcript_t;

void and_compose_commit(uint64_t *a1, uint64_t *a2,
                         const schnorr_prover_t *p1,
                         const schnorr_prover_t *p2,
                         const random_tape_t *rng);
int and_compose_verify(uint64_t a1, uint64_t a2,
                        uint64_t c, uint64_t s1, uint64_t s2,
                        uint64_t y1, uint64_t y2,
                        const group_params_t *gp);

/*
 * L5.2 -- OR-Composition (Cramer-Damgard-Schoenmakers 1994)
 *
 * Given sigma protocols for L1 and L2, construct one for L1 OR L2.
 * Prover needs witness for only ONE. Verifier cannot tell which.
 * This directly yields witness indistinguishability.
 *
 * Construction (prover knows w1 for L1):
 *   1. For L1: run real prover -> a1
 *   2. For L2: pick c2,s2 random; compute a2 via HVZK simulator
 *   3. Send (a1,a2) to V; receive challenge c
 *   4. Set c1 = c XOR c2  (forces c = c1 XOR c2)
 *   5. Complete s1 with challenge c1
 *   6. Send (c1, s1, c2, s2)
 *   V: verify1(a1,c1,s1) AND verify2(a2,c2,s2) AND c == c1 XOR c2
 *
 * The verifier sees both sides verified, but one side is simulated.
 * By the HVZK property, the simulated side is indistinguishable
 * from a real execution. Hence the verifier learns nothing about
 * which witness the prover actually holds => WI.
 */
typedef struct {
    uint64_t a1, a2;     /* commitments */
    uint64_t c;           /* verifier challenge */
    uint64_t c1, s1;      /* left: challenge + response */
    uint64_t c2, s2;      /* right: challenge + response */
} or_composition_transcript_t;

/*
 * OR-composition prover (knows witness for y1, not y2).
 * y1, y2 are the two public statements.
 * real_side: 1 (left) or 2 (right) indicates which witness is known.
 */
typedef struct {
    int      real_side;   /* 1 or 2 */
    uint64_t x;           /* known witness */
    uint64_t y1, y2;      /* both public statements */
    const group_params_t *gp;
} or_composition_prover_t;

void or_compose_prover_init(or_composition_prover_t *op,
                             int real_side, uint64_t x,
                             uint64_t y1, uint64_t y2,
                             const group_params_t *gp);
void or_compose_prover_execute(or_composition_prover_t *op,
                                const random_tape_t *rng,
                                or_composition_transcript_t *out,
                                uint64_t verifier_challenge);
int or_compose_verify(const or_composition_transcript_t *t,
                       uint64_t y1, uint64_t y2,
                       const group_params_t *gp);

/*
 * L5.3 -- Parallel Repetition for Soundness Amplification
 *
 * k independent parallel repetitions of a sigma protocol reduce
 * soundness error from 1/|C| to (1/|C|)^k.
 *
 * WARNING: Parallel repetition does NOT preserve ZK in general.
 * It DOES preserve WI (witness indistinguishability).
 *
 * For sigma protocols used in OR-proofs (where WI is the target),
 * parallel repetition is the standard method.
 */
int parallel_sigma_prover(const schnorr_prover_t *sp,
                           const random_tape_t *rng,
                           int k,
                           uint64_t *a_out, uint64_t *c_in,
                           uint64_t *s_out);
int parallel_sigma_verify(const uint64_t *a, const uint64_t *c,
                           const uint64_t *s, int k,
                           uint64_t y, const group_params_t *gp);

/*
 * L5.4 -- Generic Sigma Protocol Interfaces
 */
typedef int (*sigma_verify_fn)(uint64_t a, uint64_t c, uint64_t s,
                                uint64_t y, const group_params_t *gp);
typedef int (*sigma_simulate_fn)(uint64_t y, const group_params_t *gp,
                                  const random_tape_t *rng,
                                  uint64_t *a, uint64_t *c, uint64_t *s);

/*
 * L5.5 -- Automated Simulator for Sigma Protocols
 *
 * Given a sigma protocol, produce a statistically rigorous
 * simulation that is indistinguishable from real executions.
 * This is a generic implementation of the HVZK simulation
 * paradigm: pick random (c,s), compute matching a.
 */
int generic_sigma_simulate(sigma_simulate_fn sim,
                            uint64_t y, const group_params_t *gp,
                            const random_tape_t *rng,
                            uint64_t *a, uint64_t *c, uint64_t *s);

#endif /* SIGMA_PROTOCOLS_H */

