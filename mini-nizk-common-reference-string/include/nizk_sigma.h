/**
 * nizk_sigma.h ！ Sigma Protocols for Zero-Knowledge Proofs
 *
 * L1 Definition: A Sigma Protocol is a 3-move interactive proof system
 * between a Prover (P) and Verifier (V) for an NP relation R:
 *
 *   Prover(x, w)                          Verifier(x)
 *   -----------                           ----------
 *   commitment = t = f(x, w, rand)  --->
 *                               <---  challenge = c (random)
 *   response = s = g(x, w, rand, c) --->
 *                                       Accept iff V(x, t, c, s) = 1
 *
 * Properties:
 *   - Completeness: If (x,w) in R, honest prover always convinces verifier
 *   - Special Soundness: Given (t, c, s) and (t, c', s') with c != c',
 *     one can extract a witness w (Knowledge of Exponent / Special Soundness)
 *   - Honest-Verifier Zero-Knowledge (HVZK): There exists a simulator that,
 *     given x and random c, produces (t, s) indistinguishable from real proof
 *
 * Sigma protocols are the building blocks for NIZK via Fiat-Shamir transform
 * and for more complex proof systems via AND/OR composition.
 *
 * Reference: Damgard, I. "On Sigma Protocols." 2002.
 *            Cramer, R. "Modular Design of Secure yet Practical Cryptographic
 *            Protocols." PhD Thesis, 1996.
 *
 * Course Mapping:
 *   MIT 6.875: Sigma protocols, special soundness
 *   Stanford CS355: Interactive proof systems
 *   ETH 263-4650: Sigma protocol theory
 */

#ifndef NIZK_SIGMA_H
#define NIZK_SIGMA_H

#include "nizk_group.h"
#include "nizk_crs.h"
#include "nizk_commitment.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------------
 * L1: Sigma Protocol Message Structures
 * ------------------------------------------------------------------------- */

/**
 * nizk_sigma_statement ！ The statement (public input x) for a sigma protocol.
 *
 * For Schnorr protocol: x = public key h, statement = "I know w such that h = g^w"
 * For Chaum-Pedersen: x = (h1, h2, u1, u2), statement = "I know w such that u1=g^w AND u2=h^w"
 */
typedef struct {
    nizk_group_elem_t public_key;    /* public key / first base element result */
    nizk_group_elem_t aux_element;   /* auxiliary element for equality proofs */
    nizk_group_elem_t base_g;        /* first base (usually g, the generator) */
    nizk_group_elem_t base_h;        /* second base (for Pedersen-style proofs) */
    int               is_equality;   /* 1 for Chaum-Pedersen, 0 for Schnorr */
} nizk_sigma_statement_t;

/**
 * nizk_sigma_witness ！ The witness (secret input w) for a sigma protocol.
 *
 * The witness is what the prover knows and wants to prove knowledge of,
 * without revealing it. For Schnorr: w = sk (secret key).
 */
typedef struct {
    nizk_scalar_t secret;          /* the secret scalar (discrete log) */
    nizk_scalar_t aux_secret;      /* second secret for composite proofs */
    int           has_aux;         /* 1 if aux_secret is present */
} nizk_sigma_witness_t;

/**
 * nizk_sigma_commitment ！ The first message (commitment t) in sigma protocol.
 *
 * Prover sends this commitment to start the protocol.
 * For Schnorr: t = g^v where v is random (the "ephemeral key")
 */
typedef struct {
    nizk_group_elem_t t;           /* main commitment element */
    nizk_group_elem_t t_aux;       /* auxiliary commitment (for equality) */
    int               has_aux;     /* 1 if auxiliary commitment present */
} nizk_sigma_commitment_t;

/**
 * nizk_sigma_challenge ！ The second message (challenge c) in sigma protocol.
 *
 * Verifier sends a random challenge from Z_q.
 * In interactive version, it's randomly chosen.
 * In non-interactive (Fiat-Shamir), it's derived from hash.
 */
typedef struct {
    nizk_scalar_t c;               /* challenge value in Z_q */
} nizk_sigma_challenge_t;

/**
 * nizk_sigma_response ！ The third message (response s) in sigma protocol.
 *
 * For Schnorr: s = v - c*w (mod q)  [alternative: s = v + c*w]
 * The response completes the proof.
 */
typedef struct {
    nizk_scalar_t s;               /* response value in Z_q */
    nizk_scalar_t s_aux;           /* auxiliary response (for equality) */
    int           has_aux;         /* 1 if auxiliary response present */
} nizk_sigma_response_t;

/**
 * nizk_sigma_transcript ！ A complete sigma protocol transcript.
 *
 * Contains all three messages. Used for NIZK conversion and verification.
 */
typedef struct {
    nizk_sigma_commitment_t commitment;
    nizk_sigma_challenge_t  challenge;
    nizk_sigma_response_t   response;
} nizk_sigma_transcript_t;

/* ---------------------------------------------------------------------------
 * L5: Schnorr Protocol ！ Proving Knowledge of Discrete Logarithm
 * ------------------------------------------------------------------------- */

/**
 * nizk_schnorr_prove ！ Generate first and third messages for Schnorr protocol.
 *
 * Statement: "I know w such that h = g^w"
 * Public input: h (public key)
 * Witness: w (secret key / discrete log)
 *
 * Protocol:
 *   1. Prover picks random v <- Z_q, computes t = g^v
 *   2. Verifier sends random challenge c <- Z_q
 *   3. Prover computes s = v + c*w (mod q)
 *   4. Verifier checks: g^s == t * h^c
 *
 * This function generates t (commitment) and, given challenge c,
 * produces the response s.
 *
 * Theorem (Special Soundness): Given (t, c, s) and (t, c', s') with c != c'
 * both verifying, we can extract w = (s - s') / (c - c') mod q.
 *
 * Theorem (HVZK): Simulator picks random s, c, computes t = g^s * h^{-c}.
 * The distribution is identical to real transcripts.
 */
void nizk_schnorr_commit(nizk_sigma_commitment_t *commitment,
                          nizk_scalar_t *ephemeral,
                          const nizk_group_params_t *params);

void nizk_schnorr_respond(nizk_sigma_response_t *response,
                           const nizk_scalar_t *witness,
                           const nizk_scalar_t *ephemeral,
                           const nizk_sigma_challenge_t *challenge,
                           const nizk_group_params_t *params);

int  nizk_schnorr_verify(const nizk_sigma_statement_t *stmt,
                          const nizk_sigma_commitment_t *commitment,
                          const nizk_sigma_challenge_t *challenge,
                          const nizk_sigma_response_t *response,
                          const nizk_group_params_t *params);

/**
 * nizk_schnorr_extract ！ Extract witness from two accepting transcripts.
 *
 * Implements the "special soundness" extractor: given two transcripts
 * with same commitment t but different challenges c != c',
 * computes w = (s - s') * (c - c')^{-1} mod q.
 *
 * This is the Knowledge-of-Exponent Assumption (KEA) in action.
 *
 * Returns 1 if extraction succeeded, 0 if transcripts are invalid.
 */
int  nizk_schnorr_extract(nizk_scalar_t *witness,
                           const nizk_sigma_transcript_t *t1,
                           const nizk_sigma_transcript_t *t2,
                           const nizk_group_params_t *params);

/* ---------------------------------------------------------------------------
 * L5: Chaum-Pedersen Protocol ！ Proving Equality of Discrete Logs
 * ------------------------------------------------------------------------- */

/**
 * nizk_chaum_pedersen_prove ！ Prove knowledge of w such that u = g^w AND v = h^w.
 *
 * Statement: "I know w such that log_g(u) = log_h(v)"
 * This proves that two public keys use the same secret key.
 * Essential for verifiable encryption and threshold crypto.
 *
 * Protocol:
 *   1. Prover picks random r <- Z_q
 *   2. Computes t1 = g^r, t2 = h^r
 *   3. After receiving challenge c:
 *   4. Computes s = r + c*w (mod q)
 *   5. Verifier checks: g^s == t1 * u^c AND h^s == t2 * v^c
 *
 * Reference: Chaum & Pedersen. "Wallet Databases with Observers." CRYPTO 1992.
 */
void nizk_chaum_pedersen_commit(nizk_sigma_commitment_t *commitment,
                                 nizk_scalar_t *ephemeral,
                                 const nizk_group_elem_t *base1,
                                 const nizk_group_elem_t *base2,
                                 const nizk_group_params_t *params);

void nizk_chaum_pedersen_respond(nizk_sigma_response_t *response,
                                  const nizk_scalar_t *witness,
                                  const nizk_scalar_t *ephemeral,
                                  const nizk_sigma_challenge_t *challenge,
                                  const nizk_group_params_t *params);

int  nizk_chaum_pedersen_verify(const nizk_sigma_statement_t *stmt,
                                 const nizk_sigma_commitment_t *commitment,
                                 const nizk_sigma_challenge_t *challenge,
                                 const nizk_sigma_response_t *response,
                                 const nizk_group_params_t *params);

/* ---------------------------------------------------------------------------
 * L5: OR-Proof ！ Proving Knowledge of One of Two Secrets
 * ------------------------------------------------------------------------- */

/**
 * nizk_or_prove ！ Prove knowledge of w1 OR w2 without revealing which.
 *
 * Given two statements (h1 = g^w1 OR h2 = g^w2), the prover knows
 * one witness w_b (b in {0,1}) and wants to prove this without
 * revealing which one they know.
 *
 * This uses the standard OR-composition of sigma protocols:
 *   1. For the unknown branch, simulate using HVZK simulator
 *   2. For the known branch, run real protocol
 *   3. The sum of both challenges equals the verifier challenge
 *
 * This is the fundamental building block for:
 *   - Ring signatures
 *   - Anonymous credentials
 *   - 1-out-of-n proofs
 *
 * Reference: Cramer, Damgard, Schoenmakers. "Proofs of Partial Knowledge
 *            and Simplified Design of Witness Hiding Protocols." CRYPTO 1994.
 */

/**
 * nizk_or_statement ！ Statement for OR proof (two sub-statements).
 */
typedef struct {
    nizk_sigma_statement_t stmt[2];  /* two statements, one of which is true */
} nizk_or_statement_t;

/**
 * nizk_or_witness ！ Witness for OR proof (one of two secrets).
 */
typedef struct {
    int            known_branch;     /* 0 or 1: which witness is known */
    nizk_scalar_t  secret;           /* the known secret */
} nizk_or_witness_t;

void nizk_or_prove_commit(nizk_sigma_commitment_t *commitments,
                           nizk_scalar_t *ephemerals,
                           nizk_scalar_t *sim_challenges,
                           const nizk_or_statement_t *stmt,
                           const nizk_or_witness_t *witness,
                           const nizk_group_params_t *params);

void nizk_or_prove_respond(nizk_sigma_response_t *responses,
                            nizk_sigma_challenge_t *challenges,
                            const nizk_scalar_t *witness,
                            const nizk_scalar_t *ephemeral,
                            const nizk_scalar_t *sim_challenge,
                            const nizk_sigma_challenge_t *real_challenge,
                            int known_branch,
                            const nizk_group_params_t *params);

int  nizk_or_verify(const nizk_or_statement_t *stmt,
                     const nizk_sigma_commitment_t *commitments,
                     const nizk_sigma_challenge_t *challenges,
                     const nizk_sigma_response_t *responses,
                     const nizk_sigma_challenge_t *combined_challenge,
                     const nizk_group_params_t *params);

/* ---------------------------------------------------------------------------
 * L5: AND-Proof ！ Proving Knowledge of Two Secrets Simultaneously
 * ------------------------------------------------------------------------- */

/**
 * nizk_and_prove ！ Prove knowledge of w1 AND w2 simultaneously.
 *
 * Given statements (h1 = g^w1 AND h2 = g^w2), prove knowledge of both.
 * This is straightforward: run both protocols with the SAME challenge.
 *
 * This is the basis for proving knowledge of representations:
 *   "I know (m, r) such that C = g^m * h^r"
 */
void nizk_and_prove_commit(nizk_sigma_commitment_t *commitments,
                            nizk_scalar_t *ephemerals,
                            const nizk_group_params_t *params);

void nizk_and_prove_respond(nizk_sigma_response_t *responses,
                             const nizk_scalar_t *witnesses,
                             const nizk_scalar_t *ephemerals,
                             const nizk_sigma_challenge_t *challenge,
                             int num_witnesses,
                             const nizk_group_params_t *params);

int  nizk_and_verify(const nizk_sigma_statement_t *stmts,
                      const nizk_sigma_commitment_t *commitments,
                      const nizk_sigma_challenge_t *challenge,
                      const nizk_sigma_response_t *responses,
                      int num_statements,
                      const nizk_group_params_t *params);

/* ---------------------------------------------------------------------------
 * L2: HVZK Simulator (for sigma protocols)
 * ------------------------------------------------------------------------- */

/**
 * nizk_sigma_simulate ！ Simulate a sigma protocol transcript without witness.
 *
 * Uses the HVZK property: pick random response s and challenge c,
 * then compute t to make the verification equation hold.
 *
 * For Schnorr: t = g^s * h^{-c} (mod p)
 * This produces a transcript indistinguishable from a real one.
 *
 * This simulator is the key to proving zero-knowledge and is used
 * internally by the OR-proof protocol.
 */
void nizk_sigma_simulate_transcript(nizk_sigma_transcript_t *transcript,
                                     const nizk_sigma_statement_t *stmt,
                                     const nizk_group_params_t *params);

/** Initialize a sigma protocol statement. */
void nizk_sigma_statement_init(nizk_sigma_statement_t *stmt,
                                const nizk_group_elem_t *pubkey,
                                const nizk_group_elem_t *g,
                                const nizk_group_params_t *params);

#ifdef __cplusplus
}
#endif

#endif /* NIZK_SIGMA_H */
