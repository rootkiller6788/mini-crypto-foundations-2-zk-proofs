/**
 * nizk_proof.h ！ Non-Interactive Zero-Knowledge Proof System
 *
 * L1 Definition: A Non-Interactive Zero-Knowledge (NIZK) proof system
 * for an NP language L with relation R consists of three algorithms:
 *
 *   Setup(1^lambda) -> crs     : Generate common reference string
 *   Prove(crs, x, w) -> pi     : Generate NIZK proof using witness
 *   Verify(crs, x, pi) -> 0/1  : Verify the proof
 *
 * The Fiat-Shamir transform converts any sigma protocol (3-move interactive
 * honest-verifier ZK proof) into a NIZK proof by replacing the verifier's
 * random challenge with a hash of the commitment and statement:
 *
 *   c = H(statement || commitment)
 *
 * This yields a non-interactive proof in the Random Oracle Model (ROM).
 * The proof is simply pi = (commitment, response), and the challenge
 * is recomputed during verification.
 *
 * Reference: Fiat, A. and Shamir, A. "How to Prove Yourself: Practical
 *            Solutions to Identification and Signature Problems." CRYPTO 1986.
 *
 * Course Mapping:
 *   MIT 6.875: NIZK, Fiat-Shamir transform
 *   Stanford CS355: Non-interactive ZK
 *   Princeton COS 551: NIZK in ROM
 *   Berkeley CS278: Fiat-Shamir security
 */

#ifndef NIZK_PROOF_H
#define NIZK_PROOF_H

#include "nizk_group.h"
#include "nizk_crs.h"
#include "nizk_sigma.h"
#include "nizk_commitment.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------------
 * L1: NIZK Proof Data Structures
 * ------------------------------------------------------------------------- */

/**
 * nizk_proof_type ！ Type of NIZK proof being generated/verified.
 */
typedef enum {
    NIZK_PROOF_DLOG_KNOWLEDGE = 0,  /* Schnorr: know discrete log */
    NIZK_PROOF_DLOG_EQUALITY  = 1,  /* Chaum-Pedersen: equal discrete logs */
    NIZK_PROOF_REPRESENTATION = 2,  /* Know representation (m,r) for C=g^m*h^r */
    NIZK_PROOF_OR             = 3,  /* OR proof: know one of two secrets */
    NIZK_PROOF_COMMITMENT     = 4,  /* Prove knowledge of committed value */
} nizk_proof_type_t;

/**
 * nizk_proof ！ A non-interactive zero-knowledge proof.
 *
 * The proof consists of the commitment and response from the sigma
 * protocol. The challenge is derived via Fiat-Shamir and verified
 * during verification (not stored, as it can be recomputed).
 *
 * For OR-proofs, multiple commitments and responses are stored.
 */
#define NIZK_MAX_OR_BRANCHES 8

typedef struct {
    nizk_proof_type_t         type;
    nizk_sigma_commitment_t   commitment;
    nizk_sigma_response_t     response;
    /* For OR proofs: */
    nizk_sigma_commitment_t   or_commitments[NIZK_MAX_OR_BRANCHES];
    nizk_sigma_challenge_t    or_challenges[NIZK_MAX_OR_BRANCHES];
    nizk_sigma_response_t     or_responses[NIZK_MAX_OR_BRANCHES];
    int                       or_num_branches;
    /* Context for statement binding */
    uint8_t                   statement_hash[32];  /* hash of statement for binding */
} nizk_proof_t;

/* ---------------------------------------------------------------------------
 * L5: Fiat-Shamir Transform ！ Hash Function
 * ------------------------------------------------------------------------- */

/**
 * nizk_fiat_shamir_challenge ！ Derive challenge via Fiat-Shamir heuristic.
 *
 * Computes: c = H(statement || commitment || auxiliary_data)
 *
 * Uses SHA-256 as the random oracle. The challenge is derived by:
 *   1. Serialize the statement and commitment to bytes
 *   2. Hash with SHA-256
 *   3. Reduce the hash modulo q to get a scalar challenge
 *
 * Parameters:
 *   challenge ！ output challenge in Z_q
 *   stmt      ！ statement being proven
 *   commitment ！ sigma protocol commitment
 *   aux_data  ！ additional context (for domain separation)
 *   aux_len   ！ length of auxiliary data
 *   params    ！ group parameters (for modulo reduction)
 *
 * Theorem (Fiat-Shamir Security): In the Random Oracle Model, if the
 * underlying sigma protocol is HVZK and has special soundness, then
 * the Fiat-Shamir NIZK is zero-knowledge and simulation-sound.
 */
void nizk_fiat_shamir_challenge(nizk_sigma_challenge_t *challenge,
                                 const nizk_sigma_statement_t *stmt,
                                 const nizk_sigma_commitment_t *commitment,
                                 const uint8_t *aux_data, size_t aux_len,
                                 const nizk_group_params_t *params);

/**
 * nizk_hash_to_scalar ！ Hash arbitrary data to a scalar in Z_q.
 *
 * General-purpose hash-to-scalar utility used throughout the system.
 */
void nizk_hash_to_scalar(nizk_scalar_t *out,
                          const uint8_t *data, size_t data_len,
                          const nizk_group_params_t *params);

/* ---------------------------------------------------------------------------
 * L5: NIZK Proof Generation
 * ------------------------------------------------------------------------- */

/**
 * nizk_prove_dlog ！ Generate NIZK proof of discrete log knowledge.
 *
 * Proves: "I know w such that h = g^w"
 *
 * This is the Fiat-Shamir transform of Schnorr's protocol.
 * The resulting proof is a Schnorr signature on the empty message,
 * which is exactly the construction of Schnorr signatures!
 *
 * Parameters:
 *   proof   ！ output NIZK proof
 *   crs     ！ common reference string
 *   pubkey  ！ public key h (the statement)
 *   witness ！ secret key w (the witness)
 *   label   ！ optional context label for domain separation
 *   label_len ！ length of label
 *   params  ！ group parameters
 *
 * L7 Application: This is the basis for Schnorr digital signatures.
 */
void nizk_prove_dlog(nizk_proof_t *proof,
                      const nizk_crs_t *crs,
                      const nizk_group_elem_t *pubkey,
                      const nizk_scalar_t *witness,
                      const uint8_t *label, size_t label_len,
                      const nizk_group_params_t *params);

/**
 * nizk_verify_dlog ！ Verify NIZK proof of discrete log knowledge.
 *
 * Recomputes challenge c = H(statement || commitment || label),
 * then verifies: g^s == t * h^c
 *
 * Returns 1 if valid, 0 otherwise.
 */
int  nizk_verify_dlog(const nizk_proof_t *proof,
                       const nizk_crs_t *crs,
                       const nizk_group_elem_t *pubkey,
                       const uint8_t *label, size_t label_len,
                       const nizk_group_params_t *params);

/**
 * nizk_prove_dlog_eq ！ Generate NIZK proof of equal discrete logs.
 *
 * Proves: "I know w such that u = g^w AND v = h^w"
 *
 * Parameters:
 *   proof  ！ output NIZK proof
 *   crs    ！ common reference string
 *   u, v   ！ the two public keys (u = g^w, v = h^w)
 *   base_h ！ the second base (h)
 *   witness！ the secret w
 *   label  ！ context label
 *   label_len ！ label length
 *   params ！ group parameters
 */
void nizk_prove_dlog_eq(nizk_proof_t *proof,
                         const nizk_crs_t *crs,
                         const nizk_group_elem_t *u,
                         const nizk_group_elem_t *v,
                         const nizk_group_elem_t *base_h,
                         const nizk_scalar_t *witness,
                         const uint8_t *label, size_t label_len,
                         const nizk_group_params_t *params);

/**
 * nizk_verify_dlog_eq ！ Verify NIZK proof of equal discrete logs.
 *
 * Returns 1 if valid, 0 otherwise.
 */
int  nizk_verify_dlog_eq(const nizk_proof_t *proof,
                          const nizk_crs_t *crs,
                          const nizk_group_elem_t *u,
                          const nizk_group_elem_t *v,
                          const nizk_group_elem_t *base_h,
                          const uint8_t *label, size_t label_len,
                          const nizk_group_params_t *params);

/**
 * nizk_prove_commitment ！ Prove knowledge of opening to a Pedersen commitment.
 *
 * Proves: "I know (m, r) such that C = g^m * h^r"
 *
 * This is essential for verifiable secret sharing and confidential
 * transactions, where one must prove knowledge of committed values
 * without revealing them.
 *
 * The protocol proves knowledge of a representation of C with
 * respect to bases g and h.
 *
 * L7 Application: Used in confidential transactions (e.g., Elements,
 * Monero-style range proofs) to prove knowledge of amounts.
 */
void nizk_prove_commitment(nizk_proof_t *proof,
                            const nizk_crs_t *crs,
                            const nizk_commitment_t *com,
                            const nizk_commitment_opening_t *opening,
                            const uint8_t *label, size_t label_len,
                            const nizk_group_params_t *params);

/**
 * nizk_verify_commitment ！ Verify proof of commitment opening knowledge.
 *
 * Returns 1 if valid, 0 otherwise.
 */
int  nizk_verify_commitment(const nizk_proof_t *proof,
                             const nizk_crs_t *crs,
                             const nizk_commitment_t *com,
                             const uint8_t *label, size_t label_len,
                             const nizk_group_params_t *params);

/**
 * nizk_prove_or ！ Generate NIZK OR-proof.
 *
 * Proves knowledge of one secret among two, without revealing which.
 *
 * L7 Application: Ring signatures, anonymous voting, whistleblowing.
 */
void nizk_prove_or(nizk_proof_t *proof,
                    const nizk_crs_t *crs,
                    const nizk_group_elem_t *pubkey1,
                    const nizk_group_elem_t *pubkey2,
                    const nizk_scalar_t *witness,
                    int known_branch,
                    const uint8_t *label, size_t label_len,
                    const nizk_group_params_t *params);

/**
 * nizk_verify_or ！ Verify NIZK OR-proof.
 *
 * Returns 1 if valid, 0 otherwise.
 */
int  nizk_verify_or(const nizk_proof_t *proof,
                     const nizk_crs_t *crs,
                     const nizk_group_elem_t *pubkey1,
                     const nizk_group_elem_t *pubkey2,
                     const uint8_t *label, size_t label_len,
                     const nizk_group_params_t *params);

/* ---------------------------------------------------------------------------
 * L2: Proof Serialization
 * ------------------------------------------------------------------------- */

/**
 * nizk_proof_serialize ！ Serialize a proof to bytes for transmission.
 *
 * Returns number of bytes written (or required if buf is NULL).
 */
size_t nizk_proof_serialize(uint8_t *buf, size_t buf_len,
                             const nizk_proof_t *proof,
                             const nizk_group_params_t *params);

/**
 * nizk_proof_deserialize ！ Deserialize bytes back to a proof.
 *
 * Returns 1 on success, 0 on failure.
 */
int  nizk_proof_deserialize(nizk_proof_t *proof,
                             const uint8_t *buf, size_t buf_len,
                             const nizk_group_params_t *params);

/** Initialize a proof structure. */
void nizk_proof_init(nizk_proof_t *proof, nizk_proof_type_t type);

/** Clear/free a proof structure. */
void nizk_proof_clear(nizk_proof_t *proof);

#ifdef __cplusplus
}
#endif

#endif /* NIZK_PROOF_H */
