#ifndef SIGMA_COMPOSITION_H
#define SIGMA_COMPOSITION_H

/**
 * sigma_composition.h ? Sigma Protocol Composition (AND, OR, EQ)
 *
 * Composes sigma protocols to prove compound statements.
 * The resulting protocols inherit special soundness and SHVZK
 * from their components.
 *
 * L1 Definitions:
 *   - AND composition: prove knowledge of (w1, w2) s.t. R1(x1,w1) ? R2(x2,w2)
 *   - OR composition:  prove knowledge of w1 s.t. R1(x1,w1) ? R2(x2,w2)
 *                      WITHOUT revealing which one is true
 *   - EQ composition:  prove R1(x,w) ? R2(x',w) (same witness for two relations)
 *
 * L4 Theorems:
 *   - Theorem (Cramer, Damgard, Schoenmakers 1994): AND/OR composition
 *     of sigma protocols yields a sigma protocol for the compound relation.
 *   - OR composition preserves witness indistinguishability (WI).
 *   - The composed protocol has knowledge error ? ? max(?1, ?2).
 *
 * L7 Applications:
 *   - Ring signatures: OR of "I know sk_1" or "I know sk_2" or ...
 *   - Anonymous credentials with selective disclosure
 *   - E-voting: prove encrypted vote is valid (0 or 1) without revealing which
 *   - Group signatures: member proves membership without revealing identity
 *
 * References:
 *   - Cramer, Damgard, Schoenmakers (1994) "Proofs of Partial Knowledge
 *     and Simplified Design of Witness Hiding Protocols", CRYPTO '94
 *   - Cramer (1996) "Modular Design of Secure yet Practical Protocols"
 *     PhD Thesis, CWI Amsterdam
 *   - Abe, Ohkubo, Suzuki (2002) "1-out-of-n Signatures from a Variety
 *     of Keys", ASIACRYPT 2002 (ring signatures)
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "sigma_math.h"
#include "sigma_core.h"
#include "sigma_chaum_pedersen.h"

/* ??? AND Composition ??????????????????????????????????????????????? */

/**
 * sigma_and_public ? Public input for AND composition.
 * Statement: "I know (w1, w2) such that R1(x1, w1) AND R2(x2, w2)"
 */
typedef struct {
    sigma_schnorr_public pk1;  /* y1 = g^{x1} */
    sigma_schnorr_public pk2;  /* y2 = g^{x2} */
} sigma_and_public;

/**
 * sigma_and_witness ? Witness for AND composition.
 */
typedef struct {
    sigma_schnorr_witness wit1;  /* x1 */
    sigma_schnorr_witness wit2;  /* x2 */
} sigma_and_witness;

/**
 * sigma_and_commit ? Prover commits for both statements.
 *
 * r1 ? Z_q, a1 = g^{r1}
 * r2 ? Z_q, a2 = g^{r2}
 * challenge e ? verifier (same challenge for both!)
 * z1 = r1 + e?x1, z2 = r2 + e?x2
 *
 * The key insight: using the SAME challenge e for both sub-protocols
 * preserves special soundness AND yields a conjunction proof.
 */
void sigma_and_commit(sigma_group_elem *a1, sigma_group_elem *a2,
                      const sigma_scalar *r1, const sigma_scalar *r2,
                      const sigma_and_public *pub);

/**
 * sigma_and_respond ? Prover responds for both statements.
 */
void sigma_and_respond(sigma_scalar *z1, sigma_scalar *z2,
                       const sigma_scalar *r1, const sigma_scalar *r2,
                       const sigma_scalar *e,
                       const sigma_and_witness *wit);

/**
 * sigma_and_verify ? Verifier checks both equations with the same challenge.
 */
bool sigma_and_verify(const sigma_group_elem *a1,
                      const sigma_group_elem *a2,
                      const sigma_scalar *e,
                      const sigma_scalar *z1,
                      const sigma_scalar *z2,
                      const sigma_and_public *pub);

/* ??? OR Composition (Proof of Partial Knowledge) ??????????????????? */

/**
 * sigma_or_public ? Public input for OR composition.
 * Statement: "I know w1 s.t. R1(x1,w1) OR I know w2 s.t. R2(x2,w2)"
 * Prover knows exactly one of the two witnesses (say w1).
 */
typedef struct {
    sigma_schnorr_public pk1;
    sigma_schnorr_public pk2;
} sigma_or_public;

/**
 * sigma_or_proof ? OR protocol proof (full transcript).
 *
 * The verifier provides a SINGLE challenge e.
 * The prover splits e = e1 ? e2 (XOR as scalars, or e = e1 + e2 mod q).
 *
 * For the branch where prover KNOWS the witness (say branch 1):
 *   - Generate a1 honestly from r1
 *   - e1 is derived after the fact: e1 = e ? e2 mod q
 * For the branch where prover DOES NOT KNOW (branch 2):
 *   - Simulate: pick z2, e2 ? Z_q, compute a2 = g^{z2} ? y2^{-e2}
 *
 * This is the Cramer-Damgard-Schoenmakers OR technique.
 */
typedef struct {
    sigma_group_elem a1;       /* commitment branch 1 */
    sigma_group_elem a2;       /* commitment branch 2 */
    sigma_scalar     e;        /* verifier's challenge (total) */
    sigma_scalar     e1;       /* challenge branch 1 (e = e1 + e2 mod q) */
    sigma_scalar     e2;       /* challenge branch 2 */
    sigma_scalar     z1;       /* response branch 1 */
    sigma_scalar     z2;       /* response branch 2 */
} sigma_or_transcript;

/**
 * sigma_or_prove ? Generate an OR proof for a known branch.
 *
 * branch: 0 = know w1, 1 = know w2.
 * randomness: r for the known branch (the other branch uses simulation).
 * verifier_challenge: e from verifier (or e = H(...) for Fiat-Shamir).
 */
void sigma_or_prove(sigma_or_transcript *t,
                    int known_branch,
                    const void *known_witness,
                    const void *unknown_public,
                    const sigma_or_public *pub,
                    const sigma_scalar *randomness,
                    const sigma_scalar *verifier_challenge);

/**
 * sigma_or_verify ? Verify an OR proof.
 *
 * Check: e1 + e2 ? e mod q (challenge split)
 *        AND both verification equations hold.
 *
 * Crucially, the verifier cannot tell which branch the prover knew.
 * This provides witness indistinguishability (and witness hiding).
 */
bool sigma_or_verify(const sigma_or_transcript *t,
                     const sigma_or_public *pub);

/* ??? 1-out-of-N OR (Ring) ?????????????????????????????????????????? */

#define SIGMA_OR_MAX_RING 16

/**
 * sigma_ring_public ? 1-out-of-N ring statement.
 * Statement: "I know sk_i for some i ? [0, N-1] among these N public keys."
 */
typedef struct {
    sigma_schnorr_public pks[SIGMA_OR_MAX_RING];
    int num_keys;  /* N in [2, SIGMA_OR_MAX_RING] */
} sigma_ring_public;

/**
 * sigma_ring_proof ? Ring signature proof (1-out-of-N).
 */
typedef struct {
    sigma_group_elem commitments[SIGMA_OR_MAX_RING];  /* a_i */
    sigma_scalar     challenge;           /* total e */
    sigma_scalar     challenges[SIGMA_OR_MAX_RING];   /* e_i (sum = e) */
    sigma_scalar     responses[SIGMA_OR_MAX_RING];   /* z_i */
    int num_keys;
} sigma_ring_proof;

/**
 * sigma_ring_prove ? Generate a ring proof knowing key at index signer_idx.
 *
 * L7 Application: Ring signatures (Monero, CryptoNote).
 * The signer proves they own ONE of the public keys without revealing which.
 */
void sigma_ring_prove(sigma_ring_proof *proof,
                      const sigma_ring_public *pub,
                      int signer_idx,
                      const sigma_schnorr_witness *signer_sk,
                      const uint8_t *message, size_t message_len);

/**
 * sigma_ring_verify ? Verify a ring proof.
 * Returns true without learning which key was used.
 */
bool sigma_ring_verify(const sigma_ring_proof *proof,
                       const sigma_ring_public *pub,
                       const uint8_t *message, size_t message_len);

/* ??? EQ Composition ???????????????????????????????????????????????? */

/**
 * sigma_eq_public ? Public input for EQ composition.
 * Statement: "I know (w1, w2) s.t. R1(x1,w1) AND R2(x2,w2) AND w1 = w2"
 *
 * This is a special case of AND where the witness is the same.
 * Note: This is essentially the Chaum-Pedersen protocol.
 */
typedef struct {
    sigma_schnorr_public pk1;
    sigma_schnorr_public pk2;
} sigma_eq_public;

/**
 * sigma_eq_prove ? Prove knowledge of the same x for both y1 = g1^x and y2 = g2^x.
 * Uses the same randomness r for both commitments, merged into one.
 */
void sigma_eq_prove(sigma_cp_transcript *t,
                    const sigma_schnorr_witness *wit,
                    const sigma_eq_public *pub,
                    const sigma_scalar *randomness);

/**
 * sigma_eq_verify ? Verify the equality proof.
 */
bool sigma_eq_verify(const sigma_cp_transcript *t,
                     const sigma_eq_public *pub);

/* ??? General Composition Interface ????????????????????????????????? */

/**
 * sigma_compose_and ? Generic AND of two arbitrary sigma protocols.
 *
 * Given two protocol vtables, compose them into an AND proof.
 * The composed protocol's vtable is returned (caller must keep input
 * protocols alive as the composed vtable holds pointers to them).
 */
const sigma_protocol *sigma_compose_and(const sigma_protocol *proto1,
                                        const sigma_protocol *proto2);

/**
 * sigma_compose_or ? Generic OR of two arbitrary sigma protocols.
 * Produces a witness-indistinguishable proof of partial knowledge.
 */
const sigma_protocol *sigma_compose_or(const sigma_protocol *proto1,
                                        const sigma_protocol *proto2);

/* ??? Serialization ????????????????????????????????????????????????? */

/** Serialize ring proof to bytes. */
void sigma_ring_proof_serialize(uint8_t *out, const sigma_ring_proof *p);

/** Deserialize ring proof from bytes. */
bool sigma_ring_proof_deserialize(sigma_ring_proof *p, const uint8_t *in);

#endif /* SIGMA_COMPOSITION_H */
