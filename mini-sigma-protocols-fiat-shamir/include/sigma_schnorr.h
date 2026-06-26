#ifndef SIGMA_SCHNORR_H
#define SIGMA_SCHNORR_H

/**
 * sigma_schnorr.h ? Schnorr Sigma Protocol
 *
 * Proves knowledge of discrete logarithm x such that y = g^x mod p.
 * This is the canonical sigma protocol and the basis for the
 * Fiat-Shamir transform to signatures.
 *
 * Protocol (3-move):
 *   Prover(x, y=g^x)                    Verifier(y)
 *   ?????????????????????????????????????????????
 *   r ? Z_q, a = g^r
 *                      ?? a ???
 *                                          e ? Z_q
 *                      ??? e ??
 *   z = r + e?x mod q
 *                      ?? z ???
 *                                     g^z ? a ? y^e
 *
 * L1 Definitions:
 *   - Schnorr identification/proof protocol
 *   - Discrete logarithm relation: R(y, x) = 1 iff g^x = y
 *
 * L4 Fundamental Theorems:
 *   - Special soundness: from (a,e,z), (a,e',z') extract x = (z-z')/(e-e')
 *   - SHVZK: simulator picks z ? Z_q, a = g^z ? y^{-e}, outputs (a, e, z)
 *   - Knowledge error ? = 1/q (negligible for large q)
 *
 * References:
 *   - Schnorr (1991) "Efficient Signature Generation by Smart Cards"
 *     Journal of Cryptology, 4(3):161-174
 *   - Schnorr (1989) "Efficient Identification and Signatures for Smart Cards"
 *     CRYPTO '89, LNCS 435
 *   - Goldreich (2004) Foundations of Cryptography I, ?4.7.2
 *   - Katz & Lindell (2014) Introduction to Modern Cryptography, ?13.3
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "sigma_math.h"
#include "sigma_core.h"

/* ??? Schnorr Key Generation ???????????????????????????????????????? */

/**
 * sigma_schnorr_keygen ? Generate a Schnorr keypair.
 *
 * x ? Z_q^* (secret key)
 * y = g^x mod p (public key)
 *
 * The secret key must be from Z_q^* (non-zero) to ensure y is in the
 * subgroup of order q. The public key y = g^x uniquely determines x
 * in Z_q (by the discrete log assumption).
 */
void sigma_schnorr_keygen(sigma_schnorr_witness *sk,
                          sigma_schnorr_public  *pk);

/**
 * sigma_schnorr_keygen_seeded ? Generate keypair from deterministic seed.
 * For reproducible testing: sk = H(seed || 0), pk = g^sk.
 */
void sigma_schnorr_keygen_seeded(sigma_schnorr_witness *sk,
                                 sigma_schnorr_public  *pk,
                                 uint64_t seed);

/* ??? Protocol Functions ????????????????????????????????????????????? */

/**
 * sigma_schnorr_commit ? Prover's first message.
 *
 * Input:  randomness r ? Z_q (secret, freshly random each run)
 * Output: commitment a = g^r mod p
 *
 * The randomness r MUST be freshly generated for each proof and
 * MUST be kept secret. Reusing r leaks the secret key x.
 */
void sigma_schnorr_commit(sigma_group_elem *commitment,
                          const sigma_scalar *randomness);

/**
 * sigma_schnorr_respond ? Prover's third message.
 *
 * Input:  randomness r, challenge e, secret key x
 * Output: response z = r + e?x mod q
 *
 * Security: If r is reused with different challenges e, e',
 *           x = (z-z')/(e-e') can be extracted from the proof.
 */
void sigma_schnorr_respond(sigma_scalar *response,
                           const sigma_scalar *randomness,
                           const sigma_scalar *challenge,
                           const sigma_scalar *secret_key);

/**
 * sigma_schnorr_verify ? Verifier's check.
 *
 * Checks: g^z ? a ? y^e (mod p)
 *
 * Completeness: If z = r + e?x, then g^z = g^{r+ex} = g^r ? (g^x)^e = a ? y^e.
 *
 * Returns true iff the proof is valid.
 */
bool sigma_schnorr_verify(const sigma_group_elem *commitment,
                          const sigma_scalar *challenge,
                          const sigma_scalar *response,
                          const sigma_group_elem *public_key);

/* ??? Knowledge Extraction (Special Soundness) ?????????????????????? */

/**
 * sigma_schnorr_extract ? Extract witness from two accepting transcripts.
 *
 * Given: (a, e, z) and (a, e', z') where e ? e', both accepting.
 * Compute: x = (z - z') ? (e - e')^{-1} mod q
 *
 * L4 Theorem (Special Soundness):
 *   From any two accepting transcripts with same commitment and
 *   different challenges, the witness x can be extracted.
 *   This establishes that Schnorr is a proof of knowledge with
 *   knowledge error ? = 1/q.
 *
 * Proof sketch:
 *   g^z = a ? y^e   and   g^{z'} = a ? y^{e'}
 *   ? g^{z-z'} = y^{e-e'}
 *   ? g^{(z-z')/(e-e')} = y
 *   ? x = (z-z')/(e-e') mod q is the discrete log of y
 */
bool sigma_schnorr_extract(sigma_scalar *witness_out,
                           const sigma_transcript *t1,
                           const sigma_transcript *t2,
                           const sigma_group_elem *public_key);

/* ??? Simulation (Special Honest-Verifier ZK) ??????????????????????? */

/**
 * sigma_schnorr_simulate ? Generate accepting transcript without witness.
 *
 * Given challenge e in advance:
 *   z ? Z_q (random)
 *   a = g^z ? y^{-e} mod p
 *   Output: (a, e, z)
 *
 * L4 Theorem (SHVZK):
 *   The distribution {(a, e, z) : r?Z_q, a=g^r, z=r+ex}
 *   is identical to {(a, e, z) : z?Z_q, a=g^z?y^{-e}}.
 *   Therefore the protocol is honest-verifier zero-knowledge.
 *
 * Proof sketch:
 *   For any (a, e, z) with a = g^z?y^{-e}, let r = z - ex.
 *   Then g^r = g^{z-ex} = g^z?(g^x)^{-e} = g^z?y^{-e} = a,
 *   and z = r + ex. The mapping (r,e) ? (z,e) is a bijection.
 */
void sigma_schnorr_simulate(sigma_transcript *transcript,
                            const sigma_scalar *challenge,
                            const sigma_group_elem *public_key);

/* ??? Full Interactive Run ?????????????????????????????????????????? */

/**
 * sigma_schnorr_prove ? Run full Schnorr protocol (prover side).
 *
 * Generates commitment a, receives challenge e from verifier,
 * computes response z. Fills the transcript.
 *
 * Caller must provide randomness r (typically freshly generated).
 */
void sigma_schnorr_prove(sigma_transcript *transcript,
                         const sigma_schnorr_witness *witness,
                         const sigma_schnorr_public *public_input,
                         const sigma_scalar *randomness);

/**
 * sigma_schnorr_verify_transcript ? Verify a complete Schnorr transcript.
 */
bool sigma_schnorr_verify_transcript(const sigma_transcript *t,
                                     const sigma_schnorr_public *pk);

/* ??? Getter for VTable ????????????????????????????????????????????? */

/** Return a fully populated sigma_protocol vtable for Schnorr. */
const sigma_protocol *sigma_schnorr_get_protocol(void);

#endif /* SIGMA_SCHNORR_H */
