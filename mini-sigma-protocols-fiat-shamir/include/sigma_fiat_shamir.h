#ifndef SIGMA_FIAT_SHAMIR_H
#define SIGMA_FIAT_SHAMIR_H

/**
 * sigma_fiat_shamir.h ? Fiat-Shamir Transform
 *
 * Converts any 3-move public-coin interactive sigma protocol into
 * a non-interactive proof system (and digital signature scheme)
 * by replacing the verifier's random challenge with a hash of
 * the commitment and the message.
 *
 * The Fiat-Shamir Heuristic:
 *   Interactive:    Prover ? a,  Verifier ? e ? Z_q,  Prover ? z
 *   Non-interactive: Prover computes a, then e = H(a || msg), then z
 *   Proof is (a, z); verifier recomputes e = H(a || msg), checks (a, e, z)
 *
 * L1 Definitions:
 *   - Fiat-Shamir transform: interactive ? non-interactive
 *   - Random oracle model (ROM): hash function modeled as truly random function
 *   - NIZK (Non-Interactive Zero-Knowledge) in ROM
 *
 * L4 Theorems:
 *   - Theorem (Fiat-Shamir, 1986): If the sigma protocol is HVZK and
 *     has special soundness, then the Fiat-Shamir transform yields a
 *     NIZK proof system in the random oracle model.
 *   - Theorem (Pointcheval & Stern, 1996): Fiat-Shamir-Schnorr is
 *     existentially unforgeable under chosen-message attack (EUF-CMA)
 *     in the ROM, assuming the discrete log problem is hard.
 *   - Forking Lemma (Pointcheval & Stern, 2000): Provides the security
 *     reduction for Fiat-Shamir signatures in the ROM.
 *
 * L7 Applications:
 *   - Schnorr signatures (EdDSA/Ed25519 ancestor)
 *   - DSA/ECDSA (Fiat-Shamir variant)
 *   - Non-interactive ZK proofs (zk-SNARK preprocessing)
 *   - Bulletproofs (range proofs via Fiat-Shamir)
 *   - STARKs (Scalable Transparent Arguments of Knowledge)
 *
 * L8 Advanced Topics:
 *   - Fiat-Shamir without ROM (correlation-intractable hash functions)
 *   - Quantum security of Fiat-Shamir (post-quantum: Unruh transform)
 *   - Weak Fiat-Shamir (hashing only commitment, not message)
 *
 * References:
 *   - Fiat & Shamir (1986) "How to Prove Yourself: Practical Solutions
 *     to Identification and Signature Problems", CRYPTO '86, LNCS 263
 *   - Pointcheval & Stern (1996) "Security Proofs for Signature Schemes"
 *     EUROCRYPT '96, LNCS 1070
 *   - Pointcheval & Stern (2000) "Security Arguments for Digital
 *     Signatures and Blind Signatures", Journal of Cryptology
 *   - Bellare & Rogaway (1993) "Random Oracles are Practical"
 *     ACM CCCS '93
 *   - Canetti, Goldreich, Halevi (2004) "The Random Oracle Methodology,
 *     Revisited", STOC '98 / JACM 51(4)
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "sigma_math.h"
#include "sigma_core.h"

/* ??? Fiat-Shamir Proof Generation ?????????????????????????????????? */

/**
 * sigma_fs_prove ? Fiat-Shamir non-interactive proof.
 *
 * Given a sigma protocol and a message, produce a non-interactive proof.
 *
 * Algorithm:
 *   1. r ? Z_q (fresh randomness)
 *   2. a = proto.prove_commit(r, witness, public_input)
 *   3. e = H(a || message || public_input)  [random oracle]
 *   4. z = proto.prove_response(r, e, witness, public_input)
 *   5. Output proof = (a, z)
 *
 * The verifier recomputes e = H(a || message || public_input) and
 * checks proto.verify(a, e, z, public_input).
 *
 * Security (ROM): The proof is sound because H is unpredictable;
 * the prover cannot "try again" with different challenges as in the
 * interactive setting.
 */
void sigma_fs_prove(sigma_proof *proof,
                    const sigma_protocol *proto,
                    const void *witness,
                    const void *public_input,
                    const uint8_t *message,
                    size_t message_len,
                    const sigma_scalar *randomness);

/* ??? Fiat-Shamir Proof Verification ???????????????????????????????? */

/**
 * sigma_fs_verify ? Verify a Fiat-Shamir non-interactive proof.
 *
 *   e = H(a || message || public_input)
 *   return proto.verify(a, e, z, public_input)
 *
 * Complexity: 1 hash + 1 protocol verification.
 */
bool sigma_fs_verify(const sigma_proof *proof,
                     const sigma_protocol *proto,
                     const void *public_input,
                     const uint8_t *message,
                     size_t message_len);

/* ??? Schnorr-Specific Fiat-Shamir ?????????????????????????????????? */

/**
 * sigma_fs_schnorr_prove ? Convenience wrapper for Schnorr FS proofs.
 *
 * Produces a non-interactive Schnorr proof: (a, z) where e = H(a || msg || y).
 */
void sigma_fs_schnorr_prove(sigma_proof *proof,
                            const sigma_schnorr_witness *sk,
                            const sigma_schnorr_public *pk,
                            const uint8_t *msg, size_t msg_len,
                            const sigma_scalar *randomness);

/**
 * sigma_fs_schnorr_verify ? Verify non-interactive Schnorr proof.
 */
bool sigma_fs_schnorr_verify(const sigma_proof *proof,
                             const sigma_schnorr_public *pk,
                             const uint8_t *msg, size_t msg_len);

/* ??? Fiat-Shamir Signature Scheme ?????????????????????????????????? */

/**
 * sigma_fs_signature ? A Fiat-Shamir-based digital signature.
 *
 * Signature = (commitment, response), where:
 *   e = H(commitment || message)  (no public key in hash for EdDSA-like)
 *   or e = H(commitment || public_key || message)
 *
 * The signature is exactly the non-interactive proof of knowledge
 * of the secret key, bound to the message through the hash.
 */
typedef struct {
    sigma_group_elem commitment;  /* R = g^r (nonce commitment) */
    sigma_scalar     response;    /* s = r + e?x mod q (signature scalar) */
} sigma_fs_signature;

/**
 * sigma_fs_sign ? Sign a message using Fiat-Shamir transform.
 *
 * Algorithm (Schnorr signature):
 *   1. r ? Z_q^* (ephemeral secret, MUST be unique per signature)
 *   2. R = g^r mod p
 *   3. e = H(R || pk || message) mod q
 *   4. s = r + e?x mod q
 *   5. Signature = (R, s)
 *
 * CRITICAL: r must be fresh and uniformly random for each signature.
 * Reusing r with different messages completely leaks the secret key.
 * This is the exact vulnerability exploited in the Sony PS3 hack (2010).
 *
 * L7 Application: EdDSA, Schnorr signatures, Bitcoin BIP-340.
 */
void sigma_fs_sign(sigma_fs_signature *sig,
                   const sigma_schnorr_witness *sk,
                   const sigma_schnorr_public *pk,
                   const uint8_t *message, size_t message_len);

/**
 * sigma_fs_verify_signature ? Verify a Fiat-Shamir signature.
 *
 * Algorithm:
 *   1. e = H(R || pk || message)
 *   2. Check: g^s ? R ? y^e mod p
 *
 * Returns true iff the signature is valid.
 */
bool sigma_fs_verify_signature(const sigma_fs_signature *sig,
                               const sigma_schnorr_public *pk,
                               const uint8_t *message, size_t message_len);

/* ??? Weak vs Strong Fiat-Shamir ???????????????????????????????????? */

/**
 * sigma_fs_is_strong ? Check if proof uses strong Fiat-Shamir.
 *
 * Strong Fiat-Shamir: e = H(a || public_input || message)
 *   - Includes public input in the hash
 *   - Resistant to "weak Fiat-Shamir" attacks
 *   - Used in modern protocols (e.g., Bulletproofs)
 *
 * Weak Fiat-Shamir: e = H(a || message)
 *   - Omits public input from the hash
 *   - Vulnerable to certain malleability attacks
 *   - Historically used in early Schnorr variants
 *
 * This function always returns true because our implementation
 * uses strong Fiat-Shamir by default.
 *
 * Reference:
 *   - Bernhard, Pereira, Warinschi (2012) "How Not to Prove Yourself:
 *     Pitfalls of Fiat-Shamir", NDSS 2012
 *   - Brown (2015) "On the Provable Security of (EC)DSA"
 */
bool sigma_fs_is_strong(void);

/**
 * sigma_fs_weak_prove ? Explicitly use weak Fiat-Shamir.
 * WARNING: For educational comparison only. Not secure for production.
 */
void sigma_fs_weak_prove(sigma_proof *proof,
                         const sigma_protocol *proto,
                         const void *witness,
                         const void *public_input,
                         const uint8_t *message, size_t message_len);

/* ??? Batch Verification ???????????????????????????????????????????? */

/**
 * sigma_fs_batch_verify ? Verify multiple Schnorr signatures efficiently.
 *
 * Uses the small exponents test (Bellare, Garay, Rabin 1998):
 * Instead of verifying each signature individually (k exponentiations),
 * verify them in a batch using random linear combination.
 *
 * Algorithm:
 *   Pick random c_i for each signature
 *   Check: g^{? c_i?s_i} ? ? (R_i ? y_i^{e_i})^{c_i}
 *
 * Complexity: O(n) exponentiations vs O(k?n) for individual verification.
 *
 * L8 Advanced Topic: Batch verification optimizations.
 * Used in Bitcoin, Monero, and other cryptocurrencies for block validation.
 */
bool sigma_fs_batch_verify(const sigma_fs_signature *sigs,
                           const sigma_schnorr_public *pks,
                           const uint8_t **messages,
                           const size_t *message_lens,
                           int num_signatures);

/* ??? Serialization ????????????????????????????????????????????????? */

/** Serialize a signature to bytes for transmission/storage. */
void sigma_fs_signature_serialize(uint8_t *out,
                                  const sigma_fs_signature *sig);

/** Deserialize a signature from bytes. */
bool sigma_fs_signature_deserialize(sigma_fs_signature *sig,
                                    const uint8_t *in);

/** Serialize a non-interactive proof. */
void sigma_fs_proof_serialize(uint8_t *out, const sigma_proof *proof);

/** Deserialize a non-interactive proof. */
bool sigma_fs_proof_deserialize(sigma_proof *proof, const uint8_t *in);

/* ??? Signature Forgery Resistance Test ????????????????????????????? */

/**
 * sigma_fs_test_forgery_resistance ? Verify that forging is hard.
 *
 * Generates many valid signatures, then attempts to forge one
 * by guessing. Verifies that forgery succeeds with at most
 * negligible probability (? 1/q).
 *
 * Returns the success rate of forgery attempts.
 */
double sigma_fs_test_forgery_resistance(int num_trials);

#endif /* SIGMA_FIAT_SHAMIR_H */
