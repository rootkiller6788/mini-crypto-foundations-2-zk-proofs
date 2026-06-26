#ifndef SIGMA_GQ_H
#define SIGMA_GQ_H

/**
 * sigma_gq.h ? Guillou-Quisquater Sigma Protocol
 *
 * RSA-based identification and proof of knowledge of an RSA
 * secret key. Proves knowledge of the e-th root modulo N.
 *
 * Protocol:
 *   Public:  (N, e, X) where N = p?q (RSA modulus), X = x^e mod N
 *   Witness: x (the e-th root of X)
 *
 *   Prover(x)                          Verifier(N, e, X)
 *   ????????????????????????????????????????????????????????
 *   y ? Z_N^*, Y = y^e mod N
 *                       ?? Y ???
 *                                         c ? Z_e
 *                       ??? c ??
 *   z = y ? x^c mod N
 *                       ?? z ???
 *                                    z^e ? Y ? X^c mod N
 *
 * L1 Definitions:
 *   - Guillou-Quisquater (GQ) protocol
 *   - RSA-based sigma protocol
 *   - e-th root knowledge proof
 *
 * L4 Theorems:
 *   - Special soundness: from (Y, c, z) and (Y, c', z') with c ? c',
 *     compute x = (z/z')^{1/(c-c')} mod N (requires gcd(e, c-c') = 1)
 *   - SHVZK: pick z ? Z_N^*, c ? Z_e, Y = z^e ? X^{-c} mod N
 *   - Security: based on RSA assumption (extracting e-th roots is hard)
 *
 * L2 Core Concepts:
 *   - RSA group: Z_N^* where N = p?q for safe primes
 *   - The exponent e is typically a small prime (e.g., 3, 65537)
 *   - Unlike Schnorr (which uses Z_p^*), GQ uses Z_N^* with hidden order
 *
 * References:
 *   - Guillou & Quisquater (1988) "A Practical Zero-Knowledge Protocol
 *     Fitted to Security Microprocessor Minimizing Both Transmission
 *     and Memory", EUROCRYPT '88, LNCS 330
 *   - Bellare & Palacio (2002) "GQ and Schnorr Identification Schemes:
 *     Proofs of Security against Impersonation under Active and
 *     Concurrent Attacks", CRYPTO 2002
 *   - Goldreich (2004) Foundations of Cryptography I, ?4.7.3
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "sigma_math.h"

/* ??? RSA Parameters ???????????????????????????????????????????????? */

/** RSA modulus size in bits (2048 for 112-bit security). */
#define SIGMA_GQ_MODULUS_BITS  2048
#define SIGMA_GQ_MODULUS_WORDS 32

/** Maximum RSA public exponent (small primes only). */
#define SIGMA_GQ_MAX_EXPONENT  65537

/**
 * sigma_gq_modulus ? RSA modulus N = p ? q.
 * p and q are secret; only N is public.
 */
typedef struct {
    uint64_t limbs[SIGMA_GQ_MODULUS_WORDS];
} sigma_gq_modulus;

/**
 * sigma_gq_public ? GQ public input.
 *
 * N: RSA modulus
 * e: public exponent (small prime, typically 3 or 65537)
 * X: public value = x^e mod N
 */
typedef struct {
    sigma_gq_modulus N;
    uint64_t         e;   /* public exponent */
    sigma_gq_modulus X;   /* X = x^e mod N */
} sigma_gq_public;

/**
 * sigma_gq_witness ? GQ witness.
 * x ? Z_N^* such that X ? x^e (mod N).
 */
typedef struct {
    sigma_gq_modulus x;   /* secret e-th root */
} sigma_gq_witness;

/* ??? Key Generation ????????????????????????????????????????????????? */

/**
 * sigma_gq_keygen ? Generate a GQ keypair.
 *
 * Generates small RSA primes p, q (for testing only ? production
 * needs proper RSA key generation with large random primes).
 *
 * e: small public exponent (3 or 65537)
 * x: random e-th root candidate
 * X = x^e mod N
 *
 * L5 Algorithm: RSA parameter generation for GQ.
 */
bool sigma_gq_keygen(sigma_gq_public *pub, sigma_gq_witness *wit,
                     uint64_t e);

/**
 * sigma_gq_keygen_seeded ? Deterministic key generation for testing.
 */
bool sigma_gq_keygen_seeded(sigma_gq_public *pub, sigma_gq_witness *wit,
                            uint64_t e, uint64_t seed);

/* ??? RSA Modular Arithmetic ???????????????????????????????????????? */

/**
 * sigma_gq_mod_mul ? r = (a ? b) mod N.
 */
void sigma_gq_mod_mul(sigma_gq_modulus *r,
                      const sigma_gq_modulus *a,
                      const sigma_gq_modulus *b,
                      const sigma_gq_modulus *N);

/**
 * sigma_gq_mod_exp ? r = base^exp mod N.
 */
void sigma_gq_mod_exp(sigma_gq_modulus *r,
                      const sigma_gq_modulus *base,
                      const sigma_gq_modulus *exp,
                      int exp_bits,
                      const sigma_gq_modulus *N);

/**
 * sigma_gq_mod_exp_small ? r = base^e mod N for small exponent e.
 * Optimized version when e fits in uint64_t.
 */
void sigma_gq_mod_exp_small(sigma_gq_modulus *r,
                            const sigma_gq_modulus *base,
                            uint64_t e,
                            const sigma_gq_modulus *N);

/**
 * sigma_gq_mod_inv ? r = a^{-1} mod N.
 */
bool sigma_gq_mod_inv(sigma_gq_modulus *r,
                      const sigma_gq_modulus *a,
                      const sigma_gq_modulus *N);

/* ??? Protocol Functions ???????????????????????????????????????????? */

/**
 * sigma_gq_commit ? Prover's first message.
 *
 * y ? Z_N^* (random)
 * Y = y^e mod N
 */
void sigma_gq_commit(sigma_gq_modulus *Y,
                     const sigma_gq_modulus *y_randomness,
                     const sigma_gq_public *pub);

/**
 * sigma_gq_respond ? Prover's third message.
 *
 * z = y ? x^c mod N
 */
void sigma_gq_respond(sigma_gq_modulus *z,
                      const sigma_gq_modulus *y_randomness,
                      uint64_t challenge,
                      const sigma_gq_witness *wit,
                      const sigma_gq_public *pub);

/**
 * sigma_gq_verify ? Verifier's check.
 *
 * z^e ? Y ? X^c mod N
 *
 * Completeness: z^e = (y?x^c)^e = y^e ? (x^e)^c = Y ? X^c.
 */
bool sigma_gq_verify(const sigma_gq_modulus *Y,
                     uint64_t challenge,
                     const sigma_gq_modulus *z,
                     const sigma_gq_public *pub);

/* ??? GQ Transcript ????????????????????????????????????????????????? */

typedef struct {
    sigma_gq_modulus Y;         /* commitment */
    uint64_t         challenge;  /* c ? [0, e-1] */
    sigma_gq_modulus z;         /* response */
} sigma_gq_transcript;

/**
 * sigma_gq_prove ? Run full GQ protocol (prover side).
 */
void sigma_gq_prove(sigma_gq_transcript *t,
                    const sigma_gq_witness *wit,
                    const sigma_gq_public *pub,
                    const sigma_gq_modulus *y_randomness,
                    uint64_t challenge);

/**
 * sigma_gq_verify_transcript ? Verify GQ transcript.
 */
bool sigma_gq_verify_transcript(const sigma_gq_transcript *t,
                                const sigma_gq_public *pub);

/* ??? Knowledge Extraction ?????????????????????????????????????????? */

/**
 * sigma_gq_extract ? Extract witness from two transcripts.
 *
 * Given (Y, c, z) and (Y, c', z') with c ? c':
 *   Compute: d = c - c' (can be negative; use absolute value)
 *   Need: gcd(e, |d|) = 1 for extraction to work
 *   Then: x = (z / z')^{1/d} mod N via extended Euclid.
 *
 * With gcd(e, d) = 1, we find a,b s.t. a?e + b?d = 1,
 * then x = X^a ? (z/z')^b mod N.
 */
bool sigma_gq_extract(sigma_gq_witness *wit_out,
                      const sigma_gq_transcript *t1,
                      const sigma_gq_transcript *t2,
                      const sigma_gq_public *pub);

/* ??? Simulation ???????????????????????????????????????????????????? */

/**
 * sigma_gq_simulate ? Generate accepting transcript given challenge c.
 *
 * z ? Z_N^*
 * Y = z^e ? X^{-c} mod N
 */
void sigma_gq_simulate(sigma_gq_transcript *t,
                       uint64_t challenge,
                       const sigma_gq_public *pub);

/* ??? Fiat-Shamir for GQ ???????????????????????????????????????????? */

/**
 * sigma_gq_fs_prove ? Non-interactive GQ proof via Fiat-Shamir.
 *
 * c = H(Y || msg) mod e
 * Proof = (Y, z)
 */
void sigma_gq_fs_prove(sigma_gq_modulus *Y, sigma_gq_modulus *z,
                       const sigma_gq_witness *wit,
                       const sigma_gq_public *pub,
                       const uint8_t *msg, size_t msg_len);

/**
 * sigma_gq_fs_verify ? Verify non-interactive GQ proof.
 */
bool sigma_gq_fs_verify(const sigma_gq_modulus *Y,
                        const sigma_gq_modulus *z,
                        const sigma_gq_public *pub,
                        const uint8_t *msg, size_t msg_len);

/* ??? GQ Signature Scheme ??????????????????????????????????????????? */

typedef struct {
    sigma_gq_modulus Y;  /* commitment */
    sigma_gq_modulus s;  /* response */
} sigma_gq_signature;

/**
 * sigma_gq_sign ? GQ-based digital signature.
 *
 * L7 Application: GQ identification ? GQ signature scheme.
 * Historically used in ISO/IEC 9796-2 and smart card standards.
 */
void sigma_gq_sign(sigma_gq_signature *sig,
                   const sigma_gq_witness *wit,
                   const sigma_gq_public *pub,
                   const uint8_t *msg, size_t msg_len);

/**
 * sigma_gq_verify_signature ? Verify GQ signature.
 */
bool sigma_gq_verify_signature(const sigma_gq_signature *sig,
                               const sigma_gq_public *pub,
                               const uint8_t *msg, size_t msg_len);

/* ??? GQ VTable ????????????????????????????????????????????????????? */

/** Return sigma_protocol vtable for GQ. */
const struct sigma_protocol *sigma_gq_get_protocol(void);

/* ??? Serialization ????????????????????????????????????????????????? */

void sigma_gq_modulus_serialize(uint8_t *out, const sigma_gq_modulus *m);
bool sigma_gq_modulus_deserialize(sigma_gq_modulus *m, const uint8_t *in);
void sigma_gq_transcript_serialize(uint8_t *out, const sigma_gq_transcript *t);
bool sigma_gq_transcript_deserialize(sigma_gq_transcript *t, const uint8_t *in);

#endif /* SIGMA_GQ_H */
