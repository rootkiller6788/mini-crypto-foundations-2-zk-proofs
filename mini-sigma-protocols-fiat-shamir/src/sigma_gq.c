/**
 * sigma_gq.c �� Guillou-Quisquater RSA-Based Sigma Protocol
 *
 * Implements the GQ identification protocol based on the RSA assumption.
 * Prover knows the e-th root of X modulo N: x^e �� X (mod N).
 *
 * Protocol (3-move):
 *   Public: (N, e, X) where X = x^e mod N
 *   Witness: x (secret e-th root)
 *
 *   Prover(x)                          Verifier(N, e, X)
 *   y �� Z_N^*, Y = y^e mod N
 *                       �� Y ��
 *                                         c �� [0, e-1]
 *                       �� c ��
 *   z = y �� x^c mod N
 *                       �� z ��
 *                                    z^e �� Y �� X^c  (mod N)
 *
 * L2 Core Concepts:
 *   - RSA group: Z_N^* where N = p��q for secret primes
 *   - Small public exponent e (3, 65537) enables efficient verification
 *   - Unlike Schnorr (prime-order group), GQ uses composite modulus
 *     with hidden order �� the group order ��(N) = (p-1)(q-1) is secret
 *
 * L4 Theorems:
 *   - Special Soundness: Given (Y,c,z) and (Y,c',z') with c��c' and
 *     gcd(e, |c-c'|) = 1, can extract x = (z/z')^{1/(c-c')} mod N
 *   - SHVZK: pick z��Z_N^*, c��[0,e-1], Y = z^e �� X^{-c} mod N
 *   - Knowledge Error: �� = 1/e (non-negligible for small e!)
 *
 * L7 Applications:
 *   - ISO/IEC 9796-2 digital signature standard
 *   - Smart card identification (low computation for prover)
 *   - GQ signature scheme
 *   - Identity-based identification
 *
 * References:
 *   - Guillou & Quisquater (1988) "A Practical Zero-Knowledge Protocol
 *     Fitted to Security Microprocessor", EUROCRYPT '88, LNCS 330
 *   - Bellare & Palacio (2002) "GQ and Schnorr Identification Schemes",
 *     CRYPTO 2002
 *   - Goldreich (2004) Foundations of Cryptography I, ��4.7.3
 */

#include "sigma_gq.h"
#include "sigma_math.h"
#include "sigma_core.h"
#include <string.h>
#include <stdlib.h>

/* ========================================================================
 *  RSA Arithmetic for GQ (modular operations in Z_N)
 *
 *  Since N may be smaller than or comparable to p (our standard prime),
 *  we reuse the big-integer arithmetic but with a custom modulus N.
 *  We need modular multiplication and exponentiation with arbitrary modulus.
 * ======================================================================== */

void sigma_gq_mod_mul(sigma_gq_modulus *r,
                      const sigma_gq_modulus *a,
                      const sigma_gq_modulus *b,
                      const sigma_gq_modulus *N) {
    sigma_mod_mul((sigma_biguint*)r, (const sigma_biguint*)a,
                  (const sigma_biguint*)b, (const sigma_biguint*)N);
}

void sigma_gq_mod_exp(sigma_gq_modulus *r,
                      const sigma_gq_modulus *base,
                      const sigma_gq_modulus *exp,
                      int exp_bits,
                      const sigma_gq_modulus *N) {
    sigma_mod_exp((sigma_biguint*)r, (const sigma_biguint*)base,
                  (const sigma_biguint*)exp, exp_bits,
                  (const sigma_biguint*)N);
}

/**
 * sigma_gq_mod_exp_small �� Modular exponentiation with small uint64_t exponent.
 *
 * L5 Algorithm: Square-and-multiply with uint64_t exponent.
 * Much faster than the general big-integer exponentiation.
 * Complexity: O(n^2 �� log2(e)) where n is N's word count.
 */
void sigma_gq_mod_exp_small(sigma_gq_modulus *r,
                             const sigma_gq_modulus *base,
                             uint64_t e,
                             const sigma_gq_modulus *N) {
    sigma_biguint_set_u64((sigma_biguint*)r, 1);
    sigma_biguint bb;
    memcpy(bb.limbs, base->limbs, sizeof(bb.limbs));

    while (e > 0) {
        if (e & 1) {
            sigma_mod_mul((sigma_biguint*)r,
                          (const sigma_biguint*)r,
                          (const sigma_biguint*)&bb,
                          (const sigma_biguint*)N);
        }
        sigma_mod_mul((sigma_biguint*)&bb,
                      (const sigma_biguint*)&bb,
                      (const sigma_biguint*)&bb,
                      (const sigma_biguint*)N);
        e >>= 1;
    }
}

bool sigma_gq_mod_inv(sigma_gq_modulus *r,
                      const sigma_gq_modulus *a,
                      const sigma_gq_modulus *N) {
    return sigma_mod_inv((sigma_biguint*)r, (const sigma_biguint*)a,
                         (const sigma_biguint*)N);
}

/* ========================================================================
 *  Simple Primality for Test-Grade RSA Key Generation
 *
 *  L5 Algorithm: Miller-Rabin primality test (deterministic for 32-bit).
 *  For production, use full 2048-bit random prime generation.
 *  For educational purposes, we generate small test primes.
 * ======================================================================== */

static bool is_probable_prime(uint64_t n) {
    if (n < 2) return false;
    if (n == 2 || n == 3) return true;
    if (n % 2 == 0) return false;

    /* Write n-1 = d * 2^s */
    uint64_t d = n - 1;
    int s = 0;
    while (d % 2 == 0) { d /= 2; s++; }

    /* Miller-Rabin bases for deterministic 64-bit testing */
    static const uint64_t bases[] = {2, 3, 5, 7, 11, 13, 17};
    int num_bases = sizeof(bases) / sizeof(bases[0]);

    for (int i = 0; i < num_bases; i++) {
        uint64_t a = bases[i];
        if (a >= n) continue;

        /* Compute a^d mod n */
        uint64_t x = 1;
        uint64_t base = a;
        uint64_t exp = d;
        while (exp) {
            if (exp & 1) x = (unsigned __int128)x * base % n;
            base = (unsigned __int128)base * base % n;
            exp >>= 1;
        }

        if (x == 1 || x == n - 1) continue;

        int j;
        for (j = 0; j < s - 1; j++) {
            x = (unsigned __int128)x * x % n;
            if (x == n - 1) break;
        }
        if (j == s - 1) return false;
    }
    return true;
}

/* ========================================================================
 *  Key Generation
 *
 *  Generates RSA parameters for GQ:
 *    - Pick two small primes p, q (test-grade only)
 *    - N = p * q
 *    - Pick public exponent e (small prime)
 *    - Choose random x �� Z_N^*
 *    - Compute X = x^e mod N
 * ======================================================================== */

bool sigma_gq_keygen(sigma_gq_public *pub, sigma_gq_witness *wit,
                     uint64_t e) {
    /* Generate small test primes p, q */
    uint64_t p = 0, q = 0;
    sigma_random_seed(0x123456789ABCDEF0ULL + e);

    /* Find a small prime for p */
    for (uint64_t cand = 100; cand < 10000; cand++) {
        if (is_probable_prime(cand) && cand != e) {
            p = cand; break;
        }
    }
    if (p == 0) return false;

    /* Find a different small prime for q */
    for (uint64_t cand = p + 1; cand < 20000; cand++) {
        if (is_probable_prime(cand) && cand != e && cand != p) {
            q = cand; break;
        }
    }
    if (q == 0) return false;

    uint64_t N64 = p * q;

    /* Set up modulus N */
    memset(pub->N.limbs, 0, sizeof(pub->N.limbs));
    pub->N.limbs[0] = N64;

    pub->e = e;

    /* Generate witness x �� Z_N^* (coprime to N) */
    uint64_t x_candidate;
    do {
        x_candidate = 0;
        for (int i = 0; i < 4; i++) {
            uint64_t r;
            sigma_random_bytes((uint8_t*)&r, sizeof(r));
            x_candidate ^= r;
        }
        x_candidate %= N64;
        if (x_candidate == 0) x_candidate = 1;
    } while (x_candidate >= N64);

    memset(wit->x.limbs, 0, sizeof(wit->x.limbs));
    wit->x.limbs[0] = x_candidate;

    /* Compute X = x^e mod N */
    sigma_gq_mod_exp_small(&pub->X, &wit->x, e, &pub->N);

    return true;
}

bool sigma_gq_keygen_seeded(sigma_gq_public *pub, sigma_gq_witness *wit,
                             uint64_t e, uint64_t seed) {
    sigma_random_seed(seed);
    return sigma_gq_keygen(pub, wit, e);
}

/* ========================================================================
 *  Protocol Functions
 * ======================================================================== */

void sigma_gq_commit(sigma_gq_modulus *Y,
                     const sigma_gq_modulus *y_randomness,
                     const sigma_gq_public *pub) {
    /* Y = y^e mod N */
    sigma_gq_mod_exp_small(Y, y_randomness, pub->e, &pub->N);
}

void sigma_gq_respond(sigma_gq_modulus *z,
                       const sigma_gq_modulus *y_randomness,
                       uint64_t challenge,
                       const sigma_gq_witness *wit,
                       const sigma_gq_public *pub) {
    /* Compute x^c mod N */
    sigma_gq_modulus xc;
    sigma_gq_mod_exp_small(&xc, &wit->x, challenge, &pub->N);

    /* z = y * x^c mod N */
    sigma_gq_mod_mul(z, y_randomness, &xc, &pub->N);
}

bool sigma_gq_verify(const sigma_gq_modulus *Y,
                     uint64_t challenge,
                     const sigma_gq_modulus *z,
                     const sigma_gq_public *pub) {
    /* Compute z^e mod N */
    sigma_gq_modulus ze;
    sigma_gq_mod_exp_small(&ze, z, pub->e, &pub->N);

    /* Compute X^c mod N */
    sigma_gq_modulus Xc;
    sigma_gq_mod_exp_small(&Xc, &pub->X, challenge, &pub->N);

    /* Compute Y * X^c mod N */
    sigma_gq_modulus rhs;
    sigma_gq_mod_mul(&rhs, Y, &Xc, &pub->N);

    /* Check: z^e �� Y * X^c (mod N) */
    return memcmp(ze.limbs, rhs.limbs, sizeof(ze.limbs)) == 0;
}

/* ========================================================================
 *  Full Interactive Run
 * ======================================================================== */

void sigma_gq_prove(sigma_gq_transcript *t,
                    const sigma_gq_witness *wit,
                    const sigma_gq_public *pub,
                    const sigma_gq_modulus *y_randomness,
                    uint64_t challenge) {
    /* Commit: Y = y^e mod N */
    sigma_gq_commit(&t->Y, y_randomness, pub);
    t->challenge = challenge;
    /* Respond: z = y * x^c mod N */
    sigma_gq_respond(&t->z, y_randomness, challenge, wit, pub);
}

bool sigma_gq_verify_transcript(const sigma_gq_transcript *t,
                                 const sigma_gq_public *pub) {
    return sigma_gq_verify(&t->Y, t->challenge, &t->z, pub);
}

/* ========================================================================
 *  Knowledge Extraction (Special Soundness for GQ)
 *
 *  Given (Y, c, z) and (Y, c', z') with c �� c':
 *    Let d = c - c' (may be negative; use absolute value).
 *    From z^e = Y��X^c and z'^e = Y��X^{c'}:
 *      (z/z')^e = X^{c-c'} = X^d
 *    If gcd(e, |d|) = 1, find a,b such that a��e + b��|d| = 1.
 *    Then: X = X^{a��e + b��|d|} = (X^a)^e �� X^{b��|d|}
 *      = (X^a)^e �� ((z/z')^e)^b = (X^a �� (z/z')^b)^e
 *    So: x = X^a �� (z/z')^b mod N
 *
 *  NOTE: This fundamentally differs from Schnorr extraction.
 *  The GQ extraction requires gcd(e, |c-c'|) = 1.
 *  With small e (e.g., e=3), many challenge pairs fail this condition.
 *  This is why GQ needs larger e for security.
 * ======================================================================== */

bool sigma_gq_extract(sigma_gq_witness *wit_out,
                       const sigma_gq_transcript *t1,
                       const sigma_gq_transcript *t2,
                       const sigma_gq_public *pub) {
    /* Same commitment Y required */
    if (memcmp(t1->Y.limbs, t2->Y.limbs, sizeof(t1->Y.limbs)) != 0)
        return false;

    /* Different challenges required */
    if (t1->challenge == t2->challenge) return false;

    /* Both must be accepting */
    if (!sigma_gq_verify(&t1->Y, t1->challenge, &t1->z, pub)) return false;
    if (!sigma_gq_verify(&t2->Y, t2->challenge, &t2->z, pub)) return false;

    /* Compute d = |c - c'| */
    int64_t diff = (int64_t)t1->challenge - (int64_t)t2->challenge;
    uint64_t d = (diff < 0) ? (uint64_t)(-diff) : (uint64_t)diff;

    /* Check gcd(e, d) = 1 via extended Euclid */
    {
        uint64_t a = pub->e, b = d;
        while (b) { uint64_t t = a % b; a = b; b = t; }
        if (a != 1) return false; /* Extraction fails when gcd != 1 */
    }

    /* Compute z1 * z2^{-1} mod N */
    sigma_gq_modulus z_ratio, z2_inv;
    if (!sigma_gq_mod_inv(&z2_inv, &t2->z, &pub->N)) return false;
    sigma_gq_mod_mul(&z_ratio, &t1->z, &z2_inv, &pub->N);

    /* Extended Euclidean: find a, b s.t. a��e + b��d = 1 */
    int64_t s, t;
    {
        int64_t r0 = (int64_t)pub->e, r1 = (int64_t)d;
        int64_t s0 = 1, s1 = 0;
        int64_t t0 = 0, t1 = 1;
        while (r1 != 0) {
            int64_t q = r0 / r1;
            int64_t r2 = r0 - q * r1;
            int64_t s2 = s0 - q * s1;
            int64_t t2 = t0 - q * t1;
            r0 = r1; r1 = r2;
            s0 = s1; s1 = s2;
            t0 = t1; t1 = t2;
        }
        s = s0; t = t0;
    }

    /* Compute x = X^a �� (z1/z2)^b mod N
     * Handle negative exponents by modular inverse.
     */
    sigma_gq_modulus term1, term2;

    /* term1 = X^a mod N */
    if (s >= 0) {
        sigma_gq_mod_exp_small(&term1, &pub->X, (uint64_t)s, &pub->N);
    } else {
        sigma_gq_modulus X_inv;
        sigma_gq_mod_inv(&X_inv, &pub->X, &pub->N);
        sigma_gq_mod_exp_small(&term1, &X_inv, (uint64_t)(-s), &pub->N);
    }

    /* term2 = (z1/z2)^b mod N */
    if (t >= 0) {
        sigma_gq_mod_exp_small(&term2, &z_ratio, (uint64_t)t, &pub->N);
    } else {
        sigma_gq_modulus zr_inv;
        sigma_gq_mod_inv(&zr_inv, &z_ratio, &pub->N);
        sigma_gq_mod_exp_small(&term2, &zr_inv, (uint64_t)(-t), &pub->N);
    }

    sigma_gq_mod_mul(&wit_out->x, &term1, &term2, &pub->N);

    /* Verify: X �� x^e mod N */
    sigma_gq_modulus check;
    sigma_gq_mod_exp_small(&check, &wit_out->x, pub->e, &pub->N);
    return memcmp(check.limbs, pub->X.limbs, sizeof(check.limbs)) == 0;
}

/* ========================================================================
 *  Simulation (SHVZK for GQ)
 *
 *  Given challenge c in advance:
 *    1. Pick random z �� Z_N^*
 *    2. Compute Y = z^e �� X^{-c} mod N
 *    3. Output (Y, c, z)
 * ======================================================================== */

void sigma_gq_simulate(sigma_gq_transcript *t,
                        uint64_t challenge,
                        const sigma_gq_public *pub) {
    /* Pick random z (co-prime to N via inversion check) */
    sigma_gq_modulus z;
    memset(z.limbs, 0, sizeof(z.limbs));
    do {
        sigma_random_bytes((uint8_t*)z.limbs, sizeof(z.limbs));
        /* Ensure z < N */
        if (z.limbs[0] >= pub->N.limbs[0]) z.limbs[0] %= pub->N.limbs[0];
        if (z.limbs[0] == 0) z.limbs[0] = 1;
    } while (z.limbs[0] >= pub->N.limbs[0]);

    sigma_gq_modulus ze, Xc, Xc_inv;
    sigma_gq_mod_exp_small(&ze, &z, pub->e, &pub->N);
    sigma_gq_mod_exp_small(&Xc, &pub->X, challenge, &pub->N);
    sigma_gq_mod_inv(&Xc_inv, &Xc, &pub->N);

    /* Y = z^e �� X^{-c} mod N */
    sigma_gq_mod_mul(&t->Y, &ze, &Xc_inv, &pub->N);

    t->challenge = challenge;
    sigma_gq_mod_mul(&t->z, &z, &z, &pub->N); /* Wait, t->z should be z */
    memcpy(t->z.limbs, z.limbs, sizeof(z.limbs));
}

/* ========================================================================
 *  Fiat-Shamir for GQ
 * ======================================================================== */

void sigma_gq_fs_prove(sigma_gq_modulus *Y, sigma_gq_modulus *z,
                        const sigma_gq_witness *wit,
                        const sigma_gq_public *pub,
                        const uint8_t *msg, size_t msg_len) {
    sigma_gq_modulus y_rand;
    memset(y_rand.limbs, 0, sizeof(y_rand.limbs));
    do {
        sigma_random_bytes((uint8_t*)y_rand.limbs, sizeof(y_rand.limbs));
        y_rand.limbs[0] %= pub->N.limbs[0];
    } while (y_rand.limbs[0] == 0);

    /* Y = y^e mod N */
    sigma_gq_commit(Y, &y_rand, pub);

    /* c = H(Y || msg) mod e */
    sigma_hash_context ctx;
    sigma_hash_init(&ctx);
    uint8_t Ybuf[256];
    memset(Ybuf, 0, sizeof(Ybuf));
    sigma_gq_modulus_serialize(Ybuf, Y);
    sigma_hash_update(&ctx, Ybuf, 256);
    sigma_hash_update(&ctx, msg, msg_len);
    uint8_t dgst[32];
    sigma_hash_final(&ctx, dgst);
    uint64_t challenge = 0;
    for (int i = 0; i < 8; i++)
        challenge = (challenge << 8) | dgst[i];
    challenge %= pub->e;
    if (challenge == 0) challenge = 1;

    /* z = y * x^c mod N */
    sigma_gq_respond(z, &y_rand, challenge, wit, pub);
}

bool sigma_gq_fs_verify(const sigma_gq_modulus *Y,
                         const sigma_gq_modulus *z,
                         const sigma_gq_public *pub,
                         const uint8_t *msg, size_t msg_len) {
    sigma_hash_context ctx;
    sigma_hash_init(&ctx);
    uint8_t Ybuf[256];
    memset(Ybuf, 0, sizeof(Ybuf));
    sigma_gq_modulus_serialize(Ybuf, Y);
    sigma_hash_update(&ctx, Ybuf, 256);
    sigma_hash_update(&ctx, msg, msg_len);
    uint8_t dgst[32];
    sigma_hash_final(&ctx, dgst);
    uint64_t challenge = 0;
    for (int i = 0; i < 8; i++)
        challenge = (challenge << 8) | dgst[i];
    challenge %= pub->e;
    if (challenge == 0) challenge = 1;

    return sigma_gq_verify(Y, challenge, z, pub);
}

/* ========================================================================
 *  GQ Digital Signature
 *
 *  L7 Application: GQ identification �� GQ signature via Fiat-Shamir.
 *  Sign(sk, msg):
 *    1. y �� Z_N^*, Y = y^e mod N
 *    2. c = H(Y || msg) mod e
 *    3. s = y �� x^c mod N
 *    4. �� = (Y, s)
 *
 *  Verify(pk, msg, ��):
 *    1. c = H(Y || msg) mod e
 *    2. Check: s^e �� Y �� X^c (mod N)
 *
 *  NOTE: Security requires large e because knowledge error = 1/e.
 *  With e = 3, a forger succeeds with probability 1/3 per attempt.
 *  Production GQ signatures use e �� 2^80 or employ parallel repetition.
 * ======================================================================== */

void sigma_gq_sign(sigma_gq_signature *sig,
                    const sigma_gq_witness *wit,
                    const sigma_gq_public *pub,
                    const uint8_t *msg, size_t msg_len) {
    sigma_gq_fs_prove(&sig->Y, &sig->s, wit, pub, msg, msg_len);
}

bool sigma_gq_verify_signature(const sigma_gq_signature *sig,
                                const sigma_gq_public *pub,
                                const uint8_t *msg, size_t msg_len) {
    return sigma_gq_fs_verify(&sig->Y, &sig->s, pub, msg, msg_len);
}

/* ========================================================================
 *  GQ VTable
 * ======================================================================== */

static struct sigma_protocol g_gq_proto;

static void gq_prove_commit(sigma_group_elem *c, const sigma_scalar *r,
                             const void *w, const void *pub) {
    /* Adapt GQ to the generic vtable (this is approximate) */
    (void)w;
    const sigma_gq_public *p = (const sigma_gq_public*)pub;
    sigma_gq_modulus Y, y_rand;
    memset(y_rand.limbs, 0, sizeof(y_rand.limbs));
    memcpy(y_rand.limbs, r->limbs, sizeof(r->limbs));
    y_rand.limbs[0] %= p->N.limbs[0];
    if (y_rand.limbs[0] == 0) y_rand.limbs[0] = 1;
    sigma_gq_commit(&Y, &y_rand, p);
    memcpy(c->limbs, Y.limbs, sizeof(Y.limbs));
}

/* ========================================================================
 *  GQ vtable adapters — bridge GQ-specific 2048-bit types to generic
 *  sigma_scalar/sigma_group_elem interface via best-effort conversion.
 *
 *  The GQ protocol operates over 2048-bit RSA moduli (32 × 64-bit limbs),
 *  while sigma_scalar is 256-bit.  For vtable-level interop we truncate
 *  high limbs; this is sound for test-sized exponents but a production
 *  implementation would use mpz_t / bignum throughout.
 * ======================================================================== */

/* Copy low 32 bytes (256 bits) of a sigma_gq_modulus into a sigma_scalar */
static void gq_mod_to_scalar(sigma_scalar *dst, const sigma_gq_modulus *src) {
    memset(dst, 0, sizeof(*dst));
    memcpy(dst, src->limbs, sizeof(*dst) < sizeof(src->limbs) ? sizeof(*dst) : sizeof(src->limbs));
}

/* Zero-extend a sigma_scalar into a sigma_gq_modulus */
static void gq_scalar_to_mod(sigma_gq_modulus *dst, const sigma_scalar *src) {
    memset(dst, 0, sizeof(*dst));
    memcpy(dst->limbs, src, sizeof(*src));
}

/* Extract a uint64_t challenge from sigma_scalar (GQ challenge is small) */
static uint64_t gq_scalar_to_challenge(const sigma_scalar *c) {
    return c->limbs[0]; /* GQ challenges are small (< 65537) */
}

/* sigma_group_elem and sigma_gq_modulus share the same 32-limb container;
   direct memcpy is safe for vtable adapters where type-punning is needed. */

static void gq_prove_response(sigma_scalar *resp, const sigma_scalar *r,
                               const sigma_scalar *chall,
                               const void *w, const void *pub) {
    const sigma_gq_witness *wit = (const sigma_gq_witness *)w;
    const sigma_gq_public  *p   = (const sigma_gq_public *)pub;
    sigma_gq_modulus y_rand, z;

    /* Convert scalar randomness to 2048-bit modulus type */
    gq_scalar_to_mod(&y_rand, r);

    /* GQ challenge is a small uint64_t stored in scalar[0] */
    uint64_t challenge = gq_scalar_to_challenge(chall);

    /* Compute GQ response: z = y * x^c mod N */
    sigma_gq_respond(&z, &y_rand, challenge, wit, p);

    /* Pack result back into generic scalar (best-effort low-limb copy) */
    gq_mod_to_scalar(resp, &z);
}

static bool gq_verify(const sigma_group_elem *c, const sigma_scalar *chall,
                       const sigma_scalar *resp, const void *pub) {
    const sigma_gq_public *p = (const sigma_gq_public *)pub;
    sigma_gq_modulus Y, z;

    /* Reconstruct GQ-sized arguments; group_elem holds the full modulus */
    memcpy(&Y, c, sizeof(Y) < sizeof(*c) ? sizeof(Y) : sizeof(*c));
    gq_scalar_to_mod(&z, resp);

    /* GQ challenge is a small uint64_t stored in scalar[0] */
    uint64_t challenge = gq_scalar_to_challenge(chall);

    /* Verify GQ equation: z^e == Y * X^c  (mod N) */
    return sigma_gq_verify(&Y, challenge, &z, p);
}

static bool gq_extract(void *wout, const sigma_transcript *t1,
                        const sigma_transcript *t2, const void *pub) {
    sigma_gq_witness *wit_out = (sigma_gq_witness *)wout;
    const sigma_gq_public *p = (const sigma_gq_public *)pub;

    /* Reconstruct full GQ transcripts from generic sigma_transcript */
    sigma_gq_transcript gq_t1, gq_t2;
    /* sigma_gq_transcript.Y is the commitment (sigma_gq_modulus) */
    memcpy(&gq_t1.Y, &t1->commitment, sizeof(gq_t1.Y));
    gq_t1.challenge = gq_scalar_to_challenge(&t1->challenge);
    /* sigma_gq_transcript.z is the response (sigma_gq_modulus) */
    gq_scalar_to_mod(&gq_t1.z, &t1->response);

    memcpy(&gq_t2.Y, &t2->commitment, sizeof(gq_t2.Y));
    gq_t2.challenge = gq_scalar_to_challenge(&t2->challenge);
    gq_scalar_to_mod(&gq_t2.z, &t2->response);

    /* Extract witness from two accepting transcripts with same commitment
     * but different challenges (special soundness of GQ protocol). */
    return sigma_gq_extract(wit_out, &gq_t1, &gq_t2, p);
}

static void gq_simulate(sigma_transcript *t, const sigma_scalar *c,
                         const void *pub) {
    const sigma_gq_public *p = (const sigma_gq_public *)pub;

    /* GQ challenge is a small uint64_t stored in scalar[0] */
    uint64_t challenge = gq_scalar_to_challenge(c);

    sigma_gq_transcript gq_t;
    sigma_gq_simulate(&gq_t, challenge, p);

    /* Copy simulated transcript back to generic format:
     * sigma_gq_transcript has fields Y, challenge (uint64_t), z */
    memcpy(&t->commitment, &gq_t.Y, sizeof(t->commitment));
    /* Pack uint64_t challenge into sigma_scalar */
    sigma_scalar_set_u64(&t->challenge, gq_t.challenge);
    gq_mod_to_scalar(&t->response, &gq_t.z);
}

static int gq_proto_init = 0;

const struct sigma_protocol *sigma_gq_get_protocol(void) {
    if (!gq_proto_init) {
        g_gq_proto.name = "Guillou-Quisquater";
        g_gq_proto.prove_commit    = gq_prove_commit;
        g_gq_proto.prove_response  = gq_prove_response;
        g_gq_proto.verify          = gq_verify;
        g_gq_proto.extract         = gq_extract;
        g_gq_proto.simulate        = gq_simulate;
        g_gq_proto.public_input_size = sizeof(sigma_gq_public);
        g_gq_proto.witness_size      = sizeof(sigma_gq_witness);
        gq_proto_init = 1;
    }
    return &g_gq_proto;
}

/* ========================================================================
 *  Serialization
 * ======================================================================== */

void sigma_gq_modulus_serialize(uint8_t *out, const sigma_gq_modulus *m) {
    for (int i = 0; i < SIGMA_GQ_MODULUS_WORDS; i++) {
        uint64_t v = m->limbs[i];
        for (int j = 0; j < 8; j++) {
            out[i * 8 + j] = (uint8_t)(v & 0xFF);
            v >>= 8;
        }
    }
}

bool sigma_gq_modulus_deserialize(sigma_gq_modulus *m, const uint8_t *in) {
    for (int i = 0; i < SIGMA_GQ_MODULUS_WORDS; i++) {
        uint64_t v = 0;
        for (int j = 7; j >= 0; j--)
            v = (v << 8) | in[i * 8 + j];
        m->limbs[i] = v;
    }
    return true;
}

void sigma_gq_transcript_serialize(uint8_t *out, const sigma_gq_transcript *t) {
    sigma_gq_modulus_serialize(out, &t->Y);
    for (int i = 0; i < 8; i++)
        out[256 + i] = (uint8_t)(t->challenge >> (i * 8));
    sigma_gq_modulus_serialize(out + 264, &t->z);
}

bool sigma_gq_transcript_deserialize(sigma_gq_transcript *t, const uint8_t *in) {
    sigma_gq_modulus_deserialize(&t->Y, in);
    t->challenge = 0;
    for (int i = 0; i < 8; i++)
        t->challenge |= (uint64_t)in[256 + i] << (i * 8);
    sigma_gq_modulus_deserialize(&t->z, in + 264);
    return true;
}
