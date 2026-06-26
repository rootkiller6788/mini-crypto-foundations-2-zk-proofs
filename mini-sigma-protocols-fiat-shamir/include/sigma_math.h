#ifndef SIGMA_MATH_H
#define SIGMA_MATH_H

/**
 * sigma_math.h ? Mathematical Primitives for Sigma Protocols
 *
 * Provides the modular arithmetic, group operations, and hash functions
 * required by all sigma protocol implementations. All operations are
 * performed modulo a large safe prime to support discrete-log-based
 * protocols (Schnorr, Chaum-Pedersen, DSA-like).
 *
 * References:
 *   - Goldreich (2004) Foundations of Cryptography, Vol I, ?4 (ZK Proofs)
 *   - Katz & Lindell (2014) Introduction to Modern Cryptography, Ch 13
 *   - Arora & Barak (2009) ?9 (Cryptography in NP)
 *   - Schnorr (1991) "Efficient Signature Generation by Smart Cards"
 *   - Fiat & Shamir (1986) "How to Prove Yourself"
 *
 * L3 Mathematical Structures:
 *   - Finite cyclic group G of prime order q (subgroup of Z_p^*)
 *   - Modular exponentiation, inversion, multiplication
 *   - Hash function modeled as random oracle (SHA-256-based)
 *
 * L1 Definitions:
 *   - Group generator g ? Z_p^* of order q
 *   - Modular prime p, subgroup order q
 *   - Scalar field Z_q
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* ??? Configuration ????????????????????????????????????????????????? */

#define SIGMA_GROUP_PRIME_BITS 2048
#define SIGMA_GROUP_PRIME_WORDS 32

#define SIGMA_GROUP_ORDER_BITS 256
#define SIGMA_GROUP_ORDER_WORDS 4

/* ??? Big Integer Type ?????????????????????????????????????????????? */

typedef struct {
    uint64_t limbs[SIGMA_GROUP_PRIME_WORDS];
} sigma_biguint;

typedef struct {
    uint64_t limbs[SIGMA_GROUP_ORDER_WORDS];
} sigma_scalar;

typedef struct {
    uint64_t limbs[SIGMA_GROUP_PRIME_WORDS];
} sigma_group_elem;

/* ??? Constants ????????????????????????????????????????????????????? */

extern const sigma_biguint SIGMA_PRIME_P;
extern const sigma_scalar SIGMA_ORDER_Q;
extern const sigma_group_elem SIGMA_GENERATOR_G;

/* ??? Basic Big Integer Operations ?????????????????????????????????? */

void sigma_biguint_zero(sigma_biguint *a);
void sigma_biguint_set_u64(sigma_biguint *a, uint64_t value);
int sigma_biguint_cmp(const sigma_biguint *a, const sigma_biguint *b);
bool sigma_biguint_is_zero(const sigma_biguint *a);
bool sigma_biguint_is_one(const sigma_biguint *a);
void sigma_biguint_copy(sigma_biguint *dst, const sigma_biguint *src);
int sigma_biguint_bitlen(const sigma_biguint *a);
bool sigma_biguint_get_bit(const sigma_biguint *a, int i);

/* ??? Modular Arithmetic in Z_p ????????????????????????????????????? */

void sigma_mod_add(sigma_biguint *r, const sigma_biguint *a,
                   const sigma_biguint *b, const sigma_biguint *p);
void sigma_mod_sub(sigma_biguint *r, const sigma_biguint *a,
                   const sigma_biguint *b, const sigma_biguint *p);
void sigma_mod_mul(sigma_biguint *r, const sigma_biguint *a,
                   const sigma_biguint *b, const sigma_biguint *p);
bool sigma_mod_inv(sigma_biguint *r, const sigma_biguint *a,
                   const sigma_biguint *p);
void sigma_mod_exp(sigma_biguint *r, const sigma_biguint *base,
                   const sigma_biguint *exp, int exp_bits,
                   const sigma_biguint *p);
void sigma_mod_reduce(sigma_biguint *r, const sigma_biguint *a,
                      const sigma_biguint *p);

/* ??? Scalar Operations in Z_q ?????????????????????????????????????? */

void sigma_scalar_zero(sigma_scalar *s);
void sigma_scalar_set_u64(sigma_scalar *s, uint64_t value);
void sigma_scalar_copy(sigma_scalar *dst, const sigma_scalar *src);
void sigma_scalar_add(sigma_scalar *s, const sigma_scalar *a,
                      const sigma_scalar *b);
void sigma_scalar_sub(sigma_scalar *s, const sigma_scalar *a,
                      const sigma_scalar *b);
void sigma_scalar_mul(sigma_scalar *s, const sigma_scalar *a,
                      const sigma_scalar *b);
bool sigma_scalar_inv(sigma_scalar *s, const sigma_scalar *a);
int sigma_scalar_cmp(const sigma_scalar *a, const sigma_scalar *b);
bool sigma_scalar_is_zero(const sigma_scalar *s);

/* ??? Group Operations ?????????????????????????????????????????????? */

void sigma_group_exp_g(sigma_group_elem *r, const sigma_scalar *s);
void sigma_group_exp(sigma_group_elem *r, const sigma_group_elem *h,
                     const sigma_scalar *s);
void sigma_group_mul(sigma_group_elem *r, const sigma_group_elem *a,
                     const sigma_group_elem *b);
void sigma_group_div(sigma_group_elem *r, const sigma_group_elem *a,
                     const sigma_group_elem *b);
void sigma_group_copy(sigma_group_elem *dst, const sigma_group_elem *src);
bool sigma_group_is_identity(const sigma_group_elem *e);
void sigma_group_serialize(uint8_t *out, const sigma_group_elem *e);
bool sigma_group_eq(const sigma_group_elem *a, const sigma_group_elem *b);

/* ??? Hash Functions (Random Oracle Model) ?????????????????????????? */

#define SIGMA_HASH_SIZE 32

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buf[64];
    uint32_t buf_len;
} sigma_hash_context;

void sigma_hash_init(sigma_hash_context *ctx);
void sigma_hash_update(sigma_hash_context *ctx, const uint8_t *data,
                       size_t len);
void sigma_hash_final(sigma_hash_context *ctx, uint8_t digest[SIGMA_HASH_SIZE]);
void sigma_hash_digest(uint8_t digest[SIGMA_HASH_SIZE],
                       const uint8_t *data, size_t len);
void sigma_digest_to_scalar(sigma_scalar *out, const uint8_t dgst[SIGMA_HASH_SIZE]);
void sigma_hash_to_scalar(sigma_scalar *out, const sigma_group_elem *e);
void sigma_hash_pair_to_scalar(sigma_scalar *out,
                               const sigma_group_elem *a,
                               const sigma_group_elem *b);
void sigma_hash_triple_to_scalar(sigma_scalar *out,
                                 const sigma_group_elem *a,
                                 const sigma_group_elem *b,
                                 const sigma_group_elem *c);
void sigma_hash_message_to_scalar(sigma_scalar *out,
                                  const uint8_t *msg, size_t msg_len,
                                  const sigma_group_elem *commitment,
                                  const sigma_group_elem *public_key);

/* ??? Randomness (for Prover) ??????????????????????????????????????? */

void sigma_random_bytes(uint8_t *buf, size_t len);
void sigma_random_scalar(sigma_scalar *r);
void sigma_random_nonzero_scalar(sigma_scalar *r);
void sigma_random_seed(uint64_t seed);

/* ??? Serialization ????????????????????????????????????????????????? */

void sigma_scalar_serialize(uint8_t out[32], const sigma_scalar *s);
void sigma_scalar_deserialize(sigma_scalar *s, const uint8_t in[32]);
void sigma_biguint_serialize(uint8_t out[256], const sigma_biguint *a);

#endif /* SIGMA_MATH_H */
