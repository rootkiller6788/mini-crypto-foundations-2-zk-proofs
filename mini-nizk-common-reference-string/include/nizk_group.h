/**
 * nizk_group.h ！ Finite Field & Group Operations for NIZK Proof Systems
 *
 * Implements modular arithmetic over a prime-order group G of order q,
 * with generator g. These are the foundational mathematical structures
 * (L3) underlying all NIZK constructions in this module.
 *
 * Group: (G, ，) where G is a cyclic subgroup of Z_p^* of prime order q
 *   - p = large safe prime (p = 2q + 1, both p and q prime)
 *   - g = generator of the subgroup of order q
 *   - All operations are in the exponent group Z_q for scalar arithmetic
 *
 * Reference: Schnorr, C.P. "Efficient Signature Generation by Smart Cards"
 *            Journal of Cryptology, 1991.
 *
 * Course Mapping:
 *   Stanford CS355: Finite fields, group theory for crypto
 *   MIT 6.875: Modular arithmetic foundations
 *   ETH 263-4650: Group-based cryptography
 */

#ifndef NIZK_GROUP_H
#define NIZK_GROUP_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------------
 * L3: Mathematical Structures ！ Big Integers & Modular Arithmetic
 * ------------------------------------------------------------------------- */

/**
 * nizk_bigint ！ Multi-precision unsigned integer for cryptographic operations.
 *
 * Supports up to 2048-bit integers (32 limbs of 64 bits).
 * Used for group elements, scalars, and hash outputs.
 */
#define NIZK_BIGINT_LIMBS 32
#define NIZK_BIGINT_BITS  (NIZK_BIGINT_LIMBS * 64)

typedef struct {
    uint64_t limbs[NIZK_BIGINT_LIMBS];
} nizk_bigint_t;

/**
 * nizk_group_params ！ Parameters for a cyclic group G of prime order q.
 *
 * Group G is the unique subgroup of Z_p^* of order q, where p = 2q + 1
 * (Sophie Germain prime construction). All public keys and commitments
 * live in G; all secret scalars live in Z_q.
 *
 * Fields:
 *   p     ！ safe prime modulus (p = 2q + 1), |p| 「 2048 bits
 *   q     ！ subgroup order (prime), |q| 「 2047 bits
 *   g     ！ generator of G (element of Z_p^* of order q)
 *   p_bits, q_bits ！ bit lengths for validation
 */
typedef struct {
    nizk_bigint_t p;       /* safe prime modulus */
    nizk_bigint_t q;       /* subgroup order (prime) */
    nizk_bigint_t g;       /* generator of subgroup of order q */
    int           p_bits;  /* bit-length of p */
    int           q_bits;  /* bit-length of q */
} nizk_group_params_t;

/**
 * nizk_group_elem ！ An element of the group G (subgroup of Z_p^*).
 *
 * Each element is represented as an integer modulo p.
 * Identity element is 1 (since group operation is multiplication mod p).
 *
 * Invariant: elem （ [0, p-1] and elem^q 《 1 (mod p) for non-identity.
 */
typedef struct {
    nizk_bigint_t elem;
} nizk_group_elem_t;

/**
 * nizk_scalar ！ A scalar in Z_q (the exponent group).
 *
 * Used for secret keys, random challenges, and blinding factors.
 * Scalars are integers modulo q (the group order).
 */
typedef struct {
    nizk_bigint_t val;
} nizk_scalar_t;

/* ---------------------------------------------------------------------------
 * L3: Big Integer Operations
 * ------------------------------------------------------------------------- */

/** Initialize a bigint to zero. */
void nizk_bigint_zero(nizk_bigint_t *a);

/** Initialize a bigint to one. */
void nizk_bigint_one(nizk_bigint_t *a);

/** Set a bigint from a 64-bit unsigned integer. */
void nizk_bigint_set_u64(nizk_bigint_t *a, uint64_t val);

/** Compare two bigints. Returns -1, 0, 1 for <, =, >. */
int  nizk_bigint_cmp(const nizk_bigint_t *a, const nizk_bigint_t *b);

/** Check if bigint is zero. */
int  nizk_bigint_is_zero(const nizk_bigint_t *a);

/** Check if bigint is one. */
int  nizk_bigint_is_one(const nizk_bigint_t *a);

/** Copy src to dst. */
void nizk_bigint_copy(nizk_bigint_t *dst, const nizk_bigint_t *src);

/** Get the number of significant bits. */
int  nizk_bigint_bitlen(const nizk_bigint_t *a);

/* ---------------------------------------------------------------------------
 * L3: Modular Arithmetic Operations (mod p and mod q)
 * ------------------------------------------------------------------------- */

/**
 * Modular addition: r = (a + b) mod m.
 * Complexity: O(n) where n = number of limbs.
 */
void nizk_mod_add(nizk_bigint_t *r, const nizk_bigint_t *a,
                  const nizk_bigint_t *b, const nizk_bigint_t *m);

/**
 * Modular subtraction: r = (a - b) mod m.
 * Returns non-negative result in [0, m-1].
 */
void nizk_mod_sub(nizk_bigint_t *r, const nizk_bigint_t *a,
                  const nizk_bigint_t *b, const nizk_bigint_t *m);

/**
 * Modular multiplication: r = (a * b) mod m.
 * Uses schoolbook multiplication with Barrett reduction.
 * Complexity: O(n^2).
 */
void nizk_mod_mul(nizk_bigint_t *r, const nizk_bigint_t *a,
                  const nizk_bigint_t *b, const nizk_bigint_t *m);

/**
 * Modular exponentiation: r = (base^exp) mod m.
 * Uses square-and-multiply (binary exponentiation).
 * Complexity: O(n^2 * log(exp)).
 */
void nizk_mod_exp(nizk_bigint_t *r, const nizk_bigint_t *base,
                  const nizk_bigint_t *exp, const nizk_bigint_t *m);

/**
 * Modular inverse: r = a^{-1} mod m (m must be prime).
 * Uses Fermat little theorem: a^{-1} = a^{m-2} (mod m).
 * Complexity: O(n^2 * log(m)).
 */
void nizk_mod_inv(nizk_bigint_t *r, const nizk_bigint_t *a,
                  const nizk_bigint_t *m);

/**
 * Modular negation: r = (-a) mod m = (m - a) mod m.
 */
void nizk_mod_neg(nizk_bigint_t *r, const nizk_bigint_t *a,
                  const nizk_bigint_t *m);

/* ---------------------------------------------------------------------------
 * L3: Group Element Operations
 * ------------------------------------------------------------------------- */

/** Initialize a group element to the identity (1). */
void nizk_group_elem_identity(nizk_group_elem_t *elem);

/**
 * Group operation: r = a * b (mod p).
 * This is multiplication in Z_p^*, restricted to the subgroup G.
 */
void nizk_group_op(nizk_group_elem_t *r,
                   const nizk_group_elem_t *a,
                   const nizk_group_elem_t *b,
                   const nizk_group_params_t *params);

/**
 * Scalar multiplication (exponentiation): r = base^scalar (mod p).
 * This is the "exponentiation in G" ！ the main operation for:
 *   - Public key generation: pk = g^sk
 *   - Commitment creation:  com = g^m * h^r
 *   - Proof generation:     t = g^v
 *
 * Uses constant-time-ish square-and-multiply to mitigate timing attacks.
 */
void nizk_group_exp(nizk_group_elem_t *r,
                    const nizk_group_elem_t *base,
                    const nizk_scalar_t *scalar,
                    const nizk_group_params_t *params);

/**
 * Multi-exponentiation: r = g^a * h^b (mod p).
 * Uses Shamir trick (simultaneous multi-exponentiation) for efficiency.
 * This is critical for:
 *   - Commitment verification
 *   - Batch proof verification
 *
 * Algorithm: Interleave the binary expansions of a and b, processing
 * bits from MSB to LSB with a single squaring per bit.
 */
void nizk_group_multi_exp(nizk_group_elem_t *r,
                          const nizk_group_elem_t *g,
                          const nizk_scalar_t *a,
                          const nizk_group_elem_t *h,
                          const nizk_scalar_t *b,
                          const nizk_group_params_t *params);

/**
 * Triple exponentiation: r = g^a * h^b * u^c.
 * Generalizes Shamir trick to three bases.
 * Used in complex proof verification (e.g., OR-proofs).
 */
void nizk_group_triple_exp(nizk_group_elem_t *r,
                           const nizk_group_elem_t *g,
                           const nizk_scalar_t *a,
                           const nizk_group_elem_t *h,
                           const nizk_scalar_t *b,
                           const nizk_group_elem_t *u,
                           const nizk_scalar_t *c,
                           const nizk_group_params_t *params);

/**
 * Check if a group element is valid (in the subgroup G).
 * Verifies: elem in [1, p-1] and elem^q = 1 (mod p).
 * This is the "subgroup membership test" critical for security.
 */
int  nizk_group_elem_is_valid(const nizk_group_elem_t *elem,
                               const nizk_group_params_t *params);

/** Check equality of two group elements. */
int  nizk_group_elem_eq(const nizk_group_elem_t *a,
                         const nizk_group_elem_t *b);

/** Copy a group element. */
void nizk_group_elem_copy(nizk_group_elem_t *dst,
                           const nizk_group_elem_t *src);

/* ---------------------------------------------------------------------------
 * L3: Scalar Operations (in Z_q)
 * ------------------------------------------------------------------------- */

/** Set scalar to 0. */
void nizk_scalar_zero(nizk_scalar_t *s);

/** Set scalar from uint64_t. */
void nizk_scalar_set_u64(nizk_scalar_t *s, uint64_t val);

/** Scalar addition mod q: r = (a + b) mod q. */
void nizk_scalar_add(nizk_scalar_t *r,
                     const nizk_scalar_t *a,
                     const nizk_scalar_t *b,
                     const nizk_group_params_t *params);

/** Scalar subtraction mod q: r = (a - b) mod q. */
void nizk_scalar_sub(nizk_scalar_t *r,
                     const nizk_scalar_t *a,
                     const nizk_scalar_t *b,
                     const nizk_group_params_t *params);

/** Scalar multiplication mod q: r = (a * b) mod q. */
void nizk_scalar_mul(nizk_scalar_t *r,
                     const nizk_scalar_t *a,
                     const nizk_scalar_t *b,
                     const nizk_group_params_t *params);

/** Scalar negation mod q: r = (-a) mod q. */
void nizk_scalar_neg(nizk_scalar_t *r,
                     const nizk_scalar_t *a,
                     const nizk_group_params_t *params);

/** Scalar inverse mod q: r = a^{-1} mod q. */
void nizk_scalar_inv(nizk_scalar_t *r,
                     const nizk_scalar_t *a,
                     const nizk_group_params_t *params);

/** Compare two scalars. */
int  nizk_scalar_cmp(const nizk_scalar_t *a, const nizk_scalar_t *b);

/** Copy scalar. */
void nizk_scalar_copy(nizk_scalar_t *dst, const nizk_scalar_t *src);

/** Check if scalar is zero. */
int  nizk_scalar_is_zero(const nizk_scalar_t *s);

/* ---------------------------------------------------------------------------
 * L3: Randomness Generation
 * ------------------------------------------------------------------------- */

/**
 * Generate a cryptographically secure random scalar in Z_q.
 *
 * Uses the system secure random number generator.
 * The scalar is uniformly distributed in [0, q-1].
 *
 * This is critical for:
 *   - Secret key generation
 *   - Blinding factors in commitments
 *   - Random challenges in sigma protocols
 *   - Simulator randomness
 */
void nizk_scalar_rand(nizk_scalar_t *r, const nizk_group_params_t *params);

/**
 * Generate a cryptographically secure random group element.
 *
 * Samples a random scalar r <- Z_q and returns g^r.
 * This produces a uniformly random element of G.
 */
void nizk_group_elem_rand(nizk_group_elem_t *r,
                           const nizk_group_params_t *params);

/* ---------------------------------------------------------------------------
 * L3: Group Parameter Generation
 * ------------------------------------------------------------------------- */

/**
 * Generate standard group parameters using a pre-defined safe prime.
 *
 * For this mini-implementation, we use a fixed 256-bit safe prime
 * for reproducibility and testing. In production, parameters would
 * be generated through a trusted setup ceremony.
 *
 * The prime used is:
 *   p = 2q + 1 where q is also prime (Sophie Germain construction)
 *   g is a generator of the q-order subgroup
 *
 * The 256-bit prime chosen is:
 *   q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
 *   (the order of secp256k1, for familiarity)
 *   p = 2q + 1
 *
 * This is a "mini" 256-bit group suitable for educational purposes.
 * Real deployments use 2048+ bit groups.
 */
void nizk_group_params_init_256bit(nizk_group_params_t *params);

/**
 * Free any dynamically allocated resources in group parameters.
 */
void nizk_group_params_clear(nizk_group_params_t *params);

#ifdef __cplusplus
}
#endif

#endif /* NIZK_GROUP_H */
