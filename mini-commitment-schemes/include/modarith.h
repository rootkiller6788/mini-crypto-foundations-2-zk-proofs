/**
 * @file modarith.h
 * @brief Modular arithmetic over prime fields Z_p
 *
 * Implements the mathematical structure of the finite prime field
 * (Z_p, +, ×) used as the base group for Pedersen and other
 * discrete-log commitment schemes.
 *
 * References:
 *   - Shoup, V. "A Computational Introduction to Number Theory and Algebra" (2008)
 *   - Cohen, H. "A Course in Computational Algebraic Number Theory" (1993)
 *
 * Knowledge Mapping:
 *   L3: Mathematical Structures — Finite field Z_p, group of units Z_p^*
 *   L4: Fundamental Laws — Fermat's Little Theorem, Lagrange's Theorem for Z_p^*
 *   L5: Algorithms — Modular exponentiation, modular inverse via extended Euclidean
 */

#ifndef MINI_COMMITMENT_MODARITH_H
#define MINI_COMMITMENT_MODARITH_H

#include "bigint.h"
#include <stdbool.h>

/*============================================================================
 * Modular arithmetic context (L3: Z_p field)
 *
 * All operations use a fixed modulus p (usually a large prime).
 * The modulus is set once per context. Thread-safe if immutable after creation.
 *
 * For commitment schemes, p is typically:
 *   - A 256-bit prime (e.g., secp256k1 order)
 *   - An RSA modulus N = p*q (for integer-commitment variants)
 *============================================================================*/

typedef struct {
    bigint modulus;          /**< The prime or composite modulus */
    bigint modulus_minus_1;  /**< Cached p-1 for exponent reduction */
    size_t  modulus_bits;    /**< Bit length of modulus */
    int     is_prime;        /**< 1 if proven prime, 0 if not verified */
} modctx;

/*============================================================================
 * Context management
 *============================================================================*/

/**
 * Initialize a modular arithmetic context with a given modulus.
 * Stores p, p-1, and bit length.
 *
 * @param ctx  uninitialized context
 * @param p    the modulus (copied; must be > 1)
 *
 * Complexity: O(nlimbs(p))
 */
void modctx_init(modctx *ctx, const bigint *p);

/**
 * Initialize context from a uint64_t modulus (for testing/educational use).
 *
 * @param ctx  uninitialized context
 * @param p    modulus as uint64_t (must be > 1)
 */
void modctx_init_u64(modctx *ctx, uint64_t p);

/*============================================================================
 * Basic ring/field operations (L3: Z_p structure)
 *============================================================================*/

/**
 * Modular addition: r = (a + b) mod p.
 * a, b, r may alias.
 * Complexity: O(max(nlimbs(a), nlimbs(b)))
 */
void mod_add(const modctx *ctx, bigint *r, const bigint *a, const bigint *b);

/**
 * Modular subtraction: r = (a - b) mod p.
 * Result always non-negative.
 * Complexity: O(max(nlimbs(a), nlimbs(b)))
 */
void mod_sub(const modctx *ctx, bigint *r, const bigint *a, const bigint *b);

/**
 * Modular multiplication: r = (a * b) mod p.
 * r must not alias a or b (use a temporary if needed).
 * Complexity: O(nlimbs(a) * nlimbs(b))
 */
void mod_mul(const modctx *ctx, bigint *r, const bigint *a, const bigint *b);

/**
 * Modular negation: r = (-a) mod p.
 * Complexity: O(nlimbs(a))
 */
void mod_neg(const modctx *ctx, bigint *r, const bigint *a);

/*============================================================================
 * Group of units — Z_p^* (L3: multiplicative group)
 *
 * In a prime field, every non-zero element has a multiplicative inverse,
 * forming the cyclic group Z_p^* of order p-1.
 *============================================================================*/

/**
 * Modular inverse: r = a^{-1} mod p.
 * Uses extended Euclidean algorithm.
 * Precondition: gcd(a, p) == 1 (a and p are coprime).
 * For prime p, this holds for all a != 0 (mod p).
 *
 * Theorem source: Bézout's identity + Extended Euclidean Algorithm
 *   (Knuth Vol 2, Algorithm X, §4.5.2)
 *
 * Complexity: O(nlimbs(a)^2)
 *
 * @return true if inverse exists, false if gcd(a,p) != 1
 */
bool mod_inv(const modctx *ctx, bigint *r, const bigint *a);

/**
 * Modular exponentiation: r = a^e mod p.
 * Uses square-and-multiply (binary exponentiation).
 *
 * Theorem source: Fermat's Little Theorem:
 *   For prime p and a != 0 mod p: a^{p-1} ≡ 1 (mod p)
 *
 * Complexity: O(bitlen(e) * log^2(p))
 */
void mod_exp(const modctx *ctx, bigint *r, const bigint *a, const bigint *e);

/**
 * Modular exponentiation with uint64_t exponent (fast path).
 * Complexity: O(64 * log^2(p)) — constant 64 squarings
 */
void mod_exp_u64(const modctx *ctx, bigint *r, const bigint *a, uint64_t e);

/*============================================================================
 * Random element generation (L3, L7)
 *============================================================================*/

/**
 * Generate a random element in Z_p^* (non-zero random field element).
 * Uses system CSPRNG (CryptGenRandom on Windows, /dev/urandom on Unix).
 *
 * This is fundamental to commitment schemes: the random blinding factor
 * r is sampled uniformly from Z_p^*, ensuring the hiding property.
 *
 * Complexity: O(modulus_bits / 8) for randomness + O(nlimbs) for reduction
 *
 * @return true on success, false if randomness unavailable
 */
bool mod_rand_nonzero(const modctx *ctx, bigint *r);

/**
 * Generate a random element in Z_p (may be zero).
 * Complexity: same as mod_rand_nonzero
 */
bool mod_rand(const modctx *ctx, bigint *r);

/*============================================================================
 * Utility
 *============================================================================*/

/** Check if a ≡ 0 (mod p). O(1) after reduction. */
bool mod_is_zero(const modctx *ctx, const bigint *a);

/** Check if a ≡ 1 (mod p). O(1) */
bool mod_is_one(const modctx *ctx, const bigint *a);

/** Check if two elements are congruent: a ≡ b (mod p). */
bool mod_eq(const modctx *ctx, const bigint *a, const bigint *b);

/** Copy a reduced value into r (r = a mod p). */
void mod_reduce(const modctx *ctx, bigint *r, const bigint *a);

#endif /* MINI_COMMITMENT_MODARITH_H */
