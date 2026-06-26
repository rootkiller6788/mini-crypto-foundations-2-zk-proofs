/**
 * @file bigint.h
 * @brief Multi-precision integer arithmetic for commitment schemes
 *
 * Implements arbitrary-width big integers with modular arithmetic
 * for constructing commitment schemes over prime-order groups.
 *
 * References:
 *   - Knuth, D.E. "The Art of Computer Programming, Vol 2: Seminumerical Algorithms" (1969)
 *   - Menezes, van Oorschot, Vanstone. "Handbook of Applied Cryptography" (1996)
 *
 * Knowledge Mapping:
 *   L3: Mathematical Structures — Big integer as ring Z, modular arithmetic in Z_p
 *   L5: Algorithms — Montgomery multiplication, extended Euclidean algorithm
 */

#ifndef MINI_COMMITMENT_BIGINT_H
#define MINI_COMMITMENT_BIGINT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/*============================================================================
 * Constants
 *============================================================================*/

/** Maximum number of 64-bit limbs in a big integer (2048 bits total) */
#define BIGINT_MAX_LIMBS 32

/** Maximum byte size of a big integer */
#define BIGINT_MAX_BYTES (BIGINT_MAX_LIMBS * 8)

/** Maximum bit width supported */
#define BIGINT_MAX_BITS  (BIGINT_MAX_LIMBS * 64)

/*============================================================================
 * BigInt: arbitrary-precision unsigned integer (L3 Math Structure)
 *
 * Representation: sum_{i=0}^{nlimbs-1} limbs[i] * 2^{64*i}
 *
 * Invariants:
 *   - nlimbs <= BIGINT_MAX_LIMBS
 *   - nlimbs == 0  iff  value == 0
 *   - limbs[nlimbs-1] != 0  when nlimbs > 0 (no leading zeros)
 *
 * This structure forms a commutative ring Z under modular arithmetic,
 * and a field Z_p when p is prime.
 *============================================================================*/

typedef struct {
    uint64_t limbs[BIGINT_MAX_LIMBS];  /**< Little-endian limb array */
    size_t   nlimbs;                    /**< Number of active limbs */
} bigint;

/*============================================================================
 * Lifecycle (L3: ring element construction)
 *============================================================================*/

/** Initialize big integer to zero. O(1) */
void bigint_init(bigint *a);

/** Initialize from uint64_t. O(1) */
void bigint_init_u64(bigint *a, uint64_t val);

/** Deep copy. O(nlimbs) */
void bigint_copy(bigint *dst, const bigint *src);

/** Set to zero. O(1) */
void bigint_zero(bigint *a);

/*============================================================================
 * Comparison — total order on Z (L3)
 *============================================================================*/

/**
 * Compare two big integers.
 * @return -1 if a < b, 0 if a == b, 1 if a > b
 * Complexity: O(min(nlimbs(a), nlimbs(b)))
 */
int bigint_cmp(const bigint *a, const bigint *b);

/** Check if a == 0. O(1) */
bool bigint_is_zero(const bigint *a);

/** Check if a == 1. O(1) */
bool bigint_is_one(const bigint *a);

/**
 * Bit length (number of significant bits).
 * Returns 0 for value 0.
 * Complexity: O(nlimbs)
 */
size_t bigint_bitlen(const bigint *a);

/*============================================================================
 * Addition / Subtraction (L3: Abelian group operations on Z)
 *============================================================================*/

/**
 * In-place addition: a += b.
 * @return carry bit (0 or 1)
 * Complexity: O(max(nlimbs(a), nlimbs(b)))
 */
uint64_t bigint_add(bigint *a, const bigint *b);

/**
 * Out-of-place addition: c = a + b.
 * @return carry bit.
 */
uint64_t bigint_add_to(bigint *c, const bigint *a, const bigint *b);

/**
 * In-place subtraction: a -= b.
 * Precondition: a >= b (caller must guarantee).
 * @return borrow bit (0 if a >= b on entry, else 1 and result wraps)
 * Complexity: O(nlimbs(a))
 */
uint64_t bigint_sub(bigint *a, const bigint *b);

/**
 * Out-of-place subtraction: c = a - b.
 * Precondition: a >= b.
 * @return borrow bit.
 */
uint64_t bigint_sub_from(bigint *c, const bigint *a, const bigint *b);

/*============================================================================
 * Multiplication (L3: ring multiplication on Z)
 *============================================================================*/

/**
 * Multiply by single word: a *= word.
 * @return high word of product (carry)
 * Complexity: O(nlimbs)
 */
uint64_t bigint_mul_word(bigint *a, uint64_t word);

/**
 * Schoolbook multiplication: c = a * b.
 * c must not alias a or b.
 * Complexity: O(nlimbs(a) * nlimbs(b))
 */
void bigint_mul(bigint *c, const bigint *a, const bigint *b);

/*============================================================================
 * Division / Remainder (L3: Euclidean domain on Z)
 *============================================================================*/

/**
 * Division by single word: a = q * d + r.
 * q and r may be NULL if not needed.
 * Complexity: O(nlimbs(a))
 */
void bigint_div_word(const bigint *a, uint64_t d, bigint *q, uint64_t *r);

/**
 * Mod by single word: return a % d.
 * Complexity: O(nlimbs(a))
 */
uint64_t bigint_mod_word(const bigint *a, uint64_t d);

/**
 * Reduce modulo m in-place: a = a % m (m > 0).
 * Result satisfies 0 <= a < m.
 * Uses binary long division algorithm.
 * Complexity: O(nlimbs(a) * (nlimbs(a) - nlimbs(m) + 1))
 */
void bigint_mod(bigint *a, const bigint *m);

/*============================================================================
 * Bit operations (L3)
 *============================================================================*/

/** Left shift: a <<= shift. Complexity: O(nlimbs + shift/64) */
void bigint_shl(bigint *a, size_t shift);

/** Right shift: a >>= shift. Complexity: O(nlimbs) */
void bigint_shr(bigint *a, size_t shift);

/** Test bit n (0 = LSB). Complexity: O(1) */
int bigint_test_bit(const bigint *a, size_t n);

/** Set bit n to 1. Complexity: O(1) */
void bigint_set_bit(bigint *a, size_t n);

/*============================================================================
 * Conversion (L3)
 *============================================================================*/

/** Convert to hex string. Output buffer must be at least 2*BIGINT_MAX_BYTES+1. */
void bigint_to_hex(const bigint *a, char *out, size_t out_size);

/** Convert to uint64_t if value fits. Returns true on success. */
bool bigint_to_u64(const bigint *a, uint64_t *out);

/** Convert from hex string. Returns true on success. */
bool bigint_from_hex(bigint *a, const char *hex);

#endif /* MINI_COMMITMENT_BIGINT_H */
