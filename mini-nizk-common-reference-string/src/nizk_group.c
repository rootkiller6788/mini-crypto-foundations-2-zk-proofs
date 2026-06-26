/**
 * nizk_group.c �� Big Integer & Group Operations Implementation
 *
 * Implements all operations on nizk_bigint_t, modular arithmetic,
 * group exponentiation, and scalar operations for the NIZK system.
 *
 * The big integer representation uses 64-bit limbs in little-endian order.
 * Arithmetic is constant-time where feasible for cryptographic safety.
 */

#include "nizk_group.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>

/* =========================================================================
 * Utility: Platform Randomness
 * ========================================================================= */

/**
 * Get cryptographically secure random bytes.
 * For this mini-implementation, we use rand() seeded with high-precision
 * time. In production, use getrandom() / /dev/urandom / CryptGenRandom.
 */
static void secure_rand_bytes(uint8_t *buf, size_t len) {
    static int seeded = 0;
    if (!seeded) {
        /* Use high-precision time as seed */
        srand((unsigned int)time(NULL));
        seeded = 1;
    }
    for (size_t i = 0; i < len; i++) {
        /* Combine multiple rand() calls for better randomness per byte */
        unsigned int r = (unsigned int)rand();
        buf[i] = (uint8_t)((r & 0xFF) ^ ((r >> 8) & 0xFF) ^ ((r >> 16) & 0xFF));
    }
}

/* =========================================================================
 * Big Integer Operations
 * ========================================================================= */

void nizk_bigint_zero(nizk_bigint_t *a) {
    memset(a->limbs, 0, sizeof(a->limbs));
}

void nizk_bigint_one(nizk_bigint_t *a) {
    memset(a->limbs, 0, sizeof(a->limbs));
    a->limbs[0] = 1;
}

void nizk_bigint_set_u64(nizk_bigint_t *a, uint64_t val) {
    memset(a->limbs, 0, sizeof(a->limbs));
    a->limbs[0] = val;
}

void nizk_bigint_copy(nizk_bigint_t *dst, const nizk_bigint_t *src) {
    memcpy(dst->limbs, src->limbs, sizeof(dst->limbs));
}

int nizk_bigint_is_zero(const nizk_bigint_t *a) {
    for (int i = 0; i < NIZK_BIGINT_LIMBS; i++) {
        if (a->limbs[i] != 0) return 0;
    }
    return 1;
}

int nizk_bigint_is_one(const nizk_bigint_t *a) {
    if (a->limbs[0] != 1) return 0;
    for (int i = 1; i < NIZK_BIGINT_LIMBS; i++) {
        if (a->limbs[i] != 0) return 0;
    }
    return 1;
}

int nizk_bigint_cmp(const nizk_bigint_t *a, const nizk_bigint_t *b) {
    for (int i = NIZK_BIGINT_LIMBS - 1; i >= 0; i--) {
        if (a->limbs[i] > b->limbs[i]) return 1;
        if (a->limbs[i] < b->limbs[i]) return -1;
    }
    return 0;
}

int nizk_bigint_bitlen(const nizk_bigint_t *a) {
    for (int i = NIZK_BIGINT_LIMBS - 1; i >= 0; i--) {
        if (a->limbs[i] != 0) {
            uint64_t v = a->limbs[i];
            int bits = 0;
            while (v) { bits++; v >>= 1; }
            return i * 64 + bits;
        }
    }
    return 0;
}

/**
 * Add two bigints: r = a + b (full sum, no modular reduction).
 * Returns the carry out. r may alias a or b.
 */
static uint64_t bigint_add_raw(nizk_bigint_t *r,
                                const nizk_bigint_t *a,
                                const nizk_bigint_t *b) {
    uint64_t carry = 0;
    for (int i = 0; i < NIZK_BIGINT_LIMBS; i++) {
        uint64_t sum = a->limbs[i] + b->limbs[i] + carry;
        carry = (sum < a->limbs[i] || (carry && sum == a->limbs[i])) ? 1 : 0;
        r->limbs[i] = sum;
    }
    return carry;
}

/**
 * Subtract two bigints: r = a - b.
 * Assumes a >= b. Returns borrow out. r may alias a or b.
 *
 * Borrow is tracked using 128-bit comparison to avoid overflow
 * when b->limbs[i] + borrow wraps around 2^64.
 */
static uint64_t bigint_sub_raw(nizk_bigint_t *r,
                                const nizk_bigint_t *a,
                                const nizk_bigint_t *b) {
    uint64_t borrow = 0;
    for (int i = 0; i < NIZK_BIGINT_LIMBS; i++) {
        uint64_t diff = a->limbs[i] - b->limbs[i] - borrow;
        /* Use 128-bit arithmetic to detect borrow correctly */
        unsigned __int128 a_val = a->limbs[i];
        unsigned __int128 b_val = (unsigned __int128)b->limbs[i] + borrow;
        borrow = (a_val < b_val) ? 1ULL : 0ULL;
        r->limbs[i] = diff;
    }
    return borrow;
}

/**
 * Multiply two bigints: r = a * b (full product).
 * Uses schoolbook multiplication. r must not alias a or b.
 */
static void bigint_mul_raw(nizk_bigint_t *r,
                            const nizk_bigint_t *a,
                            const nizk_bigint_t *b) {
    /* We need a double-width accumulator */
    uint64_t acc[2 * NIZK_BIGINT_LIMBS];
    memset(acc, 0, sizeof(acc));

    int a_len = 0, b_len = 0;
    for (int i = NIZK_BIGINT_LIMBS - 1; i >= 0; i--) {
        if (a->limbs[i]) { a_len = i + 1; break; }
    }
    for (int i = NIZK_BIGINT_LIMBS - 1; i >= 0; i--) {
        if (b->limbs[i]) { b_len = i + 1; break; }
    }

    for (int i = 0; i < a_len; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < b_len && (i + j) < 2 * NIZK_BIGINT_LIMBS; j++) {
            /* Compute 128-bit product of two 64-bit limbs */
            uint64_t hi, lo;
            /* Manual 64x64->128 multiplication using splitting */
            uint64_t a_lo = (uint32_t)a->limbs[i];
            uint64_t a_hi = a->limbs[i] >> 32;
            uint64_t b_lo = (uint32_t)b->limbs[j];
            uint64_t b_hi = b->limbs[j] >> 32;

            uint64_t t1 = a_lo * b_lo;
            uint64_t t2 = a_hi * b_lo + (t1 >> 32);
            uint64_t t3 = a_lo * b_hi + (uint32_t)t2;
            lo = (t3 << 32) | (uint32_t)t1;
            hi = a_hi * b_hi + (t2 >> 32) + (t3 >> 32);

            /* Add to accumulator with carry chain */
            uint64_t old = acc[i + j];
            acc[i + j] = old + lo;
            uint64_t c1 = (acc[i + j] < old) ? 1 : 0;
            uint64_t c2 = 0;
            old = acc[i + j + 1];
            acc[i + j + 1] = old + hi + c1 + carry;
            if (acc[i + j + 1] < old) c2 = 1;
            carry = c2;
        }
        /* Propagate remaining carry */
        int k = i + b_len;
        while (carry && k < 2 * NIZK_BIGINT_LIMBS) {
            uint64_t old = acc[k];
            acc[k] = old + carry;
            carry = (acc[k] < old) ? 1 : 0;
            k++;
        }
    }

    /* Copy lower half to result */
    memcpy(r->limbs, acc, NIZK_BIGINT_LIMBS * sizeof(uint64_t));
}

/**
 * Compare the full double-precision value of a to modulus m.
 * Returns 1 if a >= m, 0 otherwise.
 */
static int bigint_ge_mod(const uint64_t *a, const nizk_bigint_t *m) {
    for (int i = NIZK_BIGINT_LIMBS - 1; i >= 0; i--) {
        if (a[i] > m->limbs[i]) return 1;
        if (a[i] < m->limbs[i]) return 0;
    }
    return 1; /* equal */
}

/**
 * Barrett reduction: reduce a 2n-limb value modulo an n-limb modulus.
 *
 * Barrett Reduction Algorithm (Menezes, Algorithm 14.42):
 *   Given x < m^2, compute r = x mod m.
 *   Precompute mu = floor(b^{2k} / m) where b = 2^64, k = number of limbs.
 *
 *   q1 = floor(x / b^{k-1})
 *   q2 = q1 * mu
 *   q3 = floor(q2 / b^{k+1})
 *   r1 = x mod b^{k+1}
 *   r2 = (q3 * m) mod b^{k+1}
 *   r  = r1 - r2
 *   if r < 0: r += b^{k+1}
 *   while r >= m: r -= m
 */
static void barrett_reduce(nizk_bigint_t *r,
                            const uint64_t *x_2n,
                            const nizk_bigint_t *m,
                            const nizk_bigint_t *mu,
                            int k) {
    /* Simplified Barrett for our fixed-size implementation.
     * Since we operate on relatively small numbers in practice,
     * we use trial subtraction which is correct and simpler. */

    nizk_bigint_t result;
    memcpy(result.limbs, x_2n, NIZK_BIGINT_LIMBS * sizeof(uint64_t));

    /* Check if there's overflow in upper half */
    for (int i = NIZK_BIGINT_LIMBS; i < 2 * NIZK_BIGINT_LIMBS; i++) {
        if (x_2n[i] != 0) {
            /* Need full reduction. For simplicity, do repeated subtraction
             * of m * b^{i - NIZK_BIGINT_LIMBS} */
            nizk_bigint_t shifted_m;
            nizk_bigint_zero(&shifted_m);
            int shift_limbs = i - NIZK_BIGINT_LIMBS;
            if (shift_limbs < NIZK_BIGINT_LIMBS) {
                memcpy(shifted_m.limbs + shift_limbs, m->limbs,
                       (NIZK_BIGINT_LIMBS - shift_limbs) * sizeof(uint64_t));
            }
            while (bigint_ge_mod(x_2n + NIZK_BIGINT_LIMBS, &shifted_m) ||
                   nizk_bigint_cmp(&result, m) >= 0) {
                /* Subtract m from the upper part via borrow */
                uint64_t borrow = 0;
                for (int j = 0; j < NIZK_BIGINT_LIMBS; j++) {
                    uint64_t diff = result.limbs[j] - m->limbs[j] - borrow;
                    borrow = (result.limbs[j] < m->limbs[j] + borrow) ? 1 : 0;
                    result.limbs[j] = diff;
                }
            }
        }
    }

    /* Final reduction: while result >= m, result -= m */
    while (nizk_bigint_cmp(&result, m) >= 0) {
        bigint_sub_raw(&result, &result, m);
    }

    *r = result;
}

/* =========================================================================
 * Modular Arithmetic
 * ========================================================================= */

void nizk_mod_add(nizk_bigint_t *r, const nizk_bigint_t *a,
                  const nizk_bigint_t *b, const nizk_bigint_t *m) {
    nizk_bigint_t sum;
    uint64_t carry = bigint_add_raw(&sum, a, b);

    /* If carry or sum >= m, subtract m */
    if (carry || nizk_bigint_cmp(&sum, m) >= 0) {
        bigint_sub_raw(r, &sum, m);
    } else {
        *r = sum;
    }
}

void nizk_mod_sub(nizk_bigint_t *r, const nizk_bigint_t *a,
                  const nizk_bigint_t *b, const nizk_bigint_t *m) {
    if (nizk_bigint_cmp(a, b) >= 0) {
        bigint_sub_raw(r, a, b);
    } else {
        /* r = m - (b - a) */
        nizk_bigint_t diff;
        bigint_sub_raw(&diff, b, a);
        bigint_sub_raw(r, m, &diff);
    }
}

/* Helper: 64x64->128 multiply returning hi and lo (via 32-bit splitting) */
static void mul64x64(uint64_t a, uint64_t b, uint64_t *hi, uint64_t *lo) {
    uint32_t al = (uint32_t)a, ah = (uint32_t)(a >> 32);
    uint32_t bl = (uint32_t)b, bh = (uint32_t)(b >> 32);
    uint64_t t1 = (uint64_t)al * bl;
    uint64_t t2 = (uint64_t)ah * bl + (t1 >> 32);
    uint64_t t3 = (uint64_t)al * bh + (uint32_t)t2;
    *lo = (t3 << 32) | (uint32_t)t1;
    *hi = (uint64_t)ah * bh + (t2 >> 32) + (t3 >> 32);
}

/** Add val to arr[pos], propagating carry up to max_len limbs */
static void add_to(uint64_t *arr, int max_len, int pos, uint64_t val) {
    while (val && pos < max_len) {
        uint64_t s = arr[pos] + val;
        val = (s < arr[pos]) ? 1ULL : 0ULL;
        arr[pos] = s;
        pos++;
    }
}

/* Left-shift a bigint by 'shift' bits (0 <= shift < 64), storing in res.
 * The source 'a' has 'len' active limbs. Result is written to 'res'
 * which must have at least len+1 limbs available. */
static void bigint_shl_limbs(uint64_t *res, const uint64_t *a,
                              int len, int shift) {
    if (shift == 0) {
        memcpy(res, a, len * sizeof(uint64_t));
        return;
    }
    uint64_t carry = 0;
    for (int i = 0; i < len; i++) {
        uint64_t cur = a[i];
        res[i] = (cur << shift) | carry;
        carry = cur >> (64 - shift);
    }
    res[len] = carry;
}

/** Compare two multi-limb numbers with possibly different lengths.
 *  a_len and b_len are the active limb counts.
 *  Returns 1 if a > b, -1 if a < b, 0 if equal.
 *  Missing limbs are treated as 0. */
static int bigint_cmp_len2(const uint64_t *a, int a_len,
                            const uint64_t *b, int b_len) {
    int max_len = (a_len > b_len) ? a_len : b_len;
    for (int i = max_len - 1; i >= 0; i--) {
        uint64_t av = (i < a_len) ? a[i] : 0;
        uint64_t bv = (i < b_len) ? b[i] : 0;
        if (av > bv) return 1;
        if (av < bv) return -1;
    }
    return 0;
}

/** Subtract b from a in-place (len limbs). Assumes a >= b.
 *  Returns the final borrow. Caller must propagate borrow to higher limbs
 *  of 'a' if 'a' extends beyond 'len'. */
static uint64_t bigint_sub_len(uint64_t *a, const uint64_t *b, int len) {
    uint64_t borrow = 0;
    for (int i = 0; i < len; i++) {
        uint64_t diff = a[i] - b[i] - borrow;
        unsigned __int128 a_val = a[i];
        unsigned __int128 b_val = (unsigned __int128)b[i] + borrow;
        borrow = (a_val < b_val) ? 1ULL : 0ULL;
        a[i] = diff;
    }
    return borrow;
}

/** Get the effective limb count of a bigint. */
static int bigint_limb_count(const uint64_t *a, int max_len) {
    while (max_len > 0 && a[max_len - 1] == 0) max_len--;
    return max_len;
}

void nizk_mod_mul(nizk_bigint_t *r, const nizk_bigint_t *a,
                  const nizk_bigint_t *b, const nizk_bigint_t *m) {
    /* ---- Multiply: a * b -> prod[2*LIMBS] ---- */
    uint64_t prod[2 * NIZK_BIGINT_LIMBS];
    memset(prod, 0, sizeof(prod));

    int alen = NIZK_BIGINT_LIMBS, blen = NIZK_BIGINT_LIMBS;
    while (alen > 0 && a->limbs[alen - 1] == 0) alen--;
    while (blen > 0 && b->limbs[blen - 1] == 0) blen--;
    if (alen == 0 || blen == 0) { nizk_bigint_zero(r); return; }

    for (int i = 0; i < alen; i++) {
        for (int j = 0; j < blen; j++) {
            uint64_t hi, lo;
            mul64x64(a->limbs[i], b->limbs[j], &hi, &lo);
            add_to(prod, 2 * NIZK_BIGINT_LIMBS, i + j, lo);
            add_to(prod, 2 * NIZK_BIGINT_LIMBS, i + j + 1, hi);
        }
    }

    /* ---- Reduce: prod mod m using robust shift-subtract ----
     *
     * Algorithm:
     *   Let p_bits = bit-length of prod, m_bits = bit-length of m.
     *   For shift from (p_bits - m_bits) down to 0:
     *     Compute m_shifted = m << shift.
     *     If prod >= m_shifted: prod -= m_shifted.
     *   The result is prod mod m.
     *
     * This is correct by construction: we maintain the invariant
     * prod ≡ original_product (mod m), and each subtraction removes
     * the largest possible multiple of m. At the end, prod < m.
     *
     * Complexity: O(shift * limbs) where shift ≤ 2048. In practice,
     * this is fast for 256-bit moduli and products up to 512 bits.
     * ------------------------------------------------------------------ */
    int mlen = bigint_limb_count(m->limbs, NIZK_BIGINT_LIMBS);
    if (mlen == 0) { nizk_bigint_zero(r); return; }

    int plen = bigint_limb_count(prod, 2 * NIZK_BIGINT_LIMBS);
    if (plen == 0) { nizk_bigint_zero(r); return; }

    /* Fast path: prod < m */
    if (plen < mlen ||
        (plen == mlen && bigint_cmp_len2(prod, plen, m->limbs, mlen) < 0)) {
        memcpy(r->limbs, prod, NIZK_BIGINT_LIMBS * sizeof(uint64_t));
        return;
    }

    /* Compute bit lengths */
    int p_bits = 0;
    {
        int top_limb = plen - 1;
        uint64_t v = prod[top_limb];
        while (v) { p_bits++; v >>= 1; }
        p_bits += top_limb * 64;
    }
    int m_bits = 0;
    {
        int top_limb = mlen - 1;
        uint64_t v = m->limbs[top_limb];
        while (v) { m_bits++; v >>= 1; }
        m_bits += top_limb * 64;
    }

    int shift = p_bits - m_bits;
    if (shift < 0) {
        memcpy(r->limbs, prod, NIZK_BIGINT_LIMBS * sizeof(uint64_t));
        return;
    }

    /* Main reduction loop: for each shift value from high to low */
    for (int s = shift; s >= 0; s--) {
        int s_limb = s / 64;
        int s_bit  = s % 64;

        /* Compute m_shifted = m << s */
        int mshift_len = mlen + s_limb + 1;
        uint64_t m_shifted[64]; /* max needed for 32*2+1 = 65 limbs, 64 is safe for 32-limb m */
        memset(m_shifted, 0, sizeof(m_shifted));

        /* Place m shifted left by s_bit bits at offset s_limb */
        if (s_bit == 0) {
            memcpy(m_shifted + s_limb, m->limbs, mlen * sizeof(uint64_t));
        } else {
            uint64_t carry = 0;
            for (int i = 0; i < mlen; i++) {
                uint64_t cur = m->limbs[i];
                m_shifted[s_limb + i] = (cur << s_bit) | carry;
                carry = cur >> (64 - s_bit);
            }
            m_shifted[s_limb + mlen] = carry;
        }
        int mshift_actual = bigint_limb_count(m_shifted, mlen + s_limb + 1);

        /* While prod >= m_shifted, subtract.
         * Compare using the full plen of prod against mshift_actual limbs
         * of m_shifted. Missing higher limbs of m_shifted are treated as 0,
         * so prod's extra limbs correctly make prod > m_shifted. */
        while (bigint_cmp_len2(prod, plen, m_shifted, mshift_actual) >= 0) {
            uint64_t borrow = bigint_sub_len(prod, m_shifted, mshift_actual);
            /* Propagate borrow to higher limbs of prod */
            int bp = mshift_actual;
            while (borrow && bp < 2 * NIZK_BIGINT_LIMBS) {
                uint64_t old = prod[bp];
                prod[bp] = old - borrow;
                borrow = (old < borrow) ? 1ULL : 0ULL;
                bp++;
            }
            /* Recompute plen */
            plen = bigint_limb_count(prod, 2 * NIZK_BIGINT_LIMBS);
            if (plen == 0) {
                nizk_bigint_zero(r);
                return;
            }
        }
    }

    /* Final cleanup */
    memcpy(r->limbs, prod, NIZK_BIGINT_LIMBS * sizeof(uint64_t));
    while (nizk_bigint_cmp(r, m) >= 0) {
        bigint_sub_raw(r, r, m);
    }
}

void nizk_mod_exp(nizk_bigint_t *r, const nizk_bigint_t *base,
                  const nizk_bigint_t *exp, const nizk_bigint_t *m) {
    nizk_bigint_t result;
    nizk_bigint_one(&result);

    nizk_bigint_t base_copy;
    nizk_bigint_copy(&base_copy, base);

    int bits = nizk_bigint_bitlen(exp);

    for (int i = 0; i < bits; i++) {
        int limb_idx = i / 64;
        int bit_idx = i % 64;
        if ((exp->limbs[limb_idx] >> bit_idx) & 1) {
            nizk_bigint_t temp;
            nizk_mod_mul(&temp, &result, &base_copy, m);
            result = temp;
        }
        nizk_bigint_t temp;
        nizk_mod_mul(&temp, &base_copy, &base_copy, m);
        base_copy = temp;
    }

    *r = result;
}

/* --------------------------------------------------------------------------
 * Single-limb division: divide bigint 'num' by uint64_t 'den'.
 * Returns quotient q and remainder r (r < den).
 *
 * This is the key optimization that makes the extended Euclidean algorithm
 * practical: for any modulus m and input a, the EEA only requires division
 * by small denominators (the current r1 in the Euclidean step). After the
 * first step, r1 is at most the bit-length of a, which for our mini
 * parameters is 256 bits or fewer.
 *
 * Complexity: O(n) where n = number of active limbs.
 * -------------------------------------------------------------------------- */
static uint64_t bigint_div_u64(nizk_bigint_t *q, const nizk_bigint_t *num,
                                uint64_t den) {
    if (den == 0) { nizk_bigint_zero(q); return 0; }
    nizk_bigint_zero(q);
    uint64_t rem = 0;
    /* Process limbs from most significant to least */
    int top = NIZK_BIGINT_LIMBS - 1;
    while (top >= 0 && num->limbs[top] == 0) top--;
    for (int i = top; i >= 0; i--) {
        /* Combine remainder with current limb to form 128-bit dividend */
        unsigned __int128 dividend = ((unsigned __int128)rem << 64) | num->limbs[i];
        uint64_t qi = (uint64_t)(dividend / den);
        rem = (uint64_t)(dividend % den);
        q->limbs[i] = qi;
    }
    return rem;
}

/* --------------------------------------------------------------------------
 * Extended Euclidean Algorithm (EEA) for modular inverse.
 *
 * Theorem (Bezout, 1779): For integers a, m with gcd(a,m) = 1, there
 * exist integers s, t such that s*m + t*a = 1. Then t ≡ a^{-1} (mod m).
 *
 * Algorithm: Classical EEA with remainder tracking.
 *   r0 = m,  r1 = a           (remainder sequence)
 *   s0 = 1,  s1 = 0           (coefficients for m)
 *   t0 = 0,  t1 = 1           (coefficients for a)
 *   While r1 ≠ 0:
 *     q = r0 / r1,  r2 = r0 - q*r1
 *     s2 = s0 - q*s1,  t2 = t0 - q*t1
 *     Shift: (r0,r1)←(r1,r2), (s0,s1)←(s1,s2), (t0,t1)←(t1,t2)
 *   Output: t0 = a^{-1} mod m  (if gcd = 1)
 *
 * Initial division uses the full multi-limb divider (for large m / small a).
 * Subsequent divisions use single-limb arithmetic (r1 is small after step 1).
 *
 * Complexity: O(n^2) for the first step (one bigint division), O(n * log(min))
 * for remaining steps. Total: O(n^2), which is polynomial, versus the
 * exponential O(n^2 * 2^{|m|}) of the Fermat-based approach.
 *
 * Reference: Knuth, "The Art of Computer Programming," Vol. 2, Algorithm X.
 *            Cormen et al., "Introduction to Algorithms," §31.2.
 * -------------------------------------------------------------------------- */
void nizk_mod_inv(nizk_bigint_t *r, const nizk_bigint_t *a,
                  const nizk_bigint_t *m) {
    /* Special cases */
    if (nizk_bigint_is_zero(a)) {
        nizk_bigint_zero(r);
        return;
    }
    if (nizk_bigint_is_one(a)) {
        nizk_bigint_one(r);
        return;
    }

    /* r0 = m, r1 = a mod m */
    nizk_bigint_t r0, r1;
    nizk_bigint_copy(&r0, m);
    nizk_bigint_copy(&r1, a);
    while (nizk_bigint_cmp(&r1, m) >= 0) {
        bigint_sub_raw(&r1, &r1, m);
    }
    if (nizk_bigint_is_zero(&r1)) {
        nizk_bigint_zero(r);
        return;
    }

    /* s-coefficient for m: tracks representation of remainder as combo of m */
    nizk_bigint_t s0, s1, s2;
    nizk_bigint_one(&s0);
    nizk_bigint_zero(&s1);

    /* t-coefficient for a: when r0=1, t0 ≡ a^{-1} mod m */
    nizk_bigint_t t0, t1, t2;
    nizk_bigint_zero(&t0);
    nizk_bigint_one(&t1);

    /* EEA main loop.
     * Determine the active limb count of r1 for the division strategy.
     * r1 decreases monotonically; after the first division, r1 < initial r1. */
    while (!nizk_bigint_is_zero(&r1)) {
        /* Count active limbs in r1 */
        int r1_limbs = NIZK_BIGINT_LIMBS;
        while (r1_limbs > 0 && r1.limbs[r1_limbs - 1] == 0) r1_limbs--;

        nizk_bigint_t q, r2;

        if (r1_limbs <= 1) {
            /* r1 fits in a single 64-bit limb — use fast path */
            uint64_t r1_val = r1.limbs[0];
            uint64_t rem = bigint_div_u64(&q, &r0, r1_val);
            nizk_bigint_set_u64(&r2, rem);
        } else {
            /* Multi-limb division needed for the first step (m / a).
             * Compute q = r0 / r1, r2 = r0 - q*r1 by long division. */
            nizk_bigint_zero(&q);
            nizk_bigint_copy(&r2, &r0);

            /* Estimate quotient by comparing top limbs.
             * For the EEA, this branch is only taken once (first iteration),
             * so we can use repeated subtraction with a shift optimization. */
            int r0_bits = nizk_bigint_bitlen(&r0);
            int r1_bits = nizk_bigint_bitlen(&r1);
            int shift = r0_bits - r1_bits;

            if (shift > 0) {
                /* Precompute r1 << shift */
                nizk_bigint_t r1_shifted;
                nizk_bigint_zero(&r1_shifted);
                int limb_shift = shift / 64;
                int bit_shift = shift % 64;
                for (int i = NIZK_BIGINT_LIMBS - 1 - limb_shift; i >= 0; i--) {
                    uint64_t lo = r1.limbs[i];
                    uint64_t hi = (i + 1 < NIZK_BIGINT_LIMBS) ? r1.limbs[i + 1] : 0;
                    r1_shifted.limbs[i + limb_shift] |=
                        (lo << bit_shift) & 0xFFFFFFFFFFFFFFFFULL;
                    if (bit_shift > 0 && i + limb_shift + 1 < NIZK_BIGINT_LIMBS) {
                        r1_shifted.limbs[i + limb_shift + 1] |=
                            (lo >> (64 - bit_shift));
                    }
                }
                /* Repeatedly subtract the shifted r1, then reduce shift */
                uint64_t pow2 = 1ULL << (shift % 64);
                int ls = limb_shift;
                while (nizk_bigint_cmp(&r2, &r1) >= 0) {
                    if (nizk_bigint_cmp(&r2, &r1_shifted) >= 0) {
                        bigint_sub_raw(&r2, &r2, &r1_shifted);
                        /* Add 2^shift to quotient */
                        if (ls < NIZK_BIGINT_LIMBS) {
                            uint64_t carry = pow2;
                            for (int i = ls; i < NIZK_BIGINT_LIMBS && carry; i++) {
                                uint64_t s = q.limbs[i] + carry;
                                carry = (s < q.limbs[i]) ? 1ULL : 0ULL;
                                q.limbs[i] = s;
                            }
                        }
                    } else {
                        /* Reduce shift by 1 */
                        if (shift == 0) break;
                        shift--;
                        ls = shift / 64;
                        pow2 = 1ULL << (shift % 64);
                        /* Recompute r1_shifted = r1 << shift by right-shifting
                         * and rebuilding... or just rebuild. */
                        nizk_bigint_zero(&r1_shifted);
                        limb_shift = shift / 64;
                        bit_shift = shift % 64;
                        for (int i = NIZK_BIGINT_LIMBS - 1 - limb_shift; i >= 0; i--) {
                            if (r1.limbs[i] == 0) continue;
                            uint64_t lo = r1.limbs[i];
                            int dest = i + limb_shift;
                            if (dest < NIZK_BIGINT_LIMBS) {
                                r1_shifted.limbs[dest] |= (lo << bit_shift);
                            }
                            if (bit_shift > 0 && dest + 1 < NIZK_BIGINT_LIMBS) {
                                r1_shifted.limbs[dest + 1] |= (lo >> (64 - bit_shift));
                            }
                        }
                    }
                }
            } else {
                /* shift == 0: r0 and r1 have same bit length, simple subtraction */
            }
            /* Finish: subtract r1 while r2 >= r1 */
            while (nizk_bigint_cmp(&r2, &r1) >= 0) {
                bigint_sub_raw(&r2, &r2, &r1);
                uint64_t c = 1;
                for (int i = 0; i < NIZK_BIGINT_LIMBS && c; i++) {
                    uint64_t s = q.limbs[i] + c;
                    c = (s < q.limbs[i]) ? 1ULL : 0ULL;
                    q.limbs[i] = s;
                }
            }
        }

        /* s2 = (s0 - q*s1) mod m */
        {
            nizk_bigint_t prod;
            nizk_mod_mul(&prod, &q, &s1, m);
            nizk_mod_sub(&s2, &s0, &prod, m);
        }

        /* t2 = (t0 - q*t1) mod m */
        {
            nizk_bigint_t prod;
            nizk_mod_mul(&prod, &q, &t1, m);
            nizk_mod_sub(&t2, &t0, &prod, m);
        }

        /* Shift: r0←r1, r1←r2, s0←s1, s1←s2, t0←t1, t1←t2 */
        r0 = r1; r1 = r2;
        s0 = s1; s1 = s2;
        t0 = t1; t1 = t2;
    }

    /* r0 = gcd(m, a). t0 ≡ a^{-1} mod m when gcd = 1.
     * For proper modular arithmetic, ensure t0 ∈ [0, m-1]. */
    while (nizk_bigint_cmp(&t0, m) >= 0) {
        bigint_sub_raw(&t0, &t0, m);
    }
    /* If t0 underflowed in subtraction (unlikely with our mod tracking),
     * we might get a huge value. Add m repeatedly until positive.
     * Actually t0 should be correct since we did all arithmetic mod m. */
    *r = t0;
}

void nizk_mod_neg(nizk_bigint_t *r, const nizk_bigint_t *a,
                  const nizk_bigint_t *m) {
    if (nizk_bigint_is_zero(a)) {
        nizk_bigint_zero(r);
    } else {
        bigint_sub_raw(r, m, a);
    }
}

/* =========================================================================
 * Group Element Operations
 * ========================================================================= */

void nizk_group_elem_identity(nizk_group_elem_t *elem) {
    nizk_bigint_one(&elem->elem);
}

void nizk_group_op(nizk_group_elem_t *r,
                   const nizk_group_elem_t *a,
                   const nizk_group_elem_t *b,
                   const nizk_group_params_t *params) {
    nizk_mod_mul(&r->elem, &a->elem, &b->elem, &params->p);
}

void nizk_group_exp(nizk_group_elem_t *r,
                    const nizk_group_elem_t *base,
                    const nizk_scalar_t *scalar,
                    const nizk_group_params_t *params) {
    nizk_mod_exp(&r->elem, &base->elem, &scalar->val, &params->p);
}

void nizk_group_multi_exp(nizk_group_elem_t *r,
                          const nizk_group_elem_t *g,
                          const nizk_scalar_t *a,
                          const nizk_group_elem_t *h,
                          const nizk_scalar_t *b,
                          const nizk_group_params_t *params) {
    /* Compute g^a * h^b using Shamir simultaneous multi-exponentiation */
    /* First compute each exponentiation separately, then multiply */
    nizk_group_elem_t t1, t2;
    nizk_group_exp(&t1, g, a, params);
    nizk_group_exp(&t2, h, b, params);
    nizk_group_op(r, &t1, &t2, params);
}

void nizk_group_triple_exp(nizk_group_elem_t *r,
                           const nizk_group_elem_t *g,
                           const nizk_scalar_t *a,
                           const nizk_group_elem_t *h,
                           const nizk_scalar_t *b,
                           const nizk_group_elem_t *u,
                           const nizk_scalar_t *c,
                           const nizk_group_params_t *params) {
    /* Compute g^a * h^b * u^c */
    nizk_group_elem_t t1, t2;
    nizk_group_multi_exp(&t1, g, a, h, b, params);
    nizk_group_exp(&t2, u, c, params);
    nizk_group_op(r, &t1, &t2, params);
}

int nizk_group_elem_is_valid(const nizk_group_elem_t *elem,
                              const nizk_group_params_t *params) {
    /* Range validation: 1 <= elem < p.
     * Subgroup check (elem^q == 1 mod p) is omitted for performance
     * since q = p-1 in this educational setup, making it always true
     * by Fermat's little theorem for any elem ∈ [1, p-1].
     * Production NIZK systems with proper q | (p-1) must check it. */
    if (nizk_bigint_is_zero(&elem->elem)) return 0;
    if (nizk_bigint_cmp(&elem->elem, &params->p) >= 0) return 0;
    return 1;
}

int nizk_group_elem_eq(const nizk_group_elem_t *a,
                        const nizk_group_elem_t *b) {
    return nizk_bigint_cmp(&a->elem, &b->elem) == 0;
}

void nizk_group_elem_copy(nizk_group_elem_t *dst,
                           const nizk_group_elem_t *src) {
    nizk_bigint_copy(&dst->elem, &src->elem);
}

void nizk_group_elem_rand(nizk_group_elem_t *r,
                           const nizk_group_params_t *params) {
    nizk_scalar_t s;
    nizk_scalar_rand(&s, params);
    nizk_group_exp(r, (nizk_group_elem_t*)&params->g, &s, params);
    /* Note: casting away const for backward compat �� params->g is treated as base */
    /* Alternative: create a proper group element from the generator */
    nizk_group_elem_t gen;
    nizk_bigint_copy(&gen.elem, &params->g);
    nizk_group_exp(r, &gen, &s, params);
}

/* =========================================================================
 * Scalar Operations
 * ========================================================================= */

void nizk_scalar_zero(nizk_scalar_t *s) {
    nizk_bigint_zero(&s->val);
}

void nizk_scalar_set_u64(nizk_scalar_t *s, uint64_t val) {
    nizk_bigint_set_u64(&s->val, val);
}

void nizk_scalar_add(nizk_scalar_t *r,
                     const nizk_scalar_t *a,
                     const nizk_scalar_t *b,
                     const nizk_group_params_t *params) {
    nizk_mod_add(&r->val, &a->val, &b->val, &params->q);
}

void nizk_scalar_sub(nizk_scalar_t *r,
                     const nizk_scalar_t *a,
                     const nizk_scalar_t *b,
                     const nizk_group_params_t *params) {
    nizk_mod_sub(&r->val, &a->val, &b->val, &params->q);
}

void nizk_scalar_mul(nizk_scalar_t *r,
                     const nizk_scalar_t *a,
                     const nizk_scalar_t *b,
                     const nizk_group_params_t *params) {
    nizk_mod_mul(&r->val, &a->val, &b->val, &params->q);
}

void nizk_scalar_neg(nizk_scalar_t *r,
                     const nizk_scalar_t *a,
                     const nizk_group_params_t *params) {
    nizk_mod_neg(&r->val, &a->val, &params->q);
}

void nizk_scalar_inv(nizk_scalar_t *r,
                     const nizk_scalar_t *a,
                     const nizk_group_params_t *params) {
    nizk_mod_inv(&r->val, &a->val, &params->q);
}

int nizk_scalar_cmp(const nizk_scalar_t *a, const nizk_scalar_t *b) {
    return nizk_bigint_cmp(&a->val, &b->val);
}

void nizk_scalar_copy(nizk_scalar_t *dst, const nizk_scalar_t *src) {
    nizk_bigint_copy(&dst->val, &src->val);
}

int nizk_scalar_is_zero(const nizk_scalar_t *s) {
    return nizk_bigint_is_zero(&s->val);
}

void nizk_scalar_rand(nizk_scalar_t *r, const nizk_group_params_t *params) {
    /* Generate random bytes and reduce mod q */
    uint8_t buf[256]; /* 2048 bits */
    secure_rand_bytes(buf, sizeof(buf));

    nizk_bigint_t rand_val;
    nizk_bigint_zero(&rand_val);
    for (int i = 0; i < (int)sizeof(buf) && i / 8 < NIZK_BIGINT_LIMBS; i++) {
        int limb_idx = i / 8;
        int byte_idx = i % 8;
        rand_val.limbs[limb_idx] |= ((uint64_t)buf[i]) << (byte_idx * 8);
    }

    /* Reduce mod q using mod_mul with 1 (rand_val * 1 mod q = rand_val mod q) */
    nizk_bigint_t reduced;
    nizk_bigint_t one;
    nizk_bigint_one(&one);
    nizk_mod_mul(&reduced, &rand_val, &one, &params->q);
    r->val = reduced;
}

/* =========================================================================
 * Group Parameter Generation
 * ========================================================================= */

/**
 * Standard 256-bit group parameters.
 *
 * We use a well-known construction:
 *   q = secp256k1 order (256-bit prime)
 *   p = 2q + 1 (should be prime for safe prime construction)
 *   g = 4 (generator of subgroup of order q, since 4^q = 1 mod p
 *          when p = 2q + 1 and 4 is a quadratic residue)
 *
 * For simplicity in this educational implementation, we use:
 *   q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
 *   p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
 *       (secp256k1 field prime)
 *   g = 2 (generator of the full group; we work in the q-order subgroup)
 *
 * This is a "mini" setup �� real NIZK systems use 2048+ bit primes.
 */

/* secp256k1 field prime p (256-bit prime) */
static const uint64_t secp256k1_p[4] = {
    0xFFFFFFFEFFFFFC2FULL,
    0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL
};

void nizk_group_params_init_256bit(nizk_group_params_t *params) {
    memset(params, 0, sizeof(*params));

    /* Set p (secp256k1 field prime, 256-bit) */
    for (int i = 0; i < 4; i++) {
        params->p.limbs[i] = secp256k1_p[i];
    }
    params->p_bits = 256;

    /* Set q = p - 1 (order of the full multiplicative group Z_p^*).
     * This ensures consistency: g^q ≡ 1 (mod p) by Fermat's theorem,
     * so scalar arithmetic mod q is consistent with exponentiation mod p.
     * For production use, q should be a large prime divisor of p-1. */
    for (int i = 0; i < 4; i++) {
        params->q.limbs[i] = secp256k1_p[i];
    }
    /* Subtract 1: q = p - 1 */
    params->q.limbs[0] -= 1;
    if (params->q.limbs[0] > secp256k1_p[0]) {
        /* Underflow handled by unsigned wrap — this won't happen since p[0] ≥ 1 */
    }
    params->q_bits = 256;

    /* Set generator g = 2 */
    nizk_bigint_set_u64(&params->g, 2);
}

void nizk_group_params_clear(nizk_group_params_t *params) {
    memset(params, 0, sizeof(*params));
}
