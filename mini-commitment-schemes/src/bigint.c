/**
 * @file bigint.c
 * @brief Multi-precision integer arithmetic implementation
 *
 * Implements arbitrary-width unsigned integers using a limb representation.
 * Each limb is a uint64_t, stored little-endian.
 *
 * Algorithm references:
 *   - Knuth, D.E. "The Art of Computer Programming, Vol 2: Seminumerical
 *     Algorithms" (1969), Chapter 4.3.1: Multiple-Precision Arithmetic
 *   - HAC §14: Multiple-Precision Integer Arithmetic
 *
 * Knowledge Mapping:
 *   L3: Mathematical Structures — big integer as ring Z
 *   L5: Algorithms — schoolbook multiplication, binary long division
 */

#include "bigint.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* =========================================================================
 * Internal helpers
 * ========================================================================= */

/** Trim leading zero limbs to maintain the invariant. */
static void bigint_trim(bigint *a) {
    while (a->nlimbs > 0 && a->limbs[a->nlimbs - 1] == 0) {
        a->nlimbs--;
    }
}

/** Count leading zeros in a uint64_t. Returns 64 for input 0. */
static int clz64(uint64_t x) {
    if (x == 0) return 64;
    int n = 0;
    if ((x & 0xFFFFFFFF00000000ULL) == 0) { n += 32; x <<= 32; }
    if ((x & 0xFFFF000000000000ULL) == 0) { n += 16; x <<= 16; }
    if ((x & 0xFF00000000000000ULL) == 0) { n += 8;  x <<= 8; }
    if ((x & 0xF000000000000000ULL) == 0) { n += 4;  x <<= 4; }
    if ((x & 0xC000000000000000ULL) == 0) { n += 2;  x <<= 2; }
    if ((x & 0x8000000000000000ULL) == 0) { n += 1; }
    return n;
}

/* =========================================================================
 * Lifecycle
 * ========================================================================= */

void bigint_init(bigint *a) {
    memset(a->limbs, 0, sizeof(a->limbs));
    a->nlimbs = 0;
}

void bigint_init_u64(bigint *a, uint64_t val) {
    bigint_init(a);
    if (val == 0) {
        a->nlimbs = 0;
    } else {
        a->limbs[0] = val;
        a->nlimbs = 1;
    }
}

void bigint_copy(bigint *dst, const bigint *src) {
    memcpy(dst->limbs, src->limbs, src->nlimbs * sizeof(uint64_t));
    dst->nlimbs = src->nlimbs;
}

void bigint_zero(bigint *a) {
    a->nlimbs = 0;
}

/* =========================================================================
 * Comparison
 * ========================================================================= */

int bigint_cmp(const bigint *a, const bigint *b) {
    /* Zero handling: nlimbs==0 means value 0 */
    size_t na = a->nlimbs;
    size_t nb = b->nlimbs;

    if (na == 0 && nb == 0) return 0;
    if (na == 0) return -1;  /* 0 < b */
    if (nb == 0) return 1;   /* a > 0 */

    if (na != nb) {
        return (na > nb) ? 1 : -1;
    }
    /* Same number of limbs — compare from most significant */
    for (size_t i = na; i > 0; i--) {
        if (a->limbs[i-1] > b->limbs[i-1]) return 1;
        if (a->limbs[i-1] < b->limbs[i-1]) return -1;
    }
    return 0;
}

bool bigint_is_zero(const bigint *a) {
    return a->nlimbs == 0;
}

bool bigint_is_one(const bigint *a) {
    return a->nlimbs == 1 && a->limbs[0] == 1;
}

size_t bigint_bitlen(const bigint *a) {
    if (a->nlimbs == 0) return 0;
    uint64_t hi = a->limbs[a->nlimbs - 1];
    return (a->nlimbs - 1) * 64 + (64 - clz64(hi));
}

/* =========================================================================
 * Addition
 * ========================================================================= */

uint64_t bigint_add(bigint *a, const bigint *b) {
    size_t n = a->nlimbs;
    if (b->nlimbs > n) n = b->nlimbs;

    uint64_t carry = 0;
    for (size_t i = 0; i < n; i++) {
        uint64_t ai = (i < a->nlimbs) ? a->limbs[i] : 0;
        uint64_t bi = (i < b->nlimbs) ? b->limbs[i] : 0;

        uint64_t sum = ai + carry;
        carry = (sum < ai) ? 1 : 0;
        sum += bi;
        if (sum < bi) carry = 1;

        a->limbs[i] = sum;
    }

    a->nlimbs = n;
    if (carry) {
        a->limbs[n] = carry;
        a->nlimbs = n + 1;
    }
    bigint_trim(a);
    return carry;
}

uint64_t bigint_add_to(bigint *c, const bigint *a, const bigint *b) {
    bigint_copy(c, a);
    return bigint_add(c, b);
}

/* =========================================================================
 * Subtraction
 *
 * Implements grade-school subtraction with borrow propagation.
 * Uses the standard algorithm: subtract limb-by-limb, propagating borrow.
 * Knuth Vol 2, Algorithm S (§4.3.1).
 * ========================================================================= */

uint64_t bigint_sub(bigint *a, const bigint *b) {
    /* We allow a to grow to match b's limb count for the operation */
    uint64_t borrow = 0;
    for (size_t i = 0; i < b->nlimbs; i++) {
        uint64_t ai = (i < a->nlimbs) ? a->limbs[i] : 0;
        uint64_t bi = b->limbs[i];

        uint64_t diff = ai - borrow;
        borrow = (diff > ai) ? 1 : 0;
        diff -= bi;
        if (diff > (ai - borrow)) borrow = 1;

        a->limbs[i] = diff;
    }

    /* Propagate borrow through remaining limbs of a */
    for (size_t i = b->nlimbs; borrow > 0 && i < a->nlimbs; i++) {
        if (a->limbs[i] >= borrow) {
            a->limbs[i] -= borrow;
            borrow = 0;
        } else {
            a->limbs[i] = a->limbs[i] - borrow; /* wraps, same effect */
            borrow = 1;
        }
    }

    bigint_trim(a);
    return borrow;
}

uint64_t bigint_sub_from(bigint *c, const bigint *a, const bigint *b) {
    bigint_copy(c, a);
    return bigint_sub(c, b);
}

/* =========================================================================
 * Multiplication
 * ========================================================================= */

uint64_t bigint_mul_word(bigint *a, uint64_t word) {
    if (word == 0) {
        bigint_zero(a);
        return 0;
    }
    uint64_t carry = 0;
    for (size_t i = 0; i < a->nlimbs; i++) {
        /* Compute 128-bit product of two 64-bit operands */
        uint64_t a_lo = (uint32_t)(a->limbs[i]);
        uint64_t a_hi = a->limbs[i] >> 32;
        uint64_t w_lo = (uint32_t)word;
        uint64_t w_hi = word >> 32;

        uint64_t mid1 = a_hi * w_lo;
        uint64_t mid2 = a_lo * w_hi;
        uint64_t lo = a_lo * w_lo;

        uint64_t mid = mid1 + mid2;
        uint64_t hi = a_hi * w_hi;

        if (mid < mid1) hi += ((uint64_t)1 << 32);

        lo += carry;
        if (lo < carry) mid++;
        mid += (lo >> 32);
        hi += (mid >> 32);

        a->limbs[i] = ((mid & 0xFFFFFFFFULL) << 32) | (lo & 0xFFFFFFFFULL);
        carry = hi;
    }

    if (carry > 0) {
        a->limbs[a->nlimbs] = carry;
        a->nlimbs++;
    }
    return carry;
}

void bigint_mul(bigint *c, const bigint *a, const bigint *b) {
    bigint_init(c);

    if (bigint_is_zero(a) || bigint_is_zero(b)) return;

    /* Schoolbook multiplication: O(n*m)
     * For each limb of b, multiply a by b_i and accumulate shifted. */
    for (size_t i = 0; i < b->nlimbs; i++) {
        uint64_t bi = b->limbs[i];
        if (bi == 0) continue;

        bigint temp;
        bigint_copy(&temp, a);
        uint64_t carry = bigint_mul_word(&temp, bi);

        /* Shift temp left by i limbs */
        if (i > 0) {
            if (temp.nlimbs + i > BIGINT_MAX_LIMBS) {
                /* Overflow — just handle gracefully */
                temp.nlimbs = BIGINT_MAX_LIMBS - i;
                if (temp.nlimbs <= 0) continue;
            }
            memmove(&temp.limbs[i], temp.limbs, temp.nlimbs * sizeof(uint64_t));
            memset(temp.limbs, 0, i * sizeof(uint64_t));
            temp.nlimbs += i;
            if (carry) {
                temp.limbs[temp.nlimbs] = carry;
                temp.nlimbs++;
            }
        } else if (carry) {
            temp.limbs[temp.nlimbs] = carry;
            temp.nlimbs++;
        }

        bigint_add(c, &temp);
    }
}

/* =========================================================================
 * Division
 *
 * Implements binary long division by repeated subtraction and comparison.
 * This is Knuth's Algorithm D simplified for clarity over performance.
 *
 * For the modulus operation (Z_p), we use:
 *   q = a / m, r = a - q*m, ensuring 0 <= r < m.
 *
 * Theorem: For any a ∈ Z, m ∈ Z\{0}, ∃! (q, r) with a = q*m + r, 0 ≤ r < |m|
 *   (Euclidean division theorem, Euclid's Elements, Book VII)
 * ========================================================================= */

void bigint_div_word(const bigint *a, uint64_t d, bigint *q, uint64_t *r) {
    if (d == 0) return; /* Division by zero — undefined */

    bigint_copy(q, a);
    uint64_t rem = 0;

    /* Process limbs from most significant to least */
    for (size_t i = q->nlimbs; i > 0; i--) {
        size_t idx = i - 1;
        /* Compute 128-bit / 64-bit division */
        /* ((uint128_t)rem << 64) | q->limbs[idx] divided by d */
        /* Since we don't have uint128_t, use the Knuth approach */

        /* We approximate using the fact that d fits in uint64_t */
        /* rem is < d, so the quotient limb is approximately
         * floor(((rem << 64) | q->limbs[idx]) / d) */

        /* Use binary long division for each limb */
        uint64_t quot = 0;
        uint64_t cur = rem;

        for (int bit = 63; bit >= 0; bit--) {
            cur = (cur << 1) | ((q->limbs[idx] >> bit) & 1);
            quot <<= 1;
            if (cur >= d) {
                cur -= d;
                quot |= 1;
            }
        }
        q->limbs[idx] = quot;
        rem = cur;
    }

    bigint_trim(q);
    if (r) *r = rem;
}

uint64_t bigint_mod_word(const bigint *a, uint64_t d) {
    uint64_t r;
    bigint q;
    bigint_init(&q);
    bigint_copy(&q, a);
    bigint_div_word(a, d, &q, &r);
    return r;
}

void bigint_mod(bigint *a, const bigint *m) {
    if (bigint_is_zero(m)) return; /* Division by zero */

    /* If a < m, nothing to do */
    int cmp = bigint_cmp(a, m);
    if (cmp < 0) return;

    /* Binary long division: repeatedly subtract shifted m */
    bigint rem;
    bigint_copy(&rem, a);

    /* While rem >= m, subtract largest shifted m */
    while (bigint_cmp(&rem, m) >= 0) {
        /* Find largest k such that (m << k) <= rem */
        size_t k = 0;
        bigint shifted;
        bigint_copy(&shifted, m);

        /* Try doubling until too large */
        while (1) {
            bigint double_shifted;
            bigint_copy(&double_shifted, &shifted);
            bigint_shl(&double_shifted, 1);

            if (bigint_cmp(&double_shifted, &rem) > 0) break;
            bigint_copy(&shifted, &double_shifted);
            k++;
        }

        /* Subtract the largest shifted m */
        bigint_sub(&rem, &shifted);
    }

    bigint_copy(a, &rem);
}

/* =========================================================================
 * Bit operations
 * ========================================================================= */

void bigint_shl(bigint *a, size_t shift) {
    if (shift == 0) return;
    if (a->nlimbs == 0) return; /* 0 << shift = 0 */

    size_t limb_shift = shift / 64;
    size_t bit_shift = shift % 64;

    if (a->nlimbs + limb_shift + 1 > BIGINT_MAX_LIMBS) {
        /* Would overflow — cap it */
        return;
    }

    if (bit_shift == 0) {
        /* Just shift limbs */
        memmove(&a->limbs[limb_shift], a->limbs, a->nlimbs * sizeof(uint64_t));
        memset(a->limbs, 0, limb_shift * sizeof(uint64_t));
        a->nlimbs += limb_shift;
        return;
    }

    /* Shift within limbs */
    size_t new_nlimbs = a->nlimbs + limb_shift;
    uint64_t carry = 0;
    uint64_t mask = ((uint64_t)1 << bit_shift) - 1;

    for (size_t i = 0; i < a->nlimbs; i++) {
        uint64_t new_carry = (a->limbs[i] >> (64 - bit_shift)) & mask;
        uint64_t new_val = (a->limbs[i] << bit_shift) | carry;
        a->limbs[i + limb_shift] = new_val;
        carry = new_carry;
    }

    if (carry) {
        a->limbs[a->nlimbs + limb_shift] = carry;
        new_nlimbs++;
    }

    /* Zero the lower limbs */
    memset(a->limbs, 0, limb_shift * sizeof(uint64_t));
    a->nlimbs = new_nlimbs;
}

void bigint_shr(bigint *a, size_t shift) {
    if (shift == 0) return;
    if (a->nlimbs == 0) return;

    size_t limb_shift = shift / 64;
    size_t bit_shift = shift % 64;

    if (limb_shift >= a->nlimbs) {
        bigint_zero(a);
        return;
    }

    if (bit_shift == 0) {
        memmove(a->limbs, &a->limbs[limb_shift],
                (a->nlimbs - limb_shift) * sizeof(uint64_t));
        a->nlimbs -= limb_shift;
        return;
    }

    /* Shift within limbs */
    for (size_t i = limb_shift; i < a->nlimbs; i++) {
        uint64_t lo = a->limbs[i] >> bit_shift;
        uint64_t hi = 0;
        if (i + 1 < a->nlimbs) {
            hi = (a->limbs[i + 1] & (((uint64_t)1 << bit_shift) - 1)) << (64 - bit_shift);
        }
        a->limbs[i - limb_shift] = lo | hi;
    }
    a->nlimbs -= limb_shift;
    bigint_trim(a);
}

int bigint_test_bit(const bigint *a, size_t n) {
    size_t limb_idx = n / 64;
    size_t bit_idx = n % 64;
    if (limb_idx >= a->nlimbs) return 0;
    return (a->limbs[limb_idx] >> bit_idx) & 1;
}

void bigint_set_bit(bigint *a, size_t n) {
    size_t limb_idx = n / 64;
    if (limb_idx >= BIGINT_MAX_LIMBS) return;

    /* Expand limbs if needed */
    while (a->nlimbs <= limb_idx) {
        a->limbs[a->nlimbs] = 0;
        a->nlimbs++;
    }
    a->limbs[limb_idx] |= ((uint64_t)1 << (n % 64));
}

/* =========================================================================
 * Conversion
 * ========================================================================= */

void bigint_to_hex(const bigint *a, char *out, size_t out_size) {
    if (bigint_is_zero(a)) {
        if (out_size > 1) {
            out[0] = '0';
            out[1] = '\0';
        }
        return;
    }

    /* Build hex from most significant limb down */
    size_t pos = 0;
    bool started = false;

    for (size_t i = a->nlimbs; i > 0; i--) {
        uint64_t limb = a->limbs[i - 1];
        for (int nibble = 15; nibble >= 0; nibble--) {
            int val = (limb >> (nibble * 4)) & 0xF;
            if (!started && val == 0) continue;
            started = true;
            if (pos + 1 < out_size) {
                out[pos++] = "0123456789abcdef"[val];
            }
        }
    }
    if (pos < out_size) out[pos] = '\0';
}

bool bigint_to_u64(const bigint *a, uint64_t *out) {
    if (a->nlimbs == 0) {
        *out = 0;
        return true;
    }
    if (a->nlimbs > 1) return false; /* Too large */
    *out = a->limbs[0];
    return true;
}

bool bigint_from_hex(bigint *a, const char *hex) {
    bigint_init(a);
    if (hex == NULL || hex[0] == '\0') return true; /* empty = 0 */

    /* Skip leading zeros */
    while (*hex == '0') hex++;
    if (*hex == '\0') return true;

    size_t len = strlen(hex);
    if (len > BIGINT_MAX_BYTES * 2) return false; /* Too long */

    for (size_t i = 0; i < len; i++) {
        char c = hex[i];  /* Process left-to-right (MSB first): a = a*16 + digit */
        int val;
        if (c >= '0' && c <= '9') val = c - '0';
        else if (c >= 'a' && c <= 'f') val = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') val = c - 'A' + 10;
        else return false;

        bigint_mul_word(a, 16);
        a->limbs[0] += val;
        if (a->limbs[0] < (uint64_t)val) {
            /* Propagate carry */
            uint64_t carry = 1;
            for (size_t j = 1; j < a->nlimbs && carry > 0; j++) {
                a->limbs[j] += carry;
                carry = (a->limbs[j] == 0) ? 1 : 0;
            }
            if (carry && a->nlimbs < BIGINT_MAX_LIMBS) {
                a->limbs[a->nlimbs++] = carry;
            }
        }
        if (a->nlimbs == 0 && a->limbs[0] != 0) a->nlimbs = 1;
    }
    bigint_trim(a);
    return true;
}
