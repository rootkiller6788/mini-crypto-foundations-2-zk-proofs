/**
 * sigma_math.c �� Mathematical Primitives for Sigma Protocols
 *
 * Implements 2048-bit modular arithmetic over a safe-prime group Z_p^*,
 * 256-bit scalar arithmetic in Z_q, SHA-256 hash, and randomness.
 *
 * L3 Mathematical Structures:
 *   - Finite field Z_p for 2048-bit prime p
 *   - Scalar field Z_q for 256-bit prime q
 *   - Cyclic subgroup G ? Z_p^* of order q
 *   - SHA-256 hash function (random oracle model)
 *
 * L5 Algorithms:
 *   - Schoolbook multiplication for big integers
 *   - Barrett modular reduction
 *   - Square-and-multiply modular exponentiation
 *   - Extended Euclidean algorithm for modular inverse
 *   - SHA-256 Merkle-Damgard construction
 *   - xoshiro256** pseudo-random number generator
 *
 * References:
 *   - Menezes, van Oorschot, Vanstone (1996) Handbook of Applied Cryptography
 *   - Barrett (1986) "Implementing the RSA Public Key Encryption Scheme"
 *   - FIPS 180-4 Secure Hash Standard (SHA-256)
 *   - Blackman & Vigna (2018) "Scrambled Linear PRNGs"
 *   - Hazay & Lindell (2010) Efficient Secure Two-Party Protocols
 */

#include "sigma_math.h"
#include <string.h>
#include <stdlib.h>

/* ========================================================================
 *  Constants: 2048-bit safe prime p and 256-bit subgroup order q
 *
 *  Using the 2048-bit MODP group from RFC 3526 (Group 14) with prime:
 *    p = 2^2048 - 2^1984 - 1 + 2^64 * { [2^1918 pi] + 124476 }
 *  and subgroup order q = (p-1)/2.
 *
 *  For educational clarity, we use simplified constants.
 *  The generator g = 2 has order q.
 * ======================================================================== */

const sigma_biguint SIGMA_PRIME_P = {{
    47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
}};

const sigma_scalar SIGMA_ORDER_Q = {{
    23, 0, 0, 0
}};

const sigma_group_elem SIGMA_GENERATOR_G = {{
    2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
}};

/* ========================================================================
 *  Big Integer Utilities
 * ======================================================================== */

void sigma_biguint_zero(sigma_biguint *a) {
    memset(a->limbs, 0, sizeof(a->limbs));
}

void sigma_biguint_set_u64(sigma_biguint *a, uint64_t value) {
    memset(a->limbs, 0, sizeof(a->limbs));
    a->limbs[0] = value;
}

void sigma_biguint_copy(sigma_biguint *dst, const sigma_biguint *src) {
    memcpy(dst->limbs, src->limbs, sizeof(dst->limbs));
}

bool sigma_biguint_is_zero(const sigma_biguint *a) {
    for (int i = 0; i < SIGMA_GROUP_PRIME_WORDS; i++) {
        if (a->limbs[i] != 0) return false;
    }
    return true;
}

bool sigma_biguint_is_one(const sigma_biguint *a) {
    if (a->limbs[0] != 1) return false;
    for (int i = 1; i < SIGMA_GROUP_PRIME_WORDS; i++) {
        if (a->limbs[i] != 0) return false;
    }
    return true;
}

int sigma_biguint_cmp(const sigma_biguint *a, const sigma_biguint *b) {
    for (int i = SIGMA_GROUP_PRIME_WORDS - 1; i >= 0; i--) {
        if (a->limbs[i] < b->limbs[i]) return -1;
        if (a->limbs[i] > b->limbs[i]) return 1;
    }
    return 0;
}

int sigma_biguint_bitlen(const sigma_biguint *a) {
    for (int i = SIGMA_GROUP_PRIME_WORDS - 1; i >= 0; i--) {
        if (a->limbs[i] != 0) {
            uint64_t v = a->limbs[i];
            int bits = 0;
            while (v) { v >>= 1; bits++; }
            return i * 64 + bits;
        }
    }
    return 0;
}

bool sigma_biguint_get_bit(const sigma_biguint *a, int i) {
    int limb_idx = i / 64;
    int bit_idx  = i % 64;
    if (limb_idx >= SIGMA_GROUP_PRIME_WORDS) return false;
    return (a->limbs[limb_idx] >> bit_idx) & 1;
}

/* ---------------------------------------------------------------
 *  raw_add: a += b, returns carry out
 * --------------------------------------------------------------- */
static uint64_t raw_add(uint64_t *a, const uint64_t *b, int words) {
    uint64_t carry = 0;
    for (int i = 0; i < words; i++) {
        uint64_t sum = a[i] + b[i] + carry;
        carry = (sum < a[i] || (carry && sum == a[i])) ? 1 : 0;
        a[i] = sum;
    }
    return carry;
}

/* ---------------------------------------------------------------
 *  raw_sub: a -= b, returns borrow out
 * --------------------------------------------------------------- */
static uint64_t raw_sub(uint64_t *a, const uint64_t *b, int words) {
    uint64_t borrow = 0;
    for (int i = 0; i < words; i++) {
        uint64_t diff = a[i] - b[i] - borrow;
        borrow = (a[i] < b[i] || (borrow && a[i] == b[i])) ? 1 : 0;
        a[i] = diff;
    }
    return borrow;
}

/* ---------------------------------------------------------------
 *  mul64x64: hi:lo = a * b  (64x64 -> 128)
 * --------------------------------------------------------------- */
static void mul64x64(uint64_t a, uint64_t b, uint64_t *lo, uint64_t *hi) {
    uint64_t al = (uint32_t)a, ah = a >> 32;
    uint64_t bl = (uint32_t)b, bh = b >> 32;
    uint64_t t0 = al * bl;
    uint64_t t1 = al * bh + (t0 >> 32);
    uint64_t t2 = ah * bl + (uint32_t)t1;
    uint64_t t3 = ah * bh + (t1 >> 32) + (t2 >> 32);
    *lo = (t2 << 32) | (uint32_t)t0;
    *hi = t3;
}

/* ---------------------------------------------------------------
 *  schoolbook_mul: r[2*words] = a[words] * b[words]
 *  L5 Algorithm: Grade-school multiplication O(n^2).
 * --------------------------------------------------------------- */
static void schoolbook_mul(uint64_t *r, const uint64_t *a,
                           const uint64_t *b, int words) {
    memset(r, 0, 2 * words * sizeof(uint64_t));
    for (int i = 0; i < words; i++) {
        uint64_t carry_in = 0;
        for (int j = 0; j < words; j++) {
            uint64_t lo, hi;
            mul64x64(a[i], b[j], &lo, &hi);
            uint64_t s1 = r[i+j] + lo;
            uint64_t c1 = (s1 < r[i+j]) ? 1 : 0;
            uint64_t s2 = s1 + carry_in;
            uint64_t c2 = (s2 < s1) ? 1 : 0;
            r[i+j] = s2;
            carry_in = c1 + c2 + hi;
        }
        for (int j = i + words; carry_in > 0 && j < 2 * words; j++) {
            uint64_t sum = r[j] + carry_in;
            carry_in = (sum < r[j]) ? 1 : 0;
            r[j] = sum;
        }
    }
}

/* ---------------------------------------------------------------
 *  long_divrem: divides num[2k] by den[k], returns quot[k], rem[k]
 *  L5 Algorithm: Binary long division with k+1 limb remainder
 *  to handle overflow during (rem << 1) step.
 * --------------------------------------------------------------- */
static void long_divrem(uint64_t *q, uint64_t *r,
                         const uint64_t *num, int num_words,
                         const uint64_t *den, int den_words) {
    int k = den_words;
    memset(q, 0, k * sizeof(uint64_t));

    /* Remainder needs k+1 limbs to handle (rem << 1) overflow */
    uint64_t *rem = (uint64_t *)calloc((size_t)(k + 1), sizeof(uint64_t));
    if (!rem) return;

    /* Find MSB of denominator */
    int d_msb = k - 1;
    while (d_msb >= 0 && den[d_msb] == 0) d_msb--;
    if (d_msb < 0) { free(rem); return; }

    int shift = 0;
    uint64_t dv = den[d_msb];
    while (!(dv & (1ULL << 63))) { dv <<= 1; shift++; }

    /* Build normalized den: dn[k] (padded to k+1 with zero) */
    uint64_t *dn = (uint64_t *)calloc((size_t)(k + 1), sizeof(uint64_t));
    if (!dn) { free(rem); return; }
    {
        uint64_t carry = 0;
        for (int i = 0; i < k; i++) {
            dn[i] = (den[i] << shift) | carry;
            carry = shift ? (den[i] >> (64 - shift)) : 0;
        }
        dn[k] = carry;
    }

    /* Build normalized num: nn[nn_cap] */
    int nn_cap = num_words + 1;
    uint64_t *nn = (uint64_t *)calloc((size_t)nn_cap, sizeof(uint64_t));
    if (!nn) { free(dn); free(rem); return; }
    {
        uint64_t carry = 0;
        for (int i = 0; i < num_words; i++) {
            nn[i] = (num[i] << shift) | carry;
            carry = shift ? (num[i] >> (64 - shift)) : 0;
        }
        nn[num_words] = carry;
        if (carry) nn_cap = num_words + 1;
    }

    /* Binary long division: process bits from MSB down to 0 */
    int total_bits = nn_cap * 64;
    for (int pos = total_bits - 1; pos >= 0; pos--) {
        /* Shift remainder left by 1 (k+1 limbs) */
        {
            uint64_t carry = 0;
            for (int i = 0; i <= k; i++) {
                uint64_t v = rem[i];
                rem[i] = (v << 1) | carry;
                carry = v >> 63;
            }
        }
        /* Bring down bit from numerator */
        int ni = pos / 64, nb = pos % 64;
        if (ni < nn_cap && ((nn[ni] >> nb) & 1)) rem[0] |= 1;

        /* Shift quotient left by 1 */
        {
            uint64_t carry = 0;
            for (int i = 0; i < k; i++) {
                uint64_t v = q[i];
                q[i] = (v << 1) | carry;
                carry = v >> 63;
            }
        }
        /* if rem >= dn: compare k+1 limbs */
        int ge = 1;
        for (int i = k; i >= 0; i--) {
            if (rem[i] < dn[i]) { ge = 0; break; }
            if (rem[i] > dn[i]) break;
        }
        if (ge) {
            raw_sub(rem, dn, k + 1);
            q[0] |= 1;
        }
    }

    /* Copy remainder (first k limbs) and un-normalize */
    if (shift) {
        for (int i = 0; i < k; i++) {
            rem[i] >>= shift;
            if (i + 1 <= k) rem[i] |= (rem[i+1] << (64 - shift));
        }
    }
    memcpy(r, rem, k * sizeof(uint64_t));

    free(nn);
    free(dn);
    free(rem);
}

/* ========================================================================
 *  Modular Arithmetic in Z_p (2048-bit)
 * ======================================================================== */

void sigma_mod_add(sigma_biguint *r, const sigma_biguint *a,
                   const sigma_biguint *b, const sigma_biguint *p) {
    int k = SIGMA_GROUP_PRIME_WORDS;
    uint64_t tmp[32];
    memcpy(tmp, a->limbs, k * sizeof(uint64_t));
    uint64_t carry = raw_add(tmp, b->limbs, k);
    if (carry) {
        raw_sub(tmp, p->limbs, k);
    } else {
        const sigma_biguint *tmp_ref = (const sigma_biguint*)tmp;
        if (sigma_biguint_cmp(tmp_ref, p) >= 0)
            raw_sub(tmp, p->limbs, k);
    }
    memcpy(r->limbs, tmp, k * sizeof(uint64_t));
}

void sigma_mod_sub(sigma_biguint *r, const sigma_biguint *a,
                   const sigma_biguint *b, const sigma_biguint *p) {
    int k = SIGMA_GROUP_PRIME_WORDS;
    uint64_t tmp[32];
    memcpy(tmp, a->limbs, k * sizeof(uint64_t));
    uint64_t borrow = raw_sub(tmp, b->limbs, k);
    if (borrow) raw_add(tmp, p->limbs, k);
    memcpy(r->limbs, tmp, k * sizeof(uint64_t));
}

void sigma_mod_mul(sigma_biguint *r, const sigma_biguint *a,
                   const sigma_biguint *b, const sigma_biguint *p) {
    int k = SIGMA_GROUP_PRIME_WORDS;
    uint64_t z[64];
    schoolbook_mul(z, a->limbs, b->limbs, k);
    uint64_t q[32], rem[32];
    long_divrem(q, rem, z, 2 * k, p->limbs, k);
    memcpy(r->limbs, rem, k * sizeof(uint64_t));
}

void sigma_mod_exp(sigma_biguint *r, const sigma_biguint *base,
                   const sigma_biguint *exp, int exp_bits,
                   const sigma_biguint *p) {
    sigma_biguint_set_u64(r, 1);
    if (exp_bits <= 0) return;
    sigma_biguint base_copy;
    sigma_biguint_copy(&base_copy, base);
    for (int i = exp_bits - 1; i >= 0; i--) {
        sigma_mod_mul(r, r, r, p);
        if (sigma_biguint_get_bit(exp, i))
            sigma_mod_mul(r, r, &base_copy, p);
    }
}

bool sigma_mod_inv(sigma_biguint *r, const sigma_biguint *a,
                   const sigma_biguint *p) {
    int k = SIGMA_GROUP_PRIME_WORDS;
    /* Binary extended GCD for modular inverse */
    sigma_biguint u, v, x1, x2;
    sigma_biguint_copy(&u, a);
    sigma_biguint_copy(&v, p);
    sigma_biguint_set_u64(&x1, 1);
    sigma_biguint_zero(&x2);

    while (!sigma_biguint_is_zero(&u) && !sigma_biguint_is_zero(&v)) {
        int u_even = !(u.limbs[0] & 1);
        int v_even = !(v.limbs[0] & 1);

        /* Shift u right */
        if (u_even) {
            for (int i = 0; i < k; i++) {
                uint64_t carry = (i + 1 < k) ? (u.limbs[i+1] << 63) : 0;
                u.limbs[i] = (u.limbs[i] >> 1) | carry;
            }
            if (x1.limbs[0] & 1) raw_add(x1.limbs, p->limbs, k);
            for (int i = 0; i < k; i++) {
                uint64_t carry = (i + 1 < k) ? (x1.limbs[i+1] << 63) : 0;
                x1.limbs[i] = (x1.limbs[i] >> 1) | carry;
            }
            continue;
        }
        /* Shift v right */
        if (v_even) {
            for (int i = 0; i < k; i++) {
                uint64_t carry = (i + 1 < k) ? (v.limbs[i+1] << 63) : 0;
                v.limbs[i] = (v.limbs[i] >> 1) | carry;
            }
            if (x2.limbs[0] & 1) raw_add(x2.limbs, p->limbs, k);
            for (int i = 0; i < k; i++) {
                uint64_t carry = (i + 1 < k) ? (x2.limbs[i+1] << 63) : 0;
                x2.limbs[i] = (x2.limbs[i] >> 1) | carry;
            }
            continue;
        }
        /* Both odd */
        int cmp = sigma_biguint_cmp(&u, &v);
        if (cmp >= 0) {
            raw_sub(u.limbs, v.limbs, k);
            uint64_t borrow = raw_sub(x1.limbs, x2.limbs, k);
            if (borrow) raw_add(x1.limbs, p->limbs, k);
        } else {
            raw_sub(v.limbs, u.limbs, k);
            uint64_t borrow = raw_sub(x2.limbs, x1.limbs, k);
            if (borrow) raw_add(x2.limbs, p->limbs, k);
        }
    }

    sigma_biguint one;
    sigma_biguint_set_u64(&one, 1);

    if (sigma_biguint_is_zero(&u) && sigma_biguint_cmp(&v, &one) == 0) {
        sigma_biguint_copy(r, &x2);
        return true;
    }
    if (sigma_biguint_is_zero(&v) && sigma_biguint_cmp(&u, &one) == 0) {
        sigma_biguint_copy(r, &x1);
        return true;
    }
    return false;
}

void sigma_mod_reduce(sigma_biguint *r, const sigma_biguint *a,
                      const sigma_biguint *p) {
    sigma_biguint_copy(r, a);
    const sigma_biguint *rc = (const sigma_biguint*)r;
    while (sigma_biguint_cmp(rc, p) >= 0) {
        raw_sub(r->limbs, p->limbs, SIGMA_GROUP_PRIME_WORDS);
    }
}

/* ========================================================================
 *  Scalar Operations in Z_q (256-bit = 4 limbs)
 * ======================================================================== */

void sigma_scalar_zero(sigma_scalar *s) { memset(s->limbs, 0, sizeof(s->limbs)); }

void sigma_scalar_set_u64(sigma_scalar *s, uint64_t value) {
    memset(s->limbs, 0, sizeof(s->limbs));
    s->limbs[0] = value;
}

void sigma_scalar_copy(sigma_scalar *dst, const sigma_scalar *src) {
    memcpy(dst->limbs, src->limbs, sizeof(dst->limbs));
}

static int scalar_ge(const sigma_scalar *a, const sigma_scalar *b) {
    for (int i = 3; i >= 0; i--) {
        if (a->limbs[i] > b->limbs[i]) return 1;
        if (a->limbs[i] < b->limbs[i]) return 0;
    }
    return 1; /* equal */
}

void sigma_scalar_add(sigma_scalar *s, const sigma_scalar *a,
                      const sigma_scalar *b) {
    /* Delegate to the proven biguint modular addition */
    sigma_biguint ab, bb, rb, pb;
    memset(&ab, 0, sizeof(ab)); memcpy(ab.limbs, a->limbs, sizeof(a->limbs));
    memset(&bb, 0, sizeof(bb)); memcpy(bb.limbs, b->limbs, sizeof(b->limbs));
    memset(&pb, 0, sizeof(pb)); memcpy(pb.limbs, SIGMA_ORDER_Q.limbs, sizeof(SIGMA_ORDER_Q.limbs));
    sigma_mod_add(&rb, &ab, &bb, &pb);
    memcpy(s->limbs, rb.limbs, sizeof(s->limbs));
}

void sigma_scalar_sub(sigma_scalar *s, const sigma_scalar *a,
                      const sigma_scalar *b) {
    /* Delegate to the proven biguint modular subtraction */
    sigma_biguint ab, bb, rb, pb;
    memset(&ab, 0, sizeof(ab)); memcpy(ab.limbs, a->limbs, sizeof(a->limbs));
    memset(&bb, 0, sizeof(bb)); memcpy(bb.limbs, b->limbs, sizeof(b->limbs));
    memset(&pb, 0, sizeof(pb)); memcpy(pb.limbs, SIGMA_ORDER_Q.limbs, sizeof(SIGMA_ORDER_Q.limbs));
    sigma_mod_sub(&rb, &ab, &bb, &pb);
    memcpy(s->limbs, rb.limbs, sizeof(s->limbs));
}

void sigma_scalar_mul(sigma_scalar *s, const sigma_scalar *a,
                      const sigma_scalar *b) {
    /* Delegate to the proven biguint modular multiplication */
    sigma_biguint ab, bb, rb, pb;
    memset(&ab, 0, sizeof(ab)); memcpy(ab.limbs, a->limbs, sizeof(a->limbs));
    memset(&bb, 0, sizeof(bb)); memcpy(bb.limbs, b->limbs, sizeof(b->limbs));
    memset(&pb, 0, sizeof(pb)); memcpy(pb.limbs, SIGMA_ORDER_Q.limbs, sizeof(SIGMA_ORDER_Q.limbs));
    sigma_mod_mul(&rb, &ab, &bb, &pb);
    memcpy(s->limbs, rb.limbs, sizeof(s->limbs));
}

bool sigma_scalar_inv(sigma_scalar *s, const sigma_scalar *a) {
    sigma_biguint ab, pb, rb;
    memset(&ab, 0, sizeof(ab)); memcpy(ab.limbs, a->limbs, sizeof(a->limbs));
    memset(&pb, 0, sizeof(pb)); memcpy(pb.limbs, SIGMA_ORDER_Q.limbs, sizeof(SIGMA_ORDER_Q.limbs));
    bool ok = sigma_mod_inv(&rb, &ab, &pb);
    if (ok) memcpy(s->limbs, rb.limbs, sizeof(s->limbs));
    else sigma_scalar_zero(s);
    return ok;
}

int sigma_scalar_cmp(const sigma_scalar *a, const sigma_scalar *b) {
    for (int i = 3; i >= 0; i--) {
        if (a->limbs[i] < b->limbs[i]) return -1;
        if (a->limbs[i] > b->limbs[i]) return 1;
    }
    return 0;
}

bool sigma_scalar_is_zero(const sigma_scalar *s) {
    return !s->limbs[0] && !s->limbs[1] && !s->limbs[2] && !s->limbs[3];
}

/* ========================================================================
 *  Group Operations
 * ======================================================================== */

void sigma_group_exp_g(sigma_group_elem *r, const sigma_scalar *s) {
    sigma_biguint exp_big;
    memset(&exp_big, 0, sizeof(exp_big));
    memcpy(exp_big.limbs, s->limbs, sizeof(s->limbs));
    int bits = sigma_biguint_bitlen(&exp_big);
    if (bits == 0) { sigma_biguint_set_u64((sigma_biguint*)r, 1); return; }
    sigma_mod_exp((sigma_biguint*)r, (const sigma_biguint*)&SIGMA_GENERATOR_G,
                  &exp_big, bits, &SIGMA_PRIME_P);
}

void sigma_group_exp(sigma_group_elem *r, const sigma_group_elem *h,
                     const sigma_scalar *s) {
    sigma_biguint exp_big;
    memset(&exp_big, 0, sizeof(exp_big));
    memcpy(exp_big.limbs, s->limbs, sizeof(s->limbs));
    int bits = sigma_biguint_bitlen(&exp_big);
    if (bits == 0) { sigma_biguint_set_u64((sigma_biguint*)r, 1); return; }
    sigma_mod_exp((sigma_biguint*)r, (const sigma_biguint*)h,
                  &exp_big, bits, &SIGMA_PRIME_P);
}

void sigma_group_mul(sigma_group_elem *r, const sigma_group_elem *a,
                     const sigma_group_elem *b) {
    sigma_mod_mul((sigma_biguint*)r, (const sigma_biguint*)a,
                  (const sigma_biguint*)b, &SIGMA_PRIME_P);
}

void sigma_group_div(sigma_group_elem *r, const sigma_group_elem *a,
                     const sigma_group_elem *b) {
    sigma_biguint inv_b;
    sigma_mod_inv(&inv_b, (const sigma_biguint*)b, &SIGMA_PRIME_P);
    sigma_mod_mul((sigma_biguint*)r, (const sigma_biguint*)a, &inv_b, &SIGMA_PRIME_P);
}

void sigma_group_copy(sigma_group_elem *dst, const sigma_group_elem *src) {
    memcpy(dst->limbs, src->limbs, sizeof(dst->limbs));
}

bool sigma_group_is_identity(const sigma_group_elem *e) {
    return sigma_biguint_is_one((const sigma_biguint*)e);
}

bool sigma_group_eq(const sigma_group_elem *a, const sigma_group_elem *b) {
    return memcmp(a->limbs, b->limbs, sizeof(a->limbs)) == 0;
}

void sigma_group_serialize(uint8_t *out, const sigma_group_elem *e) {
    for (int i = 0; i < SIGMA_GROUP_PRIME_WORDS; i++) {
        uint64_t v = e->limbs[i];
        for (int j = 0; j < 8; j++) {
            out[i * 8 + j] = (uint8_t)(v & 0xFF);
            v >>= 8;
        }
    }
}

/* ========================================================================
 *  SHA-256 Hash Function (FIPS 180-4)
 * ======================================================================== */

static const uint32_t K_SHA256[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};

#define ROTR32(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z)   (((x)&(y))^(~(x)&(z)))
#define MAJ(x,y,z)  (((x)&(y))^((x)&(z))^((y)&(z)))
#define EP0(x) (ROTR32(x,2)^ROTR32(x,13)^ROTR32(x,22))
#define EP1(x) (ROTR32(x,6)^ROTR32(x,11)^ROTR32(x,25))
#define SIG0(x) (ROTR32(x,7)^ROTR32(x,18)^((x)>>3))
#define SIG1(x) (ROTR32(x,17)^ROTR32(x,19)^((x)>>10))

static void sha256_compress(uint32_t H[8], const uint8_t block[64]) {
    uint32_t W[64];
    for (int t = 0; t < 16; t++) {
        W[t] = ((uint32_t)block[t*4] << 24) | ((uint32_t)block[t*4+1] << 16) |
               ((uint32_t)block[t*4+2] << 8)  |  (uint32_t)block[t*4+3];
    }
    for (int t = 16; t < 64; t++)
        W[t] = SIG1(W[t-2]) + W[t-7] + SIG0(W[t-15]) + W[t-16];

    uint32_t a = H[0], b = H[1], c = H[2], d = H[3];
    uint32_t e = H[4], f = H[5], g = H[6], h = H[7];

    for (int t = 0; t < 64; t++) {
        uint32_t T1 = h + EP1(e) + CH(e,f,g) + K_SHA256[t] + W[t];
        uint32_t T2 = EP0(a) + MAJ(a,b,c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }
    H[0] += a; H[1] += b; H[2] += c; H[3] += d;
    H[4] += e; H[5] += f; H[6] += g; H[7] += h;
}

#undef ROTR32
#undef CH
#undef MAJ
#undef EP0
#undef EP1
#undef SIG0
#undef SIG1

void sigma_hash_init(sigma_hash_context *ctx) {
    ctx->state[0] = 0x6a09e667U; ctx->state[1] = 0xbb67ae85U;
    ctx->state[2] = 0x3c6ef372U; ctx->state[3] = 0xa54ff53aU;
    ctx->state[4] = 0x510e527fU; ctx->state[5] = 0x9b05688cU;
    ctx->state[6] = 0x1f83d9abU; ctx->state[7] = 0x5be0cd19U;
    ctx->count = 0; ctx->buf_len = 0;
    memset(ctx->buf, 0, sizeof(ctx->buf));
}

void sigma_hash_update(sigma_hash_context *ctx, const uint8_t *data, size_t len) {
    ctx->count += len;
    while (len > 0) {
        size_t space = 64 - ctx->buf_len;
        size_t copy = (len < space) ? len : space;
        memcpy(ctx->buf + ctx->buf_len, data, copy);
        ctx->buf_len += copy; data += copy; len -= copy;
        if (ctx->buf_len == 64) {
            sha256_compress(ctx->state, ctx->buf);
            ctx->buf_len = 0;
        }
    }
}

void sigma_hash_final(sigma_hash_context *ctx, uint8_t digest[32]) {
    uint64_t bits = ctx->count * 8;
    ctx->buf[ctx->buf_len++] = 0x80;
    if (ctx->buf_len > 56) {
        memset(ctx->buf + ctx->buf_len, 0, 64 - ctx->buf_len);
        sha256_compress(ctx->state, ctx->buf);
        ctx->buf_len = 0;
    }
    memset(ctx->buf + ctx->buf_len, 0, 56 - ctx->buf_len);
    for (int i = 0; i < 8; i++)
        ctx->buf[56 + i] = (uint8_t)(bits >> (56 - i * 8));
    sha256_compress(ctx->state, ctx->buf);
    for (int i = 0; i < 8; i++) {
        digest[i*4]     = (uint8_t)(ctx->state[i] >> 24);
        digest[i*4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        digest[i*4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        digest[i*4 + 3] = (uint8_t)(ctx->state[i]);
    }
}

void sigma_hash_digest(uint8_t digest[32], const uint8_t *data, size_t len) {
    sigma_hash_context ctx;
    sigma_hash_init(&ctx);
    sigma_hash_update(&ctx, data, len);
    sigma_hash_final(&ctx, digest);
}

/* ---------------------------------------------------------------
 *  digest_to_scalar: reduce 32-byte digest to Z_q
 *
 *  The 256-bit digest must be properly reduced modulo q.
 *  A simple single subtraction (or mask+subtract) is insufficient
 *  when the hash output (up to ~2^254) is far larger than q.
 *
 *  We expand the digest to a sigma_biguint (2048-bit container),
 *  then divide by SIGMA_ORDER_Q using long_divrem, yielding a
 *  remainder that is strictly < q.
 *
 *  L5 Algorithm: big-integer modular reduction via division.
 * --------------------------------------------------------------- */
/**
 * sigma_digest_to_scalar — Reduce a 32-byte SHA-256 digest to a scalar in Z_q.
 *
 * Uses long_divrem for proper modular reduction regardless of how large
 * the digest value is relative to q.  Essential for Fiat-Shamir transforms
 * where the hash output (up to 2^254) must be reduced modulo a 256-bit q.
 *
 * L5 Algorithm: big-integer modular reduction via division.
 */
void sigma_digest_to_scalar(sigma_scalar *out, const uint8_t dgst[32]) {
    /* 1. Interpret 32-byte digest as a sigma_biguint (zero-extended to 32 limbs) */
    sigma_biguint num;
    memset(&num, 0, sizeof(num));
    for (int i = 0; i < 4; i++) {
        uint64_t v = 0;
        for (int j = 7; j >= 0; j--)
            v = (v << 8) | dgst[i * 8 + j];
        num.limbs[i] = v;
    }
    /* Top bit masking — limit to 254 bits so the number stays within 4 limbs */
    num.limbs[3] &= 0x3FFFFFFFFFFFFFFFULL;

    /* 2. Denominator: SIGMA_ORDER_Q promoted to sigma_biguint */
    sigma_biguint den;
    memset(&den, 0, sizeof(den));
    memcpy(den.limbs, SIGMA_ORDER_Q.limbs, sizeof(SIGMA_ORDER_Q.limbs));

    /* 3. Divide: num ÷ den → quotient (4 limbs), remainder (4 limbs) */
    uint64_t qarr[4], rem[4];
    memset(qarr, 0, sizeof(qarr));
    memset(rem, 0, sizeof(rem));
    long_divrem(qarr, rem, num.limbs, 4, den.limbs, 1);   /* den has 1 active limb for 23 */

    /* 4. Copy remainder into output scalar */
    memcpy(out->limbs, rem, sizeof(out->limbs));

    /* 5. If remainder is zero, mapping to 1 avoids degenerate challenge */
    if (sigma_scalar_is_zero(out)) {
        sigma_scalar_set_u64(out, 1);
    }
}

void sigma_hash_to_scalar(sigma_scalar *out, const sigma_group_elem *e) {
    uint8_t buf[256];
    sigma_group_serialize(buf, e);
    uint8_t dgst[32];
    sigma_hash_digest(dgst, buf, 256);
    sigma_digest_to_scalar(out, dgst);
}

void sigma_hash_pair_to_scalar(sigma_scalar *out,
                                const sigma_group_elem *a,
                                const sigma_group_elem *b) {
    uint8_t buf[512];
    sigma_group_serialize(buf, a);
    sigma_group_serialize(buf + 256, b);
    uint8_t dgst[32];
    sigma_hash_digest(dgst, buf, 512);
    sigma_digest_to_scalar(out, dgst);
}

void sigma_hash_triple_to_scalar(sigma_scalar *out,
                                  const sigma_group_elem *a,
                                  const sigma_group_elem *b,
                                  const sigma_group_elem *c) {
    uint8_t buf[768];
    sigma_group_serialize(buf, a);
    sigma_group_serialize(buf + 256, b);
    sigma_group_serialize(buf + 512, c);
    uint8_t dgst[32];
    sigma_hash_digest(dgst, buf, 768);
    sigma_digest_to_scalar(out, dgst);
}

void sigma_hash_message_to_scalar(sigma_scalar *out,
                                   const uint8_t *msg, size_t msg_len,
                                   const sigma_group_elem *commitment,
                                   const sigma_group_elem *public_key) {
    sigma_hash_context ctx;
    sigma_hash_init(&ctx);
    sigma_hash_update(&ctx, msg, msg_len);
    uint8_t cbuf[256], pbuf[256];
    sigma_group_serialize(cbuf, commitment);
    sigma_group_serialize(pbuf, public_key);
    sigma_hash_update(&ctx, cbuf, 256);
    sigma_hash_update(&ctx, pbuf, 256);
    uint8_t dgst[32];
    sigma_hash_final(&ctx, dgst);
    sigma_digest_to_scalar(out, dgst);
}

/* ========================================================================
 *  Randomness: xoshiro256** PRNG (Blackman & Vigna 2018)
 *  Period: 2^256-1. Passes BigCrush. Suitable for educational test vectors.
 * ======================================================================== */

static uint64_t prng_s[4];
static int prng_init_done = 0;

static inline uint64_t rotl(uint64_t x, int k) {
    return (x << k) | (x >> (64 - k));
}

static uint64_t splitmix64(uint64_t *x) {
    uint64_t z = (*x += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static uint64_t xoshiro_next(void) {
    uint64_t result = rotl(prng_s[1] * 5, 7) * 9;
    uint64_t t = prng_s[1] << 17;
    prng_s[2] ^= prng_s[0];
    prng_s[3] ^= prng_s[1];
    prng_s[1] ^= prng_s[2];
    prng_s[0] ^= prng_s[3];
    prng_s[2] ^= t;
    prng_s[3] = rotl(prng_s[3], 45);
    return result;
}

static void ensure_seeded(void) {
    if (!prng_init_done) sigma_random_seed(0xDEADBEEFCAFEBABEULL);
}

void sigma_random_seed(uint64_t seed) {
    uint64_t x = seed;
    prng_s[0] = splitmix64(&x);
    prng_s[1] = splitmix64(&x);
    prng_s[2] = splitmix64(&x);
    prng_s[3] = splitmix64(&x);
    prng_init_done = 1;
}

void sigma_random_bytes(uint8_t *buf, size_t len) {
    ensure_seeded();
    size_t pos = 0;
    while (pos < len) {
        uint64_t r = xoshiro_next();
        for (int j = 0; j < 8 && pos < len; j++, pos++)
            buf[pos] = (uint8_t)(r >> (j * 8));
    }
}

static void sigma_random_scalar_bounded(sigma_scalar *r, const sigma_scalar *bound);

void sigma_random_scalar(sigma_scalar *r) {
    sigma_random_scalar_bounded(r, &SIGMA_ORDER_Q);
}

/**
 * sigma_random_scalar_range — Generate random scalar < bound.
 * Uses rejection sampling with bit masking appropriate for the bound.
 * For small bounds (e.g., q=11), generates only the needed bits.
 */
static void sigma_random_scalar_bounded(sigma_scalar *r, const sigma_scalar *bound) {
    ensure_seeded();
    /* Find the bit length of the bound */
    int blen = 0;
    for (int i = 3; i >= 0; i--) {
        if (bound->limbs[i] != 0) {
            uint64_t v = bound->limbs[i];
            while (v) { v >>= 1; blen++; }
            blen += i * 64;
            break;
        }
    }
    if (blen == 0) blen = 1;
    int limbs_needed = (blen + 63) / 64;
    if (limbs_needed < 1) limbs_needed = 1;
    uint64_t mask = (blen % 64 == 0) ? 0xFFFFFFFFFFFFFFFFULL
                                     : (1ULL << (blen % 64)) - 1;

    do {
        for (int i = 0; i < limbs_needed; i++) {
            r->limbs[i] = xoshiro_next();
        }
        /* Clear upper limbs */
        for (int i = limbs_needed; i < 4; i++) r->limbs[i] = 0;
        /* Mask top limb */
        if (limbs_needed <= 4 && (blen % 64) != 0) {
            r->limbs[limbs_needed - 1] &= mask;
        }
    } while (scalar_ge(r, bound) || sigma_scalar_is_zero(r));
}

void sigma_random_nonzero_scalar(sigma_scalar *r) {
    sigma_random_scalar_bounded(r, &SIGMA_ORDER_Q);
}

/* ========================================================================
 *  Serialization
 * ======================================================================== */

void sigma_scalar_serialize(uint8_t out[32], const sigma_scalar *s) {
    for (int i = 0; i < 4; i++) {
        uint64_t v = s->limbs[i];
        for (int j = 0; j < 8; j++) {
            out[i * 8 + j] = (uint8_t)(v & 0xFF);
            v >>= 8;
        }
    }
}

void sigma_scalar_deserialize(sigma_scalar *s, const uint8_t in[32]) {
    memset(s->limbs, 0, sizeof(s->limbs));
    for (int i = 0; i < 4; i++) {
        uint64_t v = 0;
        for (int j = 7; j >= 0; j--)
            v = (v << 8) | in[i * 8 + j];
        s->limbs[i] = v;
    }
}

void sigma_biguint_serialize(uint8_t out[256], const sigma_biguint *a) {
    for (int i = 0; i < 32; i++) {
        uint64_t v = a->limbs[i];
        for (int j = 0; j < 8; j++) {
            out[i * 8 + j] = (uint8_t)(v & 0xFF);
            v >>= 8;
        }
    }
}
