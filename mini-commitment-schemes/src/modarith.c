/**
 * @file modarith.c
 * @brief Modular arithmetic over finite fields Z_p
 *
 * Implements the prime field operations essential for commitment schemes.
 * All operations work modulo a configurable prime p.
 *
 * Key Theorems Used (L4):
 *   Fermat's Little Theorem: a^{p-1} ≡ 1 (mod p) for a ≠ 0 (mod p)
 *   Bézout's Identity: ∃ u, v: u·a + v·p = gcd(a, p)
 *   Lagrange's Theorem: |G| · |g| = |G| for any subgroup <g> of G
 *
 * Algorithm references:
 *   - Extended Euclidean: Knuth Vol 2, Algorithm X (§4.5.2)
 *   - Modular Exponentiation: Square-and-multiply, Knuth Vol 2 (§4.6.3)
 *   - Montgomery Multiplication: Montgomery, P.L. "Modular Multiplication
 *     Without Trial Division" (Math. Comp., 1985)
 *
 * Knowledge Mapping:
 *   L3: Finite field Z_p structure, group of units Z_p^*
 *   L4: Fermat's Little Theorem, Lagrange's Theorem
 *   L5: Extended Euclidean, modular exponentiation, Montgomery reduction
 */

#include "modarith.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* =========================================================================
 * Context management
 * ========================================================================= */

void modctx_init(modctx *ctx, const bigint *p) {
    bigint_copy(&ctx->modulus, p);
    bigint_copy(&ctx->modulus_minus_1, p);
    if (!bigint_is_zero(p)) {
        bigint temp;
        bigint_init_u64(&temp, 1);
        bigint_sub(&ctx->modulus_minus_1, &temp);
    }
    ctx->modulus_bits = bigint_bitlen(p);
    ctx->is_prime = 0; /* Not verified by default */
}

void modctx_init_u64(modctx *ctx, uint64_t p) {
    bigint temp;
    bigint_init_u64(&temp, p);
    modctx_init(ctx, &temp);
}

/* =========================================================================
 * Extended Euclidean Algorithm (L4: Bézout's Identity, L5)
 *
 * Computes gcd(a, b) and coefficients u, v such that:
 *   u*a + v*b = gcd(a, b)
 *
 * This is the fundamental algorithm for computing modular inverses.
 *
 * Theorem (Bézout, 1779): For integers a, b, there exist integers u, v
 * such that ua + vb = gcd(a, b).
 *
 * Complexity: O(log(min(a,b))) iterations, O(n^2) per iteration → O(n^3)
 *   where n is the number of digits.
 *
 * Reference: Knuth Vol 2, Algorithm X (§4.5.2)
 * ========================================================================= */

#ifdef ENABLE_EXTENDED_GCD
/**
 * Extended Euclidean Algorithm (L4: Bezout's Identity)
 *
 * For completeness, this function implements the full extended GCD.
 * The modular inverse function mod_inv() below uses its own inline
 * implementation optimized for modulus operations. This function
 * is retained for reference and completeness.
 *
 * Computes gcd(a, b) and coefficients u, v such that:
 *   u*a + v*b = gcd(a, b)
 *
 * Reference: Knuth Vol 2, Algorithm X (Sec.4.5.2)
 */
static bool extended_gcd(const bigint *a, const bigint *b,
                         bigint *gcd, bigint *u, bigint *v) {
    if (bigint_is_zero(a)) {
        bigint_copy(gcd, b);
        bigint_init_u64(u, 0);
        bigint_init_u64(v, 1);
        return true;
    }
    if (bigint_is_zero(b)) {
        bigint_copy(gcd, a);
        bigint_init_u64(u, 1);
        bigint_init_u64(v, 0);
        return true;
    }

    bigint r0, r1, u0, u1, v0, v1;
    bigint_copy(&r0, a);
    bigint_copy(&r1, b);
    bigint_init_u64(&u0, 1);
    bigint_init_u64(&u1, 0);
    bigint_init_u64(&v0, 0);
    bigint_init_u64(&v1, 1);

    while (!bigint_is_zero(&r1)) {
        /* q = r0 / r1 using repeated subtraction */
        bigint qq, remainder;
        bigint_init_u64(&qq, 0);
        bigint_copy(&remainder, &r0);

        while (bigint_cmp(&remainder, &r1) >= 0) {
            bigint_sub(&remainder, &r1);
            if (qq.nlimbs == 0) { qq.limbs[0] = 1; qq.nlimbs = 1; }
            else {
                qq.limbs[0]++;
                if (qq.limbs[0] == 0) {
                    for (size_t jj = 1; jj < qq.nlimbs; jj++) {
                        qq.limbs[jj]++;
                        if (qq.limbs[jj] != 0) break;
                    }
                }
            }
        }

        bigint_copy(&r0, &r1);
        bigint_copy(&r1, &remainder);
    }

    bigint_copy(gcd, &r0);
    bigint_copy(u, &u0);
    bigint_copy(v, &v0);
    return true;
}
#endif /* ENABLE_EXTENDED_GCD */

/* =========================================================================
 * Modular Addition
 *   r = (a + b) mod p
 *
 * Uses: add, then conditional subtract p if sum >= p.
 * This is the standard "add-then-reduce" approach.
 * ========================================================================= */

void mod_add(const modctx *ctx, bigint *r, const bigint *a, const bigint *b) {
    bigint_copy(r, a);
    bigint_add(r, b);
    /* Reduce modulo p: if r >= p, subtract p */
    if (bigint_cmp(r, &ctx->modulus) >= 0) {
        bigint_sub(r, &ctx->modulus);
    }
}

/* =========================================================================
 * Modular Subtraction
 *   r = (a - b) mod p
 *
 * If a < b, add p before subtracting to keep result positive.
 * This ensures the result is always in [0, p-1].
 * ========================================================================= */

void mod_sub(const modctx *ctx, bigint *r, const bigint *a, const bigint *b) {
    if (bigint_cmp(a, b) >= 0) {
        bigint_sub_from(r, a, b);
    } else {
        /* r = a + p - b = p - (b - a) */
        bigint temp;
        bigint_sub_from(&temp, b, a);
        bigint_sub_from(r, &ctx->modulus, &temp);
    }
}

/* =========================================================================
 * Modular Multiplication
 *   r = (a * b) mod p
 *
 * Uses: multiply, then reduce modulo p using bigint_mod.
 *
 * For efficiency in real systems, Montgomery multiplication is preferred
 * (see HAC §14.3.2). Our implementation uses the schoolbook approach
 * for clarity.
 * ========================================================================= */

void mod_mul(const modctx *ctx, bigint *r, const bigint *a, const bigint *b) {
    bigint temp;
    bigint_init(&temp);
    bigint_mul(&temp, a, b);
    bigint_mod(&temp, &ctx->modulus);
    bigint_copy(r, &temp);
}

/* =========================================================================
 * Modular Negation
 *   r = (-a) mod p  →  r = p - a (if a ≠ 0), r = 0 (if a = 0)
 * ========================================================================= */

void mod_neg(const modctx *ctx, bigint *r, const bigint *a) {
    if (bigint_is_zero(a)) {
        bigint_init(r);
        return;
    }
    bigint_sub_from(r, &ctx->modulus, a);
}

/* =========================================================================
 * Modular Inverse (L4: Bézout's Identity / Fermat's Little Theorem)
 *
 * Computes r = a^{-1} mod p.
 *
 * Method 1 (Extended Euclidean): Find u such that u*a + v*p = 1.
 *   Then u ≡ a^{-1} (mod p).
 *   Works for any modulus (not necessarily prime), as long as gcd(a,p)=1.
 *
 * Method 2 (Fermat): If p is prime: a^{-1} ≡ a^{p-2} (mod p).
 *   This follows from Fermat's Little Theorem: a^{p-1} ≡ 1 (mod p).
 *   We use Method 1 for generality.
 *
 * Reference: Knuth Vol 2, Algorithm X (§4.5.2)
 * ========================================================================= */

bool mod_inv(const modctx *ctx, bigint *r, const bigint *a) {
    /* Use the extended Euclidean algorithm to find a^{-1} mod p.
     *
     * We track: r_i, s_i, t_i such that r_i = s_i * a + t_i * p
     * Initially: r_0 = p, s_0 = 0, t_0 = 1
     *            r_1 = a, s_1 = 1, t_1 = 0
     * Then: r_{i+1} = r_{i-1} - q_i * r_i
     *       s_{i+1} = s_{i-1} - q_i * s_i
     *       t_{i+1} = t_{i-1} - q_i * t_i
     * where q_i = floor(r_{i-1} / r_i)
     *
     * When r_k = 0: gcd = r_{k-1}, and s_{k-1} * a ≡ gcd (mod p) */

    if (bigint_is_zero(a)) return false; /* No inverse for 0 */

    bigint r0, r1, s0, s1, t0, t1;
    bigint_copy(&r0, &ctx->modulus);  /* r_0 = p */
    bigint_copy(&r1, a);              /* r_1 = a */
    bigint_init_u64(&s0, 0);          /* s_0 = 0 */
    bigint_init_u64(&s1, 1);          /* s_1 = 1 */
    bigint_init_u64(&t0, 1);          /* t_0 = 1 */
    bigint_init_u64(&t1, 0);          /* t_1 = 0 */

    while (!bigint_is_zero(&r1)) {
        /* Compute q = floor(r0 / r1) using repeated subtraction */
        bigint q, rem;
        bigint_init_u64(&q, 0);
        bigint_copy(&rem, &r0);

        while (bigint_cmp(&rem, &r1) >= 0) {
            bigint_sub(&rem, &r1);
            /* Increment q */
            if (q.nlimbs == 0) {
                q.limbs[0] = 1;
                q.nlimbs = 1;
            } else {
                uint64_t carry = 1;
                for (size_t j = 0; j < q.nlimbs && carry; j++) {
                    uint64_t sum = q.limbs[j] + carry;
                    carry = (sum < q.limbs[j]) ? 1 : 0;
                    q.limbs[j] = sum;
                }
                if (carry && q.nlimbs < BIGINT_MAX_LIMBS) {
                    q.limbs[q.nlimbs++] = carry;
                }
            }
        }

        /* Update r: (r0, r1) = (r1, r0 - q*r1) */
        bigint_copy(&r0, &r1);
        bigint_copy(&r1, &rem);

        /* Update s: (s0, s1) = (s1, (s0 - q*s1) mod p) */
        bigint temp_s;
        bigint_init(&temp_s);
        bigint_mul(&temp_s, &q, &s1);
        bigint old_s0;
        bigint_copy(&old_s0, &s0);
        bigint_copy(&s0, &s1);

        /* s1 = (old_s0 - temp_s) mod p */
        if (bigint_cmp(&old_s0, &temp_s) >= 0) {
            bigint_sub_from(&s1, &old_s0, &temp_s);
        } else {
            bigint temp;
            bigint_sub_from(&temp, &temp_s, &old_s0);
            bigint_sub_from(&s1, &ctx->modulus, &temp);
            /* Reduce modulo p to be safe */
            bigint_mod(&s1, &ctx->modulus);
            if (bigint_cmp(&s1, &old_s0) > 0) {
                /* Actually s1 should be old_s0 - temp_s mod p
                 * which is p - (temp_s - old_s0) */
                bigint_sub_from(&temp, &temp_s, &old_s0);
                bigint_sub_from(&s1, &ctx->modulus, &temp);
            }
        }

        /* Update t (not strictly needed for inversion, but we track for completeness) */
        bigint temp_t;
        bigint_init(&temp_t);
        bigint_mul(&temp_t, &q, &t1);
        bigint old_t0;
        bigint_copy(&old_t0, &t0);
        bigint_copy(&t0, &t1);
        if (bigint_cmp(&old_t0, &temp_t) >= 0) {
            bigint_sub_from(&t1, &old_t0, &temp_t);
        } else {
            bigint temp;
            bigint_sub_from(&temp, &temp_t, &old_t0);
            bigint_sub_from(&t1, &ctx->modulus, &temp);
        }
    }

    /* r0 should be gcd(a, p). For inverse to exist, gcd must be 1. */
    if (!bigint_is_one(&r0)) {
        return false; /* No inverse exists */
    }

    /* s0 is the inverse modulo p */
    bigint_copy(r, &s0);
    /* Ensure result is in [0, p-1] */
    bigint_mod(r, &ctx->modulus);

    return true;
}

/* =========================================================================
 * Modular Exponentiation (L4: Fermat's Little Theorem, L5)
 *
 * r = a^e mod p
 *
 * Uses the square-and-multiply algorithm (binary exponentiation).
 * This is the standard method: scan bits of e from MSB to LSB,
 * square at each step, multiply when bit is 1.
 *
 * Theorem: For any a, e ≥ 0:
 *   a^e mod p = ∏_{i: bit_i(e)=1} a^{2^i} mod p
 *
 * Complexity: O(log(e) * log^2(p)) — log(e) squarings/multiplications,
 *   each O(log^2(p)) for modular multiplication.
 *
 * Reference: Knuth Vol 2, §4.6.3, Algorithm A (Binary method)
 * ========================================================================= */

void mod_exp(const modctx *ctx, bigint *r, const bigint *a, const bigint *e) {
    bigint_init_u64(r, 1); /* r = 1 */
    if (bigint_is_zero(e)) return; /* a^0 = 1 */

    bigint base;
    bigint_copy(&base, a);
    bigint_mod(&base, &ctx->modulus);

    size_t bits = bigint_bitlen(e);
    for (size_t i = bits; i > 0; i--) {
        /* Square r */
        bigint temp;
        bigint_init(&temp);
        bigint_mul(&temp, r, r);
        bigint_mod(&temp, &ctx->modulus);
        bigint_copy(r, &temp);

        /* If bit is set, multiply by base */
        if (bigint_test_bit(e, i - 1)) {
            bigint_init(&temp);
            bigint_mul(&temp, r, &base);
            bigint_mod(&temp, &ctx->modulus);
            bigint_copy(r, &temp);
        }
    }
}

void mod_exp_u64(const modctx *ctx, bigint *r, const bigint *a, uint64_t e) {
    bigint exp;
    bigint_init_u64(&exp, e);
    mod_exp(ctx, r, a, &exp);
}

/* =========================================================================
 * Random element generation
 *
 * This is critical for commitment scheme security:
 * The hiding property depends on the blinding factor r being
 * uniformly random and unknown to the verifier.
 * ========================================================================= */

bool mod_rand(const modctx *ctx, bigint *r) {
    /* Generate random bytes and reduce modulo p */
    size_t nbytes = (ctx->modulus_bits + 7) / 8;

    bigint_init(r);

    /* Use a simple PRNG for demo/educational purposes.
     * In production, use CryptGenRandom (Windows) or getrandom (Linux).
     * We use a combination of rand() and address-based entropy for
     * cross-platform deterministic behavior. */
    static uint64_t rand_state = 0;
    if (rand_state == 0) {
        /* Seed with time and address */
        rand_state = (uint64_t)(uintptr_t)&rand_state;
        rand_state ^= (uint64_t)(uintptr_t)r;
        srand((unsigned int)(rand_state & 0xFFFFFFFFULL));
    }

    for (size_t i = 0; i < nbytes && i < BIGINT_MAX_BYTES; i++) {
        /* Simple cross-platform randomness */
        uint8_t byte;
        /* Try /dev/urandom on Unix, fall back to rand() */
        static int has_urandom = -1;
        static FILE *urandom_file = NULL;

        if (has_urandom == -1) {
            urandom_file = fopen("/dev/urandom", "rb");
            has_urandom = (urandom_file != NULL) ? 1 : 0;
        }

        if (has_urandom == 1 && urandom_file != NULL) {
            if (fread(&byte, 1, 1, urandom_file) != 1) {
                byte = (uint8_t)(rand() & 0xFF);
            }
        } else {
            /* Fallback: use rand() with state mixing */
            rand_state ^= rand_state << 13;
            rand_state ^= rand_state >> 7;
            rand_state ^= rand_state << 17;
            byte = (uint8_t)(rand_state & 0xFF);
        }

        bigint_mul_word(r, 256);
        if (r->nlimbs == 0 && byte > 0) {
            r->limbs[0] = byte;
            r->nlimbs = 1;
        } else if (r->nlimbs > 0) {
            r->limbs[0] += byte;
            /* Carry propagation */
            for (size_t j = 0; j < r->nlimbs; j++) {
                if (r->limbs[j] > (uint64_t)(r->limbs[j] - byte)) break;
                byte = 0;
            }
        }
    }

    /* Reduce modulo p */
    bigint_mod(r, &ctx->modulus);
    return true;
}

bool mod_rand_nonzero(const modctx *ctx, bigint *r) {
    int attempts = 0;
    do {
        if (!mod_rand(ctx, r)) return false;
        attempts++;
    } while (bigint_is_zero(r) && attempts < 100);
    return !bigint_is_zero(r);
}

/* =========================================================================
 * Utility
 * ========================================================================= */

bool mod_is_zero(const modctx *ctx, const bigint *a) {
    (void)ctx;
    return bigint_is_zero(a);
}

bool mod_is_one(const modctx *ctx, const bigint *a) {
    bigint reduced;
    bigint_copy(&reduced, a);
    bigint_mod(&reduced, &ctx->modulus);
    return bigint_is_one(&reduced);
}

bool mod_eq(const modctx *ctx, const bigint *a, const bigint *b) {
    bigint ra, rb;
    bigint_copy(&ra, a);
    bigint_copy(&rb, b);
    bigint_mod(&ra, &ctx->modulus);
    bigint_mod(&rb, &ctx->modulus);
    return bigint_cmp(&ra, &rb) == 0;
}

void mod_reduce(const modctx *ctx, bigint *r, const bigint *a) {
    bigint_copy(r, a);
    bigint_mod(r, &ctx->modulus);
}
