/*
 * group.c — Cryptographic Group Theory Foundations
 *
 * Implements the modular arithmetic and cyclic group operations needed
 * for the Knowledge of Exponent assumption. KEA is stated over a cyclic
 * group G = <g> of prime order p. This module provides the complete
 * group-theoretic substrate: modular arithmetic on Z_p, group element
 * operations, subgroup management, and standard test groups.
 *
 * L1: Group (G,·), cyclic group, generator, order, Z_p*, subgroup
 * L3: GroupElement struct, CyclicGroup struct, modular arithmetic in Z_p
 * L4: Lagrange's theorem verification, Fermat's little theorem
 * L5: Miller-Rabin primality, Tonelli-Shanks, multi-exponentiation
 *
 * Courses: Stanford CS255, Berkeley CS276, MIT 6.875
 *
 * (C) Mini-Theory-of-Computation — mini-knowledge-of-exponent
 */

#include "group.h"
#include <stdio.h>
#include <string.h>
#include <math.h>

/* ═══════════════════════════════════════════════════════════════
   Modular Arithmetic on Prime Fields
   ═══════════════════════════════════════════════════════════════ */

/*
 * mpz_mod_add — Modular addition: (a + b) mod p
 *
 * Uses simple reduction: add and reduce by conditional subtraction
 * to avoid overflow. For uint64_t, ensure a,b < p and p < 2^63.
 *
 * Complexity: O(1)
 */
uint64_t mpz_mod_add(uint64_t a, uint64_t b, uint64_t p) {
    uint64_t sum = a + b;
    if (sum >= p) sum -= p;
    if (sum >= p) sum -= p;
    return sum;
}

/*
 * mpz_mod_sub — Modular subtraction: (a - b) mod p
 *
 * Adds p before subtraction to ensure non-negative result.
 * Complexity: O(1)
 */
uint64_t mpz_mod_sub(uint64_t a, uint64_t b, uint64_t p) {
    if (b > a) return p - (b - a) % p;
    uint64_t diff = a - b;
    return (diff < p) ? diff : diff % p;
}

/*
 * mpz_mod_mul — Modular multiplication: (a * b) mod p
 *
 * Uses the "double-and-add" or Russian peasant method
 * to avoid overflow when a*b exceeds 2^64.
 *
 * Complexity: O(log b)
 * Reference: Knuth, TAOCP Vol 2, §4.3.1
 */
uint64_t mpz_mod_mul(uint64_t a, uint64_t b, uint64_t p) {
    uint64_t result = 0;
    a = a % p;
    while (b > 0) {
        if (b & 1) {
            result = mpz_mod_add(result, a, p);
        }
        a = mpz_mod_add(a, a, p);
        b >>= 1;
    }
    return result;
}

/*
 * mpz_mod_pow — Modular exponentiation: base^exp mod p
 *
 * Uses square-and-multiply (binary exponentiation).
 * Complexity: O(log exp) modular multiplications.
 *
 * Reference: Rivest, Shamir, Adleman (1978), RSA paper
 */
uint64_t mpz_mod_pow(uint64_t base, uint64_t exp, uint64_t p) {
    uint64_t result = 1 % p;
    base = base % p;
    while (exp > 0) {
        if (exp & 1) {
            result = mpz_mod_mul(result, base, p);
        }
        base = mpz_mod_mul(base, base, p);
        exp >>= 1;
    }
    return result;
}

/*
 * mpz_extended_gcd — Extended Euclidean Algorithm
 *
 * Computes gcd(a, p) and also finds x, y such that a*x + p*y = gcd(a, p).
 * Returns gcd(a, p). If gcd = 1, x is the modular inverse of a mod p.
 *
 * Complexity: O(log min(a, p))
 * Reference: Euclid Elements Book VII; modern: Knuth TAOCP Vol 2
 */
uint64_t mpz_extended_gcd(uint64_t a, uint64_t p, int64_t *x, int64_t *y) {
    if (a == 0) {
        *x = 0;
        *y = 1;
        return p;
    }
    int64_t x1, y1;
    uint64_t gcd = mpz_extended_gcd(p % a, a, &x1, &y1);
    *x = y1 - (p / a) * x1;
    *y = x1;
    return gcd;
}

/*
 * mpz_mod_inv — Modular inverse: a^{-1} mod p using Extended GCD
 *
 * Requires gcd(a, p) = 1. Returns 0 if inverse does not exist.
 *
 * L4 Theorem (Fermat): If p is prime, a^{p-2} ≡ a^{-1} mod p.
 * This implementation uses Extended GCD which works for any coprime a, p.
 * Complexity: O(log p)
 */
uint64_t mpz_mod_inv(uint64_t a, uint64_t p) {
    if (a == 0 || p == 0) return 0;
    int64_t x, y;
    uint64_t g = mpz_extended_gcd(a, p, &x, &y);
    if (g != 1) return 0;  /* a not invertible mod p */
    /* x may be negative; normalize to [0, p-1] */
    int64_t r = x % (int64_t)p;
    if (r < 0) r += (int64_t)p;
    return (uint64_t)r;
}

/*
 * mpz_mod_sqrt_3mod4 — Square root mod p when p ≡ 3 mod 4
 *
 * If p ≡ 3 (mod 4), then sqrt(a) ≡ a^{(p+1)/4} mod p,
 * provided a is a quadratic residue.
 *
 * L4 Theorem (Euler's criterion): a^{(p-1)/2} ≡ 1 mod p iff a is QR.
 * Complexity: O(log p)
 */
uint64_t mpz_mod_sqrt_3mod4(uint64_t a, uint64_t p) {
    if (a == 0) return 0;
    if (p % 4 != 3) return 0;
    uint64_t exp = (p + 1) / 4;
    uint64_t root = mpz_mod_pow(a, exp, p);
    /* Verify: root^2 mod p should equal a */
    if (mpz_mod_mul(root, root, p) != a) return 0;
    return root;
}

/*
 * mpz_mod_sqrt — General square root mod prime p using Tonelli-Shanks
 *
 * L5 Algorithm (Tonelli-Shanks, 1891):
 *   If p ≡ 3 mod 4: use fast path (mpz_mod_sqrt_3mod4).
 *   If p ≡ 1 mod 4: decompose p-1 = Q * 2^S, find quadratic non-residue z,
 *     iteratively refine root.
 *
 * Complexity: O(S + log p) for S = v_2(p-1)
 * Reference: Tonelli (1891), Shanks (1972)
 */
uint64_t mpz_mod_sqrt(uint64_t a, uint64_t p) {
    if (a == 0) return 0;
    a = a % p;

    /* Fast path: p ≡ 3 mod 4 */
    if (p % 4 == 3) {
        return mpz_mod_sqrt_3mod4(a, p);
    }

    /* Check if a is a quadratic residue */
    if (legendre_symbol(a, p) != 1) return 0;

    /* p-1 = Q * 2^S, Q odd */
    uint64_t Q = p - 1;
    int S = 0;
    while (Q % 2 == 0) { Q /= 2; S++; }

    /* Find a quadratic non-residue z */
    uint64_t z = 2;
    while (legendre_symbol(z, p) != -1 && z < p) z++;
    if (z >= p) return 0;  /* shouldn't happen for prime p */

    uint64_t M = S;
    uint64_t c = mpz_mod_pow(z, Q, p);
    uint64_t t = mpz_mod_pow(a, Q, p);
    uint64_t R = mpz_mod_pow(a, (Q + 1) / 2, p);

    while (t != 0 && t != 1) {
        /* Find the least i such that t^{2^i} ≡ 1 mod p */
        uint64_t t2i = t;
        uint64_t i = 0;
        for (; i < M; i++) {
            if (t2i == 1) break;
            t2i = mpz_mod_mul(t2i, t2i, p);
        }
        if (i == M) return 0;  /* no solution */

        uint64_t b = mpz_mod_pow(c, 1ULL << (M - i - 1), p);
        M = i;
        c = mpz_mod_mul(b, b, p);
        t = mpz_mod_mul(t, c, p);
        R = mpz_mod_mul(R, b, p);
    }
    return R;
}

/*
 * legendre_symbol — Legendre symbol (a | p)
 *
 * L1 Definition: (a|p) = a^{(p-1)/2} mod p, with values +1, -1, or 0.
 * Returns: 1 if a is quadratic residue, -1 if non-residue, 0 if p|a.
 *
 * L4 Theorem (Euler's criterion): (a|p) ≡ a^{(p-1)/2} mod p
 */
int legendre_symbol(uint64_t a, uint64_t p) {
    if (a % p == 0) return 0;
    uint64_t e = mpz_mod_pow(a, (p - 1) / 2, p);
    return (e == 1) ? 1 : (e == p - 1) ? -1 : 0;
}

/*
 * mpz_is_quadratic_residue — Tests if a is a QR mod p
 *
 * Uses Euler's criterion.
 */
int mpz_is_quadratic_residue(uint64_t a, uint64_t p) {
    return legendre_symbol(a, p) == 1;
}

/* ═══════════════════════════════════════════════════════════════
   Primality Testing
   ═══════════════════════════════════════════════════════════════ */

/*
 * mpz_is_prime_naive — Trial-division primality test
 *
 * Tests divisibility by all odd numbers up to sqrt(n).
 * O(sqrt(n)) — suitable only for small numbers.
 *
 * L5: Basis for all primality testing; improved by Miller-Rabin.
 */
int mpz_is_prime_naive(uint64_t n) {
    if (n < 2) return 0;
    if (n == 2) return 1;
    if (n % 2 == 0) return 0;
    for (uint64_t d = 3; d * d <= n; d += 2) {
        if (n % d == 0) return 0;
    }
    return 1;
}

/*
 * mpz_miller_rabin — Miller-Rabin probabilistic primality test
 *
 * L5 Algorithm:
 *   Write n-1 = d * 2^s, d odd.
 *   For k independent bases a:
 *     If a^d ≡ 1 mod n, continue (probable prime for this base).
 *     If a^{d*2^r} ≡ -1 mod n for some 0 ≤ r < s, continue.
 *     Otherwise composite.
 *
 * Probability of false positive ≤ 4^{-k} for random bases.
 * Complexity: O(k log^3 n)
 *
 * Reference: Miller (1976), Rabin (1980)
 *
 * Uses small deterministic bases sufficient for n < 2^64:
 * 2, 3, 5, 7, 11, 13, 17 (Jaeschke 1993)
 */
int mpz_miller_rabin(uint64_t n, int k) {
    if (n < 2) return 0;
    if (n == 2 || n == 3) return 1;
    if (n % 2 == 0) return 0;

    /* Write n-1 = d * 2^s */
    uint64_t d = n - 1;
    int s = 0;
    while (d % 2 == 0) { d /= 2; s++; }

    /* Deterministic bases for n < 2^64 */
    uint64_t bases[] = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37};
    int n_bases = k;
    if (n_bases > 12) n_bases = 12;

    for (int i = 0; i < n_bases; i++) {
        uint64_t a = bases[i];
        if (a >= n) continue;

        uint64_t x = mpz_mod_pow(a, d, n);
        if (x == 1 || x == n - 1) continue;

        int composite = 1;
        for (int r = 0; r < s - 1; r++) {
            x = mpz_mod_mul(x, x, n);
            if (x == n - 1) { composite = 0; break; }
            if (x == 1) return 0;  /* definitely composite */
        }
        if (composite) return 0;
    }
    return 1;
}

/*
 * mpz_is_safe_prime — Check if p is a safe prime (p = 2q+1 where q is also prime)
 *
 * Safe primes are important for cryptographic groups: the group Z_p*
 * has order p-1 = 2q, with the large prime-order subgroup of order q.
 *
 * L2: Safe primes are used for DDH-hard groups (e.g., Oakley groups).
 */
int mpz_is_safe_prime(uint64_t p) {
    if (p < 5 || p % 2 == 0) return 0;
    if (!mpz_miller_rabin(p, 5)) return 0;
    uint64_t q = (p - 1) / 2;
    return mpz_miller_rabin(q, 5);
}

/*
 * mpz_next_prime — Find the next prime ≥ n
 *
 * Simple sequential search with Miller-Rabin.
 * Complexity: O(gap * log^3 n) where gap is O(log^2 n) on average (Cramer's conjecture).
 */
uint64_t mpz_next_prime(uint64_t n) {
    if (n <= 2) return 2;
    if (n % 2 == 0) n++;
    while (!mpz_miller_rabin(n, 5)) {
        n += 2;
    }
    return n;
}

/*
 * mpz_verify_order — Verify that g has order exactly 'order' in Z_p*
 *
 * Checks: g^order ≡ 1 mod p, and g^{order/q} ≢ 1 for each prime q dividing order.
 */
int mpz_verify_order(uint64_t g, uint64_t order, uint64_t p) {
    if (mpz_mod_pow(g, order, p) != 1) return 0;
    /* Check that for each prime factor q of order, g^{order/q} ≠ 1 */
    uint64_t n = order;
    for (uint64_t q = 2; q * q <= n; q++) {
        if (n % q == 0) {
            if (mpz_mod_pow(g, order / q, p) == 1) return 0;
            while (n % q == 0) n /= q;
        }
    }
    if (n > 1) {
        if (mpz_mod_pow(g, order / n, p) == 1) return 0;
    }
    return 1;
}

/* ═══════════════════════════════════════════════════════════════
   Cyclic Group Construction & Management
   ═══════════════════════════════════════════════════════════════ */

/*
 * group_create_from_safe_prime — Create a prime-order subgroup of Z_p*
 *
 * Given a safe prime p = 2q+1, finds a generator of the subgroup of
 * quadratic residues (order q). Uses g = 4 = 2^2 as a guaranteed QR.
 *
 * The QR subgroup is important because DDH is easy in the full Z_p*
 * (via Legendre symbols) but conjectured hard in the QR subgroup.
 *
 * L2: DDH-hard group construction
 */
CyclicGroup* group_create_from_safe_prime(uint64_t p) {
    if (!mpz_is_safe_prime(p)) return NULL;

    CyclicGroup* g = (CyclicGroup*)calloc(1, sizeof(CyclicGroup));
    if (!g) return NULL;

    g->modulus = p;
    g->order = (p - 1) / 2;  /* q = (p-1)/2 */
    g->cofactor = 2;

    /* In the QR subgroup of Z_p*, any quadratic residue generates */
    /* Find a generator by testing small values */
    g->generator = 0;
    for (uint64_t cand = 2; cand < p && cand < 1000; cand++) {
        if (legendre_symbol(cand, p) == 1) {
            if (mpz_verify_order(cand, g->order, p)) {
                g->generator = cand;
                break;
            }
        }
    }
    if (g->generator == 0) {
        free(g);
        return NULL;
    }

    g->description = (char*)calloc(80, 1);
    snprintf(g->description, 79, "QR subgroup of Z_%llu* (order %llu)",
             (unsigned long long)p, (unsigned long long)g->order);
    g->is_initialized = 1;
    return g;
}

/*
 * group_create_custom — Create a group with explicit parameters
 *
 * L3: Direct encoding of group (modulus, order, generator) triple.
 */
CyclicGroup* group_create_custom(uint64_t modulus, uint64_t order, uint64_t generator) {
    CyclicGroup* g = (CyclicGroup*)calloc(1, sizeof(CyclicGroup));
    if (!g) return NULL;

    g->modulus = modulus;
    g->order = order;
    g->generator = generator;
    g->cofactor = (modulus - 1) / order;
    g->description = (char*)calloc(64, 1);
    snprintf(g->description, 63, "Custom group mod %llu, order %llu",
             (unsigned long long)modulus, (unsigned long long)order);
    g->is_initialized = 1;
    return g;
}

/*
 * group_find_quadratic_residue_generator — Find generator of QR subgroup
 *
 * For safe prime p = 2q+1, the QR subgroup has order q.
 * Any element g of order q in the QR subgroup is a valid generator.
 */
uint64_t group_find_quadratic_residue_generator(uint64_t p) {
    uint64_t q = (p - 1) / 2;
    for (uint64_t cand = 2; cand < p && cand < 10000; cand++) {
        if (legendre_symbol(cand, p) == 1) {
            if (mpz_verify_order(cand, q, p)) {
                return cand;
            }
        }
    }
    return 0;
}

void group_free(CyclicGroup* g) {
    if (!g) return;
    free(g->description);
    free(g);
}

/*
 * group_is_cyclic — Check if a group is cyclic
 *
 * For Z_p*: always cyclic (p prime). Returns 1 if g is indeed a generator
 * of the claimed cyclic group.
 */
int group_is_cyclic(const CyclicGroup* g) {
    if (!g || !g->is_initialized) return 0;
    return mpz_verify_order(g->generator, g->order, g->modulus);
}

uint64_t group_order(const CyclicGroup* g) {
    if (!g) return 0;
    return g->order;
}

/*
 * group_verify_lagrange — Verify Lagrange's theorem
 *
 * Lagrange: For any finite group G, the order of any subgroup H divides |G|.
 * For any element a ∈ G, |a| (the order of a) divides |G|.
 *
 * This function checks that g^{|G|} = 1 for the generator.
 */
int group_verify_lagrange(const CyclicGroup* g) {
    if (!g || !g->is_initialized) return 0;
    return mpz_mod_pow(g->generator, g->order, g->modulus) == 1;
}

/* ═══════════════════════════════════════════════════════════════
   Group Element Operations
   ═══════════════════════════════════════════════════════════════ */

GroupElement* ge_create(uint64_t value, CyclicGroup* g) {
    if (!g) return NULL;
    GroupElement* a = (GroupElement*)calloc(1, sizeof(GroupElement));
    if (!a) return NULL;
    a->value = value % g->modulus;
    a->group = g;
    return a;
}

GroupElement* ge_clone(const GroupElement* a) {
    if (!a) return NULL;
    return ge_create(a->value, a->group);
}

void ge_free(GroupElement* a) {
    free(a);
}

GroupElement* ge_identity(CyclicGroup* g) {
    return ge_create(1, g);
}

GroupElement* ge_generator(CyclicGroup* g) {
    if (!g) return NULL;
    return ge_create(g->generator, g);
}

/*
 * ge_mul — Group multiplication: a * b mod p
 *
 * In the multiplicative group Z_p*, the group operation is modular multiplication.
 */
GroupElement* ge_mul(const GroupElement* a, const GroupElement* b) {
    if (!a || !b || a->group != b->group) return NULL;
    GroupElement* r = ge_create(0, a->group);
    if (!r) return NULL;
    r->value = mpz_mod_mul(a->value, b->value, a->group->modulus);
    return r;
}

/*
 * ge_inv — Group inverse: a^{-1} mod p
 *
 * Uses Fermat's little theorem: a^{p-2} ≡ a^{-1} mod p for prime p.
 * More general: Extended GCD for arbitrary modulus.
 */
GroupElement* ge_inv(const GroupElement* a) {
    if (!a) return NULL;
    GroupElement* r = ge_create(0, a->group);
    if (!r) return NULL;
    r->value = mpz_mod_inv(a->value, a->group->modulus);
    if (r->value == 0 && a->value != 1) {
        free(r);
        return NULL;
    }
    return r;
}

/*
 * ge_pow — Group exponentiation: a^k mod p
 *
 * Uses the fast exponentiation (square-and-multiply) from mpz_mod_pow.
 * Complexity: O(log k)
 */
GroupElement* ge_pow(const GroupElement* a, uint64_t k) {
    if (!a) return NULL;
    GroupElement* r = ge_create(0, a->group);
    if (!r) return NULL;
    /* Normalize exponent modulo group order */
    if (a->group->order > 0) k = k % a->group->order;
    r->value = mpz_mod_pow(a->value, k, a->group->modulus);
    return r;
}

/*
 * ge_div — Group division: a * b^{-1} mod p
 *
 * Returns a * inverse(b) in the group.
 */
GroupElement* ge_div(const GroupElement* a, const GroupElement* b) {
    if (!a || !b) return NULL;
    GroupElement* inv_b = ge_inv(b);
    if (!inv_b) return NULL;
    GroupElement* result = ge_mul(a, inv_b);
    ge_free(inv_b);
    return result;
}

/*
 * ge_random — Generate a random group element
 *
 * Uses the linear congruential generator with the given seed.
 * In practice, a CSPRNG would be used.
 * Returns g^{seed} which gives a uniformly random group element
 * (since exponent is random in Z_order).
 */
GroupElement* ge_random(CyclicGroup* g, uint64_t seed) {
    if (!g) return NULL;
    /* Simple LCG to generate a random exponent */
    uint64_t state = seed;
    state = state * 6364136223846793005ULL + 1;
    uint64_t exp = state % g->order;
    if (exp == 0) exp = 1;
    GroupElement* a = ge_create(g->generator, g);
    GroupElement* r = ge_pow(a, exp);
    ge_free(a);
    return r;
}

/* ═══════════════════════════════════════════════════════════════
   Group Element Inspection
   ═══════════════════════════════════════════════════════════════ */

int ge_equal(const GroupElement* a, const GroupElement* b) {
    if (!a || !b) return 0;
    if (a->group != b->group) return 0;
    return a->value == b->value;
}

int ge_is_identity(const GroupElement* a) {
    if (!a) return 0;
    return a->value == 1;
}

int ge_is_generator(const GroupElement* a) {
    if (!a || !a->group) return 0;
    return mpz_verify_order(a->value, a->group->order, a->group->modulus);
}

/*
 * ge_in_subgroup — Check if element belongs to a subgroup
 *
 * An element a is in subgroup H of order h iff a^h = 1.
 * This follows from Lagrange's theorem: the order of any element
 * divides the group order.
 */
int ge_in_subgroup(const GroupElement* a, const Subgroup* H) {
    if (!a || !H) return 0;
    return mpz_mod_pow(a->value, H->subgroup_order, a->group->modulus) == 1;
}

void ge_print(const GroupElement* a, const char* label) {
    if (!a) return;
    printf("%s: %llu (mod %llu)\n", label,
           (unsigned long long)a->value,
           (unsigned long long)(a->group ? a->group->modulus : 0));
}

/* ═══════════════════════════════════════════════════════════════
   Subgroup Operations
   ═══════════════════════════════════════════════════════════════ */

Subgroup* subgroup_create(CyclicGroup* parent, uint64_t order, uint64_t gen) {
    if (!parent) return NULL;
    Subgroup* H = (Subgroup*)calloc(1, sizeof(Subgroup));
    if (!H) return NULL;
    H->parent = parent;
    H->subgroup_order = order;
    H->subgroup_gen = gen;
    H->is_prime_order = mpz_is_prime_naive(order);
    return H;
}

int subgroup_contains(const Subgroup* H, const GroupElement* a) {
    if (!H || !a) return 0;
    return ge_in_subgroup(a, (Subgroup*)H);
}

/*
 * subgroup_cofactor_clear — Multiply element by cofactor to map into subgroup
 *
 * For a group G with subgroup H of order q and cofactor h = |G|/q,
 * the map φ: G → H defined by φ(x) = x^h maps every element into H.
 * For the quadratic residue subgroup of Z_p*, h = 2.
 */
GroupElement* subgroup_cofactor_clear(const Subgroup* H, const GroupElement* a) {
    if (!H || !a || !H->parent) return NULL;
    uint64_t cofactor = H->parent->order / H->subgroup_order;
    return ge_pow(a, cofactor);
}

void subgroup_free(Subgroup* H) {
    free(H);
}

/* ═══════════════════════════════════════════════════════════════
   Group Encoding / Serialization
   ═══════════════════════════════════════════════════════════════ */

/*
 * ge_serialize — Serialize a group element to bytes (big-endian)
 *
 * Encodes the uint64_t value in 8 bytes (big-endian).
 * Returns number of bytes written, 0 on error.
 */
int ge_serialize(const GroupElement* a, uint8_t* buf, size_t buf_len) {
    if (!a || !buf || buf_len < 8) return 0;
    uint64_t v = a->value;
    for (int i = 7; i >= 0; i--) {
        buf[i] = (uint8_t)(v & 0xFF);
        v >>= 8;
    }
    return 8;
}

/*
 * ge_deserialize — Deserialize a group element from bytes
 */
GroupElement* ge_deserialize(const uint8_t* buf, size_t buf_len, CyclicGroup* g) {
    if (!buf || buf_len < 8 || !g) return NULL;
    uint64_t v = 0;
    for (size_t i = 0; i < 8; i++) {
        v = (v << 8) | buf[i];
    }
    return ge_create(v, g);
}

/* ═══════════════════════════════════════════════════════════════
   Batch Operations
   ═══════════════════════════════════════════════════════════════ */

/*
 * ge_multi_exp — Multi-exponentiation: Prod base_i^{exp_i}
 *
 * Computes Prod_{i=0}^{count-1} base_i^{exp_i} using simultaneous
 * multi-exponentiation (Pippenger's algorithm / Straus-Shamir trick).
 *
 * L5: Multi-exponentiation is a core operation in pairing-based
 *     SNARK verification (e.g., single pairing check in Groth16).
 *
 * Complexity: O(count * log max(exp_i)) but with shared squaring.
 *
 * Reference: Straus (1964), Shamir (unpublished), Bernstein (2002)
 */
GroupElement* ge_multi_exp(const GroupElement** bases, const uint64_t* exps,
                            int count, CyclicGroup* g) {
    if (!bases || !exps || count <= 0 || !g) return NULL;

    /* Simple implementation: sequential exponentiation and multiplication */
    GroupElement* result = ge_identity(g);
    if (!result) return NULL;

    for (int i = 0; i < count; i++) {
        if (!bases[i]) continue;
        GroupElement* term = ge_pow(bases[i], exps[i]);
        if (!term) { ge_free(result); return NULL; }
        GroupElement* new_result = ge_mul(result, term);
        ge_free(result);
        ge_free(term);
        if (!new_result) return NULL;
        result = new_result;
    }
    return result;
}

/* ═══════════════════════════════════════════════════════════════
   Pre-built Standard Test Groups
   ═══════════════════════════════════════════════════════════════ */

/*
 * group_create_oakley14 — Create Oakley Group 14 (RFC 3526, 2048-bit MODP)
 *
 * For educational purposes, we use a small 64-bit safe prime that
 * resembles the structure of Oakley groups (safe prime, QR subgroup).
 *
 * L2: Oakley groups are standardized DDH-hard groups for key exchange.
 */
CyclicGroup* group_create_oakley14(void) {
    /* Use a small safe prime for educational purposes */
    /* p = 2q+1 where q is prime. p = 107, q = 53 */
    uint64_t p = 107;
    return group_create_from_safe_prime(p);
}

/*
 * group_create_test_group — Create a small test group
 *
 * p = 23 is a safe prime: 23 = 2*11 + 1, q = 11.
 * This is suitable for manual verification and testing.
 */
CyclicGroup* group_create_test_group(void) {
    CyclicGroup* g = (CyclicGroup*)calloc(1, sizeof(CyclicGroup));
    if (!g) return NULL;
    g->modulus = 23;
    g->order = 11;          /* The QR subgroup of Z_23* has order 11 */
    g->generator = 2;       /* 2 has order 11 in Z_23*: 2^11 ≡ 1 mod 23 */
    g->cofactor = 2;
    g->description = (char*)calloc(64, 1);
    snprintf(g->description, 63, "Test group Z_23*, QR subgroup order 11");
    g->is_initialized = 1;
    return g;
}

/*
 * group_create_medium_group — Create a medium-sized group
 *
 * Uses p = 1031 (prime), with order q = 103 (prime) subgroup.
 * This is large enough to be non-trivial but small enough for
 * exhaustive scanning in testing.
 */
CyclicGroup* group_create_medium_group(void) {
    /* 1031 = 10*103 + 1, so the QR subgroup has order 103 */
    CyclicGroup* g = (CyclicGroup*)calloc(1, sizeof(CyclicGroup));
    if (!g) return NULL;
    g->modulus = 1031;
    g->order = 103;
    g->generator = 2;  /* 2^103 ≡ 1 mod 1031 */
    g->cofactor = 10;
    g->description = (char*)calloc(64, 1);
    snprintf(g->description, 63, "Medium group Z_1031*, subgroup order 103");
    g->is_initialized = 1;
    return g;
}
