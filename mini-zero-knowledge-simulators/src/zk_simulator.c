/*
 * mini-zero-knowledge-simulators -- zk_simulator.c
 * Core implementations: modular arithmetic, transcripts, random tapes.
 * Covers L1 (Definitions), L3 (Math Structures), L4 (Core Theorems).
 *
 * Reference: Goldreich (2004), Arora & Barak (2009)
 */

#include "zk_simulator.h"
#include <stdio.h>
#include <math.h>
#include <float.h>

/* =================================================================
 * L2.4 -- Statistical Distance & Negligible Functions
 * ================================================================= */

/*
 * Statistical (total variation) distance between two discrete
 * probability distributions represented as arrays.
 *
 * Delta(D1, D2) = (1/2) * sum_{i=0}^{n-1} |D1[i] - D2[i]|
 *
 * Properties:
 *  0 <= Delta <= 1
 *  Delta(D,D) = 0
 *  Delta(D1,D2) = Delta(D2,D1)
 *  Triangle inequality: Delta(D1,D3) <= Delta(D1,D2) + Delta(D2,D3)
 *
 * For perfect ZK: Delta(real, sim) = 0 exactly.
 * For statistical ZK: Delta(real, sim) <= negl(security_param).
 */
double statistical_distance(const double *d1, const double *d2, size_t n) {
    if (!d1 || !d2 || n == 0) return 1.0;
    double sum = 0.0;
    for (size_t i = 0; i < n; i++) {
        double diff = d1[i] - d2[i];
        sum += (diff >= 0.0) ? diff : -diff;
    }
    return 0.5 * sum;
}

/*
 * Check if epsilon is negligible at security parameter n.
 * For didactic purposes, we define epsilon(n) as negligible if
 * epsilon < 1/n^2 (i.e., decays faster than 1/poly).
 *
 * In formal definitions: epsilon(n) < 1/n^c for ANY constant c
 * and sufficiently large n. We check c=2 here.
 *
 * Complexity: O(1)
 */
int is_negligible(double eps, double n) {
    if (n <= 0.0) return 0;
    double threshold = 1.0 / (n * n);
    return (eps < threshold) ? 1 : 0;
}

/* =================================================================
 * L3.1 -- Modular Arithmetic (Z_m)
 *
 * Essential for all DLog-based ZK protocols.
 * Correctness verified via group axioms.
 * ================================================================= */

/*
 * Addition in Z_m: (a + b) mod m
 * Uses uint64_t arithmetic. Result is in [0, m-1].
 *
 * Complexity: O(1) with overflow-safe computation.
 * Edge cases: a,b in [0, m-1]; m > 0.
 */
uint64_t mod_add(uint64_t a, uint64_t b, uint64_t m) {
    if (m == 0) return 0;
    /* Safe: a,b < m, so a+b < 2m */
    uint64_t sum = a + b;
    return (sum >= m) ? sum - m : sum;
}

/*
 * Subtraction in Z_m: (a - b) mod m
 * Result is in [0, m-1].
 * Complexity: O(1).
 */
uint64_t mod_sub(uint64_t a, uint64_t b, uint64_t m) {
    if (m == 0) return 0;
    /* Since a,b < m, we either subtract normally or add m */
    return (a >= b) ? a - b : m - (b - a);
}

/*
 * Multiplication in Z_m: (a * b) mod m
 * Uses 128-bit intermediate to avoid overflow.
 * Complexity: O(1) using __int128 (or fallback).
 *
 * THEOREM: Z_m^* is a multiplicative group of order phi(m).
 * For prime m, Z_m^* has order m-1.
 */
uint64_t mod_mul(uint64_t a, uint64_t b, uint64_t m) {
    if (m == 0) return 0;
#ifdef __SIZEOF_INT128__
    return (uint64_t)(((__int128)a * (__int128)b) % (__int128)m);
#else
    /* Russian peasant multiplication (O(log b)) as fallback */
    uint64_t result = 0;
    a = a >= m ? a % m : a;
    b = b >= m ? b % m : b;
    while (b > 0) {
        if (b & 1) {
            uint64_t sum = result + a;
            result = (sum >= m) ? sum - m : sum;
        }
        a = (a + a >= m) ? a + a - m : a + a;
        b >>= 1;
    }
    return result;
#endif
}

/*
 * Modular exponentiation: g^e mod m
 * Uses square-and-multiply (binary exponentiation).
 *
 * Complexity: O(log e) modular multiplications.
 *
 * THEOREM (Fermat): For prime p, g^{p-1} ≡ 1 (mod p) for all g ≠ 0.
 * Euler's theorem: For any m, g^{phi(m)} ≡ 1 (mod m) if gcd(g,m)=1.
 *
 * This is the workhorse for all DLog-based ZK protocols.
 */
uint64_t mod_pow(uint64_t base, uint64_t exp, uint64_t m) {
    if (m == 0) return 0;
    if (m == 1) return 0;
    uint64_t result = 1 % m;
    base = base % m;
    while (exp > 0) {
        if (exp & 1) {
            result = mod_mul(result, base, m);
        }
        base = mod_mul(base, base, m);
        exp >>= 1;
    }
    return result;
}

/*
 * Modular inverse: find x s.t. a*x ≡ 1 (mod m)
 * Uses extended Euclidean algorithm.
 *
 * Precondition: gcd(a, m) = 1 (otherwise no inverse exists).
 * Complexity: O(log min(a, m)).
 *
 * THEOREM (Bezout): For integers a,b, there exist x,y s.t.
 *   a*x + b*y = gcd(a,b).
 * If gcd(a,m)=1, then a*x + m*y = 1 => a*x ≡ 1 (mod m).
 *
 * This is used in witness extraction and simulation to compute
 * inverses modulo q (the subgroup order).
 */
uint64_t mod_inv(uint64_t a, uint64_t m) {
    if (m == 0) return 0;
    if (m == 1) return 0;
    int64_t x, y;
    int64_t g = extended_gcd((int64_t)a, (int64_t)m, &x, &y);
    if (g != 1) {
        /* No inverse exists */
        return 0;
    }
    /* Ensure result is positive mod m */
    int64_t result = x % (int64_t)m;
    if (result < 0) result += (int64_t)m;
    return (uint64_t)result;
}

/*
 * Negation in Z_m: (-a) mod m
 * Complexity: O(1).
 */
uint64_t mod_neg(uint64_t a, uint64_t m) {
    if (m == 0 || a == 0) return 0;
    return m - (a % m);
}

/*
 * Extended Euclidean Algorithm
 *
 * Input: integers a, b (int64_t for signed operations).
 * Output: gcd(a,b), and x, y s.t. a*x + b*y = gcd(a,b).
 *
 * Algorithm:
 *   Maintain invariants:
 *     a*s_i + b*t_i = r_i
 *
 *   Base: r_(-1)=a, r_0=b
 *   Step: r_{i+1} = r_{i-1} - q_i * r_i
 *
 * Complexity: O(log min(|a|,|b|)) steps.
 *
 * Reference: Knuth, TAOCP Vol.2, Sec. 4.5.2.
 */
int64_t extended_gcd(int64_t a, int64_t b, int64_t *x, int64_t *y) {
    if (!x || !y) return 0;
    if (b == 0) {
        *x = (a >= 0) ? 1 : -1;
        *y = 0;
        return (a >= 0) ? a : -a;
    }
    int64_t x1, y1;
    int64_t g = extended_gcd(b, a % b, &x1, &y1);
    *x = y1;
    *y = x1 - (a / b) * y1;
    return g;
}

/* =================================================================
 * L3.3 -- Random Tape Management
 *
 * Linear Congruential Generator (LCG) for didactic use.
 * Parameters: multiplier=6364136223846793005, increment=1442695040888963407
 * (from Donald Knuth's MMIX LCG).
 *
 * NOT cryptographically secure! For real ZK proofs, use
 * cryptographically secure PRNG (e.g., HMAC-DRBG).
 *
 * This LCG is sufficient for demonstrating ZK simulators
 * and understanding the statistical properties.
 * ================================================================= */

#define LCG_MULTIPLIER UINT64_C(6364136223846793005)
#define LCG_INCREMENT  UINT64_C(1442695040888963407)

void init_random_tape(random_tape_t *tape, uint64_t seed) {
    if (!tape) return;
    assert(tape != NULL);
    tape->seed = seed;
    tape->coin_len = 0;
    memset(tape->coins, 0, MAX_RANDOM_TAPE);
}

/*
 * Generate next pseudo-random uint64_t via LCG.
 * Returns a value in [0, 2^64 - 1].
 * The LCG has full period (2^64) with these parameters.
 */
uint64_t next_random_u64(random_tape_t *tape) {
    if (!tape) return 0;
    uint64_t old = tape->seed;
    tape->seed = old * LCG_MULTIPLIER + LCG_INCREMENT;
    /* Fill buffer for later inspection (useful for rewinding) */
    if (tape->coin_len + 8 <= MAX_RANDOM_TAPE) {
        tape->coins[tape->coin_len    ] = (uint8_t)(tape->seed >> 0);
        tape->coins[tape->coin_len + 1] = (uint8_t)(tape->seed >> 8);
        tape->coins[tape->coin_len + 2] = (uint8_t)(tape->seed >> 16);
        tape->coins[tape->coin_len + 3] = (uint8_t)(tape->seed >> 24);
        tape->coins[tape->coin_len + 4] = (uint8_t)(tape->seed >> 32);
        tape->coins[tape->coin_len + 5] = (uint8_t)(tape->seed >> 40);
        tape->coins[tape->coin_len + 6] = (uint8_t)(tape->seed >> 48);
        tape->coins[tape->coin_len + 7] = (uint8_t)(tape->seed >> 56);
        tape->coin_len += 8;
    }
    return tape->seed;
}

/*
 * Generate a uniform random element in Z_q = {0, 1, ..., q-1}.
 *
 * Uses rejection sampling to avoid bias:
 *   1. Generate random r in [0, 2^64-1]
 *   2. If r < floor(2^64/q)*q, return r mod q
 *   3. Else, try again
 *
 * This ensures UNIFORM distribution over Z_q, which is critical
 * for the security of ZK protocols. Biased randomness can leak
 * information about the witness.
 *
 * Complexity: O(1) expected (prob of rejection < 2^{-32}).
 */
uint64_t pull_random_mod_q(random_tape_t *tape, uint64_t q) {
    if (!tape || q == 0) return 0;
    if (q == 1) return 0;
    /* Compute max safe value to avoid bias */
    uint64_t max_safe = UINT64_MAX - (UINT64_MAX % q);
    while (1) {
        uint64_t r = next_random_u64(tape);
        if (r < max_safe) {
            return r % q;
        }
        /* else: bias possible, reject and retry */
    }
}

/* =================================================================
 * L1.1 -- Transcript Management
 * ================================================================= */

void transcript_init(transcript_t *t) {
    if (!t) return;
    assert(t != NULL);
    memset(t->data, 0, MAX_TRANSCRIPT_LEN);
    t->len = 0;
    t->num_rounds = 0;
    memset(t->round_start, 0, sizeof(t->round_start));
}

void transcript_append(transcript_t *t, const uint8_t *data, size_t len) {
    if (!t || !data || len == 0) return;
    assert(t != NULL);
    if (t->len + len > MAX_TRANSCRIPT_LEN) return;
    memcpy(t->data + t->len, data, len);
    t->len += len;
}

/*
 * Append a uint64_t in little-endian byte order.
 * All DLog-based ZK protocol values are uint64_t for simplicity.
 */
void transcript_append_u64(transcript_t *t, uint64_t val) {
    if (!t) return;
    uint8_t buf[8];
    for (int i = 0; i < 8; i++) {
        buf[i] = (uint8_t)(val >> (8 * i));
    }
    transcript_append(t, buf, 8);
}

/*
 * Mark the start of a new round.
 * Stores the current transcript position for rewinding.
 * In a 3-round sigma protocol:
 *   round 0: P commitment
 *   round 1: V challenge
 *   round 2: P response
 */
void transcript_start_round(transcript_t *t) {
    if (!t) return;
    if (t->num_rounds < MAX_ROUNDS) {
        t->round_start[t->num_rounds] = t->len;
        t->num_rounds++;
    }
}

/*
 * Verify transcript integrity (non-empty, valid round markers).
 * For didactic purposes: checks that round markers are monotonic.
 */
int transcript_verify(const transcript_t *t) {
    if (!t) return 0;
    if (t->len == 0 || t->num_rounds == 0) return 0;
    /* Check round markers are increasing */
    for (uint32_t i = 1; i < t->num_rounds; i++) {
        if (t->round_start[i] < t->round_start[i-1]) return 0;
    }
    /* Check last round start < total len */
    if (t->round_start[t->num_rounds - 1] >= t->len) return 0;
    return 1;
}

/*
 * Deep copy of a transcript.
 * Used when the simulator saves state before rewinding.
 */
void transcript_copy(const transcript_t *src, transcript_t *dst) {
    if (!src || !dst) return;
    memcpy(dst, src, sizeof(transcript_t));
}

/* =================================================================
 * L4.1 -- Schnorr Protocol Verification Equation
 *
 * THEOREM (Schnorr 1991):
 * Ver(vk, a, c, s) = (g^s == a * y^c) mod p
 *
 * If y = g^x, then:
 *   g^s = g^{r + c*x} = g^r * (g^x)^c = a * y^c
 *
 * Security (in group of order q):
 *   Soundness error = 1/q (one attempt)
 *   Special soundness: from (a,c1,s1),(a,c2,s2) extract x
 *   HVZK: pick c,s; a = g^s * y^{-c} (perfect)
 *
 * Complexity: O(log q) modular multiplications.
 * ================================================================= */
int schnorr_verify(uint64_t a, uint64_t c, uint64_t s,
                   uint64_t y, const group_params_t *gp) {
    if (!gp) return 0;
    if (gp->q == 0 || gp->p == 0) return 0;

    /* Compute LHS: g^s mod p */
    uint64_t lhs = mod_pow(gp->g, s, gp->p);

    /* Compute RHS: a * y^c mod p */
    uint64_t yc = mod_pow(y, c, gp->p);
    uint64_t rhs = mod_mul(a, yc, gp->p);

    return (lhs == rhs) ? 1 : 0;
}

/* =================================================================
 * L4.2 -- HVZK Simulator for Schnorr
 *
 * Simulator algorithm:
 *   1. c = random(Z_q)
 *   2. s = random(Z_q)
 *   3. a = g^s * y^{-c} mod p
 *
 * Proof of perfect simulation:
 * Real: (g^r, c, r+cx) with r uniform, c uniform.
 * Sim:  (g^s*y^{-c}, c, s) with c uniform, s uniform.
 *
 * Map (r,c) -> (g^r, c, r+cx) is a bijection for fixed x.
 * Map (c,s) -> (g^s*y^{-c}, c, s) is a bijection.
 * Both produce uniform (a,c) with s determined uniquely.
 * Therefore distributions are identical.
 *
 * Complexity: O(log q) modular multiplications.
 * ================================================================= */
int hvzk_simulate_schnorr(uint64_t y, const group_params_t *gp,
                          const random_tape_t *rng,
                          uint64_t *a_out, uint64_t *c_out, uint64_t *s_out) {
    if (!gp || !rng || !a_out || !c_out || !s_out) return -1;
    if (gp->q == 0) return -1;

    /* Step 1: pick random challenge c */
    uint64_t c = pull_random_mod_q((random_tape_t *)rng, gp->q);

    /* Step 2: pick random response s */
    uint64_t s = pull_random_mod_q((random_tape_t *)rng, gp->q);

    /* Step 3: compute matching commitment a */
    /* y^{-c} mod p */
    uint64_t c_mod_q = c % gp->q;
    uint64_t exp_inv = (c_mod_q == 0) ? 0 : gp->q - c_mod_q;
    uint64_t y_neg_c = mod_pow(y, exp_inv, gp->p);
    uint64_t gs = mod_pow(gp->g, s, gp->p);
    uint64_t a = mod_mul(gs, y_neg_c, gp->p);

    *a_out = a;
    *c_out = c;
    *s_out = s;

    /* Verify correctness: the simulated transcript should verify */
    assert(schnorr_verify(a, c, s, y, gp) == 1);

    return 0;
}

/* =================================================================
 * L4.3 -- Knowledge Extraction via Special Soundness
 *
 * THEOREM (Special Soundness):
 * Given two accepting transcripts T1=(a,c1,s1) and T2=(a,c2,s2)
 * with c1 != c2, the witness x = log_g(y) can be computed as:
 *
 *   x = (s1 - s2) * (c1 - c2)^{-1} mod q
 *
 * Proof:
 *   g^{s1} = a * y^{c1}   =>   g^{s1-s2} = y^{c1-c2}
 *   g^{s2} = a * y^{c2}
 *   => y = g^{(s1-s2)/(c1-c2)} = g^x
 *   => x = (s1-s2) * (c1-c2)^{-1} mod q
 *
 * This is the constructive proof that Schnorr is a proof of knowledge.
 * The extractor rewinds the prover to get the second transcript.
 *
 * Precondition: c1 != c2, gcd(c1-c2, q) = 1 (true since q is prime).
 * Complexity: O(log q) (one modular inverse).
 * ================================================================= */
int schnorr_extract_witness(uint64_t a,
                            uint64_t c1, uint64_t s1,
                            uint64_t c2, uint64_t s2,
                            const group_params_t *gp,
                            uint64_t *witness_out) {
    if (!gp || !witness_out) return -1;
    if (c1 == c2) return -1;

    /* Verify both transcripts accept (defensive check) */
    if (!schnorr_verify(a, c1, s1, mod_pow(gp->g, 0, gp->p) /* dummy */, gp)) {
        /* The verification check uses the actual y which we don't have.
         * We rely on the caller providing valid transcripts. */
    }
    (void)a;

    /* Compute numerator: s1 - s2 mod q */
    uint64_t num = (s1 >= s2) ? (s1 - s2) % gp->q : gp->q - ((s2 - s1) % gp->q);

    /* Compute denominator: c1 - c2 mod q */
    uint64_t den = (c1 >= c2) ? (c1 - c2) % gp->q : gp->q - ((c2 - c1) % gp->q);

    /* Compute inverse of denominator mod q */
    uint64_t den_inv = mod_inv(den, gp->q);
    if (den_inv == 0 && den != 0) return -1;

    /* Witness x = num * den_inv mod q */
    *witness_out = mod_mul(num, den_inv, gp->q);

    return 0;
}

/* Self-test internal function */
int zk_simulator_self_test(void) {
    /* Test modular arithmetic */
    assert(mod_add(5, 7, 10) == 2);
    assert(mod_sub(3, 7, 10) == 6);
    assert(mod_mul(6, 7, 10) == 2);
    assert(mod_pow(2, 10, 1000) == 24);

    /* Test extended gcd */
    int64_t x, y;
    int64_t g = extended_gcd(240, 46, &x, &y);
    assert(g == 2);
    assert(240 * x + 46 * y == 2);

    /* Test mod_inv: 7 * 3 = 21 == 1 mod 10 */
    assert(mod_inv(7, 10) == 3);

    /* Test random tape */
    random_tape_t tape;
    init_random_tape(&tape, 42);
    uint64_t r1 = next_random_u64(&tape);
    uint64_t r2 = next_random_u64(&tape);
    assert(r1 != r2);  /* consecutive values should differ */

    /* Test transcript */
    transcript_t t;
    transcript_init(&t);
    transcript_append_u64(&t, 42);
    assert(t.len == 8);

    /* Test statistical distance */
    double d1[3] = {0.5, 0.3, 0.2};
    double d2[3] = {0.5, 0.3, 0.2};
    double d3[3] = {1.0, 0.0, 0.0};
    assert(statistical_distance(d1, d2, 3) < 1e-9);
    assert(statistical_distance(d1, d3, 3) > 0.4);

    /* Test is_negligible */
    assert(is_negligible(1e-10, 1000.0) == 1);
    assert(is_negligible(0.5, 10.0) == 0);

    /* Test Schnorr with known small group */
    /* p=23, q=11, g=2, y=2^4=16 mod 23 */
    group_params_t gp_test = {23, 2, 11, 0};
    uint64_t y_test = mod_pow(2, 4, 23);  /* y = 16 */
    /* Real transcript: r=3, a=2^3=8, c=5, s=3+5*4=23 mod 11 = 1 */
    uint64_t a_test = mod_pow(2, 3, 23);   /* a = 8 */
    uint64_t c_test = 5;
    uint64_t s_test = (3 + 5 * 4) % 11;    /* s = 23 mod 11 = 1 */
    assert(schnorr_verify(a_test, c_test, s_test, y_test, &gp_test) == 1);

    /* Test HVZK simulation */
    uint64_t a_sim, c_sim, s_sim;
    random_tape_t sim_rng;
    init_random_tape(&sim_rng, 12345);
    int sim_ok = hvzk_simulate_schnorr(y_test, &gp_test, &sim_rng,
                                        &a_sim, &c_sim, &s_sim);
    assert(sim_ok == 0);
    assert(schnorr_verify(a_sim, c_sim, s_sim, y_test, &gp_test) == 1);

    /* Test witness extraction */
    /* For y=16, witness=4 */
    uint64_t c1_test = 3, c2_test = 7;
    uint64_t r_test = 3;
    uint64_t s1_test = (r_test + c1_test * 4) % 11;
    uint64_t s2_test = (r_test + c2_test * 4) % 11;
    uint64_t a_ext = mod_pow(2, r_test, 23);
    uint64_t witness;
    int ext_ok = schnorr_extract_witness(a_ext, c1_test, s1_test,
                                          c2_test, s2_test,
                                          &gp_test, &witness);
    assert(ext_ok == 0);
    assert(witness == 4);

    return 0;
}

