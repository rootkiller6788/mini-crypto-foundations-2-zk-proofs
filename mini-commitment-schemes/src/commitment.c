/**
 * @file commitment.c
 * @brief Generic commitment scheme framework implementation
 *
 * Implements the commitment scheme lifecycle and protocol operations
 * independent of the specific construction. Acts as a dispatcher that
 * routes to scheme-specific implementations (Pedersen, hash, etc.).
 *
 * Knowledge Mapping:
 *   L1: Definitions �� commitment lifecycle, commit/open/verify
 *   L2: Core Concepts �� hiding game, binding game, security reduction
 *   L4: Fundamental Laws �� DL assumption reduced to Pedersen binding
 *   L7: Applications �� coin flipping, Sigma protocols
 *   L8: Advanced �� homomorphic properties, trapdoor equivocation
 */

#include "commitment.h"
#include "pedersen.h"
#include "hash_commit.h"
#include "vector_commit.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* =========================================================================
 * Internal helpers
 * ========================================================================= */

/** Simple XOR-based pseudo-random number generator for simulation.
 *  In production, use a CSPRNG. This is for deterministic testing. */
static uint64_t sim_rand_state = 0xDEADBEEFCAFE1234ULL;

static uint64_t sim_rand_u64(void) {
    sim_rand_state ^= sim_rand_state << 13;
    sim_rand_state ^= sim_rand_state >> 7;
    sim_rand_state ^= sim_rand_state << 17;
    return sim_rand_state;
}

static void sim_rand_bigint(const modctx *ctx, bigint *r) {
    bigint_init(r);
    size_t nlimbs = (ctx->modulus_bits + 63) / 64;
    if (nlimbs > BIGINT_MAX_LIMBS) nlimbs = BIGINT_MAX_LIMBS;
    for (size_t i = 0; i < nlimbs; i++) {
        r->limbs[i] = sim_rand_u64();
    }
    r->nlimbs = nlimbs;
    /* Trim leading zeros (bigint_trim is static in bigint.c, inline here) */
    while (r->nlimbs > 0 && r->limbs[r->nlimbs - 1] == 0) {
        r->nlimbs--;
    }
    bigint_mod(r, &ctx->modulus);
}

/* =========================================================================
 * Lifecycle
 * ========================================================================= */

void commit_ctx_init(commit_ctx *ctx, const bigint *modulus,
                     commit_scheme_type scheme) {
    modctx_init(&ctx->group, modulus);
    ctx->active_scheme = scheme;
    bigint_init(&ctx->g);
    bigint_init(&ctx->h);
    ctx->pedersen_setup = false;
    ctx->hash_security = 256;
    bigint_init(&ctx->fujisaki_n);
    bigint_init(&ctx->fujisaki_g);
    ctx->fujisaki_setup = false;
    bigint_init(&ctx->trapdoor);
    ctx->has_trapdoor = false;
}

void commit_ctx_init_u64(commit_ctx *ctx, uint64_t modulus,
                         commit_scheme_type scheme) {
    bigint m;
    bigint_init_u64(&m, modulus);
    commit_ctx_init(ctx, &m, scheme);
}

void commit_init(commitment *c, commit_scheme_type scheme) {
    bigint_init(&c->commitment_val);
    bigint_init(&c->message);
    bigint_init(&c->randomness);
    c->opened = false;
    c->scheme = scheme;
    /* Set security properties based on scheme type */
    switch (scheme) {
        case COMMIT_SCHEME_PEDERSEN:
            c->hiding_level  = SECURITY_PERFECT;
            c->binding_level = SECURITY_COMPUTATIONAL;
            break;
        case COMMIT_SCHEME_HASH_SHA256:
            c->hiding_level  = SECURITY_COMPUTATIONAL;
            c->binding_level = SECURITY_COMPUTATIONAL;
            break;
        case COMMIT_SCHEME_VECTOR_MERKLE:
            c->hiding_level  = SECURITY_COMPUTATIONAL;
            c->binding_level = SECURITY_COMPUTATIONAL;
            break;
        case COMMIT_SCHEME_FUJISAKI_OKAMOTO:
            c->hiding_level  = SECURITY_STATISTICAL;
            c->binding_level = SECURITY_COMPUTATIONAL;
            break;
        default:
            c->hiding_level  = SECURITY_COMPUTATIONAL;
            c->binding_level = SECURITY_COMPUTATIONAL;
            break;
    }
}

void commit_ctx_destroy(commit_ctx *ctx) {
    (void)ctx; /* Stack-allocated, no cleanup needed */
}

/* =========================================================================
 * Commit phase �� C = Commit(m, r)  (L1, L5)
 *
 * Routes to the appropriate scheme-specific commit function.
 *
 * For each scheme:
 *   Pedersen: C = g^m * h^r (mod p)
 *   Hash:     C = H(m || r)
 *   Vector:   C = MerkleRoot(v) where v is composed from m
 *
 * Theorem (Completeness):
 *   For any m, r: Verify(Commit(m, r), m, r) == true.
 *   Proof: By construction, Commit(m,r) produces C, and Verify
 *   recomputes Commit(m,r) and compares to C. Since the commit
 *   function is deterministic, the values match.
 * ========================================================================= */

bool commit_do(commit_ctx *ctx, commitment *c,
               const bigint *m, const bigint *r) {
    if (ctx == NULL || c == NULL || m == NULL || r == NULL) return false;

    switch (ctx->active_scheme) {
        case COMMIT_SCHEME_PEDERSEN:
            if (!ctx->pedersen_setup) {
                /* Auto-setup with a default generator */
                bigint g_default;
                bigint_init_u64(&g_default, 2);
                pedersen_setup(ctx, &g_default);
            }
            return pedersen_commit(ctx, c, m, r);

        case COMMIT_SCHEME_HASH_SHA256:
            hash_commit(m, r, &c->commitment_val);
            bigint_copy(&c->message, m);
            bigint_copy(&c->randomness, r);
            c->scheme = COMMIT_SCHEME_HASH_SHA256;
            return true;

        case COMMIT_SCHEME_VECTOR_MERKLE: {
            /* For vector commitment, treat m as a single-element vector */
            vector_commitment vc;
            vc_init(&vc, 1);
            vc_set_element(&vc, 0, m);
            if (!vc_commit(&vc)) return false;
            bigint_copy(&c->commitment_val, vc_get_commitment(&vc));
            bigint_copy(&c->message, m);
            bigint_copy(&c->randomness, r);
            c->scheme = COMMIT_SCHEME_VECTOR_MERKLE;
            vc_destroy(&vc);
            return true;
        }

        case COMMIT_SCHEME_FUJISAKI_OKAMOTO:
            /* Fujisaki-Okamoto uses integer commitment over Z_n:
             * C = g^m * r^n mod n (where n is an RSA modulus).
             * For educational purposes, we approximate with Pedersen
             * over a composite modulus. */
            if (!ctx->fujisaki_setup) {
                /* Use the modulus as-is; for proper FO, n would be RSA */
                bigint_copy(&ctx->fujisaki_g, &ctx->g);
                if (bigint_is_zero(&ctx->fujisaki_g)) {
                    bigint_init_u64(&ctx->fujisaki_g, 2);
                }
                ctx->fujisaki_setup = true;
            }
            /* C = g^m * r^n mod n (simplification: r^1) */
            return pedersen_commit(ctx, c, m, r);

        default:
            return false;
    }
}

bool commit_do_random(commit_ctx *ctx, commitment *c, const bigint *m) {
    bigint r;
    if (!mod_rand_nonzero(&ctx->group, &r)) return false;
    bool ok = commit_do(ctx, c, m, &r);
    /* r is copied into c->randomness by commit_do, so no leak */
    return ok;
}

/* =========================================================================
 * Open and Verify phase (L1, L5)
 * ========================================================================= */

void commit_open(commitment *c) {
    c->opened = true;
}

bool commit_verify(const commit_ctx *ctx, const commitment *c) {
    if (!c->opened) return false;
    if (ctx == NULL || c == NULL) return false;

    switch (c->scheme) {
        case COMMIT_SCHEME_PEDERSEN:
            return pedersen_verify(ctx, c);

        case COMMIT_SCHEME_HASH_SHA256:
            return hash_commit_verify(&c->commitment_val,
                                      &c->message, &c->randomness);

        case COMMIT_SCHEME_VECTOR_MERKLE: {
            /* Recompute the single-element vector commitment */
            vector_commitment vc;
            vc_init(&vc, 1);
            vc_set_element(&vc, 0, &c->message);
            if (!vc_commit(&vc)) return false;
            bool match = (bigint_cmp(&c->commitment_val,
                                     vc_get_commitment(&vc)) == 0);
            vc_destroy(&vc);
            return match;
        }

        case COMMIT_SCHEME_FUJISAKI_OKAMOTO:
            return pedersen_verify(ctx, c);

        default:
            return false;
    }
}

/* =========================================================================
 * Hiding property test (L2, L4)
 *
 * The hiding game (computationally hiding variant):
 *
 *   1. Adversary chooses m0, m1 (distinct messages).
 *   2. Challenger picks random bit b �� {0,1} and random r.
 *   3. Challenger computes C = Commit(m_b, r) and sends C to adversary.
 *   4. Adversary outputs guess b' �� {0,1}.
 *   5. Advantage = |Pr[b' = b] - 1/2|
 *
 * For perfectly hiding schemes (Pedersen):
 *   The distribution of C is identical for m0 and m1 because
 *   for any C and any m, there exists a unique r such that
 *   C = g^m * h^r. Therefore advantage = 0 (exactly).
 *
 * For computationally hiding schemes:
 *   Advantage is negligible in the security parameter.
 *
 * This function simulates the game and estimates the advantage.
 * ========================================================================= */

bool commit_test_hiding(const commit_ctx *ctx,
                        const bigint *m0, const bigint *m1,
                        double *advantage, size_t trials) {
    if (ctx == NULL || m0 == NULL || m1 == NULL || advantage == NULL)
        return false;
    if (trials == 0) trials = 100;

    size_t correct = 0;

    for (size_t t = 0; t < trials; t++) {
        /* Challenger picks random bit b */
        int b = sim_rand_u64() & 1;
        const bigint *m = (b == 0) ? m0 : m1;

        /* Challenger generates random r and commits */
        bigint r;
        sim_rand_bigint(&ctx->group, &r);
        commitment c;
        commit_init(&c, ctx->active_scheme);
        commit_do((commit_ctx *)ctx, &c, m, &r);

        /* Adversary observes c.commitment_val and guesses b.
         * For perfect hiding: C is independent of m, so adversary
         * can do no better than guessing. We simulate an "honest"
         * adversary that guesses based on observable differences:

         * For Pedersen: C = g^m * h^r. Since h = g^x for unknown x,
         * C = g^{m + x*r}. The values m0 and m1 produce commitments
         * from the same uniform distribution (perfect hiding).
         * The adversary can only guess randomly. */

        /* Simulate a simple adversary: check if commitment value
         * is "closer" to one of the messages (this is a weak test
         * that only works for non-perfectly-hiding schemes). */
        bigint diff0, diff1;
        bigint_init(&diff0);
        bigint_init(&diff1);

        if (bigint_cmp(&c.commitment_val, m0) >= 0) {
            bigint_sub_from(&diff0, &c.commitment_val, m0);
        } else {
            bigint_sub_from(&diff0, m0, &c.commitment_val);
        }
        if (bigint_cmp(&c.commitment_val, m1) >= 0) {
            bigint_sub_from(&diff1, &c.commitment_val, m1);
        } else {
            bigint_sub_from(&diff1, m1, &c.commitment_val);
        }

        int guess;
        if (bigint_cmp(&diff0, &diff1) < 0) {
            guess = 0;
        } else if (bigint_cmp(&diff1, &diff0) < 0) {
            guess = 1;
        } else {
            guess = sim_rand_u64() & 1;
        }

        if (guess == b) correct++;
    }

    *advantage = ((double)correct / (double)trials) - 0.5;
    if (*advantage < 0) *advantage = -*advantage; /* absolute value */
    return true;
}

/* =========================================================================
 * Binding property test (L2, L4)
 *
 * The binding game:
 *   Can we find (m, r) and (m', r') with m != m' such that
 *   Commit(m, r) = Commit(m', r')?
 *
 * For Pedersen: This is equivalent to computing log_g(h):
 *   g^m * h^r = g^{m'} * h^{r'}
 *   => g^{m - m'} = h^{r' - r}
 *   => h = g^{(m - m')/(r' - r)}  =>  log_g(h) = (m - m')/(r' - r)
 *
 * Theorem: Breaking the binding property of Pedersen commitments
 *   is polynomial-time equivalent to solving the discrete logarithm
 *   problem in the underlying group.
 *
 * This function attempts to find a binding collision by brute force
 * (infeasible for real parameters, demonstrating computational binding).
 * ========================================================================= */

bool commit_test_binding(const commit_ctx *ctx, size_t attempt,
                         bigint *m, bigint *r,
                         bigint *m2, bigint *r2) {
    if (ctx == NULL || m == NULL || r == NULL || m2 == NULL || r2 == NULL)
        return false;
    (void)attempt; /* Used for seed in multi-attempt scenarios */

    /* We simulate a failed binding attack to demonstrate the property.
     * The function returns false (no collision found) for real parameters,
     * illustrating computational binding. */

    /* For small test moduli, we can attempt to find collisions by brute
     * force search, but this would be infeasible for cryptographic sizes. */
    if (ctx->group.modulus_bits > 32) {
        /* Modulus too large �� binding holds computationally.
         * Return false to indicate no collision found. */
        return false;
    }

    /* For small test moduli: brute-force search for a collision.
     * This demonstrates that computational binding is a property that
     * depends on the hardness of the underlying problem. */
    uint64_t mod_u64;
    bigint_to_u64(&ctx->group.modulus, &mod_u64);

    uint64_t m_val, r_val;
    bigint_to_u64(m, &m_val);
    bigint_to_u64(r, &r_val);

    /* Search for m' != m such that g^m * h^r = g^{m'} * h^{r'}
     * For small modulus, try all possible values. */
    for (uint64_t mp = 0; mp < mod_u64; mp++) {
        if (mp == m_val) continue;
        /* If h = g^x, then we need m + x*r = m' + x*r' (mod q, the group order)
         * => r' = (m - m' + x*r) / x (mod q)
         * Since we don't know x in the normal setup, this is hard.
         * For this demo, we search r' directly. */
        for (uint64_t rp = 0; rp < mod_u64; rp++) {
            if (rp == r_val) continue;

            bigint bm, br, bmp, brp;
            bigint_init_u64(&bm, m_val);
            bigint_init_u64(&br, r_val);
            bigint_init_u64(&bmp, mp);
            bigint_init_u64(&brp, rp);

            /* Check C(m,r) == C(m',r') */
            bigint c1_val, c2_val;
            bigint_init(&c1_val);
            bigint_init(&c2_val);

            mod_exp(&ctx->group, &c1_val, &ctx->g, &bm);
            bigint temp;
            bigint_init(&temp);
            mod_exp(&ctx->group, &temp, &ctx->h, &br);
            mod_mul(&ctx->group, &c1_val, &c1_val, &temp);

            mod_exp(&ctx->group, &c2_val, &ctx->g, &bmp);
            mod_exp(&ctx->group, &temp, &ctx->h, &brp);
            mod_mul(&ctx->group, &c2_val, &c2_val, &temp);

            if (bigint_cmp(&c1_val, &c2_val) == 0) {
                bigint_init_u64(m2, mp);
                bigint_init_u64(r2, rp);
                return true; /* Collision found */
            }
        }
    }

    return false; /* No collision found */
}

/* =========================================================================
 * Homomorphic combination (L8: Advanced)
 *
 * For additively homomorphic commitment schemes (like Pedersen),
 * we can combine two commitments without knowing the openings:
 *
 *   c_out = c1 ? c2  where ? is the homomorphic operation.
 *
 * For Pedersen:
 *   Commit(m1,r1) ? Commit(m2,r2)
 *     = g^{m1}*h^{r1} * g^{m2}*h^{r2}
 *     = g^{m1+m2} * h^{r1+r2}
 *     = Commit(m1+m2, r1+r2)
 *
 * This enables constructions like range proofs, where a prover
 * commits to each bit and the verifier can check the sum.
 * ========================================================================= */

bool commit_homomorphic_combine(const commit_ctx *ctx,
                                const commitment *c1,
                                const commitment *c2,
                                commitment *c_out) {
    if (ctx == NULL || c1 == NULL || c2 == NULL || c_out == NULL)
        return false;

    /* Only Pedersen and Fujisaki-Okamoto support homomorphic combination */
    if (c1->scheme != COMMIT_SCHEME_PEDERSEN &&
        c1->scheme != COMMIT_SCHEME_FUJISAKI_OKAMOTO) {
        return false;
    }
    if (c2->scheme != c1->scheme) return false;

    /* c_out.commitment = c1.commitment * c2.commitment mod p */
    mod_mul(&ctx->group, &c_out->commitment_val,
            &c1->commitment_val, &c2->commitment_val);
    c_out->scheme = c1->scheme;
    c_out->opened = false;
    c_out->hiding_level = c1->hiding_level;
    c_out->binding_level = c1->binding_level;

    /* The message and randomness are not yet opened ��
     * they would be m1+m2 and r1+r2 respectively. */
    bigint_init(&c_out->message);
    bigint_init(&c_out->randomness);

    return true;
}

bool commit_verify_homomorphic(const commit_ctx *ctx,
                               const commitment *c1,
                               const commitment *c2,
                               const commitment *c_out) {
    if (ctx == NULL || c1 == NULL || c2 == NULL || c_out == NULL)
        return false;
    if (!c1->opened || !c2->opened || !c_out->opened) return false;

    /* Check: m_out �� m1 + m2 (mod p) */
    bigint m_sum;
    bigint_init(&m_sum);
    mod_add(&ctx->group, &m_sum, &c1->message, &c2->message);

    if (!mod_eq(&ctx->group, &c_out->message, &m_sum)) return false;

    /* Check: r_out �� r1 + r2 (mod p) */
    bigint r_sum;
    bigint_init(&r_sum);
    mod_add(&ctx->group, &r_sum, &c1->randomness, &c2->randomness);

    if (!mod_eq(&ctx->group, &c_out->randomness, &r_sum)) return false;

    /* Verify the combined commitment */
    return commit_verify(ctx, c_out);
}

/* =========================================================================
 * Trapdoor and equivocation (L8: Advanced)
 *
 * Pedersen commitment with known trapdoor x = log_g(h):
 *
 * Given C = g^m * h^r, we can open to any m' by computing:
 *   r' = r + (m - m') / x  (mod q, the group order)
 *
 * Then: g^{m'} * h^{r'} = g^{m'} * h^{r + (m-m')/x}
 *   = g^{m'} * h^r * h^{(m-m')/x}
 *   = g^{m'} * h^r * (g^x)^{(m-m')/x}
 *   = g^{m'} * h^r * g^{m-m'}
 *   = g^m * h^r = C  ?
 *
 * This is exactly how the ZK-proof simulator works:
 *   - Setup: Simulator knows x = log_g(h) (trapdoor).
 *   - Simulation: Commit to arbitrary m, then equivocate to
 *     whatever message the protocol requires.
 *
 * Theorem: If log_g(h) is known, Pedersen commitment is
 *   perfectly hiding (still) but NOT binding (for the trapdoor holder).
 * ========================================================================= */

bool commit_set_trapdoor(commit_ctx *ctx, const bigint *trapdoor) {
    if (ctx == NULL || trapdoor == NULL) return false;
    if (ctx->active_scheme != COMMIT_SCHEME_PEDERSEN &&
        ctx->active_scheme != COMMIT_SCHEME_FUJISAKI_OKAMOTO) {
        return false;
    }
    bigint_copy(&ctx->trapdoor, trapdoor);
    ctx->has_trapdoor = true;

    /* Setup h = g^x for the trapdoor */
    if (ctx->pedersen_setup) {
        mod_exp(&ctx->group, &ctx->h, &ctx->g, trapdoor);
    }
    return true;
}

bool commit_equivocate(const commit_ctx *ctx, const commitment *c,
                       const bigint *new_msg, bigint *new_rand) {
    if (ctx == NULL || c == NULL || new_msg == NULL || new_rand == NULL)
        return false;
    if (!ctx->has_trapdoor) return false;

    /* Compute new randomness: r' = r + (m - m') / x  (mod p-1 for order) */
    bigint m_diff;
    bigint_init(&m_diff);

    /* m_diff = m - m' (mod p) */
    mod_sub(&ctx->group, &m_diff, &c->message, new_msg);

    /* multiply by inverse of trapdoor: (m - m') / x �� (m - m') * x^{-1} */
    bigint inv_trapdoor;
    bigint_init(&inv_trapdoor);
    if (!mod_inv(&ctx->group, &inv_trapdoor, &ctx->trapdoor)) {
        return false; /* Trapdoor must be invertible mod p */
    }

    bigint adjustment;
    bigint_init(&adjustment);
    mod_mul(&ctx->group, &adjustment, &m_diff, &inv_trapdoor);

    /* new_rand = r + adjustment (mod p) */
    mod_add(&ctx->group, new_rand, &c->randomness, &adjustment);

    return true;
}

/* =========================================================================
 * Coin flipping protocol (L7: Application �� Blum 1981)
 *
 * Problem: Alice and Bob want to flip a fair coin over the telephone.
 * Neither should be able to cheat after seeing the other's value.
 *
 * Protocol:
 *   1. Alice picks random bit a, randomness r, computes C = Commit(a, r).
 *      She sends C to Bob.
 *   2. Bob picks random bit b and sends it to Alice (in the clear).
 *   3. Alice opens C, revealing a and r.
 *      Bob verifies Verify(C, a, r) == true.
 *   4. Result: a XOR b.
 *
 * Security:
 *   - Hiding: Bob cannot learn a from C before step 3.
 *   - Binding: Alice cannot change a after seeing b in step 2.
 *
 * Violations (demonstrating why both properties matter):
 *   - Without hiding: Bob learns a, can choose b to force result.
 *   - Without binding: Alice can change a after seeing b.
 * ========================================================================= */

bool commit_coin_flip(commit_ctx *ctx, int alice_bit, int bob_bit, int *result) {
    if (ctx == NULL || result == NULL) return false;
    if (alice_bit != 0 && alice_bit != 1) return false;
    if (bob_bit != 0 && bob_bit != 1) return false;

    /* Step 1: Alice commits to her bit */
    bigint m, r;
    bigint_init_u64(&m, (uint64_t)alice_bit);
    if (!mod_rand_nonzero(&ctx->group, &r)) return false;

    commitment c;
    commit_init(&c, ctx->active_scheme);
    if (!commit_do(ctx, &c, &m, &r)) return false;

    /* Step 2: Bob sends his bit (simulated �� already known) */

    /* Step 3: Alice opens */
    commit_open(&c);

    /* Step 4: Bob verifies and computes result */
    if (!commit_verify(ctx, &c)) return false;

    *result = alice_bit ^ bob_bit;
    return true;
}

/* =========================================================================
 * Sigma-protocol commitment step (L7: Application)
 *
 * In a Sigma-protocol (3-move ZK proof):
 *   Prover                    Verifier
 *   ------                    --------
 *   t = random();             
 *   a = Commit(t)      --->
 *                           <--- c = challenge()
 *   z = f(witness, t, c) --->
 *                            Verify(a, c, z)
 *
 * The commitment a prevents the prover from adapting their
 * response after seeing the challenge c.
 *
 * This is the "first message" of the protocol.
 * ========================================================================= */

bool commit_sigma_protocol_commit(commit_ctx *ctx, commitment *c,
                                  const bigint *witness) {
    if (ctx == NULL || c == NULL || witness == NULL) return false;

    /* t = random nonce (simulated commitment to a random value) */
    bigint t;
    if (!mod_rand_nonzero(&ctx->group, &t)) return false;

    /* a = Commit(t) �� the prover's first message */
    return commit_do(ctx, c, &t, witness);
}

/* =========================================================================
 * Scheme description utilities (L2, L6)
 * ========================================================================= */

const char* commit_scheme_name(commit_scheme_type scheme) {
    switch (scheme) {
        case COMMIT_SCHEME_PEDERSEN:         return "Pedersen";
        case COMMIT_SCHEME_HASH_SHA256:      return "Hash-based (SHA-256)";
        case COMMIT_SCHEME_VECTOR_MERKLE:    return "Vector (Merkle tree)";
        case COMMIT_SCHEME_FUJISAKI_OKAMOTO: return "Fujisaki-Okamoto";
        default:                              return "Unknown";
    }
}

const char* security_level_name(security_level level) {
    switch (level) {
        case SECURITY_PERFECT:       return "Perfect";
        case SECURITY_STATISTICAL:   return "Statistical";
        case SECURITY_COMPUTATIONAL: return "Computational";
        default:                     return "Unknown";
    }
}

void commit_describe(const commit_ctx *ctx, const commitment *c, char *buf, size_t n) {
    char chex[512];
    char mhex[512];
    char rhez[512];

    bigint_to_hex(&c->commitment_val, chex, sizeof(chex));
    bigint_to_hex(&c->message, mhex, sizeof(mhex));
    bigint_to_hex(&c->randomness, rhez, sizeof(rhez));

    snprintf(buf, n,
        "Commitment Scheme: %s\n"
        "  Commitment C: %s\n"
        "  Message m:    %s\n"
        "  Randomness r: %s\n"
        "  Opened:       %s\n"
        "  Hiding:       %s\n"
        "  Binding:      %s\n",
        commit_scheme_name(c->scheme),
        chex,
        c->opened ? mhex : "(hidden)",
        c->opened ? rhez : "(hidden)",
        c->opened ? "yes" : "no",
        security_level_name(c->hiding_level),
        security_level_name(c->binding_level));
    (void)ctx;
}
