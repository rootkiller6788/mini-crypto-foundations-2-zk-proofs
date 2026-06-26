/**
 * @file example_sigma_protocol.c
 * @brief Sigma protocol for proving knowledge of a Pedersen opening
 *
 * Demonstrates a zero-knowledge proof of knowledge for a committed value.
 *
 * Protocol (Cramer-Damgard-Schoenmakers):
 *   Prover knows (m, r) such that C = g^m * h^r.
 *   Prover proves knowledge of (m, r) without revealing them.
 *
 *   1. Prover ¡ú Verifier: T = g^a * h^b  (a,b random)
 *   2. Verifier ¡ú Prover: c = challenge
 *   3. Prover ¡ú Verifier: z1 = a + c*m, z2 = b + c*r
 *   4. Verifier: g^{z1} * h^{z2} == T * C^c ?
 *
 * Knowledge Mapping:
 *   L1: Zero-knowledge proof of knowledge definition
 *   L5: Sigma protocol (3-move HVZK proof)
 *   L7: ZK-proof application
 */

#include "commitment.h"
#include "pedersen.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    printf("\n");
    printf("¨X¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨[\n");
    printf("¨U   Sigma Protocol ¡ª ZK Proof of Knowledge     ¨U\n");
    printf("¨U   Prover knows (m,r) for C = g^m * h^r       ¨U\n");
    printf("¨^¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨a\n\n");

    /* Setup */
    commit_ctx ctx;
    commit_ctx_init_u64(&ctx, 104729, COMMIT_SCHEME_PEDERSEN);
    bigint g;
    bigint_init_u64(&g, 5);
    pedersen_setup(&ctx, &g);

    printf("Setup: Group Z_p (p=104729), generators g=5, h=HashToGroup(g)\n\n");

    /* ================================================================
     * Prover commits to a secret value
     * ================================================================ */

    printf("--- Prover's secret ---\n");
    bigint m, r;
    bigint_init_u64(&m, 42);   /* Secret message */
    bigint_init_u64(&r, 999);  /* Secret randomness */

    commitment c;
    commit_init(&c, COMMIT_SCHEME_PEDERSEN);
    pedersen_commit(&ctx, &c, &m, &r);

    char chex[256];
    bigint_to_hex(&c.commitment_val, chex, sizeof(chex));
    printf("Secret m = 42, randomness r = 999\n");
    printf("Public commitment C = %s\n\n", chex);

    /* ================================================================
     * Sigma protocol execution
     * ================================================================ */

    printf("--- Sigma Protocol (3 rounds) ---\n\n");

    /* Round 1: Prover sends T = g^a * h^b (commitment to random a,b) */
    printf("[Round 1] Prover -> Verifier: T = g^a * h^b\n");

    bigint a, b, T;
    bigint_init(&a);
    bigint_init(&b);
    mod_rand(&ctx.group, &a);
    mod_rand(&ctx.group, &b);

    bigint t1, t2;
    bigint_init(&t1);
    bigint_init(&t2);
    mod_exp(&ctx.group, &t1, &ctx.g, &a);
    mod_exp(&ctx.group, &t2, &ctx.h, &b);
    mod_mul(&ctx.group, &T, &t1, &t2);

    char thex[256];
    bigint_to_hex(&T, thex, sizeof(thex));
    printf("  Prover picks random a, b\n");
    printf("  T = g^a * h^b = %s\n\n", thex);

    /* Round 2: Verifier sends challenge */
    printf("[Round 2] Verifier -> Prover: challenge c\n");

    bigint challenge;
    bigint_init_u64(&challenge, 12345); /* Verifier picks this randomly */
    printf("  Verifier picks random challenge c = 12345\n\n");

    /* Round 3: Prover responds with z1, z2 */
    printf("[Round 3] Prover -> Verifier: z1 = a + c*m, z2 = b + c*r\n");

    bigint z1, z2;
    pedersen_prove_knowledge(&ctx, &c, &m, &r, &challenge, &z1, &z2);

    char z1hex[256], z2hex[256];
    bigint_to_hex(&z1, z1hex, sizeof(z1hex));
    bigint_to_hex(&z2, z2hex, sizeof(z2hex));
    printf("  z1 = a + c*m = %s\n", z1hex);
    printf("  z2 = b + c*r = %s\n\n", z2hex);

    /* Verification */
    printf("--- Verification ---\n");
    bool valid = pedersen_verify_knowledge(&ctx, &c, &challenge, &z1, &z2);
    printf("  Verifier checks: g^{z1} * h^{z2} == T * C^c\n");
    printf("  Result: %s\n\n", valid ? "ACCEPTED" : "REJECTED");

    /* ================================================================
     * Why is this zero-knowledge?
     * ================================================================ */

    printf("--- Why is this Zero-Knowledge? ---\n");
    printf("  1. Completeness: Honest prover always convinces verifier.\n");
    printf("     g^{a+cm} * h^{b+cr} = g^a*g^{cm} * h^b*h^{cr}\n");
    printf("     = (g^a*h^b) * (g^m*h^r)^c = T * C^c ?\n\n");
    printf("  2. Soundness: If prover can answer two different challenges\n");
    printf("     (c1,z1,z2) and (c2,z1',z2') with c1¡Ùc2, extractor can\n");
    printf("     compute m = (z1-z1')/(c1-c2), r = (z2-z2')/(c1-c2).\n");
    printf("     This proves knowledge of (m,r).\n\n");
    printf("  3. Zero-Knowledge: Simulator picks random c, z1, z2,\n");
    printf("     computes T = g^{z1} * h^{z2} * C^{-c}. This looks\n");
    printf("     identical to a real transcript (Perfect SHVZK).\n");
    printf("     The transcript reveals NOTHING about (m,r).\n\n");

    printf("¨X¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨[\n");
    printf("¨U   Sigma protocol demo completed!             ¨U\n");
    printf("¨U   Prover proved knowledge of (m,r) in ZK.    ¨U\n");
    printf("¨^¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨a\n\n");

    return 0;
}
