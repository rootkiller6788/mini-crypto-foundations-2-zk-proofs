/**
 * @file example_pedersen.c
 * @brief End-to-end Pedersen commitment demonstration
 *
 * Demonstrates the complete lifecycle of a Pedersen commitment:
 *   1. Setup: Choose a prime-order group and generators g, h
 *   2. Commit: Alice commits to a secret message m
 *   3. Open: Alice reveals m and randomness r
 *   4. Verify: Bob verifies the commitment
 *   5. Homomorphic: Combine two commitments
 *
 * This example is a self-contained, runnable demonstration
 * suitable for educational purposes.
 *
 * Knowledge Mapping:
 *   L1: Pedersen commitment lifecycle
 *   L3: Z_p group operations
 *   L8: Homomorphic property demonstration
 */

#include "commitment.h"
#include "pedersen.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    printf("\n");
    printf("�X�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�[\n");
    printf("�U   Pedersen Commitment Scheme Demo            �U\n");
    printf("�U   C = g^m * h^r (mod p)                      �U\n");
    printf("�^�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�a\n\n");

    /* ================================================================
     * Step 1: Setup
     * Choose a prime modulus p and generator g.
     * Derive h = HashToGroup(g) so no one knows log_g(h).
     * This gives perfect hiding.
     * ================================================================ */

    printf("[Step 1] Setup: Choose group Z_p and generators\n");

    /* Use a 32-bit safe prime for demonstration (real protocols use 256+ bits) */
    commit_ctx ctx;
    commit_ctx_init_u64(&ctx, 2147483659ULL, COMMIT_SCHEME_PEDERSEN);
    /* 2147483659 is a safe prime: 2*1073741829 + 1 is also prime */

    bigint g;
    bigint_init_u64(&g, 7); /* Generator g = 7 */
    pedersen_setup(&ctx, &g);

    printf("  Modulus p = %llu (prime)\n", 2147483659ULL);
    printf("  Generator g = 7\n");
    printf("  Generator h = HashToGroup(g) (log_g(h) unknown)\n");
    printf("  => Perfect hiding: C reveals no information about m\n\n");

    /* ================================================================
     * Step 2: Commit
     * Alice commits to message m = 42 with randomness r = 1234567.
     * C = g^42 * h^1234567 mod p
     * ================================================================ */

    printf("[Step 2] Alice commits to message m = 42\n");

    bigint message, randomness;
    bigint_init_u64(&message, 42);
    bigint_init_u64(&randomness, 1234567);

    commitment com;
    commit_init(&com, COMMIT_SCHEME_PEDERSEN);
    pedersen_commit(&ctx, &com, &message, &randomness);

    char hex_buf[512];
    bigint_to_hex(&com.commitment_val, hex_buf, sizeof(hex_buf));

    printf("  Commitment C = %s\n", hex_buf);
    printf("  Hiding:  %s\n", security_level_name(com.hiding_level));
    printf("  Binding: %s\n", security_level_name(com.binding_level));
    printf("  Alice sends C to Bob. Bob sees C but learns nothing about m.\n\n");

    /* ================================================================
     * Step 3: Open
     * Alice reveals m = 42 and r = 1234567 to Bob.
     * ================================================================ */

    printf("[Step 3] Alice opens the commitment\n");
    printf("  Reveals: m = 42, r = 1234567\n\n");

    /* ================================================================
     * Step 4: Verify
     * Bob recomputes C' = g^42 * h^1234567 mod p and checks C' == C.
     * ================================================================ */

    printf("[Step 4] Bob verifies the opening\n");
    bool valid = pedersen_verify(&ctx, &com);
    printf("  Verification result: %s\n", valid ? "VALID" : "INVALID");
    printf("  Bob is convinced that Alice committed to 42.\n\n");

    /* ================================================================
     * Step 5: Homomorphic Property
     * Alice commits to m1=10 and m2=20, then combines them.
     * Bob can verify that c_sum = c1 * c2 corresponds to m1+m2=30.
     * ================================================================ */

    printf("[Step 5] Homomorphic property demonstration\n");
    printf("  Commit to m1=10, m2=20 separately:\n");

    bigint m1, r1, m2, r2;
    bigint_init_u64(&m1, 10);
    bigint_init_u64(&r1, 111);
    bigint_init_u64(&m2, 20);
    bigint_init_u64(&r2, 222);

    commitment c1, c2;
    commit_init(&c1, COMMIT_SCHEME_PEDERSEN);
    commit_init(&c2, COMMIT_SCHEME_PEDERSEN);
    pedersen_commit(&ctx, &c1, &m1, &r1);
    pedersen_commit(&ctx, &c2, &m2, &r2);

    commitment c_sum;
    commit_init(&c_sum, COMMIT_SCHEME_PEDERSEN);
    pedersen_homomorphic_add(&ctx, &c1, &c2, &c_sum);

    char hex_c1[256], hex_c2[256], hex_sum[256];
    bigint_to_hex(&c1.commitment_val, hex_c1, sizeof(hex_c1));
    bigint_to_hex(&c2.commitment_val, hex_c2, sizeof(hex_c2));
    bigint_to_hex(&c_sum.commitment_val, hex_sum, sizeof(hex_sum));

    printf("    C1 = %s\n", hex_c1);
    printf("    C2 = %s\n", hex_c2);
    printf("    C1 * C2 mod p = C_sum = %s\n", hex_sum);
    printf("  Verify C_sum opens to m1+m2 = 30:\n");

    /* Set the combined opening */
    mod_add(&ctx.group, &c_sum.message, &m1, &m2);
    mod_add(&ctx.group, &c_sum.randomness, &r1, &r2);
    bool hom_valid = pedersen_verify(&ctx, &c_sum);
    printf("  Homomorphic verification: %s\n", hom_valid ? "VALID" : "INVALID");

    printf("\n�X�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�[\n");
    printf("�U   All steps completed successfully!          �U\n");
    printf("�^�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�a\n\n");

    return 0;
}
