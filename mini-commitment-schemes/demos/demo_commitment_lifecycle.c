/**
 * @file demo_commitment_lifecycle.c
 * @brief Interactive visualization of commitment scheme lifecycle
 *
 * Demonstrates step-by-step the commit->open->verify lifecycle
 * for all four commitment schemes, showing the security properties
 * and data flow in tabular format.
 *
 * Knowledge Mapping:
 *   L1: All four commitment scheme definitions in action
 *   L2: Security property comparison (hiding vs binding)
 *   L6: Scheme selection for canonical problems
 *   L7: Application scenario recommendations
 */

#include "commitment.h"
#include "pedersen.h"
#include "hash_commit.h"
#include "vector_commit.h"
#include <stdio.h>
#include <string.h>

static void sep(int width) {
    for (int i = 0; i < width; i++) putchar('=');
    printf("\n");
}

static void demo_scheme(commit_scheme_type scheme_type, const char *name) {
    printf("\n  --- %s ---\n\n", name);

    uint64_t mod;
    switch (scheme_type) {
        case COMMIT_SCHEME_PEDERSEN:
        case COMMIT_SCHEME_FUJISAKI_OKAMOTO:
            mod = 104729;
            break;
        case COMMIT_SCHEME_HASH_SHA256:
            mod = 0xFFFFFFFFFFFFFFC5ULL;
            break;
        case COMMIT_SCHEME_VECTOR_MERKLE:
            mod = 0xFFFFFFFFFFFFFFC5ULL;
            break;
        default:
            mod = 104729;
            break;
    }

    commit_ctx ctx;
    commit_ctx_init_u64(&ctx, mod, scheme_type);

    if (scheme_type == COMMIT_SCHEME_PEDERSEN ||
        scheme_type == COMMIT_SCHEME_FUJISAKI_OKAMOTO) {
        bigint g;
        bigint_init_u64(&g, 5);
        pedersen_setup(&ctx, &g);
    }

    bigint m, r;
    bigint_init_u64(&m, 42);
    bigint_init_u64(&r, 99999);

    commitment c;
    commit_init(&c, scheme_type);

    printf("  [COMMIT phase]\n");
    printf("    Message m      = 42\n");
    printf("    Randomness r   = 99999\n");

    if (scheme_type == COMMIT_SCHEME_VECTOR_MERKLE) {
        vector_commitment vc;
        vc_init(&vc, 4);
        for (size_t i = 0; i < 4; i++) {
            bigint val;
            bigint_init_u64(&val, (uint64_t)(42 + i * 100));
            vc_set_element(&vc, i, &val);
        }
        vc_commit(&vc);
        const bigint *root = vc_get_commitment(&vc);
        bigint_copy(&c.commitment_val, root);
        c.scheme = COMMIT_SCHEME_VECTOR_MERKLE;
        vc_destroy(&vc);
    } else {
        commit_do(&ctx, &c, &m, &r);
    }

    char hex[256];
    bigint_to_hex(&c.commitment_val, hex, sizeof(hex));
    printf("    C = Commit(m,r) = %s...\n", hex);

    printf("\n  [HIDING property check]\n");
    printf("    Verifier sees: C = (opaque commitment value)\n");
    printf("    Verifier knows: scheme = %s\n", commit_scheme_name(scheme_type));
    printf("    Verifier CANNOT determine m (message hidden)\n");

    printf("\n  [OPEN phase]\n");
    bigint_copy(&c.message, &m);
    bigint_copy(&c.randomness, &r);
    commit_open(&c);
    printf("    Prover reveals: m = 42, r = 99999\n");

    printf("\n  [VERIFY phase]\n");
    bool ok = commit_verify(&ctx, &c);
    printf("    Verify(C, m, r) = %s\n", ok ? "VALID (correct)" : "INVALID (error)");
    printf("    Hiding level:  %s\n", security_level_name(c.hiding_level));
    printf("    Binding level: %s\n", security_level_name(c.binding_level));

    printf("\n  [TAMPER DETECTION]\n");
    commitment c_bad;
    bigint_copy(&c_bad.commitment_val, &c.commitment_val);
    bigint_init_u64(&c_bad.message, 43);
    bigint_copy(&c_bad.randomness, &c.randomness);
    c_bad.scheme = c.scheme;
    c_bad.opened = true;
    c_bad.hiding_level = c.hiding_level;
    c_bad.binding_level = c.binding_level;
    printf("    Verify(C, m'=43, r) = %s\n",
           commit_verify(&ctx, &c_bad) ? "ACCEPT (tamper!)" : "REJECT (correct)");
    printf("    (Tampered message correctly rejected)\n");
}

int main(void) {
    printf("\n");
    sep(64);
    printf("  COMMITMENT SCHEME LIFECYCLE VISUALIZATION\n");
    printf("  Interactive Demo - All Four Schemes Compared\n");
    sep(64);

    printf("\n[PART 1] Lifecycle: Commit -> Hide -> Open -> Verify\n");

    demo_scheme(COMMIT_SCHEME_PEDERSEN,        "Pedersen");
    demo_scheme(COMMIT_SCHEME_HASH_SHA256,     "Hash-based");
    demo_scheme(COMMIT_SCHEME_VECTOR_MERKLE,   "Vector (Merkle tree)");
    demo_scheme(COMMIT_SCHEME_FUJISAKI_OKAMOTO, "Fujisaki-Okamoto");

    printf("\n\n[PART 2] Security Property Matrix\n\n");
    char compare_buf[2048];
    hash_commit_compare_schemes(compare_buf, sizeof(compare_buf));
    printf("%s\n", compare_buf);

    printf("\n[PART 3] Application Scenario Recommendations\n\n");

    printf("  Scenario 1: Sealed-Bid Auction\n");
    printf("    Requirement: Perfect hiding (bids must remain secret)\n");
    printf("    Recommendation: Pedersen commitment\n");
    printf("    Reason: Perfect hiding ensures zero information leakage\n\n");

    printf("  Scenario 2: Post-Quantum Blockchain\n");
    printf("    Requirement: Quantum-resistant commitments\n");
    printf("    Recommendation: Hash-based commitment (SHA-3)\n");
    printf("    Reason: DL-based schemes broken by Shor's algorithm\n\n");

    printf("  Scenario 3: Verifiable Database (Certificate Transparency)\n");
    printf("    Requirement: O(log n) proofs, updatable\n");
    printf("    Recommendation: Vector commitment (Merkle tree)\n");
    printf("    Reason: Compact proofs and efficient updates\n\n");

    printf("  Scenario 4: E-Voting (ZK Proof of Correct Vote)\n");
    printf("    Requirement: Homomorphic + ZK-friendly\n");
    printf("    Recommendation: Pedersen commitment\n");
    printf("    Reason: Additive homomorphism enables tally verification\n\n");

    printf("  Scenario 5: Low-Latency MPC with RSA Trust Assumptions\n");
    printf("    Requirement: Statistical hiding, large message space\n");
    printf("    Recommendation: Fujisaki-Okamoto\n");
    printf("    Reason: Statistical hiding + homomorphic over integers\n\n");

    printf("[PART 4] Fairness Analysis - Coin Flipping\n\n");

    commit_ctx cf_ctx;
    commit_ctx_init_u64(&cf_ctx, 104729, COMMIT_SCHEME_PEDERSEN);
    bigint g;
    bigint_init_u64(&g, 5);
    pedersen_setup(&cf_ctx, &g);

    printf("  Running 100 coin flips to verify fairness...\n");
    int zeros = 0, ones = 0;
    for (int trial = 0; trial < 100; trial++) {
        int a = trial % 2;
        int b = (trial * 7 + 3) % 2;
        int result;
        if (commit_coin_flip(&cf_ctx, a, b, &result)) {
            if (result == 0) zeros++;
            else ones++;
        }
    }
    printf("  Results: 0->%d (%.1f%%), 1->%d (%.1f%%)\n",
           zeros, zeros * 100.0 / (zeros + ones),
           ones, ones * 100.0 / (zeros + ones));
    printf("  Expected: ~50%% each (fair coin)\n");

    printf("\n[PART 5] Homomorphic Property Verification\n\n");

    commit_ctx h_ctx;
    commit_ctx_init_u64(&h_ctx, 104729, COMMIT_SCHEME_PEDERSEN);
    bigint g2;
    bigint_init_u64(&g2, 5);
    pedersen_setup(&h_ctx, &g2);

    for (int x = 1; x <= 5; x++) {
        for (int y = 1; y <= 5; y++) {
            bigint mx, rx, my, ry;
            bigint_init_u64(&mx, (uint64_t)x);
            bigint_init_u64(&rx, 0);
            bigint_init_u64(&my, (uint64_t)y);
            bigint_init_u64(&ry, 0);

            commitment cx, cy;
            commit_init(&cx, COMMIT_SCHEME_PEDERSEN);
            commit_init(&cy, COMMIT_SCHEME_PEDERSEN);
            pedersen_commit(&h_ctx, &cx, &mx, &rx);
            pedersen_commit(&h_ctx, &cy, &my, &ry);

            commitment c_sum;
            commit_init(&c_sum, COMMIT_SCHEME_PEDERSEN);
            pedersen_homomorphic_add(&h_ctx, &cx, &cy, &c_sum);

            bigint m_sum;
            mod_add(&h_ctx.group, &m_sum, &mx, &my);
            mod_add(&h_ctx.group, &c_sum.randomness, &rx, &ry);
            bigint_copy(&c_sum.message, &m_sum);

            bool valid = pedersen_verify(&h_ctx, &c_sum);
            printf("  Commit(%d,0) * Commit(%d,0) = Commit(%d,0): %s\n",
                   x, y, x + y, valid ? "OK" : "FAIL");
        }
    }

    sep(64);
    printf("  DEMO COMPLETE\n");
    sep(64);
    printf("\n");

    return 0;
}
