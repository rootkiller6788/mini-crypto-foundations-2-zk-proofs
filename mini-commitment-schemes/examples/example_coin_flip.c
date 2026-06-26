/**
 * @file example_coin_flip.c
 * @brief Coin-flipping over a telephone using commitments
 *
 * Demonstrates Blum's 1981 protocol for fair coin flipping
 * between two parties who don't trust each other.
 *
 * Protocol (Blum, CRYPTO 1981):
 *   1. Alice commits to random bit a:  C = Commit(a, r)
 *   2. Bob sends his random bit b (in the clear)
 *   3. Alice opens C, revealing a and r
 *   4. Bob verifies C == Commit(a, r), then computes result = a XOR b
 *
 * Why each step is necessary:
 *   - Without commitment (step 1): Bob could choose b based on a
 *   - Without hiding: Bob could learn a from C before step 2
 *   - Without opening: Alice could refuse to reveal a
 *   - Without binding: Alice could change a after seeing b
 *
 * This protocol is a fundamental building block for:
 *   - Multiparty computation (MPC)
 *   - Mental poker (playing cards over the phone)
 *   - Zero-knowledge proofs (commit-challenge-response)
 *
 * Knowledge Mapping:
 *   L1: Commitment definition (hiding + binding both needed)
 *   L7: Coin-flipping application
 */

#include "commitment.h"
#include "pedersen.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    printf("\n");
    printf("¨X¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨[\n");
    printf("¨U   Coin Flipping by Telephone (Blum 1981)     ¨U\n");
    printf("¨U   Using Pedersen Commitments                 ¨U\n");
    printf("¨^¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨a\n\n");

    /* Setup: shared group parameters */
    commit_ctx ctx;
    commit_ctx_init_u64(&ctx, 2147483659ULL, COMMIT_SCHEME_PEDERSEN);
    bigint g;
    bigint_init_u64(&g, 7);
    pedersen_setup(&ctx, &g);

    printf("Shared parameters established.\n");
    printf("Group: Z_p with safe prime p = 2147483659\n\n");

    /* ================================================================
     * Full protocol simulation with multiple rounds
     * ================================================================ */

    int num_rounds = 5;
    int alice_wins = 0, bob_wins = 0;

    for (int round = 0; round < num_rounds; round++) {
        printf("--- Round %d ---\n", round + 1);

        /* Alice picks a random bit */
        int alice_bit = (round * 7 + 3) % 2; /* Deterministic "random" for demo */
        printf("  [Alice]   Picks random bit a = %d\n", alice_bit);

        /* Step 1: Alice commits */
        bigint m, r;
        bigint_init_u64(&m, (uint64_t)alice_bit);
        mod_rand_nonzero(&ctx.group, &r);

        commitment c;
        commit_init(&c, COMMIT_SCHEME_PEDERSEN);
        pedersen_commit(&ctx, &c, &m, &r);

        char chex[256];
        bigint_to_hex(&c.commitment_val, chex, sizeof(chex));
        printf("  [Alice]   Commits: C = Commit(a=%d, r) = %s\n",
               alice_bit, chex);
        printf("  [Alice ¡ú Bob] Sends C\n");

        /* Step 2: Bob picks and sends his bit */
        int bob_bit = (round * 3 + 1) % 2; /* Deterministic "random" */
        printf("  [Bob]     Picks random bit b = %d\n", bob_bit);
        printf("  [Bob ¡ú Alice] Sends b = %d\n", bob_bit);

        /* At this point:
         * - Alice knows b but is bound to a (can't change it)
         * - Bob knows C but can't learn a (hiding property) */

        /* Step 3: Alice opens */
        printf("  [Alice]   Opens commitment: reveals a=%d, r\n", alice_bit);

        /* Step 4: Bob verifies */
        bool ok = pedersen_verify(&ctx, &c);
        int result = alice_bit ^ bob_bit;

        printf("  [Bob]     Verifies commitment: %s\n", ok ? "VALID" : "INVALID");
        printf("  [Bob]     Computes result = a XOR b = %d XOR %d = %d\n",
               alice_bit, bob_bit, result);
        printf("  Result:   %s wins this round!\n",
               result == 0 ? "Alice" : "Bob");

        if (result == 0) alice_wins++;
        else bob_wins++;
        printf("\n");
    }

    printf("========================================\n");
    printf("  Final Score: Alice %d - %d Bob\n", alice_wins, bob_wins);
    if (alice_wins > bob_wins) printf("  Alice wins the match!\n");
    else if (bob_wins > alice_wins) printf("  Bob wins the match!\n");
    else printf("  It's a tie!\n");
    printf("========================================\n\n");

    /* ================================================================
     * What if someone tries to cheat?
     * ================================================================ */

    printf("--- Cheating demo ---\n");
    printf("Scenario: Alice tries to change her bit after seeing Bob's.\n\n");

    int alice_original = 0;
    int bob_sends = 1;

    bigint m_orig, r_orig;
    bigint_init_u64(&m_orig, (uint64_t)alice_original);
    mod_rand_nonzero(&ctx.group, &r_orig);

    commitment c2;
    commit_init(&c2, COMMIT_SCHEME_PEDERSEN);
    pedersen_commit(&ctx, &c2, &m_orig, &r_orig);

    printf("  Alice commits to a = %d\n", alice_original);
    printf("  Bob sends b = %d\n", bob_sends);
    printf("  Result would be %d XOR %d = %d (Bob wins)\n",
           alice_original, bob_sends, alice_original ^ bob_sends);
    printf("  Alice wants result = 0 (Alice wins),\n");
    printf("  so she needs a = 1 (since 1 XOR 1 = 0).\n");

    /* Alice tries to open with m'=1 instead of m=0.
     * She needs r' such that Commit(1, r') = C.
     * But Commit(0, r) = g^0 * h^r = h^r.
     * She needs h^{r'} = g^1 * h^{r} = g * h^{r}.
     * This requires finding log_h(g), which is the DL problem. */

    printf("  To change to a'=1, Alice needs r' = log_h(g) - r.\n");
    printf("  Computing log_h(g) is the Discrete Log problem ¡ú INFEASIBLE.\n");
    printf("  Alice CANNOT change her committed bit!\n");
    printf("  This demonstrates the BINDING property.\n\n");

    printf("¨X¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨[\n");
    printf("¨U   Coin-flipping demo completed!              ¨U\n");
    printf("¨U   Hiding + Binding = Fairness.               ¨U\n");
    printf("¨^¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨a\n\n");

    return 0;
}
