/*
 * example_kea.c — Knowledge of Exponent Assumption: End-to-End Example
 *
 * Demonstrates the complete KEA1 security model:
 *   1. Setup: generate cyclic group, create KEA challenge (g, g^a)
 *   2. Adversary: honest party computes (C, C') = (g^r, g^{ar})
 *   3. Verify: check C' = C^a
 *   4. Extract: recover witness r via non-black-box extraction
 *   5. Analyze: verify extraction correctness, compare with malicious adversary
 *
 * L6: KEA as canonical cryptographic problem
 * L7: Foundation for SNARK knowledge extraction
 *
 * (C) Mini-Theory-of-Computation — mini-knowledge-of-exponent
 */
#include "discrete_log.h"
#include "kea.h"
#include "pairing.h"
#include "snark_kea.h"
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    printf("\n╔══════════════════════════════════════════════════╗\n");
    printf("║   Knowledge of Exponent — Live Demonstration    ║\n");
    printf("╚══════════════════════════════════════════════════╝\n\n");

    /* Create a cyclic group */
    CyclicGroup* g = group_create_test_group();
    printf("Group: Z_%llu*, QR subgroup order %llu, generator %llu\n\n",
           (unsigned long long)g->modulus,
           (unsigned long long)g->order,
           (unsigned long long)g->generator);

    /* KEA vs DLP comparison */
    kea_vs_dlp_comparison(g);

    /* Run full KEA1 security game (verbose) */
    printf("\n--- Running KEA1 Security Game ---\n");
    int adv_wins = kea_security_game(g, 1);
    printf("KEA1 security holds: adversary %s\n\n",
           adv_wins ? "BREAKS KEA (FAIL)" : "does NOT break KEA (PASS)");

    /* Run KEA2 security game */
    printf("--- Running KEA2 Security Game ---\n");
    kea2_security_game(g, 1);

    /* Compare honest vs malicious adversaries */
    printf("\n--- KEA Adversary Comparison ---\n");
    kea_compare_adversaries(g, 5);

    /* Show DLP algorithms */
    printf("\n--- DLP Algorithm Comparison ---\n");
    dlp_compare_methods(g);

    /* Demonstrate pairs of core concepts */
    printf("\n--- DLP ⇒ CDH Reduction ---\n");
    proof_dlp_implies_cdh(g);

    printf("\n--- DLP Self-Reducibility ---\n");
    proof_dlp_self_reducibility(g, 10);

    /* q-KEA example */
    printf("\n--- q-KEA Example (q=3) ---\n");
    QKEAInstance* qkea = qkea_instance_create(g, 3);
    if (qkea) {
        printf("q-KEA instance with %d powers:\n", qkea->q);
        for (int i = 0; i < qkea->q && i < 3; i++) {
            printf("  g^{a^%d} = %llu\n", i+1,
                   (unsigned long long)qkea->powers[i]->value);
        }
        qkea_instance_free(qkea);
    }

    /* Extraction rate analysis */
    printf("\n--- Extraction Rate ---\n");
    double rate = kea_extraction_rate(g, 20);
    printf("Extraction success rate: %.0f%% (20 trials)\n", rate * 100);
    printf("  In GGM: rate should be 100%% for honest adversaries.\n");

    group_free(g);

    printf("\n═══ KEA Demonstration Complete ═══\n\n");
    return 0;
}
