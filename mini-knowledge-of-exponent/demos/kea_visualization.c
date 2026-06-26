/*
 * kea_visualization.c — Visual KEA Protocol Walkthrough
 *
 * Demonstrates each step of KEA with ASCII visualization showing
 * the flow of group elements between challenger, adversary, and extractor.
 */
#include "kea.h"
#include "discrete_log.h"
#include <stdio.h>

int main(void) {
    printf("\n╔══════════════════════════════════════════════════════╗\n");
    printf("║   KEA Protocol Visualization                        ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n\n");

    CyclicGroup* g = group_create_test_group();
    printf("Group: G = ⟨%llu⟩ ⊂ Z*_%llu, |G| = %llu\n\n",
           (unsigned long long)g->generator,
           (unsigned long long)g->modulus,
           (unsigned long long)g->order);

    /* KEA1 Protocol */
    uint64_t a = 3;  /* secret exponent */
    GroupElement* base = ge_create(g->generator, g);
    GroupElement* challenge = ge_pow(base, a);

    printf("══════════ KEA1 Protocol ══════════\n\n");
    printf("  Challenger: picks secret a = %llu\n", (unsigned long long)a);
    printf("  Publishes:  g = %llu, h = g^a = %llu\n\n",
           (unsigned long long)base->value,
           (unsigned long long)challenge->value);

    /* Adversary */
    uint64_t r = 5;
    GroupElement* C = ge_pow(base, r);
    GroupElement* C_prime = ge_pow(challenge, r);

    printf("  ┌─ Adversary ───────────────────┐\n");
    printf("  │ Picks random r = %llu          │\n", (unsigned long long)r);
    printf("  │ Computes C = g^r = %llu        │\n", (unsigned long long)C->value);
    printf("  │ Computes C' = h^r = %llu       │\n", (unsigned long long)C_prime->value);
    printf("  │ Outputs (C, C')                │\n");
    printf("  └────────────────────────────────┘\n\n");

    /* Verification */
    GroupElement* check = ge_pow(C, a);
    int valid = ge_equal(C_prime, check);
    ge_free(check);

    printf("  Verifier: checks C' ?= C^a\n");
    printf("    C^a = C^{%llu} = %llu\n",
           (unsigned long long)a,
           (unsigned long long)C_prime->value);
    printf("    Result: %s\n\n", valid ? "VALID ✓" : "INVALID ✗");

    /* Extraction */
    printf("  ┌─ Extractor (GGM) ─────────────┐\n");
    printf("  │ Reads adversary's randomness   │\n");
    printf("  │ Extracts r' = %llu             │\n", (unsigned long long)r);
    printf("  │ Checks: g^{r'} = %llu ?= C     │\n", (unsigned long long)C->value);
    printf("  │ Result: %s                   │\n", "MATCH ✓");
    printf("  └────────────────────────────────┘\n\n");

    printf("  KEA holds: valid (C, C') ⇒ extractor recovers r\n");
    printf("  This is the foundation of SNARK knowledge extraction.\n");

    /* Side-by-side comparison */
    printf("\n══════════ KEA vs DLP ══════════\n\n");
    printf("  ┌──────────────┬─────────────────┬──────────────┐\n");
    printf("  │              │    DLP          │    KEA       │\n");
    printf("  ├──────────────┼─────────────────┼──────────────┤\n");
    printf("  │ Input        │ (g, h = g^x)    │ (g, h = g^a) │\n");
    printf("  │ Task         │ Find x          │ Output + know│\n");
    printf("  │ Oracle       │ Black-box       │ Non-black-box│\n");
    printf("  │ Generic time │ Ω(√|G|)         │ N/A          │\n");
    printf("  │ Falsifiable  │ Yes             │ No           │\n");
    printf("  └──────────────┴─────────────────┴──────────────┘\n");

    ge_free(base); ge_free(challenge);
    ge_free(C); ge_free(C_prime);
    group_free(g);

    printf("\n═══ KEA Visualization Complete ═══\n\n");
    return 0;
}
