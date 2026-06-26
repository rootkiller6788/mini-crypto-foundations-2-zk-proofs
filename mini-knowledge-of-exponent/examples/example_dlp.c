/*
 * example_dlp.c — Discrete Logarithm Problem: Algorithms & Reductions
 *
 * Demonstrates all DLP-solving algorithms and hardness relationships:
 *   - Baby-step Giant-step (Shanks 1971)
 *   - Pollard's Rho (Pollard 1978)
 *   - Pohlig-Hellman reduction (1978)
 *   - Index Calculus for Z_p* (simplified)
 *   - DLP ⇒ CDH reduction proof
 *   - DDH via Legendre symbol analysis
 *   - DLP random self-reducibility
 *
 * L5: Algorithm implementations with correctness verification
 * L6: DLP/CDH/DDH as canonical hardness problems
 *
 * (C) Mini-Theory-of-Computation — mini-knowledge-of-exponent
 */
#include "discrete_log.h"
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    printf("\n╔══════════════════════════════════════════════════╗\n");
    printf("║   Discrete Logarithm — Algorithms & Hardness    ║\n");
    printf("╚══════════════════════════════════════════════════╝\n\n");

    CyclicGroup* g = group_create_test_group();
    printf("Group: Z_%llu*, QR subgroup order %llu\n\n",
           (unsigned long long)g->modulus, (unsigned long long)g->order);

    /* Create DLP instances with different secrets */
    GroupElement* base = ge_generator(g);

    printf("--- DLP Solving: Baby-step Giant-step ---\n");
    for (uint64_t secret = 1; secret <= 5; secret++) {
        GroupElement* h = ge_pow(base, secret);
        uint64_t x = dlp_baby_giant_step(base, h, g);
        printf("  dlog(%llu) via BSGS = %llu %s\n",
               (unsigned long long)h->value, (unsigned long long)x,
               x == secret ? "✓" : "✗");
        ge_free(h);
    }

    printf("\n--- Pollard's Rho ---\n");
    for (uint64_t secret = 1; secret <= 5; secret++) {
        GroupElement* h = ge_pow(base, secret);
        uint64_t x = dlp_pollard_rho(base, h, g);
        printf("  dlog(%llu) via Rho = %llu %s\n",
               (unsigned long long)h->value, (unsigned long long)x,
               x == secret ? "✓" : "✗");
        ge_free(h);
    }

    printf("\n--- DLP→CDH Reduction ---\n");
    CDHInstance* cdh = cdh_instance_create(g, 3, 5);
    printf("Given: (g, g^3, g^5), need g^{15}\n");
    cdh_solve_via_dlp(cdh);
    if (cdh->solved) {
        GroupElement* expected = ge_pow(base, 3*5);
        printf("CDH solved: g^{ab} = %llu, expected %llu %s\n",
               (unsigned long long)cdh->answer->value,
               (unsigned long long)expected->value,
               ge_equal(cdh->answer, expected) ? "✓" : "✗");
        ge_free(expected);
    }
    cdh_instance_free(cdh);

    printf("\n--- DDH via Legendre Symbols ---\n");
    DDHInstance* ddh_dh = ddh_instance_create(g, 2, 3, 1);
    DDHInstance* ddh_non = ddh_instance_create(g, 2, 3, 0);
    printf("DH tuple: Legendre predicts %s\n",
           ddh_solve_legendre(ddh_dh) ? "DH" : "non-DH");
    printf("Non-DH:   Legendre predicts %s\n",
           ddh_solve_legendre(ddh_non) ? "DH" : "non-DH");
    ddh_instance_free(ddh_dh); ddh_instance_free(ddh_non);

    printf("\n--- DLP Random Self-Reducibility ---\n");
    proof_dlp_self_reducibility(g, 15);

    printf("\n--- Algorithm Comparison ---\n");
    dlp_compare_methods(g);

    ge_free(base);
    group_free(g);

    printf("\n═══ DLP Demonstration Complete ═══\n\n");
    return 0;
}
