/*
 * example_schnorr_zk.c — End-to-End: Schnorr Identification as ZK Proof
 *
 * Demonstrates the complete Schnorr sigma protocol (3-move):
 *   P → V: a = g^r mod p
 *   V → P: c ∈ Z_q
 *   P → V: s = r + c·x mod q
 *   V:     g^s == a · y^c mod p
 *
 * Proves: (1) Completeness, (2) Special Soundness via extraction,
 *         (3) HVZK via simulation.
 *
 * Courses: MIT 6.875, Stanford CS355, Berkeley CS276, ETH 263-4660
 * Reference: Schnorr (1991)
 */

#include "zk_simulator.h"
#include "sigma_protocols.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>

/* ── Toy group: p=23, g=2, q=11 ── */
static group_params_t toy_group(void) {
    group_params_t gp;
    gp.p = 23;   /* prime modulus */
    gp.g = 2;    /* generator of subgroup order q=11 */
    gp.q = 11;   /* subgroup order */
    gp.h = 8;    /* second generator (trapdoor h = g^3 mod 23) */
    return gp;
}

int main(void) {
    group_params_t gp = toy_group();
    uint64_t witness = 4;                   /* secret key x */
    uint64_t public_key = mod_pow(gp.g, witness, gp.p);

    /* Completeness */
    printf("=== Schnorr ZK Identification Demo ===\n\n");
    printf("Public params: p=%llu, g=%llu, q=%llu\n",
           (unsigned long long)gp.p, (unsigned long long)gp.g,
           (unsigned long long)gp.q);
    printf("Prover secret x = %llu\n", (unsigned long long)witness);
    printf("Public key y = g^x = %llu\n\n", (unsigned long long)public_key);

    schnorr_prover_t prover;
    schnorr_prover_init(&prover, witness, &gp);

    random_tape_t rng;
    init_random_tape(&rng, (uint64_t)time(NULL));

    int passed = 0;
    for (int round = 0; round < 5; round++) {
        uint64_t a = schnorr_prover_commit(&prover, &rng);
        printf("[Round %d] a = %llu\n", round+1, (unsigned long long)a);
        uint64_t c = pull_random_mod_q(&rng, gp.q);
        printf("           c = %llu\n", (unsigned long long)c);
        uint64_t s = schnorr_prover_respond(&prover, c);
        printf("           s = %llu", (unsigned long long)s);
        if (schnorr_verify(a, c, s, public_key, &gp)) {
            printf("  VERIFIED\n"); passed++;
        } else { printf("  FAILED\n"); }
    }
    printf("Completeness: %d/5 rounds OK\n\n", passed);

    /* HVZK Simulation */
    printf("=== HVZK Simulation ===\n");
    init_random_tape(&rng, 99999);
    for (int i = 0; i < 5; i++) {
        uint64_t a, c, s;
        int ret = hvzk_simulate_schnorr(public_key, &gp, &rng, &a, &c, &s);
        printf("  Sim[%d] (a=%llu, c=%llu, s=%llu) %s\n",
               i+1, (unsigned long long)a, (unsigned long long)c,
               (unsigned long long)s,
               (ret == 0 && schnorr_verify(a,c,s,public_key,&gp)) ? "OK" : "FAIL");
    }
    printf("\n");

    /* Witness Extraction via Special Soundness */
    printf("=== Witness Extraction (Special Soundness) ===\n");
    uint64_t r_ext = 7;
    uint64_t a_ext = mod_pow(gp.g, r_ext, gp.p);
    uint64_t c1 = 3, c2 = 8;
    uint64_t s1 = mod_add(r_ext, mod_mul(c1, witness, gp.q), gp.q);
    uint64_t s2 = mod_add(r_ext, mod_mul(c2, witness, gp.q), gp.q);
    uint64_t extracted;
    if (schnorr_extract_witness(a_ext, c1, s1, c2, s2, &gp, &extracted) == 0) {
        printf("Extracted = %llu, True = %llu → %s\n",
               (unsigned long long)extracted, (unsigned long long)witness,
               (extracted == witness) ? "MATCH" : "MISMATCH");
    }
    printf("\n");

    /* Parallel Repetition */
    printf("=== Parallel Repetition (k=4) ===\n");
    int k = 4;
    uint64_t a_par[4], c_par[4] = {2,3,5,7}, s_par[4];
    schnorr_prover_t sp2;
    schnorr_prover_init(&sp2, witness, &gp);
    init_random_tape(&rng, 33333);
    if (parallel_sigma_prover(&sp2, &rng, k, a_par, c_par, s_par) == 0) {
        int ver = parallel_sigma_verify(a_par, c_par, s_par, k, public_key, &gp);
        printf("  %d parallel rounds: %s\n", k, ver ? "VERIFIED" : "FAILED");
    }
    printf("\n=== Demo Complete ===\n");
    return 0;
}
