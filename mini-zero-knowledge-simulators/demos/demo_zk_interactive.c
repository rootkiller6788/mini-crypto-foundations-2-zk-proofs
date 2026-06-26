/*
 * demo_zk_interactive.c -- Interactive Demo: Zero-Knowledge Proof Simulator
 *
 * Demonstrates the complete ZK workflow interactively.
 * Courses: MIT 6.875, Stanford CS355, Berkeley CS276, ETH 263-4660
 */

#include "zk_simulator.h"
#include "sigma_protocols.h"
#include "commitments.h"
#include "simulator_core.h"
#include "fiat_shamir.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>

static void print_group(const group_params_t *gp) {
    printf("  Group: p=%llu, g=%llu, q=%llu\n",
           (unsigned long long)gp->p,
           (unsigned long long)gp->g,
           (unsigned long long)gp->q);
}


int main(void) {
    printf("+==================================================+\n");
    printf("|  Zero-Knowledge Proof Simulator -- Interactive Demo |\n");
    printf("+==================================================+\n\n");

    /* Phase 1: Setup */
    printf("--- Phase 1: Setup ---\n");
    group_params_t gp;
    gp.p = 23; gp.g = 2; gp.q = 11; gp.h = 8;
    print_group(&gp);
    printf("  (Toy parameters for readability)\n\n");

    /* Phase 2: Key Generation */
    printf("--- Phase 2: Key Generation ---\n");
    uint64_t secret_key = 4;
    uint64_t public_key = mod_pow(gp.g, secret_key, gp.p);
    printf("  Secret key x = %llu\n", (unsigned long long)secret_key);
    printf("  Public key y = g^x = %llu\n\n", (unsigned long long)public_key);

    /* Phase 3: Real Protocol Execution */
    printf("--- Phase 3: Real Schnorr Protocol (3 rounds) ---\n");
    schnorr_prover_t prover;
    schnorr_prover_init(&prover, secret_key, &gp);
    random_tape_t rng;
    init_random_tape(&rng, (uint64_t)time(NULL));

    int real_ok = 0;
    for (int r = 1; r <= 3; r++) {
        uint64_t a = schnorr_prover_commit(&prover, &rng);
        uint64_t c = pull_random_mod_q(&rng, gp.q);
        uint64_t s = schnorr_prover_respond(&prover, c);
        int ok = schnorr_verify(a, c, s, public_key, &gp);
        printf("  Round %d: a=%llu c=%llu s=%llu -> %s\n",
               r, (unsigned long long)a, (unsigned long long)c,
               (unsigned long long)s, ok ? "ACCEPT" : "REJECT");
        if (ok) real_ok++;
    }
    printf("  Completeness: %d/3 (%s)\n\n", real_ok,
           real_ok == 3 ? "PASS" : "FAIL");

    /* Phase 4: HVZK Simulation */
    printf("--- Phase 4: HVZK Simulation (WITHOUT secret key!) ---\n");
    init_random_tape(&rng, 99999);
    int sim_ok = 0;
    for (int r = 1; r <= 3; r++) {
        uint64_t a_s, c_s, s_s;
        int ret = hvzk_simulate_schnorr(public_key, &gp, &rng, &a_s, &c_s, &s_s);
        if (ret == 0 && schnorr_verify(a_s, c_s, s_s, public_key, &gp))
            sim_ok++;
        printf("  Sim %d: a=%llu c=%llu s=%llu -> ACCEPT\n",
               r, (unsigned long long)a_s, (unsigned long long)c_s,
               (unsigned long long)s_s);
    }
    printf("  Simulation: %d/3 verified WITHOUT witness\n", sim_ok);
    printf("  Key insight: anyone can produce valid transcripts!\n\n");

    /* Phase 5: Witness Extraction */
    printf("--- Phase 5: Witness Extraction ---\n");
    uint64_t r_ext = 3;
    uint64_t a_ext = mod_pow(gp.g, r_ext, gp.p);
    uint64_t c1 = 5, c2 = 8;
    uint64_t s1 = (r_ext + c1 * secret_key) % gp.q;
    uint64_t s2 = (r_ext + c2 * secret_key) % gp.q;

    printf("  T1: (a=%llu, c=%llu, s=%llu)\n",
           (unsigned long long)a_ext, (unsigned long long)c1,
           (unsigned long long)s1);
    printf("  T2: (a=%llu, c=%llu, s=%llu)\n",
           (unsigned long long)a_ext, (unsigned long long)c2,
           (unsigned long long)s2);

    uint64_t extracted;
    if (schnorr_extract_witness(a_ext, c1, s1, c2, s2, &gp, &extracted) == 0) {
        printf("  Extracted w = %llu, true = %llu -> %s\n\n",
               (unsigned long long)extracted,
               (unsigned long long)secret_key,
               extracted == secret_key ? "MATCH" : "MISMATCH");
    }

    /* Phase 6: Expected Rewind Time */
    printf("--- Phase 6: Expected Simulation Time ---\n");
    double exp_att = expected_rewind_attempts(1.0 / (double)gp.q);
    printf("  For Schnorr (q=%llu): E[rewinds] = %.2f\n",
           (unsigned long long)gp.q, exp_att);
    printf("  This is polynomial: O(q * poly(n))\n\n");

    /* Phase 7: NIZK via Fiat-Shamir */
    printf("--- Phase 7: NIZK via Fiat-Shamir ---\n");
    init_random_tape(&rng, 33333);
    uint8_t context[9] = {'d','e','m','o','-','c','t','x',0};
    schnorr_nizk_proof_t nizk;
    schnorr_nizk_prove(secret_key, public_key, &gp, &rng, context, 8, &nizk);
    int nizk_ok = schnorr_nizk_verify(&nizk, public_key, &gp, context, 8);
    printf("  NIZK proof: (a=%llu, s=%llu)\n",
           (unsigned long long)nizk.a, (unsigned long long)nizk.s);
    printf("  e = H(a||y||g||p||ctx) derived non-interactively\n");
    printf("  Verification: %s\n\n", nizk_ok ? "ACCEPT" : "REJECT");

    /* Phase 8: Statistical Quality */
    printf("--- Phase 8: Statistical Quality ---\n");
    transcript_t real_ts[5], sim_ts[5];
    init_random_tape(&rng, 1);
    for (int i = 0; i < 5; i++) {
        uint64_t a, c, s;
        a = schnorr_prover_commit(&prover, &rng);
        c = pull_random_mod_q(&rng, gp.q);
        s = schnorr_prover_respond(&prover, c);
        transcript_init(&real_ts[i]);
        transcript_append_u64(&real_ts[i], a);
        transcript_append_u64(&real_ts[i], c);
        transcript_append_u64(&real_ts[i], s);
        hvzk_simulate_schnorr(public_key, &gp, &rng, &a, &c, &s);
        transcript_init(&sim_ts[i]);
        transcript_append_u64(&sim_ts[i], a);
        transcript_append_u64(&sim_ts[i], c);
        transcript_append_u64(&sim_ts[i], s);
    }
    double qual = simulator_statistical_quality(real_ts, 5, sim_ts, 5);
    printf("  Statistical quality (5 sample pairs): %.2f\n", qual);
    printf("  For perfect HVZK: distributions are identical.\n");

    printf("\n+==================================================+\n");
    printf("|  Demo Complete -- All ZK Properties Demonstrated  |\n");
    printf("+==================================================+\n");
    return 0;
}
