/*
 * bench_simulator.c -- Performance benchmark for ZK simulators
 *
 * Measures: Schnorr prover time, HVZK simulator time, witness extraction,
 *           OR-composition, Fiat-Shamir NIZK, commitment operations.
 */

#include "zk_simulator.h"
#include "sigma_protocols.h"
#include "commitments.h"
#include "simulator_core.h"
#include "fiat_shamir.h"
#include "zk_problems.h"
#include <stdio.h>
#include <time.h>

static double get_time_ms(clock_t start, clock_t end) {
    return 1000.0 * (double)(end - start) / (double)CLOCKS_PER_SEC;
}

int main(void) {
    printf("=== ZK Simulator Benchmarks ===\n\n");

    group_params_t gp = {23, 2, 11, 8};
    uint64_t x = 4, y = mod_pow(2, 4, 23);
    random_tape_t rng;
    init_random_tape(&rng, 42);

    int iterations = 100000;
    clock_t start, end;

    /* Benchmark 1: Schnorr prover commit+respond */
    printf("[1] Schnorr prover (%d iterations)\n", iterations);
    start = clock();
    schnorr_prover_t sp;
    schnorr_prover_init(&sp, x, &gp);
    for (int i = 0; i < iterations; i++) {
        uint64_t a = schnorr_prover_commit(&sp, &rng);
        uint64_t c = (uint64_t)(i % gp.q);
        uint64_t s = schnorr_prover_respond(&sp, c);
        (void)a; (void)s;
    }
    end = clock();
    printf("    Time: %.2f ms (%.2f us/op)\n",
           get_time_ms(start, end),
           get_time_ms(start, end) * 1000.0 / iterations);

    /* Benchmark 2: HVZK simulation */
    printf("[2] HVZK simulator (%d iterations)\n", iterations);
    start = clock();
    for (int i = 0; i < iterations; i++) {
        uint64_t a, c, s;
        hvzk_simulate_schnorr(y, &gp, &rng, &a, &c, &s);
    }
    end = clock();
    printf("    Time: %.2f ms (%.2f us/op)\n",
           get_time_ms(start, end),
           get_time_ms(start, end) * 1000.0 / iterations);

    /* Benchmark 3: Pedersen commitments */
    printf("[3] Pedersen commitment (%d iterations)\n", iterations);
    start = clock();
    pedersen_commitment_t pc;
    for (int i = 0; i < iterations; i++) {
        pedersen_commit(&pc, (uint64_t)(i % gp.q), &rng, &gp);
    }
    end = clock();
    printf("    Time: %.2f ms (%.2f us/op)\n",
           get_time_ms(start, end),
           get_time_ms(start, end) * 1000.0 / iterations);

    /* Benchmark 4: OR-composition */
    uint64_t y2 = mod_pow(2, 7, 23);
    int or_iterations = 50000;
    printf("[4] OR-composition prover (%d iterations)\n", or_iterations);
    start = clock();
    or_composition_prover_t op;
    or_compose_prover_init(&op, 1, x, y, y2, &gp);
    for (int i = 0; i < or_iterations; i++) {
        or_composition_transcript_t ot;
        uint64_t vc = (uint64_t)(i % gp.q);
        or_compose_prover_execute(&op, &rng, &ot, vc);
    }
    end = clock();
    printf("    Time: %.2f ms (%.2f us/op)\n",
           get_time_ms(start, end),
           get_time_ms(start, end) * 1000.0 / (or_iterations > 0 ? or_iterations : 1));

    /* Benchmark 5: Fiat-Shamir NIZK */
    int nizk_iterations = 50000;
    printf("[5] Fiat-Shamir NIZK (%d iterations)\n", nizk_iterations);
    uint8_t ctx[4] = {1,2,3,4};
    start = clock();
    schnorr_nizk_proof_t proof;
    for (int i = 0; i < nizk_iterations; i++) {
        schnorr_nizk_prove(x, y, &gp, &rng, ctx, 4, &proof);
    }
    end = clock();
    printf("    Time: %.2f ms (%.2f us/op)\n",
           get_time_ms(start, end),
           get_time_ms(start, end) * 1000.0 / (nizk_iterations > 0 ? nizk_iterations : 1));

    /* Benchmark 6: Modular exponentiation */
    printf("[6] Modular exponentiation (%d iterations)\n", iterations);
    start = clock();
    for (int i = 0; i < iterations; i++) {
        mod_pow(2, (uint64_t)i % 1000, 23);
    }
    end = clock();
    printf("    Time: %.2f ms (%.2f us/op)\n",
           get_time_ms(start, end),
           get_time_ms(start, end) * 1000.0 / iterations);

    /* Benchmark 7: Statistical distance */
    printf("[7] Statistical distance (%d iterations)\n", iterations);
    double d1[3] = {0.5, 0.3, 0.2};
    double d2[3] = {1.0, 0.0, 0.0};
    start = clock();
    for (int i = 0; i < iterations; i++) {
        volatile double dist = statistical_distance(d1, d2, 3);
        (void)dist;
    }
    end = clock();
    printf("    Time: %.2f ms (%.2f us/op)\n",
           get_time_ms(start, end),
           get_time_ms(start, end) * 1000.0 / iterations);

    /* Benchmark 8: Simulation quality over samples */
    int sim_iterations = 1000;
    printf("[8] Simulator quality (stat dist over %d sample pairs)\n", sim_iterations);
    transcript_t real_samples[100], sim_samples[100];
    for (int i = 0; i < 100; i++) {
        transcript_init(&real_samples[i]);
        transcript_append_u64(&real_samples[i], (uint64_t)i);
        transcript_init(&sim_samples[i]);
        transcript_append_u64(&sim_samples[i], (uint64_t)i);
    }
    start = clock();
    for (int i = 0; i < sim_iterations; i++) {
        volatile double qual = simulator_statistical_quality(
            real_samples, 100, sim_samples, 100);
        (void)qual;
    }
    end = clock();
    printf("    Time: %.2f ms (%.2f us/op)\n",
           get_time_ms(start, end),
           get_time_ms(start, end) * 1000.0 / (sim_iterations > 0 ? sim_iterations : 1));

    printf("\n=== Benchmarks Complete ===\n");
    printf("All operations are polynomial-time.\n");
    printf("Expected simulation time scales linearly with iterations.\n");
    return 0;
}
