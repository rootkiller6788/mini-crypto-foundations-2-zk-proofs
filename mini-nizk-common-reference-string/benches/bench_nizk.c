/**
 * bench_nizk.c - Performance Benchmarks for NIZK CRS Module
 *
 * Benchmarks: mod_exp, group_exp, Pedersen commit/verify,
 * Schnorr prove/verify, NIZK Fiat-Shamir, simulation, serialization.
 */

#include "nizk_group.h"
#include "nizk_crs.h"
#include "nizk_commitment.h"
#include "nizk_sigma.h"
#include "nizk_proof.h"
#include "nizk_simulator.h"
#include <stdio.h>
#include <time.h>
#include <string.h>

static double elapsed_ms(clock_t start) {
    return 1000.0 * (clock() - start) / CLOCKS_PER_SEC;
}

#define BENCH(name, N, code) do { \
    clock_t _start = clock(); \
    for (int _i = 0; _i < (N); _i++) { code; } \
    double _ms = elapsed_ms(_start); \
    double _ops = (N) * 1000.0 / _ms; \
    printf("  %-35s %8d iters  %8.1f ops/sec\n", name, (N), _ops); \
} while(0)

int main(void) {
    nizk_group_params_t params;
    nizk_group_params_init_256bit(&params);

    printf("=== NIZK CRS Module Benchmarks ===\n\n");

    /* ---- L3: Group Operations ---- */
    printf("-- Group & Big Integer Operations --\n");

    nizk_bigint_t a, b, r;
    nizk_bigint_set_u64(&a, 1234567890);
    nizk_bigint_set_u64(&b, 987654321);

    BENCH("bigint_cmp", 500000, nizk_bigint_cmp(&a, &b));
    BENCH("mod_add", 500000, nizk_mod_add(&r, &a, &b, &params.p));
    BENCH("mod_sub", 500000, nizk_mod_sub(&r, &a, &b, &params.p));
    BENCH("mod_mul (small*small)", 100000, nizk_mod_mul(&r, &a, &b, &params.p));

    /* Large multiplication */
    nizk_bigint_copy(&a, &params.p);
    a.limbs[0] -= 1;
    nizk_bigint_copy(&b, &params.p);
    b.limbs[0] -= 2;
    BENCH("mod_mul (large*large)", 10000, nizk_mod_mul(&r, &a, &b, &params.p));

    /* Modular inverse */
    nizk_bigint_set_u64(&a, 12345);
    BENCH("mod_inv", 1000, nizk_mod_inv(&r, &a, &params.p));

    /* Modular exponentiation */
    nizk_scalar_t exp_small; nizk_scalar_set_u64(&exp_small, 65537);
    nizk_group_elem_t base, result;
    nizk_bigint_copy(&base.elem, &params.g);
    BENCH("mod_exp (17-bit exp)", 1000,
        nizk_mod_exp(&result.elem, &base.elem, &exp_small.val, &params.p));

    /* Group exponentiation */
    nizk_scalar_t scalar;
    nizk_scalar_set_u64(&scalar, 12345);
    nizk_bigint_copy(&base.elem, &params.g);
    BENCH("group_exp (14-bit)", 5000,
        nizk_group_exp(&result, &base, &scalar, &params));

    printf("\n-- Scalar Operations --\n");
    nizk_scalar_t sa, sb, sr;
    nizk_scalar_set_u64(&sa, 100);
    nizk_scalar_set_u64(&sb, 50);
    BENCH("scalar_add", 500000, nizk_scalar_add(&sr, &sa, &sb, &params));
    BENCH("scalar_mul", 500000, nizk_scalar_mul(&sr, &sa, &sb, &params));
    BENCH("scalar_inv", 10000, nizk_scalar_inv(&sr, &sa, &params));
    BENCH("scalar_rand", 10000, nizk_scalar_rand(&sr, &params));

    /* ---- CRS Operations ---- */
    printf("\n-- CRS Operations --\n");
    uint8_t seed[] = "benchmark-seed";
    nizk_crs_t crs_sound, crs_zk;
    BENCH("crs_setup_soundness", 1000,
        nizk_crs_setup_soundness(&crs_sound, &params, seed, sizeof(seed)));
    BENCH("crs_setup_zk", 1000,
        nizk_crs_setup_zk(&crs_zk, &params, NULL));
    BENCH("crs_validate", 5000,
        nizk_crs_validate(&crs_sound, &params));

    /* ---- Pedersen Commitments ---- */
    printf("\n-- Pedersen Commitment --\n");
    nizk_crs_t crs_com;
    nizk_crs_setup_pedersen(&crs_com, &params, seed, sizeof(seed));
    nizk_scalar_t m, r_com;
    nizk_scalar_set_u64(&m, 42);
    nizk_scalar_rand(&r_com, &params);
    nizk_commitment_t com;
    nizk_commitment_opening_t open;
    BENCH("pedersen_commit", 10000,
        nizk_pedersen_commit(&com, &open, &m, &r_com, &crs_com, &params));
    BENCH("pedersen_verify", 20000,
        nizk_pedersen_verify(&com, &open, &crs_com, &params));

    /* Homomorphic operations */
    nizk_commitment_t c1, c2, csum;
    nizk_scalar_t m1, r1_val, m2, r2_val;
    nizk_scalar_set_u64(&m1, 10); nizk_scalar_set_u64(&r1_val, 100);
    nizk_scalar_set_u64(&m2, 20); nizk_scalar_set_u64(&r2_val, 200);
    nizk_commitment_opening_t o1, o2;
    nizk_pedersen_commit(&c1, &o1, &m1, &r1_val, &crs_com, &params);
    nizk_pedersen_commit(&c2, &o2, &m2, &r2_val, &crs_com, &params);
    BENCH("commitment_add (homomorphic)", 20000,
        nizk_commitment_add(&csum, &c1, &c2, &params));

    /* ---- Sigma Protocols ---- */
    printf("\n-- Sigma Protocols --\n");
    nizk_scalar_t sk; nizk_scalar_rand(&sk, &params);
    nizk_group_elem_t gen, pk;
    nizk_bigint_copy(&gen.elem, &params.g);
    nizk_group_exp(&pk, &gen, &sk, &params);
    nizk_sigma_statement_t stmt;
    nizk_sigma_statement_init(&stmt, &pk, &gen, &params);
    nizk_scalar_t v;
    nizk_sigma_commitment_t commit;
    nizk_sigma_challenge_t challenge;
    nizk_sigma_response_t response;
    BENCH("schnorr_commit", 10000,
        nizk_schnorr_commit(&commit, &v, &params));
    nizk_scalar_rand(&challenge.c, &params);
    BENCH("schnorr_respond", 50000,
        nizk_schnorr_respond(&response, &sk, &v, &challenge, &params));
    BENCH("schnorr_verify", 20000,
        nizk_schnorr_verify(&stmt, &commit, &challenge, &response, &params));

    /* HVZK simulator */
    nizk_sigma_transcript_t sim_transcript;
    BENCH("sigma_simulate (HVZK)", 10000,
        nizk_sigma_simulate_transcript(&sim_transcript, &stmt, &params));

    /* ---- NIZK Fiat-Shamir ---- */
    printf("\n-- NIZK Fiat-Shamir --\n");
    nizk_proof_t proof;
    uint8_t label[] = "bench";
    BENCH("nizk_prove_dlog", 1000,
        nizk_prove_dlog(&proof, &crs_sound, &pk, &sk, label, sizeof(label), &params));
    BENCH("nizk_verify_dlog", 5000,
        nizk_verify_dlog(&proof, &crs_sound, &pk, label, sizeof(label), &params));

    /* ---- Simulator ---- */
    printf("\n-- Zero-Knowledge Simulator --\n");
    nizk_simulator_state_t sim_state;
    nizk_simulator_init(&sim_state, &crs_zk);
    BENCH("simulate_dlog", 1000,
        nizk_simulate_dlog(&proof, &sim_state, &crs_zk, &pk,
                           label, sizeof(label), &params));
    nizk_simulator_clear(&sim_state);

    /* ---- Serialization ---- */
    printf("\n-- Proof Serialization --\n");
    nizk_prove_dlog(&proof, &crs_sound, &pk, &sk,
                     label, sizeof(label), &params);
    size_t slen = nizk_proof_serialize(NULL, 0, &proof, &params);
    uint8_t buf[4096];
    BENCH("serialize", 10000,
        nizk_proof_serialize(buf, slen, &proof, &params));
    BENCH("deserialize", 10000, {
        nizk_proof_t dp;
        nizk_proof_deserialize(&dp, buf, slen, &params);
        nizk_proof_clear(&dp);
    });

    /* Cleanup */
    nizk_proof_clear(&proof);
    nizk_crs_clear(&crs_sound);
    nizk_crs_clear(&crs_zk);
    nizk_crs_clear(&crs_com);
    nizk_group_params_clear(&params);

    printf("\n=== Benchmarks Complete ===\n");
    return 0;
}
