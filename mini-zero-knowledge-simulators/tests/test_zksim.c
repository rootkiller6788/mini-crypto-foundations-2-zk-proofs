#include "zk_simulator.h"
#include "sigma_protocols.h"
#include "commitments.h"
#include "simulator_core.h"
#include "zk_problems.h"
#include "fiat_shamir.h"
#include <stdio.h>
#include <assert.h>

/* Forward declarations for self-test functions */
extern int zk_simulator_self_test(void);
extern int sigma_protocols_self_test(void);
extern int commitments_self_test(void);
extern int simulator_core_self_test(void);
extern int zk_problems_self_test(void);
extern int fiat_shamir_self_test(void);
extern int concurrent_zk_self_test(void);

/* Simple Schnorr ZK demonstration test */
static void test_schnorr_zk_property(void) {
    printf("  Testing Schnorr ZK property...\n");
    group_params_t gp = {23, 2, 11, 8};
    uint64_t x = 4;  /* secret key */
    uint64_t y = mod_pow(2, 4, 23);  /* public key */

    /* Create 100 real transcripts */
    random_tape_t rng;
    init_random_tape(&rng, 12345);
    schnorr_prover_t sp;
    schnorr_prover_init(&sp, x, &gp);

    for (int i = 0; i < 100; i++) {
        uint64_t a = schnorr_prover_commit(&sp, &rng);
        uint64_t c = pull_random_mod_q(&rng, gp.q);
        uint64_t s = schnorr_prover_respond(&sp, c);
        int ok = schnorr_verify(a, c, s, y, &gp);
        assert(ok == 1);
    }
    printf("    Real transcripts: all 100 verified OK\n");

    /* Create 100 simulated transcripts */
    init_random_tape(&rng, 54321);
    for (int i = 0; i < 100; i++) {
        uint64_t a, c, s;
        int sim_ok = hvzk_simulate_schnorr(y, &gp, &rng, &a, &c, &s);
        assert(sim_ok == 0);
        int verify_ok = schnorr_verify(a, c, s, y, &gp);
        assert(verify_ok == 1);
    }
    printf("    Simulated transcripts: all 100 verified OK\n");
    printf("  Schnorr ZK property: PASSED\n");
}

/* Test witness extraction (special soundness) */
static void test_witness_extraction(void) {
    printf("  Testing witness extraction...\n");
    group_params_t gp = {23, 2, 11, 8};
    uint64_t x = 4;
    uint64_t y = mod_pow(2, 4, 23);

    /* Create two transcripts with same commitment, different challenges */
    uint64_t r = 3;
    uint64_t a = mod_pow(2, r, 23);
    uint64_t c1 = 5, c2 = 7;
    uint64_t s1 = (r + c1 * x) % 11;
    uint64_t s2 = (r + c2 * x) % 11;

    assert(schnorr_verify(a, c1, s1, y, &gp) == 1);
    assert(schnorr_verify(a, c2, s2, y, &gp) == 1);

    uint64_t witness;
    int ext_ok = schnorr_extract_witness(a, c1, s1, c2, s2, &gp, &witness);
    assert(ext_ok == 0);
    assert(witness == x);
    printf("    Extracted witness = %llu (expected %llu)\n",
           (unsigned long long)witness, (unsigned long long)x);
    printf("  Witness extraction: PASSED\n");
}

/* Test OR-composition */
static void test_or_composition(void) {
    printf("  Testing OR-composition (Cramer-Damgard-Schoenmakers)...\n");
    group_params_t gp = {23, 2, 11, 8};
    uint64_t x1 = 4, y1 = mod_pow(2, 4, 23);
    uint64_t x2 = 7, y2 = mod_pow(2, 7, 23);
    random_tape_t rng;
    init_random_tape(&rng, 7777);

    /* Test: prover knows x1, not x2 */
    or_composition_prover_t op;
    or_compose_prover_init(&op, 1, x1, y1, y2, &gp);

    for (int i = 0; i < 20; i++) {
        or_composition_transcript_t ot;
        uint64_t vc = pull_random_mod_q(&rng, gp.q);
        or_compose_prover_execute(&op, &rng, &ot, vc);
        int ok = or_compose_verify(&ot, y1, y2, &gp);
        assert(ok == 1);
    }

    /* Test: prover knows x2, not x1 */
    or_compose_prover_init(&op, 2, x2, y1, y2, &gp);
    for (int i = 0; i < 20; i++) {
        or_composition_transcript_t ot;
        uint64_t vc = pull_random_mod_q(&rng, gp.q);
        or_compose_prover_execute(&op, &rng, &ot, vc);
        int ok = or_compose_verify(&ot, y1, y2, &gp);
        assert(ok == 1);
    }
    printf("  OR-composition: PASSED (40/40)\n");
}

/* Test NIZK via Fiat-Shamir */
static void test_fiat_shamir_nizk(void) {
    printf("  Testing Fiat-Shamir NIZK...\n");
    group_params_t gp = {23, 2, 11, 8};
    uint64_t x = 4, y = mod_pow(2, 4, 23);
    random_tape_t rng;
    init_random_tape(&rng, 3333);
    uint8_t ctx[4] = {0xAA, 0xBB, 0xCC, 0xDD};

    schnorr_nizk_proof_t proof;
    int ret = schnorr_nizk_prove(x, y, &gp, &rng, ctx, 4, &proof);
    assert(ret == 0);
    int verify = schnorr_nizk_verify(&proof, y, &gp, ctx, 4);
    assert(verify == 1);
    printf("    Schnorr NIZK proof verified OK\n");

    /* Test OR-NIZK */
    uint64_t y2 = mod_pow(2, 7, 23);
    or_nizk_proof_t or_proof;
    ret = or_nizk_prove(1, x, y, y2, &gp, &rng, ctx, 4, &or_proof);
    assert(ret == 0);
    verify = or_nizk_verify(&or_proof, y, y2, &gp, ctx, 4);
    assert(verify == 1);
    printf("    OR-NIZK proof verified OK\n");
    printf("  Fiat-Shamir NIZK: PASSED\n");
}

/* Test statistical distance */
static void test_statistical_distance(void) {
    printf("  Testing statistical distance...\n");
    double d1[3] = {0.5, 0.3, 0.2};
    double d2[3] = {0.5, 0.3, 0.2};
    double d3[3] = {1.0, 0.0, 0.0};
    assert(statistical_distance(d1, d2, 3) < 1e-9);
    assert(statistical_distance(d1, d3, 3) > 0.4);
    assert(statistical_distance(d1, d3, 3) <= 1.0);
    assert(is_negligible(1e-10, 1000.0) == 1);
    assert(is_negligible(0.5, 10.0) == 0);
    printf("  Statistical distance: PASSED\n");
}

int main(void) {
    printf("=== mini-zero-knowledge-simulators Test Suite ===\n\n");

    printf("[1] zk_simulator self-test\n");
    assert(zk_simulator_self_test() == 0);
    printf("    PASSED\n\n");

    printf("[2] sigma_protocols self-test\n");
    assert(sigma_protocols_self_test() == 0);
    printf("    PASSED\n\n");

    printf("[3] commitments self-test\n");
    assert(commitments_self_test() == 0);
    printf("    PASSED\n\n");

    printf("[4] simulator_core self-test\n");
    assert(simulator_core_self_test() == 0);
    printf("    PASSED\n\n");

    printf("[5] zk_problems self-test\n");
    assert(zk_problems_self_test() == 0);
    printf("    PASSED\n\n");

    printf("[6] fiat_shamir self-test\n");
    assert(fiat_shamir_self_test() == 0);
    printf("    PASSED\n\n");

    printf("[7] concurrent_zk self-test\n");
    assert(concurrent_zk_self_test() == 0);
    printf("    PASSED\n\n");

    printf("[8] Schnorr ZK property\n");
    test_schnorr_zk_property();

    printf("[9] Witness extraction\n");
    test_witness_extraction();

    printf("[10] OR-composition\n");
    test_or_composition();

    printf("[11] Fiat-Shamir NIZK\n");
    test_fiat_shamir_nizk();

    printf("[12] Statistical distance\n");
    test_statistical_distance();

    printf("\n=== ALL TESTS PASSED ===\n");
    return 0;
}
