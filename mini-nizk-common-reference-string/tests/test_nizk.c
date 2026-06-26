/**
 * test_nizk.c - Comprehensive tests for NIZK CRS Module
 *
 * Tests: group ops, CRS setup, Pedersen commitments,
 * sigma protocols, NIZK Fiat-Shamir, simulator, serialization.
 */

#include "nizk_group.h"
#include "nizk_crs.h"
#include "nizk_commitment.h"
#include "nizk_sigma.h"
#include "nizk_proof.h"
#include "nizk_simulator.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

static int tests_run = 0;
static int tests_passed = 0;

/* ---- L3: Group & Big Integer Tests ---- */

static void test_group_params(void) {
    tests_run++;
    printf("  TEST group_params... ");
    nizk_group_params_t p;
    nizk_group_params_init_256bit(&p);
    assert(p.p_bits == 256 && p.q_bits == 256);
    assert(!nizk_bigint_is_zero(&p.g));
    assert(!nizk_bigint_is_zero(&p.p));
    nizk_group_params_clear(&p);
    tests_passed++;
    printf("PASSED\n");
}

static void test_bigint(void) {
    tests_run++;
    printf("  TEST bigint_ops... ");
    nizk_bigint_t a, b;
    nizk_bigint_set_u64(&a, 42);
    nizk_bigint_set_u64(&b, 42);
    assert(nizk_bigint_cmp(&a, &b) == 0);
    nizk_bigint_set_u64(&b, 99);
    assert(nizk_bigint_cmp(&a, &b) < 0);
    nizk_bigint_zero(&a);
    assert(nizk_bigint_is_zero(&a));
    nizk_bigint_one(&a);
    assert(nizk_bigint_is_one(&a));
    tests_passed++;
    printf("PASSED\n");
}

static void test_modular(void) {
    tests_run++;
    printf("  TEST modular_ops... ");
    nizk_group_params_t p;
    nizk_group_params_init_256bit(&p);
    nizk_bigint_t a, b, r, e;
    nizk_bigint_set_u64(&a, 100);
    nizk_bigint_set_u64(&b, 50);
    nizk_mod_add(&r, &a, &b, &p.p);
    nizk_bigint_set_u64(&e, 150);
    assert(nizk_bigint_cmp(&r, &e) == 0);
    nizk_mod_sub(&r, &a, &b, &p.p);
    nizk_bigint_set_u64(&e, 50);
    assert(nizk_bigint_cmp(&r, &e) == 0);
    nizk_mod_inv(&r, &a, &p.p);
    nizk_mod_mul(&r, &r, &a, &p.p);
    assert(nizk_bigint_is_one(&r));
    nizk_group_params_clear(&p);
    tests_passed++;
    printf("PASSED\n");
}

static void test_scalar(void) {
    tests_run++;
    printf("  TEST scalar_ops... ");
    nizk_group_params_t p;
    nizk_group_params_init_256bit(&p);
    nizk_scalar_t a, b, r, e;
    nizk_scalar_set_u64(&a, 10);
    nizk_scalar_set_u64(&b, 7);
    nizk_scalar_add(&r, &a, &b, &p);
    nizk_scalar_set_u64(&e, 17);
    assert(nizk_scalar_cmp(&r, &e) == 0);
    nizk_scalar_neg(&r, &a, &p);
    nizk_scalar_add(&r, &r, &a, &p);
    assert(nizk_scalar_is_zero(&r));
    nizk_group_params_clear(&p);
    tests_passed++;
    printf("PASSED\n");
}

static void test_group_exp(void) {
    tests_run++;
    printf("  TEST group_exp... ");
    nizk_group_params_t p;
    nizk_group_params_init_256bit(&p);
    nizk_group_elem_t gen;
    nizk_bigint_copy(&gen.elem, &p.g);
    nizk_scalar_t zero; nizk_scalar_zero(&zero);
    nizk_group_elem_t r;
    nizk_group_exp(&r, &gen, &zero, &p);
    assert(nizk_bigint_is_one(&r.elem));
    nizk_scalar_t one; nizk_scalar_set_u64(&one, 1);
    nizk_group_exp(&r, &gen, &one, &p);
    assert(nizk_group_elem_eq(&r, &gen));
    nizk_group_elem_t re;
    nizk_group_elem_rand(&re, &p);
    assert(nizk_group_elem_is_valid(&re, &p));
    nizk_group_params_clear(&p);
    tests_passed++;
    printf("PASSED\n");
}

/* ---- L2: CRS Tests ---- */

static void test_crs_soundness(void) {
    tests_run++;
    printf("  TEST crs_soundness... ");
    nizk_group_params_t p;
    nizk_group_params_init_256bit(&p);
    nizk_crs_t crs;
    uint8_t seed[] = "seed123";
    nizk_crs_setup_soundness(&crs, &p, seed, sizeof(seed));
    assert(crs.has_trapdoor == 0);
    assert(nizk_crs_validate(&crs, &p) == 1);
    nizk_crs_clear(&crs);
    nizk_group_params_clear(&p);
    tests_passed++;
    printf("PASSED\n");
}

static void test_crs_zk(void) {
    tests_run++;
    printf("  TEST crs_zk_mode... ");
    nizk_group_params_t p;
    nizk_group_params_init_256bit(&p);
    nizk_crs_t crs;
    nizk_crs_setup_zk(&crs, &p, NULL);
    assert(crs.has_trapdoor == 1);
    assert(nizk_crs_validate(&crs, &p) == 1);
    assert(nizk_crs_verify_trapdoor(&crs, &p) == 1);
    nizk_crs_clear(&crs);
    nizk_group_params_clear(&p);
    tests_passed++;
    printf("PASSED\n");
}

static void test_crs_pedersen(void) {
    tests_run++;
    printf("  TEST crs_pedersen... ");
    nizk_group_params_t p;
    nizk_group_params_init_256bit(&p);
    nizk_crs_t crs;
    uint8_t seed[] = "ped";
    nizk_crs_setup_pedersen(&crs, &p, seed, sizeof(seed));
    assert(crs.type == NIZK_CRS_CHAUM_PEDERSEN);
    assert(nizk_crs_validate(&crs, &p) == 1);
    nizk_crs_clear(&crs);
    nizk_group_params_clear(&p);
    tests_passed++;
    printf("PASSED\n");
}

/* ---- L5: Pedersen Commitment Tests ---- */

static void test_pedersen(void) {
    tests_run++;
    printf("  TEST pedersen_commit... ");
    nizk_group_params_t p;
    nizk_group_params_init_256bit(&p);
    nizk_crs_t crs;
    uint8_t seed[] = "com";
    nizk_crs_setup_pedersen(&crs, &p, seed, sizeof(seed));
    nizk_scalar_t m, r;
    nizk_scalar_set_u64(&m, 42);
    nizk_scalar_set_u64(&r, 12345);
    nizk_commitment_t c;
    nizk_commitment_opening_t o;
    nizk_pedersen_commit(&c, &o, &m, &r, &crs, &p);
    assert(nizk_pedersen_verify(&c, &o, &crs, &p) == 1);
    nizk_commitment_opening_t fake;
    nizk_scalar_set_u64(&fake.m, 99);
    nizk_scalar_copy(&fake.r, &o.r);
    assert(nizk_pedersen_verify(&c, &fake, &crs, &p) == 0);
    nizk_commitment_opening_clear(&o);
    nizk_crs_clear(&crs);
    nizk_group_params_clear(&p);
    tests_passed++;
    printf("PASSED\n");
}

static void test_homomorphic(void) {
    tests_run++;
    printf("  TEST homomorphic... ");
    nizk_group_params_t p;
    nizk_group_params_init_256bit(&p);
    nizk_crs_t crs;
    uint8_t seed[] = "homo";
    nizk_crs_setup_pedersen(&crs, &p, seed, sizeof(seed));
    nizk_scalar_t m1, r1, m2, r2;
    nizk_scalar_set_u64(&m1, 10); nizk_scalar_set_u64(&r1, 100);
    nizk_scalar_set_u64(&m2, 20); nizk_scalar_set_u64(&r2, 200);
    nizk_commitment_t c1, c2;
    nizk_commitment_opening_t o1, o2;
    nizk_pedersen_commit(&c1, &o1, &m1, &r1, &crs, &p);
    nizk_pedersen_commit(&c2, &o2, &m2, &r2, &crs, &p);
    nizk_commitment_t cs;
    nizk_commitment_add(&cs, &c1, &c2, &p);
    nizk_commitment_opening_t os;
    nizk_scalar_add(&os.m, &m1, &m2, &p);
    nizk_scalar_add(&os.r, &r1, &r2, &p);
    assert(nizk_pedersen_verify(&cs, &os, &crs, &p) == 1);
    nizk_crs_clear(&crs);
    nizk_group_params_clear(&p);
    tests_passed++;
    printf("PASSED\n");
}

/* ---- L5: Sigma Protocol Tests ---- */

static void test_schnorr(void) {
    tests_run++;
    printf("  TEST schnorr_sigma... ");
    nizk_group_params_t p;
    nizk_group_params_init_256bit(&p);
    nizk_scalar_t sk; nizk_scalar_rand(&sk, &p);
    nizk_group_elem_t gen, pk;
    nizk_bigint_copy(&gen.elem, &p.g);
    nizk_group_exp(&pk, &gen, &sk, &p);
    nizk_sigma_statement_t stmt;
    nizk_sigma_statement_init(&stmt, &pk, &gen, &p);
    nizk_scalar_t v;
    nizk_sigma_commitment_t c;
    nizk_schnorr_commit(&c, &v, &p);
    nizk_sigma_challenge_t ch;
    nizk_scalar_rand(&ch.c, &p);
    nizk_sigma_response_t r;
    nizk_schnorr_respond(&r, &sk, &v, &ch, &p);
    assert(nizk_schnorr_verify(&stmt, &c, &ch, &r, &p) == 1);
    /* Special soundness: extract witness */
    nizk_sigma_challenge_t ch2;
    nizk_scalar_t one;
    nizk_scalar_set_u64(&one, 1);
    nizk_scalar_add(&ch2.c, &ch.c, &one, &p);
    nizk_sigma_response_t r2;
    nizk_schnorr_respond(&r2, &sk, &v, &ch2, &p);
    nizk_sigma_transcript_t t1 = {c, ch, r};
    nizk_sigma_transcript_t t2 = {c, ch2, r2};
    nizk_scalar_t ext;
    assert(nizk_schnorr_extract(&ext, &t1, &t2, &p) == 1);
    assert(nizk_scalar_cmp(&ext, &sk) == 0);
    nizk_group_params_clear(&p);
    tests_passed++;
    printf("PASSED\n");
}

static void test_hvzk(void) {
    tests_run++;
    printf("  TEST hvzk_simulator... ");
    nizk_group_params_t p;
    nizk_group_params_init_256bit(&p);
    nizk_scalar_t sk; nizk_scalar_rand(&sk, &p);
    nizk_group_elem_t gen, pk;
    nizk_bigint_copy(&gen.elem, &p.g);
    nizk_group_exp(&pk, &gen, &sk, &p);
    nizk_sigma_statement_t stmt;
    nizk_sigma_statement_init(&stmt, &pk, &gen, &p);
    nizk_sigma_transcript_t sim;
    nizk_sigma_simulate_transcript(&sim, &stmt, &p);
    assert(nizk_schnorr_verify(&stmt, &sim.commitment,
            &sim.challenge, &sim.response, &p) == 1);
    nizk_group_params_clear(&p);
    tests_passed++;
    printf("PASSED\n");
}

static void test_or(void) {
    tests_run++;
    printf("  TEST or_protocol... ");
    nizk_group_params_t p;
    nizk_group_params_init_256bit(&p);
    nizk_scalar_t sk1, sk2;
    nizk_scalar_rand(&sk1, &p); nizk_scalar_rand(&sk2, &p);
    nizk_group_elem_t gen, pk1, pk2;
    nizk_bigint_copy(&gen.elem, &p.g);
    nizk_group_exp(&pk1, &gen, &sk1, &p);
    nizk_group_exp(&pk2, &gen, &sk2, &p);
    nizk_or_statement_t os;
    nizk_sigma_statement_init(&os.stmt[0], &pk1, &gen, &p);
    nizk_sigma_statement_init(&os.stmt[1], &pk2, &gen, &p);
    nizk_or_witness_t ow = {0};
    nizk_scalar_copy(&ow.secret, &sk1);
    nizk_sigma_commitment_t cs[2];
    nizk_scalar_t es[2], sc[2];
    nizk_or_prove_commit(cs, es, sc, &os, &ow, &p);
    nizk_scalar_t ct; nizk_scalar_rand(&ct, &p);
    int known = 0, unknown = 1;

    /* Build OR responses manually (matching nizk_proof.c's correct pattern) */
    nizk_sigma_response_t rs[2];
    nizk_sigma_challenge_t chs[2];

    /* Real branch (known=0): c_real = ct - sc[unknown], response = es[known] + c_real * witness */
    nizk_scalar_t c_real;
    nizk_scalar_sub(&c_real, &ct, &sc[unknown], &p);
    nizk_scalar_copy(&chs[known].c, &c_real);
    nizk_scalar_t cw;
    nizk_scalar_mul(&cw, &c_real, &ow.secret, &p);
    nizk_scalar_add(&rs[known].s, &es[known], &cw, &p);

    /* Simulated branch (unknown=1): use pre-computed challenge and ephemeral */
    nizk_scalar_copy(&chs[unknown].c, &sc[unknown]);
    nizk_scalar_copy(&rs[unknown].s, &es[unknown]);

    nizk_sigma_challenge_t cc; nizk_scalar_copy(&cc.c, &ct);
    assert(nizk_or_verify(&os, cs, chs, rs, &cc, &p) == 1);
    nizk_group_params_clear(&p);
    tests_passed++;
    printf("PASSED\n");
}

/* ---- L5: NIZK Fiat-Shamir Tests ---- */

static void test_nizk_dlog(void) {
    tests_run++;
    printf("  TEST nizk_dlog... ");
    nizk_group_params_t p;
    nizk_group_params_init_256bit(&p);
    nizk_crs_t crs;
    uint8_t seed[] = "nizk";
    nizk_crs_setup_soundness(&crs, &p, seed, sizeof(seed));
    nizk_scalar_t sk; nizk_scalar_rand(&sk, &p);
    nizk_group_elem_t gen, pk;
    nizk_bigint_copy(&gen.elem, &p.g);
    nizk_group_exp(&pk, &gen, &sk, &p);
    nizk_proof_t pf;
    uint8_t lb[] = "test";
    nizk_prove_dlog(&pf, &crs, &pk, &sk, lb, sizeof(lb), &p);
    assert(nizk_verify_dlog(&pf, &crs, &pk, lb, sizeof(lb), &p) == 1);
    uint8_t bad[] = "bad";
    assert(nizk_verify_dlog(&pf, &crs, &pk, bad, sizeof(bad), &p) == 0);
    nizk_proof_clear(&pf);
    nizk_crs_clear(&crs);
    nizk_group_params_clear(&p);
    tests_passed++;
    printf("PASSED\n");
}

static void test_nizk_dlog_eq(void) {
    tests_run++;
    printf("  TEST nizk_dlog_eq... ");
    nizk_group_params_t p;
    nizk_group_params_init_256bit(&p);
    nizk_crs_t crs;
    uint8_t seed[] = "eq";
    nizk_crs_setup_soundness(&crs, &p, seed, sizeof(seed));
    nizk_scalar_t w; nizk_scalar_rand(&w, &p);
    nizk_group_elem_t gen, u, v;
    nizk_bigint_copy(&gen.elem, &p.g);
    nizk_group_exp(&u, &gen, &w, &p);
    nizk_group_exp(&v, &crs.h, &w, &p);
    nizk_proof_t pf;
    uint8_t lb[] = "eq";
    nizk_prove_dlog_eq(&pf, &crs, &u, &v, &crs.h, &w, lb, sizeof(lb), &p);
    assert(nizk_verify_dlog_eq(&pf, &crs, &u, &v, &crs.h, lb, sizeof(lb), &p) == 1);
    nizk_proof_clear(&pf);
    nizk_crs_clear(&crs);
    nizk_group_params_clear(&p);
    tests_passed++;
    printf("PASSED\n");
}

static void test_nizk_com(void) {
    tests_run++;
    printf("  TEST nizk_commitment_proof... ");
    nizk_group_params_t p;
    nizk_group_params_init_256bit(&p);
    nizk_crs_t crs;
    uint8_t seed[] = "cpf";
    nizk_crs_setup_pedersen(&crs, &p, seed, sizeof(seed));
    nizk_scalar_t m, r;
    nizk_scalar_set_u64(&m, 42); nizk_scalar_set_u64(&r, 12345);
    nizk_commitment_t c;
    nizk_commitment_opening_t o;
    nizk_pedersen_commit(&c, &o, &m, &r, &crs, &p);
    nizk_proof_t pf;
    uint8_t lb[] = "com";
    nizk_prove_commitment(&pf, &crs, &c, &o, lb, sizeof(lb), &p);
    assert(nizk_verify_commitment(&pf, &crs, &c, lb, sizeof(lb), &p) == 1);
    nizk_commitment_opening_clear(&o);
    nizk_proof_clear(&pf);
    nizk_crs_clear(&crs);
    nizk_group_params_clear(&p);
    tests_passed++;
    printf("PASSED\n");
}

static void test_nizk_or(void) {
    tests_run++;
    printf("  TEST nizk_or_proof... ");
    nizk_group_params_t p;
    nizk_group_params_init_256bit(&p);
    nizk_crs_t crs;
    uint8_t seed[] = "or";
    nizk_crs_setup_soundness(&crs, &p, seed, sizeof(seed));
    nizk_scalar_t sk1, sk2;
    nizk_scalar_rand(&sk1, &p); nizk_scalar_rand(&sk2, &p);
    nizk_group_elem_t gen, pk1, pk2;
    nizk_bigint_copy(&gen.elem, &p.g);
    nizk_group_exp(&pk1, &gen, &sk1, &p);
    nizk_group_exp(&pk2, &gen, &sk2, &p);
    nizk_proof_t pf;
    uint8_t lb[] = "or";
    nizk_prove_or(&pf, &crs, &pk1, &pk2, &sk1, 0, lb, sizeof(lb), &p);
    assert(nizk_verify_or(&pf, &crs, &pk1, &pk2, lb, sizeof(lb), &p) == 1);
    nizk_proof_clear(&pf);
    nizk_crs_clear(&crs);
    nizk_group_params_clear(&p);
    tests_passed++;
    printf("PASSED\n");
}

/* ---- L2: Simulator Tests ---- */

static void test_sim(void) {
    tests_run++;
    printf("  TEST simulator... ");
    nizk_group_params_t p;
    nizk_group_params_init_256bit(&p);
    nizk_crs_t crs_zk;
    nizk_crs_setup_zk(&crs_zk, &p, NULL);
    nizk_simulator_state_t sim;
    assert(nizk_simulator_init(&sim, &crs_zk) == 1);
    nizk_scalar_t d; nizk_scalar_rand(&d, &p);
    nizk_group_elem_t gen, pk;
    nizk_bigint_copy(&gen.elem, &p.g);
    nizk_group_exp(&pk, &gen, &d, &p);
    nizk_proof_t sp;
    uint8_t lb[] = "sim";
    nizk_simulate_dlog(&sp, &sim, &crs_zk, &pk, lb, sizeof(lb), &p);
    assert(sp.type == NIZK_PROOF_DLOG_KNOWLEDGE);
    nizk_proof_clear(&sp);
    nizk_simulator_clear(&sim);
    nizk_crs_clear(&crs_zk);
    nizk_group_params_clear(&p);
    tests_passed++;
    printf("PASSED\n");
}

static void test_dist(void) {
    tests_run++;
    printf("  TEST distinguisher... ");
    nizk_group_params_t p;
    nizk_group_params_init_256bit(&p);
    nizk_crs_t crs_zk, crs_s;
    nizk_crs_setup_zk(&crs_zk, &p, NULL);
    uint8_t seed[] = "dist";
    nizk_crs_setup_soundness(&crs_s, &p, seed, sizeof(seed));
    nizk_scalar_t sk; nizk_scalar_rand(&sk, &p);
    nizk_group_elem_t gen, pk;
    nizk_bigint_copy(&gen.elem, &p.g);
    nizk_group_exp(&pk, &gen, &sk, &p);
    nizk_proof_t rp[10], sp[10];
    nizk_distinguisher_test(rp, sp, 10, &crs_zk, &crs_s, &pk, &sk, &p);
    double s = nizk_compare_proofs(rp, sp, 10, &p);
    assert(s >= 0.0 && s <= 1.0);
    printf("(sim=%.3f) ", s);
    for (int i = 0; i < 10; i++) {
        nizk_proof_clear(&rp[i]);
        nizk_proof_clear(&sp[i]);
    }
    nizk_crs_clear(&crs_zk);
    nizk_crs_clear(&crs_s);
    nizk_group_params_clear(&p);
    tests_passed++;
    printf("PASSED\n");
}

static void test_ser(void) {
    tests_run++;
    printf("  TEST serialization... ");
    nizk_group_params_t p;
    nizk_group_params_init_256bit(&p);
    nizk_crs_t crs;
    uint8_t seed[] = "ser";
    nizk_crs_setup_soundness(&crs, &p, seed, sizeof(seed));
    nizk_scalar_t sk; nizk_scalar_rand(&sk, &p);
    nizk_group_elem_t gen, pk;
    nizk_bigint_copy(&gen.elem, &p.g);
    nizk_group_exp(&pk, &gen, &sk, &p);
    nizk_proof_t pf;
    uint8_t lb[] = "ser";
    nizk_prove_dlog(&pf, &crs, &pk, &sk, lb, sizeof(lb), &p);
    size_t len = nizk_proof_serialize(NULL, 0, &pf, &p);
    uint8_t *buf = (uint8_t*)malloc(len);
    assert(buf && nizk_proof_serialize(buf, len, &pf, &p) == len);
    nizk_proof_t dp;
    assert(nizk_proof_deserialize(&dp, buf, len, &p) == 1);
    assert(nizk_verify_dlog(&dp, &crs, &pk, lb, sizeof(lb), &p) == 1);
    free(buf);
    nizk_proof_clear(&pf);
    nizk_proof_clear(&dp);
    nizk_crs_clear(&crs);
    nizk_group_params_clear(&p);
    tests_passed++;
    printf("PASSED\n");
}

int main(void) {
    printf("=== NIZK CRS Module Tests ===\n\n");
    printf("-- L3: Group & Big Integer --\n");
    test_group_params();
    test_bigint();
    test_modular();
    test_scalar();
    test_group_exp();
    printf("\n-- L2: CRS --\n");
    test_crs_soundness();
    test_crs_zk();
    test_crs_pedersen();
    printf("\n-- L5: Pedersen Commitments --\n");
    test_pedersen();
    test_homomorphic();
    printf("\n-- L5: Sigma Protocols --\n");
    test_schnorr();
    test_hvzk();
    test_or();
    printf("\n-- L5: NIZK (Fiat-Shamir) --\n");
    test_nizk_dlog();
    test_nizk_dlog_eq();
    test_nizk_com();
    test_nizk_or();
    printf("\n-- L2: Simulator --\n");
    test_sim();
    test_dist();
    printf("\n-- Serialization --\n");
    test_ser();
    printf("\n=== %d/%d tests passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
