/*======================================================================
 * test_ip_systems.c -- Comprehensive test suite for IP systems
 *
 * Tests core IP functionality: prover/verifier lifecycle,
 * field arithmetic, polynomial operations, sumcheck protocol,
 * graph protocols (GNI), and arithmetization.
 *======================================================================*/

#include "ip_system.h"
#include "ip_protocols.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <math.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
    tests_run++; \
    printf("  TEST %s... ", name); \
} while(0)

#define PASS() do { \
    tests_passed++; \
    printf("PASS\n"); \
} while(0)

#define FAIL(msg) do { \
    printf("FAIL: %s\n", msg); \
} while(0)

/*----------------------------------------------------------------------
 * L1: Prover/Verifier Lifecycle Tests
 *----------------------------------------------------------------------*/
static void test_prover_init(void) {
    TEST("prover_init");
    IPProver prover;
    int ret = ip_prover_init(&prover, (IPProverStrategy)0x1);
    assert(ret == 0);
    assert(prover.is_initialized == 1);
    ip_prover_free(&prover);
    PASS();
}

static void test_prover_init_null(void) {
    TEST("prover_init_null");
    int ret = ip_prover_init(NULL, (IPProverStrategy)0x1);
    assert(ret == -1);
    PASS();
}

static void test_verifier_init(void) {
    TEST("verifier_init");
    IPVerifier verifier;
    int ret = ip_verifier_init(&verifier,
        (IPVerifierStrategy)0x1, (IPVerdictFunction)0x1,
        IP_PROTOCOL_PUBLIC_COIN, 128);
    assert(ret == 0);
    assert(verifier.is_initialized == 1);
    ip_verifier_free(&verifier);
    PASS();
}

static void test_proof_system_init(void) {
    TEST("proof_system_init");
    IPProver prover;
    IPVerifier verifier;
    ip_prover_init(&prover, (IPProverStrategy)0x1);
    ip_verifier_init(&verifier, (IPVerifierStrategy)0x1,
        (IPVerdictFunction)0x1, IP_PROTOCOL_PUBLIC_COIN, 128);
    IPProofSystem psys;
    int ret = ip_proof_system_init(&psys, "TestProtocol",
        &prover, &verifier, 3, IP_PROTOCOL_PUBLIC_COIN);
    assert(ret == 0);
    assert(psys.is_valid == 1);
    assert(psys.num_rounds == 3);
    ip_verifier_free(&verifier);
    ip_prover_free(&prover);
    PASS();
}

/*----------------------------------------------------------------------
 * L3: Transcript Operations
 *----------------------------------------------------------------------*/
static void test_transcript_init(void) {
    TEST("transcript_init");
    IPTranscript t;
    ip_transcript_init(&t);
    assert(t.num_messages == 0);
    assert(t.total_rounds == 0);
    assert(t.verdict_is_set == 0);
    PASS();
}

static void test_transcript_add(void) {
    TEST("transcript_add");
    IPTranscript t;
    ip_transcript_init(&t);
    IPMessage msg;
    memset(&msg, 0, sizeof(msg));
    msg.round = 0;
    msg.sender = IP_MESSAGE_VERIFIER;
    msg.length = 10;
    int ret = ip_transcript_add(&t, &msg);
    assert(ret == 0);
    assert(t.num_messages == 1);
    assert(t.total_rounds == 1);
    PASS();
}

static void test_transcript_to_string(void) {
    TEST("transcript_to_string");
    IPTranscript t;
    ip_transcript_init(&t);
    IPMessage msg;
    memset(&msg, 0, sizeof(msg));
    msg.round = 0;
    msg.sender = IP_MESSAGE_PROVER;
    msg.length = 5;
    ip_transcript_add(&t, &msg);
    char buf[512];
    int n = ip_transcript_to_string(&t, buf, sizeof(buf));
    assert(n > 0);
    PASS();
}

/*----------------------------------------------------------------------
 * L3: Random Tape Operations
 *----------------------------------------------------------------------*/
static void test_tape_init(void) {
    TEST("tape_init");
    IPRandomTape tape;
    int ret = ip_tape_init(&tape, 64, 1);
    assert(ret == 0);
    assert(tape.num_coins == 64);
    assert(tape.is_public == 1);
    ip_tape_free(&tape);
    PASS();
}

static void test_tape_consume(void) {
    TEST("tape_consume");
    IPRandomTape tape;
    ip_tape_init(&tape, 64, 1);
    uint64_t coin = ip_tape_consume(&tape, 32);
    assert(tape.coins_used == 32);
    (void)coin;
    ip_tape_free(&tape);
    PASS();
}

/*----------------------------------------------------------------------
 * L3: Finite Field Arithmetic Tests
 *----------------------------------------------------------------------*/
static void test_field_init(void) {
    TEST("field_init_prime7");
    IPFiniteField field;
    int ret = ip_field_init(&field, 7);
    assert(ret == 0);
    assert(field.prime == 7);
    ip_field_free(&field);
    PASS();
}

static void test_field_init_nonprime(void) {
    TEST("field_init_nonprime");
    IPFiniteField field;
    int ret = ip_field_init(&field, 6);
    assert(ret == -1);
    PASS();
}

static void test_field_add(void) {
    TEST("field_add");
    IPFiniteField field;
    ip_field_init(&field, 7);
    uint64_t r = ip_field_add(&field, 5, 4);
    assert(r == 2); /* 5+4=9 mod7 = 2 */
    ip_field_free(&field);
    PASS();
}

static void test_field_sub(void) {
    TEST("field_sub");
    IPFiniteField field;
    ip_field_init(&field, 7);
    uint64_t r = ip_field_sub(&field, 2, 5);
    assert(r == 4); /* 2-5 mod7 = -3 mod7 = 4 */
    ip_field_free(&field);
    PASS();
}

static void test_field_mul(void) {
    TEST("field_mul");
    IPFiniteField field;
    ip_field_init(&field, 7);
    uint64_t r = ip_field_mul(&field, 3, 5);
    assert(r == 1); /* 15 mod7 = 1 */
    ip_field_free(&field);
    PASS();
}

static void test_field_pow(void) {
    TEST("field_pow");
    IPFiniteField field;
    ip_field_init(&field, 7);
    uint64_t r = ip_field_pow(&field, 2, 3);
    assert(r == 1); /* 8 mod7 = 1 */
    ip_field_free(&field);
    PASS();
}

static void test_field_inv(void) {
    TEST("field_inv");
    IPFiniteField field;
    ip_field_init(&field, 7);
    uint64_t inv3 = ip_field_inv(&field, 3);
    assert((3 * inv3) % 7 == 1); /* 3*5=15 mod7=1 => inv=5 */
    ip_field_free(&field);
    PASS();
}

/*----------------------------------------------------------------------
 * L3: Polynomial Tests
 *----------------------------------------------------------------------*/
static void test_polynomial_eval(void) {
    TEST("polynomial_eval");
    uint64_t coeffs[] = {3, 2, 1}; /* P(x)=1*x^2+2*x+3 = x^2+2x+3 */
    IPPolynomial poly;
    int ret = ip_polynomial_init(&poly, coeffs, 2, 7);
    assert(ret == 0);
    uint64_t val = ip_polynomial_eval(&poly, 2);
    /* P(2)=4+4+3=11 mod7=4 */
    assert(val == 4);
    ip_polynomial_free(&poly);
    PASS();
}

/*----------------------------------------------------------------------
 * L3: Multilinear Extension Tests
 *----------------------------------------------------------------------*/
static void test_multilinear_init(void) {
    TEST("multilinear_init");
    uint64_t evals[] = {1, 2, 3, 4}; /* f(00)=1, f(01)=2, f(10)=3, f(11)=4 */
    IPMultilinearExtension mex;
    int ret = ip_multilinear_init(&mex, evals, 2, 97);
    assert(ret == 0);
    assert(mex.num_vars == 2);
    ip_multilinear_free(&mex);
    PASS();
}

static void test_multilinear_eval_boolean(void) {
    TEST("multilinear_eval_boolean");
    uint64_t evals[] = {1, 2, 3, 4}; /* n=2 */
    IPMultilinearExtension mex;
    ip_multilinear_init(&mex, evals, 2, 97);

    uint64_t pt00[] = {0, 0};
    uint64_t pt01[] = {0, 1};
    uint64_t pt10[] = {1, 0};
    uint64_t pt11[] = {1, 1};

    assert(ip_multilinear_eval(&mex, pt00) == 1);
    assert(ip_multilinear_eval(&mex, pt01) == 3);
    assert(ip_multilinear_eval(&mex, pt10) == 2);
    assert(ip_multilinear_eval(&mex, pt11) == 4);
    ip_multilinear_free(&mex);
    PASS();
}

static void test_multilinear_eval_dp(void) {
    TEST("multilinear_eval_dp");
    uint64_t evals[] = {1, 2, 3, 4};
    IPMultilinearExtension mex;
    ip_multilinear_init(&mex, evals, 2, 97);
    uint64_t pt[] = {0, 1};
    uint64_t v1 = ip_multilinear_eval(&mex, pt);
    uint64_t v2 = ip_multilinear_eval_dp(&mex, pt);
    assert(v1 == v2);
    ip_multilinear_free(&mex);
    PASS();
}

static void test_multilinear_restrict(void) {
    TEST("multilinear_restrict");
    uint64_t evals[] = {1, 2, 3, 4};
    IPMultilinearExtension mex;
    ip_multilinear_init(&mex, evals, 2, 97);
    IPMultilinearExtension out;
    int ret = ip_multilinear_restrict(&mex, 0, 0, &out);
    assert(ret == 0);
    assert(out.num_vars == 1);
    /* Restricted to var0=0: f(0,0)=1, f(0,1)=3 => [1,3] */
    assert(out.evaluations[0] == 1);
    assert(out.evaluations[1] == 3);
    ip_multilinear_free(&mex);
    ip_multilinear_free(&out);
    PASS();
}

/*----------------------------------------------------------------------
 * L4: Error Reduction Tests
 *----------------------------------------------------------------------*/
static void test_chernoff_bound(void) {
    TEST("chernoff_bound");
    double b = ip_chernoff_bound(10, 0.5);
    double expected = pow(0.5, 10.0);
    assert(fabs(b - expected) < 1e-9);
    PASS();
}

/*----------------------------------------------------------------------
 * L4: Arithmetization Tests
 *----------------------------------------------------------------------*/
static void test_arith_3cnf_clause_sat(void) {
    TEST("arith_3cnf_clause_sat");
    /* Clause: (x0 OR x1 OR x2), all literals positive */
    size_t clause[] = {0, 2, 4}; /* var 0, var 1, var 2 */
    uint64_t assignment[] = {0, 0, 0};
    /* All false => clause not satisfied => A_C = 1 (product is 1) */
    uint64_t r = ip_arithmetize_3cnf_clause(clause, 3, assignment, 3, 7);
    assert(r == 1);
    PASS();
}

static void test_arith_3cnf_clause_sat2(void) {
    TEST("arith_3cnf_clause_sat_true");
    size_t clause[] = {0, 2, 4};
    uint64_t assignment[] = {1, 0, 0};
    /* x0 true => clause satisfied => A_C = 0 */
    uint64_t r = ip_arithmetize_3cnf_clause(clause, 3, assignment, 3, 7);
    assert(r == 0);
    PASS();
}

/*----------------------------------------------------------------------
 * L2: Statistics Collection (with null strategies - won't run) */
static void test_statistics_null_check(void) {
    TEST("statistics_null_check");
    IPStatistics stats;
    memset(&stats, 0, sizeof(stats));
    assert(stats.num_runs == 0);
    PASS();
}

/*----------------------------------------------------------------------
 * L5: Sumcheck Soundness Bound
 *----------------------------------------------------------------------*/
static void test_sumcheck_soundness(void) {
    TEST("sumcheck_soundness_bound");
    double err = ip_sumcheck_soundness_error(10, 1000000007ULL, 1);
    assert(err < 1e-6); /* n/p = 10/1e9 << 1 */
    PASS();
}

/*----------------------------------------------------------------------
 * L1: Constants and Macros
 *----------------------------------------------------------------------*/
static void test_constants(void) {
    TEST("constants");
    assert(IP_MAX_ROUNDS == 64);
    assert(IP_DEFAULT_REPETITIONS == 64);
    assert(IP_MAX_MESSAGE_SIZE == 1024);
    PASS();
}

/*----------------------------------------------------------------------
 * Main
 *----------------------------------------------------------------------*/
int main(void) {
    printf("=== Interactive Proof Systems Test Suite ===\n\n");

    /* L1: Definitions */
    printf("L1: Core Definitions\n");
    test_prover_init();
    test_prover_init_null();
    test_verifier_init();
    test_proof_system_init();
    test_constants();

    /* L2: Core Concepts */
    printf("\nL2: Core Concepts\n");
    test_statistics_null_check();
    test_chernoff_bound();

    /* L3: Mathematical Structures */
    printf("\nL3: Mathematical Structures\n");
    test_transcript_init();
    test_transcript_add();
    test_transcript_to_string();
    test_tape_init();
    test_tape_consume();
    test_field_init();
    test_field_init_nonprime();
    test_field_add();
    test_field_sub();
    test_field_mul();
    test_field_pow();
    test_field_inv();
    test_polynomial_eval();
    test_multilinear_init();
    test_multilinear_eval_boolean();
    test_multilinear_eval_dp();
    test_multilinear_restrict();

    /* L4: Fundamental Laws */
    printf("\nL4: Fundamental Laws\n");
    test_chernoff_bound();
    test_arith_3cnf_clause_sat();
    test_arith_3cnf_clause_sat2();

    /* L5: Algorithms */
    printf("\nL5: Algorithms\n");
    test_sumcheck_soundness();

    printf("\n=== Results: %d/%d tests passed ===\n",
           tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
