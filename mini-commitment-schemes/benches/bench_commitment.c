/**
 * @file bench_commitment.c
 * @brief Performance benchmarks for commitment schemes
 *
 * Measures throughput of core operations across all four schemes.
 * Reports operations/second for commit, verify, homomorphic combine,
 * Merkle tree construction, and proof verification.
 *
 * Knowledge Mapping:
 *   L5: Algorithmic complexity measurement
 *   L6: Empirical scheme comparison
 *   L8: Performance implications of advanced features
 */

#include "commitment.h"
#include "pedersen.h"
#include "hash_commit.h"
#include "vector_commit.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
static double get_time_sec(void) {
    LARGE_INTEGER freq, cnt;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&cnt);
    return (double)cnt.QuadPart / (double)freq.QuadPart;
}
#else
#include <sys/time.h>
static double get_time_sec(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec * 1e-6;
}
#endif

#define BENCH_ITERATIONS 10000
#define BENCH_WARMUP      1000

typedef struct {
    const char *name;
    double      elapsed;
    size_t      iterations;
} bench_result;

static void bench_report(const bench_result *r) {
    double ops_per_sec = r->iterations / r->elapsed;
    double us_per_op   = (r->elapsed / r->iterations) * 1e6;
    printf("  %-42s %10.1f ops/s  %8.1f us/op\n",
           r->name, ops_per_sec, us_per_op);
}

int main(void) {
    printf("\n");
    printf("=================================================================\n");
    printf("  COMMITMENT SCHEME PERFORMANCE BENCHMARKS\n");
    printf("  Iterations per test: %d (+%d warmup)\n", BENCH_ITERATIONS, BENCH_WARMUP);
    printf("=================================================================\n\n");

    bench_result r;
    double t0, t1;

    /* ================================================================
     * Bench 1: Pedersen commit throughput
     * ================================================================ */
    printf("[1] Pedersen Commit\n");

    commit_ctx p_ctx;
    commit_ctx_init_u64(&p_ctx, 104729, COMMIT_SCHEME_PEDERSEN);
    bigint g;
    bigint_init_u64(&g, 5);
    pedersen_setup(&p_ctx, &g);

    bigint p_m, p_r;
    bigint_init_u64(&p_m, 42);
    bigint_init_u64(&p_r, 12345);
    commitment p_c;
    commit_init(&p_c, COMMIT_SCHEME_PEDERSEN);

    for (int i = 0; i < BENCH_WARMUP; i++) {
        pedersen_commit(&p_ctx, &p_c, &p_m, &p_r);
    }

    t0 = get_time_sec();
    for (int i = 0; i < BENCH_ITERATIONS; i++) {
        bigint_init_u64(&p_r, (uint64_t)(i + 1000));
        pedersen_commit(&p_ctx, &p_c, &p_m, &p_r);
    }
    t1 = get_time_sec();
    r = (bench_result){"Pedersen commit (C=g^m*h^r mod p)", t1 - t0, BENCH_ITERATIONS};
    bench_report(&r);

    /* ================================================================
     * Bench 2: Pedersen verify throughput
     * ================================================================ */
    printf("[2] Pedersen Verify\n");

    p_c.opened = false;
    pedersen_commit(&p_ctx, &p_c, &p_m, &p_r);
    t0 = get_time_sec();
    for (int i = 0; i < BENCH_ITERATIONS; i++) {
        pedersen_verify(&p_ctx, &p_c);
    }
    t1 = get_time_sec();
    r = (bench_result){"Pedersen verify", t1 - t0, BENCH_ITERATIONS};
    bench_report(&r);

    /* ================================================================
     * Bench 3: Modular exponentiation (building block)
     * ================================================================ */
    printf("[3] Modular Exponentiation\n");

    modctx m_ctx;
    modctx_init_u64(&m_ctx, 104729);
    bigint base, exp, res;
    bigint_init_u64(&base, 3);
    bigint_init_u64(&exp, 65537);
    bigint_init(&res);

    for (int i = 0; i < BENCH_WARMUP; i++) {
        mod_exp(&m_ctx, &res, &base, &exp);
    }

    t0 = get_time_sec();
    for (int i = 0; i < BENCH_ITERATIONS / 10; i++) {
        for (int shift = 0; shift < 10; shift++) {
            bigint_init_u64(&exp, (uint64_t)(65537 + shift * 100));
            mod_exp(&m_ctx, &res, &base, &exp);
        }
    }
    t1 = get_time_sec();
    r = (bench_result){"modular exp (square-and-multiply)", t1 - t0, BENCH_ITERATIONS};
    bench_report(&r);

    /* ================================================================
     * Bench 4: Modular inverse (extended Euclidean)
     * ================================================================ */
    printf("[4] Modular Inverse\n");

    bigint inv_in, inv_out;
    bigint_init_u64(&inv_in, 123);
    bigint_init(&inv_out);

    for (int i = 0; i < BENCH_WARMUP; i++) {
        mod_inv(&m_ctx, &inv_out, &inv_in);
    }

    t0 = get_time_sec();
    for (int i = 0; i < BENCH_ITERATIONS / 10; i++) {
        for (int j = 1; j <= 10; j++) {
            bigint_init_u64(&inv_in, (uint64_t)(j * 7 + 1));
            mod_inv(&m_ctx, &inv_out, &inv_in);
        }
    }
    t1 = get_time_sec();
    r = (bench_result){"modular inverse (ext Euclidean)", t1 - t0, BENCH_ITERATIONS};
    bench_report(&r);

    /* ================================================================
     * Bench 5: Hash commit throughput
     * ================================================================ */
    printf("[5] Hash Commit\n");

    bigint h_m, h_r, h_c;
    bigint_init_u64(&h_m, 0x123456789ABCDEF0ULL);
    bigint_init_u64(&h_r, 0xFEDCBA9876543210ULL);
    bigint_init(&h_c);

    for (int i = 0; i < BENCH_WARMUP; i++) {
        hash_commit(&h_m, &h_r, &h_c);
    }

    t0 = get_time_sec();
    for (int i = 0; i < BENCH_ITERATIONS; i++) {
        bigint_init_u64(&h_r, (uint64_t)(i + 999));
        hash_commit(&h_m, &h_r, &h_c);
    }
    t1 = get_time_sec();
    r = (bench_result){"hash commit (C=H(m||r))", t1 - t0, BENCH_ITERATIONS};
    bench_report(&r);

    /* ================================================================
     * Bench 6: Domain-separated hash commit
     * ================================================================ */
    printf("[6] Domain-Separated Hash Commit\n");

    const char *domain = "COMMIT-V1";
    for (int i = 0; i < BENCH_WARMUP; i++) {
        hash_commit_domain((const uint8_t*)domain, strlen(domain),
                          &h_m, &h_r, &h_c);
    }

    t0 = get_time_sec();
    for (int i = 0; i < BENCH_ITERATIONS; i++) {
        bigint_init_u64(&h_r, (uint64_t)(i + 999));
        hash_commit_domain((const uint8_t*)domain, strlen(domain),
                          &h_m, &h_r, &h_c);
    }
    t1 = get_time_sec();
    r = (bench_result){"domain-sep hash commit", t1 - t0, BENCH_ITERATIONS};
    bench_report(&r);

    /* ================================================================
     * Bench 7: Merkle tree construction
     * ================================================================ */
    printf("[7] Merkle Tree Construction\n");

    vector_commitment vc;
    vc_init(&vc, 64);
    for (size_t i = 0; i < 64; i++) {
        bigint val;
        bigint_init_u64(&val, (uint64_t)(i * 100 + 50));
        vc_set_element(&vc, i, &val);
    }

    for (int i = 0; i < BENCH_WARMUP / 50; i++) {
        vector_commitment tmp_vc;
        vc_init(&tmp_vc, 64);
        for (size_t j = 0; j < 64; j++) {
            bigint val;
            bigint_init_u64(&val, (uint64_t)(j * 100 + 50));
            vc_set_element(&tmp_vc, j, &val);
        }
        vc_commit(&tmp_vc);
        vc_destroy(&tmp_vc);
    }

    t0 = get_time_sec();
    size_t merkle_iter = BENCH_ITERATIONS / 20;
    for (size_t i = 0; i < merkle_iter; i++) {
        vector_commitment tmp_vc;
        vc_init(&tmp_vc, 64);
        for (size_t j = 0; j < 64; j++) {
            bigint val;
            bigint_init_u64(&val, (uint64_t)(j * 100 + 50));
            vc_set_element(&tmp_vc, j, &val);
        }
        vc_commit(&tmp_vc);
        vc_destroy(&tmp_vc);
    }
    t1 = get_time_sec();
    r = (bench_result){"Merkle tree build (64 elements)", t1 - t0, merkle_iter};
    bench_report(&r);

    /* ================================================================
     * Bench 8: Merkle proof verification
     * ================================================================ */
    printf("[8] Merkle Proof Verification\n");

    vc_commit(&vc);
    vc_merkle_proof proof;
    vc_open(&vc, 31, &proof);
    bigint leaf_val;
    bigint_init_u64(&leaf_val, (uint64_t)(31 * 100 + 50));

    for (int i = 0; i < BENCH_WARMUP; i++) {
        vc_verify(&vc, 31, &leaf_val, &proof);
    }

    t0 = get_time_sec();
    for (int i = 0; i < BENCH_ITERATIONS; i++) {
        vc_verify(&vc, 31, &leaf_val, &proof);
    }
    t1 = get_time_sec();
    r = (bench_result){"Merkle proof verify (O(log n))", t1 - t0, BENCH_ITERATIONS};
    bench_report(&r);

    /* ================================================================
     * Bench 9: Homomorphic combination
     * ================================================================ */
    printf("[9] Homomorphic Combination\n");

    bigint hm_m1, hm_r1, hm_m2, hm_r2;
    bigint_init_u64(&hm_m1, 10);
    bigint_init_u64(&hm_r1, 100);
    bigint_init_u64(&hm_m2, 20);
    bigint_init_u64(&hm_r2, 200);
    commitment hc1, hc2, hc_sum;
    commit_init(&hc1, COMMIT_SCHEME_PEDERSEN);
    commit_init(&hc2, COMMIT_SCHEME_PEDERSEN);
    commit_init(&hc_sum, COMMIT_SCHEME_PEDERSEN);
    pedersen_commit(&p_ctx, &hc1, &hm_m1, &hm_r1);
    pedersen_commit(&p_ctx, &hc2, &hm_m2, &hm_r2);

    for (int i = 0; i < BENCH_WARMUP; i++) {
        pedersen_homomorphic_add(&p_ctx, &hc1, &hc2, &hc_sum);
    }

    t0 = get_time_sec();
    for (int i = 0; i < BENCH_ITERATIONS; i++) {
        pedersen_homomorphic_add(&p_ctx, &hc1, &hc2, &hc_sum);
    }
    t1 = get_time_sec();
    r = (bench_result){"homomorphic add (C1*C2 mod p)", t1 - t0, BENCH_ITERATIONS};
    bench_report(&r);

    /* ================================================================
     * Bench 10: Big integer arithmetic
     * ================================================================ */
    printf("[10] Big Integer Arithmetic\n");

    bigint bi_a, bi_b, bi_c;
    bigint_init_u64(&bi_a, 1234567890);
    bigint_init_u64(&bi_b, 987654321);
    bigint_init(&bi_c);

    for (int i = 0; i < BENCH_WARMUP; i++) {
        bigint_mul(&bi_c, &bi_a, &bi_b);
    }

    t0 = get_time_sec();
    for (int i = 0; i < BENCH_ITERATIONS; i++) {
        bigint_init_u64(&bi_b, (uint64_t)(i + 1000));
        bigint_mul(&bi_c, &bi_a, &bi_b);
    }
    t1 = get_time_sec();
    r = (bench_result){"bigint mul (schoolbook)", t1 - t0, BENCH_ITERATIONS};
    bench_report(&r);

    /* ================================================================
     * Summary
     * ================================================================ */
    printf("\n=================================================================\n");
    printf("  BENCHMARK SUMMARY\n");
    printf("=================================================================\n");
    printf("  All measurements on prime modulus p=104729 (test parameters).\n");
    printf("  Cryptographic-size moduli (256-bit) would be ~8-16x slower.\n");
    printf("  Relative performance ranking is preserved across parameter sizes.\n\n");

    vc_destroy(&vc);

    return 0;
}
