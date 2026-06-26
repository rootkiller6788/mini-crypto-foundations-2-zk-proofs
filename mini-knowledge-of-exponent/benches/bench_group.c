/*
 * bench_group.c — Benchmark cyclic group operations
 * Measures: modular arithmetic, exponentiation, group element ops.
 */
#include "group.h"
#include <stdio.h>
#include <time.h>

int main(void) {
    printf("=== Group Operations Benchmark ===\n");
    CyclicGroup* g = group_create_medium_group();
    if (!g) { printf("FAIL\n"); return 1; }
    GroupElement* a = ge_create(5, g);
    GroupElement* b = ge_create(7, g);
    clock_t start, end;
    int iters = 100000;

    start = clock();
    for (int i = 0; i < iters; i++) ge_mul(a, b);
    end = clock();
    printf("ge_mul x%d: %.3f ms\n", iters, 1000.0*(end-start)/CLOCKS_PER_SEC);

    start = clock();
    for (int i = 0; i < iters; i++) ge_pow(a, 3);
    end = clock();
    printf("ge_pow x%d: %.3f ms\n", iters, 1000.0*(end-start)/CLOCKS_PER_SEC);

    start = clock();
    for (int i = 0; i < iters/100; i++) ge_random(g, i);
    end = clock();
    printf("ge_random x%d: %.3f ms\n", iters/100, 1000.0*(end-start)/CLOCKS_PER_SEC);

    start = clock();
    for (int i = 0; i < iters; i++) mpz_mod_mul(123, 456, g->modulus);
    end = clock();
    printf("mpz_mod_mul x%d: %.3f ms\n", iters, 1000.0*(end-start)/CLOCKS_PER_SEC);

    ge_free(a); ge_free(b); group_free(g);
    printf("==================================\n");
    return 0;
}
