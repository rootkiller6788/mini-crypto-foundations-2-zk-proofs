/*
 * bench_kea.c — Benchmark KEA operations
 * Measures: challenge creation, response, verification, extraction.
 */
#include "kea.h"
#include <stdio.h>
#include <time.h>

int main(void) {
    printf("=== KEA Operations Benchmark ===\n");
    CyclicGroup* g = group_create_test_group();
    if (!g) { printf("FAIL\n"); return 1; }

    int iters = 10000;
    clock_t start, end;

    /* KEA Instance creation */
    start = clock();
    for (int i = 0; i < iters; i++) {
        KEAInstance* inst = kea_instance_create(g);
        kea_instance_free(inst);
    }
    end = clock();
    printf("kea_instance_create/free x%d: %.3f ms\n",
           iters, 1000.0*(end-start)/CLOCKS_PER_SEC);

    /* KEA Response creation + verify */
    KEAInstance* inst = kea_instance_create(g);
    start = clock();
    for (int i = 0; i < iters; i++) {
        KEAResponse* resp = kea_response_create(inst, 3);
        kea_response_free(resp);
    }
    end = clock();
    printf("kea_response_create/free x%d: %.3f ms\n",
           iters, 1000.0*(end-start)/CLOCKS_PER_SEC);

    /* Security game */
    start = clock();
    for (int i = 0; i < iters/100; i++) {
        kea_security_game(g, 0);
    }
    end = clock();
    printf("kea_security_game x%d: %.3f ms\n",
           iters/100, 1000.0*(end-start)/CLOCKS_PER_SEC);

    kea_instance_free(inst);
    group_free(g);
    printf("==================================\n");
    return 0;
}
