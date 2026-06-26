// bench_ntt.c - NTT vs Naive Polynomial Multiplication Benchmarks
// Compares O(n log n) NTT against O(n^2) naive convolution.
// Knowledge: L5 Algorithm (performance analysis), L8 Advanced (optimization)
// Reference: Cooley & Tukey (1965), Bernstein (2001)

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "fft.h"
#include "polynomial.h"

static double bench_ntt_mul(int n, int trials) {
    FieldParams fp = FIELD_BN254;
    NTTDomain* d = ntt_domain_create(n, &fp);
    if (!d) return -1.0;

    fe_t* a = (fe_t*)calloc((size_t)n, sizeof(fe_t));
    fe_t* b = (fe_t*)calloc((size_t)n, sizeof(fe_t));
    fe_t* res = (fe_t*)calloc((size_t)n, sizeof(fe_t));

    for (int i = 0; i < n/2; i++) {
        fe_random(a[i], &fp);
        fe_random(b[i], &fp);
    }

    clock_t start = clock();
    for (int t = 0; t < trials; t++) {
        poly_mul_ntt(res, a, n/2 - 1, b, n/2 - 1, d);
    }
    clock_t end = clock();

    double elapsed = ((double)(end - start)) / CLOCKS_PER_SEC / trials;
    free(a); free(b); free(res);
    ntt_domain_free(d);
    return elapsed;
}

static double bench_naive_mul(int n, int trials) {
    FieldParams fp = FIELD_BN254;
    Polynomial* a = poly_create(n/2);
    Polynomial* b = poly_create(n/2);
    Polynomial* r = poly_create(n);

    for (int i = 0; i < n/2; i++) {
        fe_random(a->coeffs[i], &fp);
        fe_random(b->coeffs[i], &fp);
    }
    a->degree = n/2 - 1;
    b->degree = n/2 - 1;

    clock_t start = clock();
    for (int t = 0; t < trials; t++) {
        poly_mul(r, a, b, &fp);
    }
    clock_t end = clock();

    double elapsed = ((double)(end - start)) / CLOCKS_PER_SEC / trials;
    poly_free(a); poly_free(b); poly_free(r);
    return elapsed;
}

static void bench_field_ops(int n_ops) {
    FieldParams fp = FIELD_BN254;
    fe_t a, b, c;
    fe_random(a, &fp);
    fe_random(b, &fp);

    clock_t start = clock();
    for (int i = 0; i < n_ops; i++) {
        fe_add(c, a, b, &fp);
        fe_set(a, c);
    }
    clock_t end = clock();
    printf("  fe_add: %.3f us/op\n", ((double)(end - start)) / CLOCKS_PER_SEC / n_ops * 1e6);

    fe_random(a, &fp); fe_random(b, &fp);
    start = clock();
    for (int i = 0; i < n_ops / 10; i++) {
        fe_mul(c, a, b, &fp);
        fe_set(a, c);
    }
    end = clock();
    printf("  fe_mul (Montgomery): %.3f us/op\n", ((double)(end - start)) / CLOCKS_PER_SEC / (n_ops/10) * 1e6);

    fe_random(a, &fp);
    start = clock();
    for (int i = 0; i < n_ops / 100; i++) {
        fe_inv(c, a, &fp);
    }
    end = clock();
    printf("  fe_inv: %.3f us/op\n", ((double)(end - start)) / CLOCKS_PER_SEC / (n_ops/100) * 1e6);
}

int main(void) {
    printf("=== NTT vs Naive Poly Mul Benchmark ===\n\n");
    printf("Comparing O(n log n) NTT vs O(n^2) naive.\n\n");

    printf("%-10s %-15s %-15s %-10s\n", "Size", "NTT (us)", "Naive (us)", "Speedup");
    printf("%-10s %-15s %-15s %-10s\n", "----", "-------", "---------", "-------");

    int sizes[] = {64, 128, 256, 512, 1024};
    for (int si = 0; si < 5; si++) {
        int n = sizes[si];
        int trials = (n <= 256) ? 100 : ((n <= 512) ? 50 : 20);
        double ntt_t = bench_ntt_mul(n, trials);
        double naive_t = bench_naive_mul(n, trials);
        if (ntt_t > 0 && naive_t > 0) {
            printf("%-10d %-15.2f %-15.2f %-10.1fx\n", n, ntt_t * 1e6, naive_t * 1e6, naive_t / ntt_t);
        }
    }

    printf("\n=== Field Operation Benchmarks ===\n");
    bench_field_ops(100000);
    printf("\n=== Benchmarks Complete ===\n");
    return 0;
}