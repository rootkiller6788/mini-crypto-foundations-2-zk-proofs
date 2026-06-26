/*
 * bench_dlp.c — Benchmark DLP algorithms
 * Compares BSGS vs Pollard Rho vs Brute Force for small groups.
 */
#include "discrete_log.h"
#include <stdio.h>
#include <time.h>

int main(void) {
    printf("=== DLP Algorithm Benchmark ===\n");

    /* Test with different group sizes */
    uint64_t primes[] = {1031, 2003, 4001};
    int n_tests = 3;

    for (int i = 0; i < n_tests; i++) {
        uint64_t p = primes[i];
        if (!mpz_is_prime_naive(p)) continue;

        CyclicGroup* g = group_create_custom(p, p - 1, 2);
        if (!g) continue;

        GroupElement* base = ge_create(2, g);
        uint64_t secret = p / 3;
        GroupElement* target = ge_pow(base, secret);

        printf("\nGroup mod %llu (order %llu):\n",
               (unsigned long long)p, (unsigned long long)g->order);

        clock_t start, end;
        double t_bsgs, t_rho, t_force;

        start = clock();
        uint64_t x1 = dlp_baby_giant_step(base, target, g);
        end = clock();
        t_bsgs = 1000.0 * (end - start) / CLOCKS_PER_SEC;
        printf("  BSGS:   x=%llu (%.3f ms)\n", (unsigned long long)x1, t_bsgs);

        start = clock();
        uint64_t x2 = dlp_pollard_rho(base, target, g);
        end = clock();
        t_rho = 1000.0 * (end - start) / CLOCKS_PER_SEC;
        printf("  Rho:    x=%llu (%.3f ms)\n", (unsigned long long)x2, t_rho);

        /* Brute force (only up to reasonable limit) */
        start = clock();
        uint64_t cur = 1;
        for (uint64_t x = 0; x < g->order && x < 5000; x++) {
            if (cur == target->value) { x2 = x; break; }
            cur = mpz_mod_mul(cur, 2, p);
        }
        end = clock();
        t_force = 1000.0 * (end - start) / CLOCKS_PER_SEC;
        printf("  Brute:  x=%llu (%.3f ms)\n", (unsigned long long)x2, t_force);

        ge_free(base); ge_free(target); group_free(g);
    }

    printf("\n==================================\n");
    return 0;
}
