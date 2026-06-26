/*======================================================================
 * example_sumcheck.c -- Sumcheck Protocol Example
 *
 * Demonstrates the sumcheck protocol: verifying that the sum of
 * a multilinear polynomial over the Boolean hypercube equals a
 * claimed value.
 *
 * L6: #SAT via sumcheck -- counting satisfying assignments
 *======================================================================*/

#include "ip_system.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* External functions we use (declared in sumcheck headers) */
extern uint64_t ip_sumcheck_compute_sum(const IPMultilinearExtension *mex);
extern int ip_sumcheck_full(const IPMultilinearExtension *mex,
                             uint64_t claimed_sum, IPRandomTape *tape,
                             int *accepted);
extern double ip_sumcheck_soundness_error(size_t n, uint64_t field_size,
                                           size_t repetitions);
extern int ip_multilinear_product(const IPMultilinearExtension *A,
                                   const IPMultilinearExtension *B,
                                   IPMultilinearExtension *out);

int main(void) {
    printf("=== Sumcheck Protocol Example ===\n\n");

    /* Define a simple function f: {0,1}^2 -> GF(97)
     * f(0,0)=1, f(0,1)=2, f(1,0)=3, f(1,1)=4
     * Sum over hypercube = 1+2+3+4 = 10
     */
    uint64_t evals[] = {1, 2, 3, 4};
    uint64_t prime = 97;

    IPMultilinearExtension mex;
    ip_multilinear_init(&mex, evals, 2, prime);

    uint64_t true_sum = ip_sumcheck_compute_sum(&mex);
    printf("Function f on {0,1}^2:\n");
    printf("  f(0,0)=1, f(0,1)=2, f(1,0)=3, f(1,1)=4\n");
    printf("True sum over hypercube: %llu\n\n", (unsigned long long)true_sum);

    /* Run sumcheck protocol with correct claim */
    printf("Running sumcheck with correct claim H=%llu:\n",
           (unsigned long long)true_sum);

    IPRandomTape tape;
    ip_tape_init(&tape, 256, 1); /* Public-coin protocol */

    int accepted = 0;
    ip_sumcheck_full(&mex, true_sum, &tape, &accepted);
    printf("  Verdict: %s\n\n", accepted ? "ACCEPT" : "REJECT");

    /* Run sumcheck with WRONG claim */
    printf("Running sumcheck with wrong claim H=999:\n");
    ip_tape_free(&tape);
    ip_tape_init(&tape, 256, 1);
    ip_sumcheck_full(&mex, 999, &tape, &accepted);
    printf("  Verdict: %s\n\n", accepted ? "ACCEPT" : "REJECT");

    /* Soundness analysis */
    printf("Soundness analysis:\n");
    double err = ip_sumcheck_soundness_error(mex.num_vars, prime, 1);
    printf("  Single round error bound: %.6f (n/|F| = %zu/%llu)\n",
           err, mex.num_vars, (unsigned long long)prime);
    err = ip_sumcheck_soundness_error(mex.num_vars, prime, 5);
    printf("  After 5 repetitions: %.12f\n\n", err);

    /* Product of multilinear extensions */
    printf("Multilinear extension product example:\n");
    uint64_t evals2[] = {5, 6, 7, 8};
    IPMultilinearExtension mex2;
    ip_multilinear_init(&mex2, evals2, 2, prime);

    IPMultilinearExtension prod;
    ip_multilinear_product(&mex, &mex2, &prod);
    printf("  f*g product sum: %llu\n",
           (unsigned long long)ip_sumcheck_compute_sum(&prod));
    printf("  Expected: (1*5)+(2*6)+(3*7)+(4*8) = 5+12+21+32 = 70 mod 97 = 70\n");

    /* Cleanup */
    ip_multilinear_free(&mex);
    ip_multilinear_free(&mex2);
    ip_multilinear_free(&prod);
    ip_tape_free(&tape);

    printf("\n=== Sumcheck Example Complete ===\n");
    return 0;
}
