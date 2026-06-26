/* fft.h — Fast Fourier Transform over finite fields
 *
 * Implements the NTT (Number-Theoretic Transform), which is the finite-field
 * analog of the FFT. Essential for efficient polynomial operations in SNARKs:
 *   - O(n log n) polynomial multiplication (via convolution theorem)
 *   - Fast evaluation of polynomials at roots of unity
 *   - Fast Lagrange interpolation
 *
 * Key concepts:
 *   - Roots of unity in F_p: ω such that ω^n = 1, ω^k ≠ 1 for k < n
 *   - Cooley-Tukey butterfly: the basic FFT decomposition
 *   - Inverse NTT for interpolation
 *   - Bit-reversal permutation for in-place radix-2 FFT
 *   - 2-adicity: n must divide p-1 for n-th roots of unity to exist
 *
 * References:
 *   - Cooley & Tukey (1965) "An algorithm for the machine calculation of
 *     complex Fourier series"
 *   - Ben-Sasson et al. (2014) "Scalable Zero Knowledge via Cycles of
 *     Elliptic Curves"
 *   - Bernstein (2001) "Multidigit multiplication for mathematicians"
 */
#ifndef FFT_H
#define FFT_H
#include "field.h"
#include <stdint.h>

/* ─── NTT domain ─── */
typedef struct {
    fe_t*         roots;        /* powers of primitive root ω */
    fe_t*         inv_roots;    /* powers of ω^{-1} for inverse NTT */
    int           size;         /* n (must be power of 2) */
    int           log_size;     /* log2(n) */
    FieldParams*  fp;
} NTTDomain;

/* ─── Domain management ─── */
/* Create an NTT domain of size n over field fp.
   Returns NULL if n is not a power of 2 or no n-th root of unity exists. */
NTTDomain* ntt_domain_create(int n, const FieldParams* fp);
void       ntt_domain_free(NTTDomain* d);
int        ntt_domain_get_root(const NTTDomain* d, int k); /* ω^k */

/* ─── Forward NTT (evaluation) ─── */
/* In-place forward NTT: a_k → Σ_{j=0}^{n-1} a_j · ω^{jk}
   Also known as the DFT over F_p. */
void ntt_forward(fe_t* a, const NTTDomain* d);

/* ─── Inverse NTT (interpolation) ─── */
/* In-place inverse NTT: a_k → (1/n) · Σ_{j=0}^{n-1} a_j · ω^{-jk} */
void ntt_inverse(fe_t* a, const NTTDomain* d);

/* ─── Polynomial multiplication via NTT ─── */
/* Multiply two polynomials using the convolution theorem:
   1. NTT both to get evaluation form
   2. Pointwise multiply
   3. Inverse NTT to get coefficient form
   Requires result_degree ≤ n-1. */
void poly_mul_ntt(fe_t* result, const fe_t* a_coeffs, int a_deg,
                  const fe_t* b_coeffs, int b_deg,
                  const NTTDomain* d);

/* ─── Multi-point evaluation via NTT ─── */
/* Evaluate polynomial at all n roots of unity in O(n log n).
   Assumes deg(p) < n. */
void poly_eval_all_roots(fe_t* results, const fe_t* coeffs, int deg,
                         const NTTDomain* d);

/* ─── Interpolation at roots of unity ─── */
/* Given evaluations at n roots of unity, recover coefficients.
   Equivalent to inverse NTT. */
void poly_interp_from_roots(fe_t* coeffs, const fe_t* evals,
                            const NTTDomain* d);

/* ─── Coset evaluation ─── */
/* Evaluate polynomial at shifted domain: s·ω^k for k=0..n-1 */
void poly_eval_coset(fe_t* results, const fe_t* coeffs, int deg,
                     const fe_t shift, const NTTDomain* d);

/* ─── Matrix-vector multiplication in NTT domain ─── */
/* Compute (A * v) where A is an n×n circulant matrix defined by
   its first column col[0..n-1]. Does this in O(n log n) via NTT. */
void circulant_mul(fe_t* result, const fe_t* col, const fe_t* vec,
                   const NTTDomain* d);

/* ─── Batch polynomial evaluation (non-FFT, Horner's method) ─── */
/* For arbitrary evaluation points (not domain roots). O(n·deg). */
void poly_eval_multi(fe_t* results, const fe_t* coeffs, int deg,
                     const fe_t* points, int n_points,
                     const FieldParams* fp);

#endif /* FFT_H */
