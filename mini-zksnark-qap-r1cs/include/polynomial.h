/* polynomial.h — univariate polynomials over F_p
 *
 * Core operations on polynomials over finite fields. Essential for QAP
 * construction where each constraint maps to a polynomial evaluated at
 * distinct roots of unity.
 *
 * Key concepts:
 *   - Polynomial representation: coefficient form vs evaluation form
 *   - Lagrange interpolation: recover polynomial from evaluations
 *   - FFT/NTT: O(n log n) evaluation/interpolation over root-of-unity domain
 *   - Polynomial division: needed for QAP witness polynomial
 *   - Schwartz-Zippel lemma: poly identity testing by random evaluation
 *
 * References:
 *   - Cooley-Tukey (1965) "FFT algorithm"
 *   - Gennaro, Gentry, Parno, Raykova (2013) "Quadratic Span Programs"
 *   - Ben-Sasson et al. (2014) "Succinct Non-Interactive Zero Knowledge"
 */
#ifndef POLYNOMIAL_H
#define POLYNOMIAL_H
#include "field.h"
#include <stdint.h>

/* ─── Polynomial in coefficient form ─── */
typedef struct {
    fe_t*  coeffs;    /* coefficient array: a_0 + a_1*x + ... + a_{deg}*x^{deg} */
    int    degree;    /* highest index with non-zero coefficient */
    int    capacity;  /* allocated size */
} Polynomial;

/* ─── Lifecycle ─── */
Polynomial* poly_create(int max_degree);
void poly_free(Polynomial* p);
Polynomial* poly_copy(const Polynomial* src);
void poly_trim(Polynomial* p);  /* remove trailing zeros */

/* ─── Elementary operations ─── */
void poly_set_zero(Polynomial* p);
void poly_set_constant(Polynomial* p, const fe_t c);
void poly_neg(Polynomial* r, const Polynomial* a, const FieldParams* fp);
void poly_add(Polynomial* r, const Polynomial* a, const Polynomial* b,
              const FieldParams* fp);
void poly_sub(Polynomial* r, const Polynomial* a, const Polynomial* b,
              const FieldParams* fp);
void poly_mul(Polynomial* r, const Polynomial* a, const Polynomial* b,
              const FieldParams* fp);
void poly_mul_scalar(Polynomial* r, const Polynomial* a, const fe_t s,
                     const FieldParams* fp);

/* ─── Evaluation ─── */
void poly_eval(fe_t r, const Polynomial* p, const fe_t x,
               const FieldParams* fp);
void poly_eval_batch(fe_t* results, const Polynomial* p, const fe_t* xs,
                     int n, const FieldParams* fp);

/* ─── Interpolation ─── */
/* Lagrange: given n points (x_i, y_i), returns the unique poly of degree < n */
Polynomial* lagrange_interpolate(const fe_t* xs, const fe_t* ys, int n,
                                 const FieldParams* fp);

/* ─── Kernel polynomials (for QAP) ─── */
/* Z(x) = ∏_{i∈H} (x - ω^i) where H is the domain */
Polynomial* vanishing_polynomial(const fe_t* domain, int n,
                                 const FieldParams* fp);

/* ─── Polynomial division ─── */
/* r = a / b with quotient q and remainder r, returns 1 on success */
int poly_divmod(Polynomial* q, Polynomial* r, const Polynomial* a,
                const Polynomial* b, const FieldParams* fp);

/* ─── FFT over root-of-unity domain ─── */
/* Evaluate polynomial at all n-th roots of unity in O(n log n) */
void fft_evaluate(fe_t* out, const Polynomial* p, const fe_t* roots,
                  int n, const FieldParams* fp);
/* Interpolate from n evaluation points to degree-(n-1) polynomial */
void fft_interpolate(Polynomial* p, const fe_t* evals, const fe_t* roots,
                     int n, const FieldParams* fp);

/* ─── Random polynomial (ZK blinding) ─── */
void poly_random(Polynomial* p, int max_deg, const FieldParams* fp);

/* ─── Utility ─── */
void poly_print(const Polynomial* p);
int  poly_degree(const Polynomial* p);

#endif /* POLYNOMIAL_H */
