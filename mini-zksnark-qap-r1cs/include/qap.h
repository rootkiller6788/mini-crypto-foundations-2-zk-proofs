/* qap.h — Quadratic Arithmetic Programs
 *
 * QAP is the algebraic representation that makes SNARK proving possible.
 * Given an R1CS instance, the QAP encodes constraints as polynomial equations.
 * A witness w satisfies the R1CS iff the resulting polynomial H(x) satisfies
 * the divisibility relation: A(x)·B(x) - C(x) = H(x)·Z(x)
 *
 * Key concepts:
 *   - QAP: triple of polynomial vectors (A_i(x), B_i(x), C_i(x))
 *   - Target polynomial: Z(x) = ∏_{k=1}^m (x - r_k) where r_k are distinct roots
 *   - Witness polynomial: A_w(x)·B_w(x) - C_w(x) must be divisible by Z(x)
 *   - Schwartz-Zippel: enough to check at random point for soundness
 *   - Lagrange basis: one polynomial set per variable, interpolated from R1CS
 *
 * QAP definition:
 *   Let A_i(x), B_i(x), C_i(x) for i=0..ℓ be degree-(m-1) polynomials.
 *   Let Z(x) = ∏_{k=1}^m (x - r_k) where r_k are the m constraint roots.
 *   For witness w = (1, u, w_aux):
 *     A(x) = ∑ w_i·A_i(x),  B(x) = ∑ w_i·B_i(x),  C(x) = ∑ w_i·C_i(x)
 *   R1CS satisfied ⇔ A(x)·B(x) - C(x) = H(x)·Z(x) for some H(x)
 *
 * References:
 *   - Gennaro, Gentry, Parno, Raykova (2013) "Quadratic Span Programs"
 *   - Parno, Howell, Gentry, Raykova (2013) "Pinocchio"
 *   - Ben-Sasson et al. (2014) "Succinct Non-Interactive Zero Knowledge"
 */
#ifndef QAP_H
#define QAP_H
#include "r1cs.h"
#include "polynomial.h"

/* ─── QAP instance (polynomial form of R1CS) ─── */
typedef struct {
    Polynomial** A;        /* A[i](x) for variable i = 0..n_vars-1 */
    Polynomial** B;        /* B[i](x) for variable i = 0..n_vars-1 */
    Polynomial** C;        /* C[i](x) for variable i = 0..n_vars-1 */
    Polynomial*  Z;        /* vanishing polynomial Z(x) */
    fe_t*        roots;    /* constraint evaluation roots r_1..r_m */
    int          n_vars;   /* number of variables */
    int          n_constraints; /* number of constraints = degree of Z */
} QAP;

/* ─── Lifecycle ─── */
QAP*  qap_create(int n_vars, int n_constraints);
void  qap_free(QAP* qap);
QAP*  qap_copy(const QAP* src);

/* ─── Core QAP construction ─── */
/* R1CS → QAP: interpolate each variable's contribution from constraint matrices.
 *
 * For each variable i, A_i(x) is the polynomial of degree < m such that
 * A_i(r_k) = A[k][i] (the coefficient of variable i in constraint k's A term).
 * Same for B_i, C_i.
 */
QAP* qap_from_r1cs(const R1CS* r1cs, const fe_t* roots,
                   const FieldParams* fp);

/* ─── QAP evaluation ─── */
/* Compute A(x)·B(x) - C(x) for a given witness at point x */
void qap_eval(fe_t result, const QAP* qap, const fe_t* witness,
              const fe_t x, const FieldParams* fp);

/* Compute the witness polynomials A_w(x), B_w(x), C_w(x) */
Polynomial* qap_witness_poly(const QAP* qap, const fe_t* witness,
                              int poly_idx, /* 0=A, 1=B, 2=C */
                              const FieldParams* fp);

/* Compute H(x) = (A(x)·B(x) - C(x)) / Z(x) */
Polynomial* qap_compute_h(const QAP* qap, const fe_t* witness,
                          const FieldParams* fp);

/* ─── QAP satisfiability check ─── */
/* Direct polynomial check: A·B - C divisible by Z ? */
int  qap_verify_poly(const QAP* qap, const fe_t* witness,
                     const FieldParams* fp);

/* Schwartz-Zippel probabilistic check: evaluate at random point */
int  qap_verify_sz(const QAP* qap, const fe_t* witness,
                   const FieldParams* fp);

/* ─── Size properties ─── */
int  qap_degree_A(const QAP* qap);  /* max degree among A_i */
int  qap_degree_B(const QAP* qap);
int  qap_degree_C(const QAP* qap);
int  qap_total_polys(const QAP* qap); /* 3 * n_vars */
void qap_print_summary(const QAP* qap);

#endif /* QAP_H */
