
// qap.c - Quadratic Arithmetic Programs
// QAP encodes R1CS constraints as polynomial divisibility relations.
// A(w)*B(w) - C(w) = H(w)*Z(w) for witness w.
// Knowledge: L4 Fundamental Law (QAP reduction), L3 Math Structure

#include "qap.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

QAP* qap_create(int n_vars, int n_constraints) {
    QAP* q = (QAP*)malloc(sizeof(QAP));
    if (!q) return NULL;
    q->n_vars = n_vars;
    q->n_constraints = n_constraints;
    q->A = (Polynomial**)calloc((size_t)n_vars, sizeof(Polynomial*));
    q->B = (Polynomial**)calloc((size_t)n_vars, sizeof(Polynomial*));
    q->C = (Polynomial**)calloc((size_t)n_vars, sizeof(Polynomial*));
    q->Z = NULL;
    q->roots = (fe_t*)malloc((size_t)n_constraints * sizeof(fe_t));
    for (int i = 0; i < n_vars; i++) {
        q->A[i] = poly_create(n_constraints);
        q->B[i] = poly_create(n_constraints);
        q->C[i] = poly_create(n_constraints);
    }
    return q;
}

void qap_free(QAP* q) {
    if (!q) return;
    for (int i = 0; i < q->n_vars; i++) {
        poly_free(q->A[i]); poly_free(q->B[i]); poly_free(q->C[i]);
    }
    free(q->A); free(q->B); free(q->C);
    poly_free(q->Z); free(q->roots); free(q);
}

QAP* qap_copy(const QAP* src) {
    QAP* d = qap_create(src->n_vars, src->n_constraints);
    if (!d) return NULL;
    for (int i = 0; i < src->n_vars; i++) {
        poly_free(d->A[i]); d->A[i] = poly_copy(src->A[i]);
        poly_free(d->B[i]); d->B[i] = poly_copy(src->B[i]);
        poly_free(d->C[i]); d->C[i] = poly_copy(src->C[i]);
    }
    if (src->Z) { poly_free(d->Z); d->Z = poly_copy(src->Z); }
    for (int i = 0; i < src->n_constraints; i++)
        fe_set(d->roots[i], src->roots[i]);
    return d;
}

QAP* qap_from_r1cs(const R1CS* r1cs, const fe_t* roots, const FieldParams* fp) {
    int m = r1cs->n_constraints;
    int nv = r1cs->n_vars;
    QAP* q = qap_create(nv, m);
    if (!q) return NULL;
    for (int i = 0; i < m; i++) fe_set(q->roots[i], roots[i]);

    /* Build vanishing polynomial Z(x) = prod_{k=0}^{m-1} (x - roots[k]) */
    q->Z = vanishing_polynomial(roots, m, fp);

    /* For each variable i, build A_i(x), B_i(x), C_i(x) by interpolation.
       A_i(r_k) = coefficient of variable i in constraint k's A term.
       We extract from the R1CS sparse matrices. */
    /* First collect evaluations for each variable */
    fe_t* A_vals = (fe_t*)malloc((size_t)m * sizeof(fe_t));
    fe_t* B_vals = (fe_t*)malloc((size_t)m * sizeof(fe_t));
    fe_t* C_vals = (fe_t*)malloc((size_t)m * sizeof(fe_t));

    for (int var = 0; var < nv; var++) {
        /* Clear evaluation arrays */
        for (int k = 0; k < m; k++) {
            fe_zero(A_vals[k]); fe_zero(B_vals[k]); fe_zero(C_vals[k]);
        }
        /* Scan sparse matrices for this variable */
        for (int e = 0; e < r1cs->A.n_entries; e++) {
            if (r1cs->A.entries[e].col == var)
                fe_set(A_vals[r1cs->A.entries[e].row], r1cs->A.entries[e].val);
        }
        for (int e = 0; e < r1cs->B.n_entries; e++) {
            if (r1cs->B.entries[e].col == var)
                fe_set(B_vals[r1cs->B.entries[e].row], r1cs->B.entries[e].val);
        }
        for (int e = 0; e < r1cs->C.n_entries; e++) {
            if (r1cs->C.entries[e].col == var)
                fe_set(C_vals[r1cs->C.entries[e].row], r1cs->C.entries[e].val);
        }
        /* Interpolate to get polynomials A_i, B_i, C_i */
        Polynomial* pA = lagrange_interpolate(roots, A_vals, m, fp);
        Polynomial* pB = lagrange_interpolate(roots, B_vals, m, fp);
        Polynomial* pC = lagrange_interpolate(roots, C_vals, m, fp);
        if (pA) { poly_free(q->A[var]); q->A[var] = pA; }
        if (pB) { poly_free(q->B[var]); q->B[var] = pB; }
        if (pC) { poly_free(q->C[var]); q->C[var] = pC; }
    }
    free(A_vals); free(B_vals); free(C_vals);
    return q;
}

void qap_eval(fe_t result, const QAP* q, const fe_t* witness, const fe_t x, const FieldParams* fp) {
    fe_t A_x, B_x, C_x;
    fe_zero(A_x); fe_zero(B_x); fe_zero(C_x);
    /* A(x) = sum_i w_i * A_i(x) */
    for (int i = 0; i < q->n_vars; i++) {
        fe_t ai; poly_eval(ai, q->A[i], x, fp);
        fe_t term; fe_mul(term, ai, witness[i], fp);
        fe_add(A_x, A_x, term, fp);
    }
    /* B(x) = sum_i w_i * B_i(x) */
    for (int i = 0; i < q->n_vars; i++) {
        fe_t bi; poly_eval(bi, q->B[i], x, fp);
        fe_t term; fe_mul(term, bi, witness[i], fp);
        fe_add(B_x, B_x, term, fp);
    }
    /* C(x) = sum_i w_i * C_i(x) */
    for (int i = 0; i < q->n_vars; i++) {
        fe_t ci; poly_eval(ci, q->C[i], x, fp);
        fe_t term; fe_mul(term, ci, witness[i], fp);
        fe_add(C_x, C_x, term, fp);
    }
    /* result = A(x)*B(x) - C(x) */
    fe_t AB; fe_mul(AB, A_x, B_x, fp);
    fe_sub(result, AB, C_x, fp);
}

Polynomial* qap_witness_poly(const QAP* q, const fe_t* witness, int poly_idx, const FieldParams* fp) {
    Polynomial** src = (poly_idx == 0) ? q->A : ((poly_idx == 1) ? q->B : q->C);
    Polynomial* result = poly_create(q->n_constraints);
    if (!result) return NULL;
    poly_set_zero(result);
    for (int i = 0; i < q->n_vars; i++) {
        fe_t wi; fe_set(wi, witness[i]);
        Polynomial* term = poly_copy(src[i]);
        if (!term) continue;
        poly_mul_scalar(term, term, wi, fp);
        poly_add(result, result, term, fp);
        poly_free(term);
    }
    return result;
}

Polynomial* qap_compute_h(const QAP* q, const fe_t* witness, const FieldParams* fp) {
    /* H(x) = (A(x)*B(x) - C(x)) / Z(x) */
    Polynomial* A = qap_witness_poly(q, witness, 0, fp);
    Polynomial* B = qap_witness_poly(q, witness, 1, fp);
    Polynomial* C = qap_witness_poly(q, witness, 2, fp);
    if (!A || !B || !C) { poly_free(A); poly_free(B); poly_free(C); return NULL; }
    Polynomial* AB = poly_create(A->degree + B->degree);
    if (!AB) { poly_free(A); poly_free(B); poly_free(C); return NULL; }
    poly_mul(AB, A, B, fp);
    poly_sub(AB, AB, C, fp);
    /* H = (AB - C) / Z */
    Polynomial* H = poly_create(AB->degree - q->Z->degree);
    Polynomial* rem = poly_create(0);
    if (H && rem) {
        poly_divmod(H, rem, AB, q->Z, fp);
    }
    poly_free(A); poly_free(B); poly_free(C); poly_free(AB); poly_free(rem);
    return H;
}

int qap_verify_poly(const QAP* q, const fe_t* witness, const FieldParams* fp) {
    Polynomial* H = qap_compute_h(q, witness, fp);
    if (!H) return 0;
    /* Check: H(x)*Z(x) should be exactly A(x)*B(x) - C(x).
       Since H was computed by division, if division was exact (remainder=0),
       the polynomial identity holds. Re-verify by recomputing. */
    Polynomial* A = qap_witness_poly(q, witness, 0, fp);
    Polynomial* B = qap_witness_poly(q, witness, 1, fp);
    Polynomial* C = qap_witness_poly(q, witness, 2, fp);
    if (!A || !B || !C) { poly_free(A); poly_free(B); poly_free(C); poly_free(H); return 0; }
    Polynomial* AB = poly_create(A->degree + B->degree);
    poly_mul(AB, A, B, fp);
    poly_sub(AB, AB, C, fp);
    /* Compute H*Z and compare */
    Polynomial* HZ = poly_create(H->degree + q->Z->degree);
    poly_mul(HZ, H, q->Z, fp);
    /* Compare AB-C with H*Z */
    poly_sub(AB, AB, HZ, fp);
    int ok = (poly_degree(AB) == 0 && fe_is_zero(AB->coeffs[0]));
    poly_free(A); poly_free(B); poly_free(C); poly_free(AB); poly_free(H); poly_free(HZ);
    return ok;
}

int qap_verify_sz(const QAP* q, const fe_t* witness, const FieldParams* fp) {
    /* Schwartz-Zippel: evaluate at random point tau */
    fe_t tau;
    fe_random(tau, fp);
    fe_t eval_result;
    qap_eval(eval_result, q, witness, tau, fp);
    /* Should be divisible by Z(tau), i.e., eval_result / Z(tau) should be H(tau).
       But simpler: just check that eval_result equals H(tau)*Z(tau) */
    fe_t Z_tau; poly_eval(Z_tau, q->Z, tau, fp);
    if (fe_is_zero(Z_tau)) { fe_one(tau); poly_eval(Z_tau, q->Z, tau, fp); }
    /* If A(tau)*B(tau)-C(tau) is NOT divisible by Z(tau) with high prob,
       it means the QAP is not satisfied. For a complete check:
       We verify by checking H(tau)*Z(tau) == A(tau)*B(tau)-C(tau) */
    Polynomial* H = qap_compute_h(q, witness, fp);
    if (!H) return 0;
    fe_t H_tau; poly_eval(H_tau, H, tau, fp);
    fe_t HZ_tau; fe_mul(HZ_tau, H_tau, Z_tau, fp);
    int ok = fe_equal(eval_result, HZ_tau);
    poly_free(H);
    return ok;
}

int qap_degree_A(const QAP* q) {
    int md = 0; for (int i = 0; i < q->n_vars; i++) {
        int d = poly_degree(q->A[i]); if (d > md) md = d; } return md; }
int qap_degree_B(const QAP* q) {
    int md = 0; for (int i = 0; i < q->n_vars; i++) {
        int d = poly_degree(q->B[i]); if (d > md) md = d; } return md; }
int qap_degree_C(const QAP* q) {
    int md = 0; for (int i = 0; i < q->n_vars; i++) {
        int d = poly_degree(q->C[i]); if (d > md) md = d; } return md; }
int qap_total_polys(const QAP* q) { return 3 * q->n_vars; }

void qap_print_summary(const QAP* q) {
    printf("QAP: %d vars, %d constraints, deg A=%d B=%d C=%d, Z deg=%d\n",
           q->n_vars, q->n_constraints, qap_degree_A(q), qap_degree_B(q),
           qap_degree_C(q), q->Z ? poly_degree(q->Z) : 0);
}
