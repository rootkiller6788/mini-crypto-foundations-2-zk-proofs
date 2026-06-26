/* r1cs.h — Rank-1 Constraint System
 *
 * R1CS is the fundamental arithmetic constraint representation used in all
 * modern zkSNARKs. A constraint is: (A·w) ○ (B·w) = (C·w)
 * where ○ denotes element-wise product and A, B, C are sparse matrices.
 *
 * Key concepts:
 *   - Rank-1: each constraint is bilinear (product of two linear combinations)
 *   - Witness vector w = (1, input_vars, aux_vars) with first entry fixed to 1
 *   - Public inputs vs private witness distinction
 *   - Sparse matrix representation for efficiency
 *   - R1CS → QAP reduction via polynomial interpolation
 *
 * Constraints in R1CS form:
 *   ∀k: (∑_i A_{k,i} · w_i) · (∑_i B_{k,i} · w_i) = ∑_i C_{k,i} · w_i
 *
 * References:
 *   - Gennaro, Gentry, Parno, Raykova (2013) "Quadratic Span Programs"
 *   - Ben-Sasson et al. (2013) "SNARKs for C" (Pinocchio)
 *   - Groth (2016) "On the Size of Pairing-based Non-interactive Arguments"
 */
#ifndef R1CS_H
#define R1CS_H
#include "field.h"
#include <stdint.h>

/* ─── Sparse matrix entry (COO format) ─── */
typedef struct {
    int   row;        /* constraint index */
    int   col;        /* variable index */
    fe_t  val;        /* non-zero coefficient */
} SparseEntry;

/* ─── Sparse matrix in COO format ─── */
typedef struct {
    SparseEntry* entries;
    int          n_entries;
    int          capacity;
    int          n_rows;      /* number of constraints */
    int          n_cols;      /* number of variables */
} SparseMatrix;

/* ─── R1CS instance ─── */
typedef struct {
    SparseMatrix A;     /* left linear combination per constraint */
    SparseMatrix B;     /* right linear combination per constraint */
    SparseMatrix C;     /* output linear combination per constraint */
    int n_constraints;  /* number of constraints (= gates) */
    int n_vars;         /* total variables = 1 + n_pub_input + n_witness */
    int n_pub_inputs;   /* number of public inputs (statement vars) */
} R1CS;

/* ─── Witness ─── */
typedef struct {
    fe_t* values;       /* w[0..n_vars-1] with w[0]=1 (constant term) */
    int   n_vars;
} Witness;

/* ─── Lifecycle ─── */
R1CS*   r1cs_create(int n_constraints, int n_vars, int n_pub_inputs);
void    r1cs_free(R1CS* r1cs);
R1CS*   r1cs_copy(const R1CS* src);

/* ─── Matrix operations ─── */
void    sm_init(SparseMatrix* sm, int n_rows, int n_cols, int capacity);
void    sm_free(SparseMatrix* sm);
void    sm_add_entry(SparseMatrix* sm, int row, int col, const fe_t val,
                     const FieldParams* fp);
void    sm_clear(SparseMatrix* sm);

/* ─── Constraint management ─── */
void    r1cs_add_constraint_A(R1CS* r1cs, int constraint_idx,
                               const int* vars, const fe_t* coeffs, int len,
                               const FieldParams* fp);
void    r1cs_add_constraint_B(R1CS* r1cs, int constraint_idx,
                               const int* vars, const fe_t* coeffs, int len,
                               const FieldParams* fp);
void    r1cs_add_constraint_C(R1CS* r1cs, int constraint_idx,
                               const int* vars, const fe_t* coeffs, int len,
                               const FieldParams* fp);
void    r1cs_add_full_constraint(R1CS* r1cs, int constraint_idx,
                                  const int* a_vars, const fe_t* a_coeffs, int a_len,
                                  const int* b_vars, const fe_t* b_coeffs, int b_len,
                                  const int* c_vars, const fe_t* c_coeffs, int c_len,
                                  const FieldParams* fp);

/* ─── R1CS constraint checking ─── */
/* Compute (A·w)_k * (B·w)_k - (C·w)_k for constraint k.
   Returns 0 if constraint satisfied (difference = 0). */
void r1cs_eval_constraint(fe_t result, const R1CS* r1cs, int k,
                           const fe_t* witness, const FieldParams* fp);

/* Verify all constraints: returns 1 if ALL constraints satisfied */
int  r1cs_verify(const R1CS* r1cs, const fe_t* witness,
                 const FieldParams* fp);

/* ─── Witness management ─── */
Witness* witness_create(int n_vars);
void     witness_free(Witness* w);
void     witness_set(Witness* w, int idx, const fe_t val,
                     const FieldParams* fp);
void     witness_copy(Witness* dst, const Witness* src);

/* ─── R1CS statistics ─── */
int  r1cs_nonzero_entries(const R1CS* r1cs);
void r1cs_print_summary(const R1CS* r1cs);

#endif /* R1CS_H */
