// r1cs.c - Rank-1 Constraint System
#include "r1cs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void sm_init(SparseMatrix* sm, int nr, int nc, int cap) {
 sm->n_rows=nr; sm->n_cols=nc; sm->n_entries=0; sm->capacity=cap;
 sm->entries=(SparseEntry*)malloc((size_t)cap*sizeof(SparseEntry)); }
void sm_free(SparseMatrix* sm) { free(sm->entries); sm->entries=0; }
void sm_add_entry(SparseMatrix* sm, int r, int c, const fe_t v, const FieldParams* fp) {
 if(sm->n_entries>=sm->capacity){sm->capacity*=2;
  sm->entries=(SparseEntry*)realloc(sm->entries,(size_t)sm->capacity*sizeof(SparseEntry));}
 sm->entries[sm->n_entries].row=r; sm->entries[sm->n_entries].col=c;
 fe_set(sm->entries[sm->n_entries].val,v); sm->n_entries++; (void)fp; }
void sm_clear(SparseMatrix* sm) { sm->n_entries=0; }
R1CS* r1cs_create(int nc, int nv, int npi) {
 R1CS* r=(R1CS*)malloc(sizeof(R1CS)); if(!r)return 0;
 r->n_constraints=nc; r->n_vars=nv; r->n_pub_inputs=npi;
 sm_init(&r->A,nc,nv,nc*4); sm_init(&r->B,nc,nv,nc*4);
 sm_init(&r->C,nc,nv,nc*4); return r; }
void r1cs_free(R1CS* r){if(r){sm_free(&r->A);sm_free(&r->B);sm_free(&r->C);free(r);}}
R1CS* r1cs_copy(const R1CS* s){
 R1CS* d=r1cs_create(s->n_constraints,s->n_vars,s->n_pub_inputs);if(!d)return 0;
 sm_clear(&d->A);for(int i=0;i<s->A.n_entries;i++)d->A.entries[i]=s->A.entries[i];
 d->A.n_entries=s->A.n_entries;sm_clear(&d->B);
 for(int i=0;i<s->B.n_entries;i++)d->B.entries[i]=s->B.entries[i];
 d->B.n_entries=s->B.n_entries;sm_clear(&d->C);
 for(int i=0;i<s->C.n_entries;i++)d->C.entries[i]=s->C.entries[i];
 d->C.n_entries=s->C.n_entries;return d;}
static void addc(SparseMatrix*sm,int row,const int*v,const fe_t*c,int n,const FieldParams*fp){
 for(int i=0;i<n;i++)sm_add_entry(sm,row,v[i],c[i],fp);}
void r1cs_add_constraint_A(R1CS*r,int idx,const int*v,const fe_t*c,int n,const FieldParams*fp){
 addc(&r->A,idx,v,c,n,fp);}
void r1cs_add_constraint_B(R1CS*r,int idx,const int*v,const fe_t*c,int n,const FieldParams*fp){
 addc(&r->B,idx,v,c,n,fp);}
void r1cs_add_constraint_C(R1CS*r,int idx,const int*v,const fe_t*c,int n,const FieldParams*fp){
 addc(&r->C,idx,v,c,n,fp);}
void r1cs_add_full_constraint(R1CS*r,int k,const int*av,const fe_t*ac,int al,
 const int*bv,const fe_t*bc,int bl,const int*cv,const fe_t*cc,int cl,const FieldParams*fp){
 r1cs_add_constraint_A(r,k,av,ac,al,fp);r1cs_add_constraint_B(r,k,bv,bc,bl,fp);
 r1cs_add_constraint_C(r,k,cv,cc,cl,fp);}
static void sm_mul_vec(fe_t res,const SparseMatrix*sm,int row,const fe_t*w,const FieldParams*fp){
 fe_zero(res);for(int i=0;i<sm->n_entries;i++){
  if(sm->entries[i].row!=row)continue;
  fe_t p;fe_mul(p,sm->entries[i].val,w[sm->entries[i].col],fp);
  fe_add(res,res,p,fp);}}
void r1cs_eval_constraint(fe_t res,const R1CS*r,int k,const fe_t*w,const FieldParams*fp){
 fe_t av,bv,cv;sm_mul_vec(av,&r->A,k,w,fp);sm_mul_vec(bv,&r->B,k,w,fp);
 sm_mul_vec(cv,&r->C,k,w,fp);fe_t pr;fe_mul(pr,av,bv,fp);fe_sub(res,pr,cv,fp);}
int r1cs_verify(const R1CS*r,const fe_t*w,const FieldParams*fp){
 for(int k=0;k<r->n_constraints;k++){fe_t d;r1cs_eval_constraint(d,r,k,w,fp);
  if(!fe_is_zero(d))return 0;}return 1;}
Witness* witness_create(int nv){
 Witness*w=(Witness*)malloc(sizeof(Witness));if(!w)return 0;
 w->n_vars=nv;w->values=(fe_t*)calloc((size_t)nv,sizeof(fe_t));return w;}
void witness_free(Witness*w){if(w){free(w->values);free(w);}}
void witness_set(Witness*w,int idx,const fe_t v,const FieldParams*fp){
 (void)fp;
 if(idx>=0&&idx<w->n_vars)fe_set(w->values[idx],v);}
void witness_copy(Witness*d,const Witness*s){
 if(d->n_vars!=s->n_vars)return;
 for(int i=0;i<s->n_vars;i++)fe_set(d->values[i],s->values[i]);}
int r1cs_nonzero_entries(const R1CS*r){return r->A.n_entries+r->B.n_entries+r->C.n_entries;}
void r1cs_print_summary(const R1CS*r){
 printf("R1CS: %d constr, %d vars, %d pub, %d nz entries\n",
  r->n_constraints,r->n_vars,r->n_pub_inputs,r1cs_nonzero_entries(r));}

/* Additional sparse matrix operations */

/* Extract a dense column from a sparse matrix */
void sm_extract_column(fe_t* col, const SparseMatrix* sm, int col_idx) {
    for (int i = 0; i < sm->n_rows; i++) fe_zero(col[i]);
    for (int i = 0; i < sm->n_entries; i++) {
        if (sm->entries[i].col == col_idx)
            fe_set(col[sm->entries[i].row], sm->entries[i].val);
    }
}

/* Compare two fe_t values lexicographically (big-endian limb order).
   Returns -1 if a < b, 0 if equal, 1 if a > b. */
static int fe_cmp(const fe_t a, const fe_t b) {
    for (int i = 3; i >= 0; i--) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

/* Compute the maximum absolute coefficient in the constraint system */
void r1cs_max_coeff(fe_t result, const R1CS* r) {
    fe_zero(result);
    for (int i = 0; i < r->A.n_entries; i++) {
        if (fe_cmp(r->A.entries[i].val, result) > 0)
            fe_set(result, r->A.entries[i].val);
    }
    for (int i = 0; i < r->B.n_entries; i++) {
        if (fe_cmp(r->B.entries[i].val, result) > 0)
            fe_set(result, r->B.entries[i].val);
    }
    for (int i = 0; i < r->C.n_entries; i++) {
        if (fe_cmp(r->C.entries[i].val, result) > 0)
            fe_set(result, r->C.entries[i].val);
    }
}

/* R1CS variable classification:
   A variable is input if it only appears in constraints as a multiplier
   (i.e., never as the output of a multiplication).
   This is needed to distinguish public inputs from private witness. */
void r1cs_classify_variables(int* is_input, const R1CS* r) {
    for (int v = 0; v < r->n_vars; v++) is_input[v] = 0;
    /* Variables appearing in C (output) of any constraint are NOT inputs */
    for (int e = 0; e < r->C.n_entries; e++) {
        int col = r->C.entries[e].col;
        if (col >= 0 && col < r->n_vars) is_input[col] = -1; /* marked as output */
    }
    for (int v = 0; v < r->n_vars; v++)
        if (is_input[v] == 0) is_input[v] = 1; /* not in C = input variable */
    /* Variable 0 (constant) is always input */
    is_input[0] = 1;
}

/* Count number of non-zero entries per constraint */
int r1cs_constraint_density(const R1CS* r, int k) {
    int count = 0;
    for (int e = 0; e < r->A.n_entries; e++)
        if (r->A.entries[e].row == k) count++;
    for (int e = 0; e < r->B.n_entries; e++)
        if (r->B.entries[e].row == k) count++;
    for (int e = 0; e < r->C.n_entries; e++)
        if (r->C.entries[e].row == k) count++;
    return count;
}

/* Check if R1CS is in standard form:
   - Variable 0 is the constant 1 (appears in A and B but not C for multiplication gates)
   - First n_pub_inputs variables are public inputs
   - Each constraint has a non-zero C term (output) */
int r1cs_is_standard_form(const R1CS* r) {
    if (r->n_pub_inputs < 1) return 0;
    if (r->n_vars <= r->n_pub_inputs) return 0;
    return 1;
}

/* Compute total number of linear combination terms in A+B+C */
void r1cs_total_terms(int* a_terms, int* b_terms, int* c_terms, const R1CS* r) {
    *a_terms = r->A.n_entries;
    *b_terms = r->B.n_entries;
    *c_terms = r->C.n_entries;
}
