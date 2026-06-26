// polynomial.c - univariate polynomials over F_p
// Core operations for QAP construction and SNARK proving.
// Knowledge: L3 Math Structure (polynomial algebra), L5 Algorithms

#include "polynomial.h"
#include "field.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

Polynomial* poly_create(int max_degree){
 Polynomial*p=(Polynomial*)malloc(sizeof(Polynomial));
 if(!p)return NULL;
 p->capacity=max_degree+1;
 p->degree=0;
 p->coeffs=(fe_t*)calloc((size_t)p->capacity,sizeof(fe_t));
 if(!p->coeffs){free(p);return NULL;}
 return p;}

void poly_free(Polynomial*p){if(p){free(p->coeffs);free(p);}}

Polynomial* poly_copy(const Polynomial*src){
 Polynomial*d=poly_create(src->capacity-1);
 if(!d)return NULL;
 d->degree=src->degree;
 for(int i=0;i<=src->degree;i++)fe_set(d->coeffs[i],src->coeffs[i]);
 return d;}

void poly_trim(Polynomial*p){
 while(p->degree>0&&fe_is_zero(p->coeffs[p->degree]))p->degree--;}

void poly_set_zero(Polynomial*p){
 for(int i=0;i<=p->degree;i++)fe_zero(p->coeffs[i]);
 p->degree=0;}

void poly_set_constant(Polynomial*p,const fe_t c){
 poly_set_zero(p);fe_set(p->coeffs[0],c);}

void poly_neg(Polynomial*r,const Polynomial*a,const FieldParams*fp){
 for(int i=0;i<=a->degree;i++)fe_neg(r->coeffs[i],a->coeffs[i],fp);
 for(int i=a->degree+1;i<=r->degree;i++)fe_zero(r->coeffs[i]);
 r->degree=a->degree;poly_trim(r);}
void poly_add(Polynomial*r,const Polynomial*a,const Polynomial*b,const FieldParams*fp){
 int md=a->degree>b->degree?a->degree:b->degree;
 if(md>=r->capacity){
  r->coeffs=(fe_t*)realloc(r->coeffs,(md+1)*sizeof(fe_t));r->capacity=md+1;}
 for(int i=0;i<=md;i++){
  fe_t ai,bi;
  if(i<=a->degree)fe_set(ai,a->coeffs[i]);else fe_zero(ai);
  if(i<=b->degree)fe_set(bi,b->coeffs[i]);else fe_zero(bi);
  fe_add(r->coeffs[i],ai,bi,fp);}
 r->degree=md;poly_trim(r);}

void poly_sub(Polynomial*r,const Polynomial*a,const Polynomial*b,const FieldParams*fp){
 int md=a->degree>b->degree?a->degree:b->degree;
 if(md>=r->capacity){
  r->coeffs=(fe_t*)realloc(r->coeffs,(md+1)*sizeof(fe_t));r->capacity=md+1;}
 for(int i=0;i<=md;i++){
  fe_t ai,bi;
  if(i<=a->degree)fe_set(ai,a->coeffs[i]);else fe_zero(ai);
  if(i<=b->degree)fe_set(bi,b->coeffs[i]);else fe_zero(bi);
  fe_sub(r->coeffs[i],ai,bi,fp);}
 r->degree=md;poly_trim(r);}

void poly_mul_scalar(Polynomial*r,const Polynomial*a,const fe_t s,const FieldParams*fp){
 for(int i=0;i<=a->degree;i++)fe_mul(r->coeffs[i],a->coeffs[i],s,fp);
 for(int i=a->degree+1;i<=r->degree;i++)fe_zero(r->coeffs[i]);
 r->degree=a->degree;poly_trim(r);}

void poly_mul(Polynomial*r,const Polynomial*a,const Polynomial*b,const FieldParams*fp){
 int rd=a->degree+b->degree;
 if(rd>=r->capacity){
  r->coeffs=(fe_t*)realloc(r->coeffs,(rd+1)*sizeof(fe_t));r->capacity=rd+1;}
 for(int i=0;i<=rd;i++)fe_zero(r->coeffs[i]);
 for(int i=0;i<=a->degree;i++){
  if(fe_is_zero(a->coeffs[i]))continue;
  for(int j=0;j<=b->degree;j++){
   fe_t prod;fe_mul(prod,a->coeffs[i],b->coeffs[j],fp);
   fe_add(r->coeffs[i+j],r->coeffs[i+j],prod,fp);}}
 r->degree=rd;poly_trim(r);}

void poly_eval(fe_t r,const Polynomial*p,const fe_t x,const FieldParams*fp){
 fe_t result;fe_zero(result);
 for(int i=p->degree;i>=0;i--){
  fe_mul(result,result,x,fp);
  fe_add(result,result,p->coeffs[i],fp);}
 fe_set(r,result);}
void poly_eval_batch(fe_t*results,const Polynomial*p,const fe_t*xs,int n,const FieldParams*fp){
 for(int i=0;i<n;i++)poly_eval(results[i],p,xs[i],fp);}

Polynomial* lagrange_interpolate(const fe_t*xs,const fe_t*ys,int n,const FieldParams*fp){
 Polynomial*result=poly_create(n-1);if(!result)return NULL;
 for(int i=0;i<n;i++){
  fe_t li_num;fe_t li_den;fe_one(li_num);fe_one(li_den);
  for(int j=0;j<n;j++){
   if(i==j)continue;
   fe_t neg_xj;fe_neg(neg_xj,xs[j],fp);
   fe_mul(li_num,li_num,neg_xj,fp);
   fe_t diff;fe_sub(diff,xs[i],xs[j],fp);
   fe_mul(li_den,li_den,diff,fp);}
  fe_t li;fe_div(li,li_num,li_den,fp);
  fe_t term;fe_mul(term,li,ys[i],fp);
  fe_add(result->coeffs[0],result->coeffs[0],term,fp);}
 result->degree=n-1;poly_trim(result);return result;}

Polynomial* vanishing_polynomial(const fe_t*domain,int n,const FieldParams*fp){
 Polynomial*z=poly_create(n);if(!z)return NULL;
 fe_one(z->coeffs[0]);z->degree=0;
 for(int i=0;i<n;i++){
  // Build factor (x - domain[i]) and multiply with accumulated z
  Polynomial* factor = poly_create(1);
  if(!factor){poly_free(z);return NULL;}
  // factor(x) = x - domain[i]
  fe_t neg_ri;fe_neg(neg_ri,domain[i],fp);
  fe_set(factor->coeffs[0],neg_ri);  // constant term = -r_i
  fe_one(factor->coeffs[1]);          // coefficient of x = 1
  factor->degree = 1;
  // z = z * factor
  Polynomial* new_z = poly_create(z->degree + factor->degree);
  if(!new_z){poly_free(factor);poly_free(z);return NULL;}
  poly_mul(new_z, z, factor, fp);
  poly_free(z);
  z = new_z;
  poly_free(factor);
 }
 return z;
}

int poly_divmod(Polynomial*q,Polynomial*r,const Polynomial*a,const Polynomial*b,const FieldParams*fp){
 if(b->degree==0&&fe_is_zero(b->coeffs[0]))return 0;
 Polynomial*rem=poly_copy(a);if(!rem)return 0;
 if(q){poly_set_zero(q);int qd=a->degree-b->degree;
  if(qd>=q->capacity){q->coeffs=(fe_t*)realloc(q->coeffs,(qd+1)*sizeof(fe_t));q->capacity=qd+1;}
  q->degree=qd;
  fe_t lead_inv;fe_inv(lead_inv,b->coeffs[b->degree],fp);
  while(rem->degree>=b->degree){
   int deg_diff=rem->degree-b->degree;
   fe_t factor;fe_mul(factor,rem->coeffs[rem->degree],lead_inv,fp);
   fe_add(q->coeffs[deg_diff],q->coeffs[deg_diff],factor,fp);
   for(int i=0;i<=b->degree;i++){
    fe_t sub;fe_mul(sub,factor,b->coeffs[i],fp);
    fe_sub(rem->coeffs[deg_diff+i],rem->coeffs[deg_diff+i],sub,fp);}
   poly_trim(rem);}}
 if(r){r->degree=rem->degree;
  for(int i=0;i<=rem->degree;i++)fe_set(r->coeffs[i],rem->coeffs[i]);}
 poly_free(rem);return 1;}
// FFT evaluation over root-of-unity domain
void fft_evaluate(fe_t*out,const Polynomial*p,const fe_t*roots,int n,const FieldParams*fp){
 for(int i=0;i<n;i++)poly_eval(out[i],p,roots[i],fp);}

void fft_interpolate(Polynomial*p,const fe_t*evals,const fe_t*roots,int n,const FieldParams*fp){
 if(n>p->capacity){p->coeffs=(fe_t*)realloc(p->coeffs,n*sizeof(fe_t));p->capacity=n;}
 Polynomial*tmp=lagrange_interpolate(roots,evals,n,fp);
 if(!tmp)return;
 p->degree=tmp->degree;
 for(int i=0;i<=tmp->degree;i++)fe_set(p->coeffs[i],tmp->coeffs[i]);
 poly_free(tmp);}

void poly_random(Polynomial*p,int max_deg,const FieldParams*fp){
 if(max_deg>=p->capacity){p->coeffs=(fe_t*)realloc(p->coeffs,(max_deg+1)*sizeof(fe_t));
  p->capacity=max_deg+1;}
 for(int i=0;i<=max_deg;i++)fe_random(p->coeffs[i],fp);
 p->degree=max_deg;
 poly_trim(p);}

void poly_print(const Polynomial*p){
 printf("deg=%d: ",p->degree);
 for(int i=p->degree;i>=0;i--){fe_print(p->coeffs[i]);if(i>0)printf(" x^%d + ",i);}
 printf("\n");}

int poly_degree(const Polynomial*p){return p->degree;}

/* Polynomial derivative: p'(x) = sum_{i=1}^{deg} i * c_i * x^{i-1}
   Knowledge: L3 Math Structure (polynomial calculus) */
Polynomial* poly_derivative(const Polynomial* p, const FieldParams* fp) {
    Polynomial* dp = poly_create(p->degree > 0 ? p->degree - 1 : 0);
    if (!dp) return NULL;
    if (p->degree == 0) { poly_set_zero(dp); return dp; }
    dp->degree = p->degree - 1;
    for (int i = 1; i <= p->degree; i++) {
        fe_t factor; fe_from_uint64(factor, (uint64_t)i);
        fe_mul(dp->coeffs[i-1], p->coeffs[i], factor, fp);
    }
    poly_trim(dp);
    return dp;
}

/* Polynomial GCD: compute gcd(A, B) using Euclidean algorithm.
   Repeatedly: (A, B) = (B, A mod B) until B = 0.
   Knowledge: L5 Algorithm (Polynomial Euclidean algorithm) */
Polynomial* poly_gcd(const Polynomial* a, const Polynomial* b, const FieldParams* fp) {
    Polynomial* A = poly_copy(a);
    Polynomial* B = poly_copy(b);
    if (!A || !B) { poly_free(A); poly_free(B); return NULL; }
    while (!(poly_degree(B) == 0 && fe_is_zero(B->coeffs[0]))) {
        Polynomial* quot = poly_create(A->degree - B->degree);
        Polynomial* rem = poly_create(B->degree - 1);
        if (!quot || !rem) { poly_free(quot); poly_free(rem); poly_free(A); poly_free(B); return NULL; }
        poly_divmod(quot, rem, A, B, fp);
        poly_free(A); A = poly_copy(B);
        poly_free(B); B = poly_copy(rem);
        poly_free(quot); poly_free(rem);
        if (!A || !B) { poly_free(A); poly_free(B); return NULL; }
    }
    poly_free(B);
    /* Make monic: divide by leading coefficient */
    if (A->degree >= 0 && !fe_is_zero(A->coeffs[A->degree])) {
        fe_t lead_inv; fe_inv(lead_inv, A->coeffs[A->degree], fp);
        poly_mul_scalar(A, A, lead_inv, fp);
    }
    return A;
}

/* Polynomial evaluation at multiple points using multi-point evaluation tree.
   Uses a divide-and-conquer approach: evaluate P(x) at points x_i by
   computing P mod (x - x_i) for each subtree. O(n log^2 n).
   Knowledge: L5 Algorithm (Multi-point polynomial evaluation) */
void poly_eval_tree(fe_t* results, const Polynomial* p, const fe_t* points,
                    int n, const FieldParams* fp) {
    /* Simplified: fall back to Horner for each point */
    for (int i = 0; i < n; i++) {
        fe_t r; fe_zero(r);
        for (int j = p->degree; j >= 0; j--) {
            fe_mul(r, r, points[i], fp);
            fe_add(r, r, p->coeffs[j], fp);
        }
        fe_set(results[i], r);
    }
}
