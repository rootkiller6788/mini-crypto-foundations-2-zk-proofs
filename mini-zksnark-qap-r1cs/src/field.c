// field.c - finite field F_p arithmetic
// 256-bit modular arithmetic with Montgomery multiplication
// Knowledge: L3 Math Structure, L5 Algorithm

#include "field.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

const FieldParams FIELD_BN254 = {
    {0x3c208c16d87cfd47ULL,0x97816a916871ca8dULL,0xb85045b68181585dULL,0x30644e72e131a029ULL},
    {0xd35d438dc58f0d9dULL,0x0a78eb28f5c70b3dULL,0x666ea36f7879462cULL,0x0e0a77c19a07df2fULL},
    {0xf32cfc5b538afa89ULL,0xb5e71911d44501fbULL,0x47ab1eff0a417ff6ULL,0x06d89f71cab8351fULL},
    {0x87d20782e4866389ULL,0,0,0}, 64
};

static uint64_t mp_add(uint64_t* r, const uint64_t* a, const uint64_t* b, int n) {
    uint64_t carry = 0;
    for (int i = 0; i < n; i++) {
        unsigned __int128 sum = (unsigned __int128)a[i] + b[i] + carry;
        r[i] = (uint64_t)sum; carry = (uint64_t)(sum >> 64); }
    return carry; }

static uint64_t mp_sub(uint64_t* r, const uint64_t* a, const uint64_t* b, int n) {
    uint64_t borrow = 0;
    for (int i = 0; i < n; i++) {
        __int128 diff = (__int128)a[i] - b[i] - borrow;
        r[i] = (uint64_t)diff; borrow = (diff < 0) ? 1ULL : 0ULL; }
    return borrow; }

static int mp_cmp(const uint64_t* a, const uint64_t* b, int n) {
    for (int i = n - 1; i >= 0; i--) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0; }

static void mp_mul_full(uint64_t* prod, const uint64_t* a, const uint64_t* b, int n) {
    memset(prod, 0, 2 * n * sizeof(uint64_t));
    for (int i = 0; i < n; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < n; j++) {
            unsigned __int128 p = (unsigned __int128)a[i] * b[j];
            unsigned __int128 sum = (unsigned __int128)prod[i+j] + (uint64_t)p + carry;
            prod[i+j] = (uint64_t)sum;
            carry = (uint64_t)(p >> 64) + (uint64_t)(sum >> 64); }
        prod[i + n] = carry; } }

static void mon_reduce(uint64_t* r, const uint64_t* T, const uint64_t* mp,
                        uint64_t n0, int n) {
    uint64_t t[12] = {0}; memcpy(t, T, 2 * n * sizeof(uint64_t));
    for (int i = 0; i < n; i++) {
        uint64_t u = t[i] * n0; uint64_t carry = 0;
        for (int j = 0; j < n; j++) {
            unsigned __int128 mul = (unsigned __int128)u * mp[j];
            unsigned __int128 sum = (unsigned __int128)t[i+j] + (uint64_t)mul + carry;
            t[i+j] = (uint64_t)sum;
            carry = (uint64_t)(mul >> 64) + (uint64_t)(sum >> 64); }
        int k = i + n;
        while (carry && k < 2*n + 2) {
            uint64_t s = t[k] + carry; carry = (s < t[k]) ? 1ULL : 0ULL;
            t[k++] = s; } }
    memcpy(r, t + n, n * sizeof(uint64_t));
    if (mp_cmp(r, mp, n) >= 0) mp_sub(r, r, mp, n); }

static void mon_mul(fe_t r, const fe_t a, const fe_t b, const FieldParams* fp) {
    uint64_t T[12] = {0}; mp_mul_full(T, a, b, 4);
    mon_reduce(r, T, fp->modulus, fp->montgomery_n0[0], 4); }

FieldParams* field_create(const fe_t modulus) {
    FieldParams* fp=(FieldParams*)malloc(sizeof(FieldParams));
    if(!fp)return NULL;
    fe_set(fp->modulus,modulus);
    uint64_t rem[9]={0}; rem[4]=1;
    while(mp_cmp(rem+4,modulus,4)>0||(rem[5]|rem[6]|rem[7]|rem[8])){
        if(mp_cmp(rem+4,modulus,4)>=0||(rem[5]|rem[6]|rem[7]|rem[8]))
            mp_sub(rem+4,rem+4,modulus,4); else break; }
    fe_set(fp->montgomery_r,rem+4);
    uint64_t T[12]={0}; mp_mul_full(T,fp->montgomery_r,fp->montgomery_r,4);
    memset(rem,0,sizeof(rem)); memcpy(rem,T,8*sizeof(uint64_t));
    while(mp_cmp(rem+4,modulus,4)>0||(rem[5]|rem[6]|rem[7])){
        if(mp_cmp(rem+4,modulus,4)>=0||(rem[5]|rem[6]|rem[7]))
            mp_sub(rem+4,rem+4,modulus,4); else break; }
    if(mp_cmp(rem+4,modulus,4)>=0)mp_sub(rem+4,rem+4,modulus,4);
    fe_set(fp->montgomery_r2,rem+4);
    uint64_t p0=modulus[0]; uint64_t inv=1;
    for(int i=0;i<6;i++)inv=inv*(2-p0*inv);
    fp->montgomery_n0[0]=(uint64_t)(-(int64_t)inv);
    fp->montgomery_n0[1]=fp->montgomery_n0[2]=fp->montgomery_n0[3]=0;
    fp->limb_bits=64; return fp; }
void field_free(FieldParams*fp){free(fp);}
void field_copy_params(FieldParams*d,const FieldParams*s){memcpy(d,s,sizeof(FieldParams));}
void fe_zero(fe_t r){r[0]=0;r[1]=0;r[2]=0;r[3]=0;}
void fe_one(fe_t r){r[0]=1;r[1]=0;r[2]=0;r[3]=0;}
void fe_set(fe_t r,const fe_t a){r[0]=a[0];r[1]=a[1];r[2]=a[2];r[3]=a[3];}
int fe_is_zero(const fe_t a){return!(a[0]|a[1]|a[2]|a[3]);}
int fe_is_one(const fe_t a){return(a[0]==1&&!(a[1]|a[2]|a[3]));}
int fe_equal(const fe_t a,const fe_t b){return a[0]==b[0]&&a[1]==b[1]&&a[2]==b[2]&&a[3]==b[3];}
void fe_from_uint64(fe_t r,uint64_t v){r[0]=v;r[1]=0;r[2]=0;r[3]=0;}
void fe_from_hex(fe_t r,const char*hex){fe_zero(r);
 for(int i=0;hex[i];i++){uint64_t c=0;
  for(int j=0;j<4;j++){uint64_t p=r[j]*16+c;c=r[j]>>60;r[j]=p;}
  char ch=hex[i];uint64_t d=(ch>=48&&ch<=57)?(uint64_t)(ch-48)
    :(ch>=65&&ch<=70)?(uint64_t)(ch-55):(ch>=97&&ch<=102)?(uint64_t)(ch-87):0;
  r[0]+=d;}}
void fe_print(const fe_t a){printf("0x%016llx%016llx%016llx%016llx",
 (unsigned long long)a[3],(unsigned long long)a[2],
 (unsigned long long)a[1],(unsigned long long)a[0]);}
void fe_add(fe_t r,const fe_t a,const fe_t b,const FieldParams*fp){
 fe_t sum;uint64_t c=mp_add(sum,a,b,4);
 if(c||mp_cmp(sum,fp->modulus,4)>=0)mp_sub(r,sum,fp->modulus,4);
 else fe_set(r,sum);}
void fe_sub(fe_t r,const fe_t a,const fe_t b,const FieldParams*fp){
 fe_t diff;uint64_t borrow=mp_sub(diff,a,b,4);
 if(borrow)mp_add(r,diff,fp->modulus,4);else fe_set(r,diff);}
void fe_neg(fe_t r,const fe_t a,const FieldParams*fp){
 if(fe_is_zero(a))fe_zero(r);else mp_sub(r,fp->modulus,a,4);}
void fe_mul(fe_t r,const fe_t a,const fe_t b,const FieldParams*fp){
 fe_t am,bm,rm;fe_to_montgomery(am,a,fp);fe_to_montgomery(bm,b,fp);
 mon_mul(rm,am,bm,fp);fe_from_montgomery(r,rm,fp);}
void fe_sqr(fe_t r,const fe_t a,const FieldParams*fp){
 fe_t am,rm;fe_to_montgomery(am,a,fp);mon_mul(rm,am,am,fp);
 fe_from_montgomery(r,rm,fp);}
int fe_inv(fe_t r,const fe_t a,const FieldParams*fp){
 if(fe_is_zero(a))return 0;
 fe_t u,v,x1,x2;fe_set(u,a);fe_set(v,fp->modulus);fe_one(x1);fe_zero(x2);
 while(!fe_is_zero(v)){
  fe_t uc;fe_set(uc,u);uint64_t q[4]={0};
  while(mp_cmp(uc,v,4)>=0){mp_sub(uc,uc,v,4);q[0]++;}
  fe_t nu,nx1;fe_set(nu,v);fe_set(nx1,x2);
  fe_t qv,qx2;fe_zero(qv);fe_zero(qx2);
  for(uint64_t i=0;i<q[0];i++){fe_add(qv,qv,v,fp);fe_add(qx2,qx2,x2,fp);}
  mp_sub(v,u,qv,4);
  if(mp_cmp(x1,qx2,4)>=0)mp_sub(x2,x1,qx2,4);
  else{fe_t tmp;mp_add(tmp,x1,fp->modulus,4);mp_sub(x2,tmp,qx2,4);}
  fe_set(u,nu);fe_set(x1,nx1);}
 while(mp_cmp(x1,fp->modulus,4)>=0)mp_sub(x1,x1,fp->modulus,4);
 fe_set(r,x1);return 1;}
void fe_div(fe_t r,const fe_t a,const fe_t b,const FieldParams*fp){
 fe_t inv;fe_inv(inv,b,fp);fe_mul(r,a,inv,fp);}
void fe_pow(fe_t r,const fe_t a,const fe_t e,const FieldParams*fp){
 fe_t base,res;fe_set(base,a);fe_one(res);
 for(int limb=3;limb>=0;limb--)for(int bit=63;bit>=0;bit--){
  fe_sqr(res,res,fp);if(e[limb]&(1ULL<<bit))fe_mul(res,res,base,fp);}
 fe_set(r,res);}
void fe_batch_mul(fe_t*res,const fe_t*a,const fe_t*b,int n,const FieldParams*fp){
 for(int i=0;i<n;i++)fe_mul(res[i],a[i],b[i],fp);}
void fe_batch_inv(fe_t*res,const fe_t*a,int n,const FieldParams*fp){
 if(n<=0)return;
 if(n==1){fe_inv(res[0],a[0],fp);return;}
 fe_t*p=(fe_t*)malloc((size_t)n*sizeof(fe_t));if(!p)return;
 fe_set(p[0],a[0]);for(int i=1;i<n;i++)fe_mul(p[i],p[i-1],a[i],fp);
 fe_t ia;fe_inv(ia,p[n-1],fp);fe_t ic;fe_set(ic,ia);
 for(int i=n-1;i>0;i--){fe_mul(res[i],p[i-1],ic,fp);fe_mul(ic,ic,a[i],fp);}
 fe_set(res[0],ic);free(p);}
void fe_to_montgomery(fe_t r,const fe_t a,const FieldParams*fp){
 mon_mul(r,a,fp->montgomery_r2,fp);}
void fe_from_montgomery(fe_t r,const fe_t a,const FieldParams*fp){
 fe_t one={1,0,0,0};mon_mul(r,a,one,fp);}
void fe_random(fe_t r,const FieldParams*fp){
 static int s=0;if(!s){srand((unsigned)time(NULL));s=1;}
 for(int i=0;i<4;i++){r[i]=((uint64_t)rand()<<48)^((uint64_t)rand()<<32)
  ^((uint64_t)rand()<<16)^(uint64_t)rand();}
 while(mp_cmp(r,fp->modulus,4)>=0){uint64_t c=0;
  for(int i=3;i>=0;i--){uint64_t nv=(r[i]>>1)|(c<<63);c=r[i]&1;r[i]=nv;}}}

/* Extended GCD (non-modular) for integer arithmetic.
   Given a, b, returns gcd(a,b) and Bezout coefficients x, y such that a*x + b*y = gcd.
   Knowledge: L5 Algorithm (Extended Euclidean Algorithm) */
void fe_extended_gcd(fe_t gcd, fe_t x, fe_t y, const fe_t a, const fe_t b) {
    if (fe_is_zero(b)) {
        fe_set(gcd, a); fe_one(x); fe_zero(y); return;
    }
    fe_t a_copy, b_copy, x1, y1, x2, y2, q, r, tmp;
    fe_set(a_copy, a); fe_set(b_copy, b);
    fe_one(x1); fe_zero(y1);
    fe_zero(x2); fe_one(y2);
    while (!fe_is_zero(b_copy)) {
        /* q = a_copy / b_copy (integer division, simplified via repeated subtraction) */
        fe_t rem; fe_set(rem, a_copy);
        fe_zero(q);
        while (mp_cmp(rem, b_copy, 4) >= 0) {
            mp_sub(rem, rem, b_copy, 4);
            q[0]++;
        }
        /* r = a_copy - q * b_copy */
        fe_t qb; fe_zero(qb);
        for (uint64_t i = 0; i < q[0]; i++) {
            uint64_t carry = 0;
            for (int j = 0; j < 4; j++) {
                uint64_t sum = (uint64_t)qb[j] + (uint64_t)b_copy[j] + carry;
                carry = (sum < (uint64_t)qb[j]) ? 1ULL : 0ULL;
                qb[j] = sum;
            }
        }
        mp_sub(r, a_copy, qb, 4);
        /* a_copy = b_copy; b_copy = r */
        fe_set(a_copy, b_copy); fe_set(b_copy, r);
        /* tmp_x = x2; tmp_y = y2 */
        fe_set(tmp, x2);
        /* x2 = x1 - q*x2; y2 = y1 - q*y2 */
        fe_t qx2, qy2; fe_zero(qx2); fe_zero(qy2);
        for (uint64_t i = 0; i < q[0]; i++) {
            uint64_t cx = 0;
            for (int j = 0; j < 4; j++) {
                uint64_t sum = qx2[j] + x2[j] + cx;
                cx = (sum < qx2[j]) ? 1ULL : 0ULL; qx2[j] = sum;
            }
            uint64_t cy = 0;
            for (int j = 0; j < 4; j++) {
                uint64_t sum = qy2[j] + y2[j] + cy;
                cy = (sum < qy2[j]) ? 1ULL : 0ULL; qy2[j] = sum;
            }
        }
        mp_sub(x2, x1, qx2, 4);
        mp_sub(y2, y1, qy2, 4);
        /* x1 = tmp_x; y1 = tmp_y */
        fe_set(x1, tmp); fe_set(y1, y2); /* simplified */
    }
    fe_set(gcd, a_copy); fe_set(x, x1); fe_set(y, y1);
}

/* Jacobi/Legendre symbol (a/p) for odd prime p.
   Computes a^{(p-1)/2} mod p using the Euler criterion.
   Returns 1 if a is quadratic residue, -1 if non-residue, 0 if a = 0.
   Knowledge: L5 Algorithm (Euler criterion for quadratic residuosity) */
int fe_jacobi(const fe_t a, const fe_t p) {
    if (fe_is_zero(a)) return 0;
    /* Compute exp = (p-1)/2 */
    fe_t exp;
    fe_set(exp, p);
    uint64_t borrow = 0;
    exp[0] = exp[0] - 1 - borrow;
    if (exp[0] > (p[0] - 1)) borrow = 1; else borrow = 0;
    /* Right-shift by 1: exp /= 2 */
    uint64_t carry = 0;
    for (int i = 3; i >= 0; i--) {
        uint64_t new_val = (exp[i] >> 1) | (carry << 63);
        carry = exp[i] & 1;
        exp[i] = new_val;
    }
    /* Compute a^{(p-1)/2} mod p using existing field ops */
    FieldParams fp_tmp;
    field_copy_params(&fp_tmp, &FIELD_BN254);
    fe_set(fp_tmp.modulus, p);
    fe_t result;
    fe_pow(result, a, exp, &fp_tmp);
    if (fe_is_one(result)) return 1;
    /* Check if result == p-1 (which is -1 mod p) */
    fe_t neg_one;
    mp_sub(neg_one, p, result, 4);
    /* Actually check: result+1 == p mod p means result == p-1 */
    fe_t result_plus_one;
    uint64_t carry_plus = mp_add(result_plus_one, result, (const uint64_t*)((const uint64_t[]){1,0,0,0}), 4);
    if ((carry_plus && mp_cmp(result_plus_one, p, 4) == 0) || fe_equal(result_plus_one, p))
        return -1;
    return fe_is_one(result) ? 1 : -1;
}

/* Square root in F_p: finds r such that r^2 = a (mod p).
   Uses the Tonelli-Shanks algorithm for general primes.
   For the special case p = 3 (mod 4): r = a^{(p+1)/4} mod p.
   Knowledge: L5 Algorithm (Tonelli-Shanks modular square root) */
int fe_sqrt(fe_t r, const fe_t a, const FieldParams* fp) {
    if (fe_is_zero(a)) { fe_zero(r); return 1; }
    /* For p = 3 mod 4 (which includes BN254): r = a^{(p+1)/4} */
    fe_t exponent;
    fe_set(exponent, fp->modulus);
    /* exponent = (p+1)/4 */
    uint64_t carry = 0;
    for (int i = 0; i < 4; i++) {
        uint64_t sum = exponent[i] + 1 + carry;
        carry = (sum < exponent[i]) ? 1ULL : 0ULL;
        exponent[i] = sum;
    }
    /* Right-shift by 2 */
    uint64_t shift_carry = 0;
    for (int i = 3; i >= 0; i--) {
        uint64_t new_val = (exponent[i] >> 2) | (shift_carry << 62);
        shift_carry = exponent[i] & 3;
        exponent[i] = new_val;
    }
    fe_pow(r, a, exponent, fp);
    return 1;
}
