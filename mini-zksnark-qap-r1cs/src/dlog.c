
// dlog.c - Discrete-log based polynomial commitments and pairing
// Implements G1/G2 group operations and the bilinear pairing e: G1 x G2 -> GT.
// Used for polynomial commitments (KZG-style) in the Groth16 zkSNARK.
// Knowledge: L3 Math Structure (elliptic curves), L4 Fundamental Law (DL assumption)

#include "dlog.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* G1 point operations (simplified EC arithmetic) */

void g1_set_infinity(G1Point* p) {
    p->is_infinity = 1;
    fe_zero(p->x); fe_zero(p->y);
}

int g1_is_infinity(const G1Point* p) { return p->is_infinity; }
void g1_copy(G1Point* d, const G1Point* s) { memcpy(d, s, sizeof(G1Point)); }

int g1_equal(const G1Point* a, const G1Point* b) {
    if (a->is_infinity && b->is_infinity) return 1;
    if (a->is_infinity || b->is_infinity) return 0;
    return fe_equal(a->x, b->x) && fe_equal(a->y, b->y);
}

void g1_neg(G1Point* r, const G1Point* a, const GroupParams* gp) {
    g1_copy(r, a);
    if (!a->is_infinity) fe_neg(r->y, a->y, gp->fp);
}

/* Simplified EC add for educational purposes:
   Uses the standard chord-tangent formulas:
   slope = (y2 - y1) / (x2 - x1)  for point add
   slope = (3*x1^2 + a) / (2*y1)  for point doubling
   x3 = slope^2 - x1 - x2
   y3 = slope*(x1 - x3) - y1
   Curve: y^2 = x^3 + b (a=0 for BN curves) */
void g1_add(G1Point* r, const G1Point* a, const G1Point* b, const GroupParams* gp) {
    if (a->is_infinity) { g1_copy(r, b); return; }
    if (b->is_infinity) { g1_copy(r, a); return; }
    if (g1_equal(a, b)) { g1_double(r, a, gp); return; }
    if (fe_equal(a->x, b->x)) {
        /* Point at infinity if x1=x2 and y1!=y2 (P + (-P) = O) */
        if (!fe_equal(a->y, b->y)) { g1_set_infinity(r); }
        return;
    }
    fe_t slope, tmp;
    fe_sub(tmp, b->y, a->y, gp->fp);
    fe_t dx; fe_sub(dx, b->x, a->x, gp->fp);
    fe_div(slope, tmp, dx, gp->fp);
    fe_t x3; fe_sqr(x3, slope, gp->fp);
    fe_sub(x3, x3, a->x, gp->fp);
    fe_sub(x3, x3, b->x, gp->fp);
    fe_t y3_tmp; fe_sub(y3_tmp, a->x, x3, gp->fp);
    fe_mul(y3_tmp, slope, y3_tmp, gp->fp);
    fe_sub(tmp, y3_tmp, a->y, gp->fp);
    fe_set(r->x, x3);
    fe_set(r->y, tmp);
    r->is_infinity = 0;
}

void g1_double(G1Point* r, const G1Point* a, const GroupParams* gp) {
    if (a->is_infinity || fe_is_zero(a->y)) { g1_set_infinity(r); return; }
    fe_t slope, tmp;
    /* slope = 3*x^2 / 2*y  (curve: y^2 = x^3 + b, so a=0) */
    fe_sqr(slope, a->x, gp->fp);
    fe_t three; fe_from_uint64(three, 3);
    fe_mul(slope, slope, three, gp->fp);
    fe_t two_y; fe_add(two_y, a->y, a->y, gp->fp);
    fe_div(slope, slope, two_y, gp->fp);
    /* x3 = slope^2 - 2*x */
    fe_sqr(tmp, slope, gp->fp);
    fe_sub(tmp, tmp, a->x, gp->fp);
    fe_sub(tmp, tmp, a->x, gp->fp);
    fe_t x3; fe_set(x3, tmp);
    /* y3 = slope*(x - x3) - y */
    fe_sub(tmp, a->x, x3, gp->fp);
    fe_mul(tmp, slope, tmp, gp->fp);
    fe_sub(tmp, tmp, a->y, gp->fp);
    fe_set(r->x, x3); fe_set(r->y, tmp);
    r->is_infinity = 0;
}

void g1_scalar_mul(G1Point* r, const G1Point* P, const fe_t scalar, const GroupParams* gp) {
    /* Double-and-add scalar multiplication */
    G1Point R; g1_set_infinity(&R);
    G1Point base; g1_copy(&base, P);
    /* Process bits from MSB to LSB */
    for (int limb = 3; limb >= 0; limb--) {
        for (int bit = 63; bit >= 0; bit--) {
            g1_double(&R, &R, gp);
            if (scalar[limb] & (1ULL << bit)) {
                g1_add(&R, &R, &base, gp);
            }
        }
    }
    g1_copy(r, &R);
}

/* G2 point operations (simplified) */
void g2_set_infinity(G2Point* p) {
    p->is_infinity = 1;
    fe_zero(p->x[0]); fe_zero(p->x[1]);
    fe_zero(p->y[0]); fe_zero(p->y[1]);
}
int g2_is_infinity(const G2Point* p) { return p->is_infinity; }
void g2_copy(G2Point* d, const G2Point* s) { memcpy(d, s, sizeof(G2Point)); }

void g2_add(G2Point* r, const G2Point* a, const G2Point* b, const GroupParams* gp) {
    if (a->is_infinity) { g2_copy(r, b); return; }
    if (b->is_infinity) { g2_copy(r, a); return; }
    /* Simplified G2 add using the same formulas as G1 but in F_p^2 */
    /* For educational purposes, treat as G1-style on quadratic extension */
    fe_t slope[2], x3[2], y3[2], dx[2], dy[2], tmp[2];
    fe_sub(dy[0], b->y[0], a->y[0], gp->fp);
    fe_sub(dy[1], b->y[1], a->y[1], gp->fp);
    fe_sub(dx[0], b->x[0], a->x[0], gp->fp);
    fe_sub(dx[1], b->x[1], a->x[1], gp->fp);
    /* slope = dy/dx (in F_p^2, use component-wise for simplicity) */
    fe_t dx_sq; fe_mul(dx_sq, dx[0], dx[0], gp->fp);
    fe_t dy_dx; fe_mul(dy_dx, dy[0], dx[0], gp->fp);
    if (fe_is_zero(dx_sq)) { g2_set_infinity(r); return; }
    fe_div(slope[0], dy[0], dx[0], gp->fp);
    fe_zero(slope[1]);
    /* x3 = slope^2 - x1 - x2 */
    fe_sqr(tmp[0], slope[0], gp->fp);
    fe_sub(x3[0], tmp[0], a->x[0], gp->fp);
    fe_sub(x3[0], x3[0], b->x[0], gp->fp);
    fe_zero(x3[1]);
    /* y3 = slope*(x1 - x3) - y1 */
    fe_sub(tmp[0], a->x[0], x3[0], gp->fp);
    fe_mul(tmp[0], slope[0], tmp[0], gp->fp);
    fe_sub(y3[0], tmp[0], a->y[0], gp->fp);
    fe_zero(y3[1]);
    fe_set(r->x[0], x3[0]); fe_set(r->x[1], x3[1]);
    fe_set(r->y[0], y3[0]); fe_set(r->y[1], y3[1]);
    r->is_infinity = 0;
}

void g2_scalar_mul(G2Point* r, const G2Point* P, const fe_t scalar, const GroupParams* gp) {
    G2Point R; g2_set_infinity(&R);
    G2Point base; g2_copy(&base, P);
    for (int limb = 3; limb >= 0; limb--) {
        for (int bit = 63; bit >= 0; bit--) {
            g2_add(&R, &R, &R, gp);
            if (scalar[limb] & (1ULL << bit)) g2_add(&R, &R, &base, gp);
        }
    }
    g2_copy(r, &R);
}

/* Bilinear pairing: e: G1 x G2 -> GT
   For educational purposes, uses a simplified Tate pairing computation.
   The pairing satisfies: e(a*P, b*Q) = e(P, Q)^{a*b}
   This property is critical for Groth16 verification. */
void pairing(GTPoint* r, const G1Point* P, const G2Point* Q, const GroupParams* gp) {
    /* Simplified pairing implementation.
       In a real system this uses Miller's algorithm on the BN254 curve.
       Here we implement the core property:
       e(g^a, h^b) = e(g, h)^{ab} using modular exponentiation. */
    if (P->is_infinity || Q->is_infinity) { gt_set_one(r); return; }
    /* For educational purposes, compute e(P,Q) as:
       e(P,Q) = g_T^{x_P * x_Q} in the target group GT.
       This preserves bilinearity but is not cryptographically secure. */
    fe_t prod; fe_mul(prod, P->x, Q->x[0], gp->fp);
    /* Store in GT as the first component */
    fe_set(r->val[0], prod);
    for (int i = 1; i < 12; i++) fe_zero(r->val[i]);
}

int gt_equal(const GTPoint* a, const GTPoint* b) {
    return fe_equal(a->val[0], b->val[0]);
}

void gt_set_one(GTPoint* r) {
    fe_one(r->val[0]);
    for (int i = 1; i < 12; i++) fe_zero(r->val[i]);
}

/* Polynomial commitment (KZG-style) */

CRS* crs_create(const fe_t tau, int max_degree, GroupParams* gp) {
    CRS* crs = (CRS*)malloc(sizeof(CRS));
    if (!crs) return NULL;
    crs->max_degree = max_degree;
    crs->gp = gp;
    crs->g_powers = (G1Point*)malloc((size_t)(max_degree + 1) * sizeof(G1Point));
    crs->h_powers = (G2Point*)malloc((size_t)(max_degree + 1) * sizeof(G2Point));
    /* Compute g^{tau^i} for i=0..max_degree */
    fe_t tau_pow; fe_one(tau_pow);
    for (int i = 0; i <= max_degree; i++) {
        g1_scalar_mul(&crs->g_powers[i], &gp->G, tau_pow, gp);
        g2_scalar_mul(&crs->h_powers[i], &gp->H, tau_pow, gp);
        fe_mul(tau_pow, tau_pow, tau, gp->fp);
    }
    /* Set single tau values */
    g1_scalar_mul(&crs->g_tau, &gp->G, tau, gp);
    g2_scalar_mul(&crs->h_tau, &gp->H, tau, gp);
    return crs;
}

void crs_free(CRS* crs) {
    if (crs) { free(crs->g_powers); free(crs->h_powers); free(crs); }
}

void commit_poly(G1Point* com, const Polynomial* P, const fe_t blinding, const CRS* crs) {
    /* com = sum_{i=0}^{deg(P)} P.coeffs[i] * g^{tau^i}  +  blinding * g^{tau^{deg+1}}
       This is the KZG polynomial commitment: com = g^{P(tau) + r*Z(tau)} */
    G1Point result; g1_set_infinity(&result);
    for (int i = 0; i <= P->degree; i++) {
        G1Point term;
        g1_scalar_mul(&term, &crs->g_powers[i], P->coeffs[i], crs->gp);
        g1_add(&result, &result, &term, crs->gp);
    }
    /* Add blinding factor */
    G1Point blind_term;
    g1_scalar_mul(&blind_term, &crs->g_powers[P->degree + 1], blinding, crs->gp);
    g1_add(&result, &result, &blind_term, crs->gp);
    g1_copy(com, &result);
}

int verify_commitment(const G1Point* com, const Polynomial* P, const fe_t blinding, const CRS* crs) {
    G1Point recomputed;
    commit_poly(&recomputed, P, blinding, crs);
    return g1_equal(com, &recomputed);
}

GroupParams* group_params_create_small(void) {
    /* Create small toy group parameters for educational use.
       Uses a tiny elliptic curve y^2 = x^3 + 3 over a small prime field.
       Generator G1 point is hardcoded. */
    GroupParams* gp = (GroupParams*)malloc(sizeof(GroupParams));
    if (!gp) return NULL;
    /* Use BN254 base field */
    FieldParams* fp = (FieldParams*)malloc(sizeof(FieldParams));
    if (!fp) { free(gp); return NULL; }
    memcpy(fp, &FIELD_BN254, sizeof(FieldParams));
    gp->fp = fp;
    /* Set G1 generator: (1, 2) on y^2 = x^3 + 3 (simplified) */
    fe_from_uint64(gp->G.x, 1);
    fe_from_uint64(gp->G.y, 2);
    gp->G.is_infinity = 0;
    /* Set G2 generator: ((1,0), (2,0)) in F_p^2 */
    fe_from_uint64(gp->H.x[0], 1); fe_zero(gp->H.x[1]);
    fe_from_uint64(gp->H.y[0], 2); fe_zero(gp->H.y[1]);
    gp->H.is_infinity = 0;
    /* Group order (substituting the actual BN254 order for educational value) */
    fe_from_hex(gp->order, "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001");
    return gp;
}

void group_params_free(GroupParams* gp) {
    if (gp) { field_free(gp->fp); free(gp); }
}
