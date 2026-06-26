/* dlog.h — discrete-log based polynomial commitments
 *
 * Implements polynomial commitment schemes based on the discrete logarithm
 * assumption in bilinear groups. This is the "cryptographic compiler" that
 * turns a QAP into a zkSNARK:
 *   - Prover commits to A(x), B(x), C(x) via group elements
 *   - Verifier checks the QAP relation in the exponent using a pairing
 *
 * Key concepts:
 *   - Pedersen commitment: C = g^v · h^r
 *   - Polynomial commitment: commit(f) = g^{f(τ)} where τ is toxic waste
 *   - Knowledge of Exponent (KEA): extractability from group elements
 *   - d-power assumption: hardness of distinguishing g^{P(τ)} from random
 *   - Bilinear pairing: e(g^a, h^b) = e(g, h)^{ab}
 *
 * This is NOT a production-grade implementation (uses toy-sized groups).
 * For educational purposes, we use small prime fields and simulate pairings.
 *
 * References:
 *   - Kate, Zaverucha, Goldberg (2010) "Constant-Size Commitments to Polynomials"
 *   - Groth (2010) "Short Pairing-based Non-interactive Zero-Knowledge Arguments"
 *   - Boneh, Boyen, Shacham (2004) "Short Group Signatures"
 */
#ifndef DLOG_H
#define DLOG_H
#include "field.h"
#include "polynomial.h"
#include <stdint.h>

/* ─── Group element in G1 (elliptic curve point, simplified) ─── */
typedef struct {
    fe_t x;
    fe_t y;
    int  is_infinity;   /* point at infinity = identity */
} G1Point;

/* ─── Group element in G2 ─── */
typedef struct {
    fe_t x[2];           /* quadratic extension field F_{p^2} */
    fe_t y[2];
    int  is_infinity;
} G2Point;

/* ─── Pairing target group GT ─── */
typedef struct {
    fe_t val[12];        /* F_{p^12} element, simplified */
} GTPoint;

/* ─── Group parameters ─── */
typedef struct {
    FieldParams* fp;     /* base field */
    G1Point      G;      /* generator of G1 */
    G2Point      H;      /* generator of G2 */
    fe_t         order;  /* group order (for scalar multiplication) */
} GroupParams;

/* ─── G1 operations ─── */
void g1_set_infinity(G1Point* p);
int  g1_is_infinity(const G1Point* p);
void g1_copy(G1Point* dst, const G1Point* src);
int  g1_equal(const G1Point* a, const G1Point* b);
void g1_add(G1Point* r, const G1Point* a, const G1Point* b,
            const GroupParams* gp);
void g1_double(G1Point* r, const G1Point* a, const GroupParams* gp);
void g1_scalar_mul(G1Point* r, const G1Point* P, const fe_t scalar,
                   const GroupParams* gp);
void g1_neg(G1Point* r, const G1Point* a, const GroupParams* gp);

/* ─── G2 operations ─── */
void g2_set_infinity(G2Point* p);
int  g2_is_infinity(const G2Point* p);
void g2_copy(G2Point* dst, const G2Point* src);
void g2_add(G2Point* r, const G2Point* a, const G2Point* b,
            const GroupParams* gp);
void g2_scalar_mul(G2Point* r, const G2Point* P, const fe_t scalar,
                   const GroupParams* gp);

/* ─── Bilinear pairing ─── */
/* e: G1 × G2 → GT. Computed via Miller's algorithm (simplified). */
void pairing(GTPoint* r, const G1Point* P, const G2Point* Q,
             const GroupParams* gp);
int  gt_equal(const GTPoint* a, const GTPoint* b);
void gt_set_one(GTPoint* r);

/* ─── Polynomial commitment (KZG-style) ─── */
typedef struct {
    G1Point*  g_powers;    /* g, g^τ, g^{τ^2}, ..., g^{τ^d} — for committing */
    G2Point*  h_powers;    /* h, h^τ — for verification */
    G2Point   h_tau;       /* h^τ */
    G1Point   g_tau;       /* g^τ */
    int       max_degree;
    GroupParams* gp;
} CRS;  /* Common Reference String */

/* Create a CRS with a known τ (for testing only — in production, τ is
 * destroyed after setup via MPC ceremony). */
CRS*  crs_create(const fe_t tau, int max_degree, GroupParams* gp);
void  crs_free(CRS* crs);

/* Commit to polynomial P with blinding r: com = g^{P(τ) + r·Z(τ)} */
void commit_poly(G1Point* commitment, const Polynomial* P,
                 const fe_t blinding, const CRS* crs);

/* Open commitment: verify that P is correctly committed */
int  verify_commitment(const G1Point* commitment, const Polynomial* P,
                       const fe_t blinding, const CRS* crs);

/* ─── Group parameter initialization ─── */
GroupParams* group_params_create_small(void); /* toy group for education */
void group_params_free(GroupParams* gp);

#endif /* DLOG_H */
