/* field.h — finite field F_p arithmetic
 *
 * Implements arithmetic in prime-order fields — the algebraic foundation
 * for all SNARK constructions. Supports F_p with p = 2^254 + 0x... (BN254
 * base field) and generic prime fields.
 *
 * Key concepts:
 *   - Finite field: Z/pZ for prime p
 *   - Modular arithmetic: add, sub, mul, inv (Fermat or extended GCD)
 *   - Montgomery multiplication for performance
 *   - Square-and-multiply exponentiation
 *
 * References:
 *   - Pippenger (1980) "On the evaluation of powers and monomials"
 *   - Ben-Sasson et al. (2013) "SNARKs for C"
 *   - Bowe & Gabizon (2017) "Making Groth's zk-SNARK Simulation Extractable"
 */
#ifndef FIELD_H
#define FIELD_H
#include <stdint.h>
#include <stdlib.h>

/* ─── Core field element type ─── */
typedef uint64_t fe_t[4];  /* 256-bit element in 4-limb representation */

/* ─── Field parameters ─── */
typedef struct {
    fe_t modulus;          /* prime p */
    fe_t montgomery_r;     /* R = 2^256 mod p */
    fe_t montgomery_r2;    /* R^2 mod p */
    fe_t montgomery_n0;    /* -p^{-1} mod 2^64 */
    int  limb_bits;        /* bits per limb (typically 64) */
} FieldParams;

/* ─── Standard field: BN254 base field ─── */
/* p = 21888242871839275222246405745257275088696311157297823662689037894645226208583 */
extern const FieldParams FIELD_BN254;

/* ─── Allocation / initialization ─── */
FieldParams* field_create(const fe_t modulus);
void field_free(FieldParams* fp);
void field_copy_params(FieldParams* dst, const FieldParams* src);

/* ─── Element I/O ─── */
void fe_zero(fe_t r);
void fe_one(fe_t r);
void fe_set(fe_t r, const fe_t a);
int  fe_is_zero(const fe_t a);
int  fe_is_one(const fe_t a);
int  fe_equal(const fe_t a, const fe_t b);
void fe_from_uint64(fe_t r, uint64_t v);
void fe_from_hex(fe_t r, const char* hex);
void fe_print(const fe_t a);

/* ─── Modular arithmetic ─── */
/* All ops compute result in [0, p-1]. a, b may alias r. */
void fe_add(fe_t r, const fe_t a, const fe_t b, const FieldParams* fp);
void fe_sub(fe_t r, const fe_t a, const fe_t b, const FieldParams* fp);
void fe_neg(fe_t r, const fe_t a, const FieldParams* fp);
void fe_mul(fe_t r, const fe_t a, const fe_t b, const FieldParams* fp);
void fe_sqr(fe_t r, const fe_t a, const FieldParams* fp);
int  fe_inv(fe_t r, const fe_t a, const FieldParams* fp); /* returns 0 if a=0 */
void fe_div(fe_t r, const fe_t a, const fe_t b, const FieldParams* fp);
void fe_pow(fe_t r, const fe_t a, const fe_t e, const FieldParams* fp);

/* ─── Batched operations (amortized cost) ─── */
void fe_batch_mul(fe_t* results, const fe_t* a, const fe_t* b, int n,
                  const FieldParams* fp);
void fe_batch_inv(fe_t* results, const fe_t* a, int n,
                  const FieldParams* fp);

/* ─── Montgomery form conversion ─── */
void fe_to_montgomery(fe_t r, const fe_t a, const FieldParams* fp);
void fe_from_montgomery(fe_t r, const fe_t a, const FieldParams* fp);

/* ─── Random element (for ZK blinding) ─── */
void fe_random(fe_t r, const FieldParams* fp);

#endif /* FIELD_H */
