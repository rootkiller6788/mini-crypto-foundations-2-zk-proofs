#include "sigma_composition.h"
#include "sigma_chaum_pedersen.h"
#include "sigma_schnorr.h"
#include <string.h>

void sigma_and_commit(sigma_group_elem *a1, sigma_group_elem *a2,
                      const sigma_scalar *r1, const sigma_scalar *r2,
                      const sigma_and_public *pub) {
    (void)pub;
    sigma_group_exp_g(a1, r1);
    sigma_group_exp_g(a2, r2);
}

void sigma_and_respond(sigma_scalar *z1, sigma_scalar *z2,
                       const sigma_scalar *r1, const sigma_scalar *r2,
                       const sigma_scalar *e,
                       const sigma_and_witness *wit) {
    sigma_scalar ex1, ex2;
    sigma_scalar_mul(&ex1, e, &wit->wit1.x);
    sigma_scalar_mul(&ex2, e, &wit->wit2.x);
    sigma_scalar_add(z1, r1, &ex1);
    sigma_scalar_add(z2, r2, &ex2);
}

bool sigma_and_verify(const sigma_group_elem *a1,
                      const sigma_group_elem *a2,
                      const sigma_scalar *e,
                      const sigma_scalar *z1,
                      const sigma_scalar *z2,
                      const sigma_and_public *pub) {
    sigma_group_elem lhs1, rhs1, rhs1_term;
    sigma_group_exp_g(&lhs1, z1);
    sigma_group_exp(&rhs1_term, &pub->pk1.y, e);
    sigma_group_mul(&rhs1, a1, &rhs1_term);
    if (!sigma_group_eq(&lhs1, &rhs1)) return false;
    sigma_group_elem lhs2, rhs2, rhs2_term;
    sigma_group_exp_g(&lhs2, z2);
    sigma_group_exp(&rhs2_term, &pub->pk2.y, e);
    sigma_group_mul(&rhs2, a2, &rhs2_term);
    return sigma_group_eq(&lhs2, &rhs2);
}

/* OR composition: e1 + e2 = e, known_branch determines honest vs simulated */
void sigma_or_prove(sigma_or_transcript *t,
                    int known_branch,
                    const void *known_witness,
                    const void *unknown_public,
                    const sigma_or_public *pub,
                    const sigma_scalar *randomness,
                    const sigma_scalar *verifier_challenge) {
    const sigma_schnorr_witness *wit = (const sigma_schnorr_witness*)known_witness;
    (void)unknown_public;
    sigma_scalar_copy(&t->e, verifier_challenge);
    if (known_branch == 0) {
        /* Known: branch 0 (uses e1/z1/a1), Unknown: branch 1 (uses e2/z2/a2) */
        sigma_random_scalar(&t->e2);
        sigma_scalar_sub(&t->e1, &t->e, &t->e2);
        sigma_random_scalar(&t->z2);
        {
            const sigma_schnorr_public *p2 = &pub->pk2;
            sigma_group_elem y2_e2;
            sigma_group_exp(&y2_e2, &p2->y, &t->e2);
            sigma_biguint inv;
            sigma_mod_inv(&inv, (const sigma_biguint*)&y2_e2, &SIGMA_PRIME_P);
            sigma_group_elem gz2;
            sigma_group_exp_g(&gz2, &t->z2);
            sigma_mod_mul((sigma_biguint*)&t->a2, (const sigma_biguint*)&gz2,
                          &inv, &SIGMA_PRIME_P);
        }
        sigma_group_exp_g(&t->a1, randomness);
        sigma_scalar e1x;
        sigma_scalar_mul(&e1x, &t->e1, &wit->x);
        sigma_scalar_add(&t->z1, randomness, &e1x);
    } else {
        /* Known: branch 1, Unknown: branch 0 */
        sigma_random_scalar(&t->e1);
        sigma_scalar_sub(&t->e2, &t->e, &t->e1);
        sigma_random_scalar(&t->z1);
        {
            const sigma_schnorr_public *p1 = &pub->pk1;
            sigma_group_elem y1_e1;
            sigma_group_exp(&y1_e1, &p1->y, &t->e1);
            sigma_biguint inv;
            sigma_mod_inv(&inv, (const sigma_biguint*)&y1_e1, &SIGMA_PRIME_P);
            sigma_group_elem gz1;
            sigma_group_exp_g(&gz1, &t->z1);
            sigma_mod_mul((sigma_biguint*)&t->a1, (const sigma_biguint*)&gz1,
                          &inv, &SIGMA_PRIME_P);
        }
        sigma_group_exp_g(&t->a2, randomness);
        sigma_scalar e2x;
        sigma_scalar_mul(&e2x, &t->e2, &wit->x);
        sigma_scalar_add(&t->z2, randomness, &e2x);
    }
}

bool sigma_or_verify(const sigma_or_transcript *t,
                     const sigma_or_public *pub) {
    sigma_scalar sum;
    sigma_scalar_add(&sum, &t->e1, &t->e2);
    if (sigma_scalar_cmp(&sum, &t->e) != 0) return false;
    sigma_group_elem lhs1, rhs1, rhs1_term;
    sigma_group_exp_g(&lhs1, &t->z1);
    sigma_group_exp(&rhs1_term, &pub->pk1.y, &t->e1);
    sigma_group_mul(&rhs1, &t->a1, &rhs1_term);
    if (!sigma_group_eq(&lhs1, &rhs1)) return false;
    sigma_group_elem lhs2, rhs2, rhs2_term;
    sigma_group_exp_g(&lhs2, &t->z2);
    sigma_group_exp(&rhs2_term, &pub->pk2.y, &t->e2);
    sigma_group_mul(&rhs2, &t->a2, &rhs2_term);
    return sigma_group_eq(&lhs2, &rhs2);
}

/* Ring signature */
void sigma_ring_prove(sigma_ring_proof *proof,
                      const sigma_ring_public *pub,
                      int signer_idx,
                      const sigma_schnorr_witness *signer_sk,
                      const uint8_t *message, size_t message_len) {
    int N = pub->num_keys;
    if (N < 2 || N > SIGMA_OR_MAX_RING) return;
    proof->num_keys = N;
    sigma_scalar r_k;
    sigma_random_nonzero_scalar(&r_k);
    sigma_scalar sum_ej;
    sigma_scalar_zero(&sum_ej);
    for (int j = 0; j < N; j++) {
        if (j == signer_idx) {
            sigma_group_exp_g(&proof->commitments[j], &r_k);
        } else {
            sigma_random_scalar(&proof->challenges[j]);
            sigma_random_scalar(&proof->responses[j]);
            sigma_group_elem yj_ej, gzj, inv_ej;
            sigma_group_exp(&yj_ej, &pub->pks[j].y, &proof->challenges[j]);
            sigma_mod_inv((sigma_biguint*)&inv_ej,
                          (const sigma_biguint*)&yj_ej, &SIGMA_PRIME_P);
            sigma_group_exp_g(&gzj, &proof->responses[j]);
            sigma_mod_mul((sigma_biguint*)&proof->commitments[j],
                          (const sigma_biguint*)&gzj,
                          (const sigma_biguint*)&inv_ej, &SIGMA_PRIME_P);
            sigma_scalar_add(&sum_ej, &sum_ej, &proof->challenges[j]);
        }
    }
    sigma_hash_context ctx;
    sigma_hash_init(&ctx);
    for (int j = 0; j < N; j++) {
        uint8_t abuf[256];
        sigma_group_serialize(abuf, &proof->commitments[j]);
        sigma_hash_update(&ctx, abuf, 256);
    }
    sigma_hash_update(&ctx, message, message_len);
    uint8_t dgst[32];
    sigma_hash_final(&ctx, dgst);
    /* Reduce digest modulo q properly — uses long_divrem internally */
    sigma_digest_to_scalar(&proof->challenge, dgst);
    sigma_scalar_sub(&proof->challenges[signer_idx],
                     &proof->challenge, &sum_ej);
    sigma_scalar ek_xk;
    sigma_scalar_mul(&ek_xk, &proof->challenges[signer_idx], &signer_sk->x);
    sigma_scalar_add(&proof->responses[signer_idx], &r_k, &ek_xk);
}

bool sigma_ring_verify(const sigma_ring_proof *proof,
                       const sigma_ring_public *pub,
                       const uint8_t *message, size_t message_len) {
    int N = proof->num_keys;
    if (N < 2 || N > SIGMA_OR_MAX_RING) return false;
    sigma_scalar sum_ej;
    sigma_scalar_zero(&sum_ej);
    for (int j = 0; j < N; j++)
        sigma_scalar_add(&sum_ej, &sum_ej, &proof->challenges[j]);
    sigma_hash_context ctx;
    sigma_hash_init(&ctx);
    for (int j = 0; j < N; j++) {
        uint8_t abuf[256];
        sigma_group_serialize(abuf, &proof->commitments[j]);
        sigma_hash_update(&ctx, abuf, 256);
    }
    sigma_hash_update(&ctx, message, message_len);
    uint8_t dgst[32];
    sigma_hash_final(&ctx, dgst);
    sigma_scalar expected_e;
    /* Reduce digest modulo q properly — uses long_divrem internally */
    sigma_digest_to_scalar(&expected_e, dgst);
    if (sigma_scalar_cmp(&sum_ej, &expected_e) != 0) return false;
    for (int j = 0; j < N; j++) {
        sigma_group_elem lhs, rhs, rhs_term;
        sigma_group_exp_g(&lhs, &proof->responses[j]);
        sigma_group_exp(&rhs_term, &pub->pks[j].y, &proof->challenges[j]);
        sigma_group_mul(&rhs, &proof->commitments[j], &rhs_term);
        if (!sigma_group_eq(&lhs, &rhs)) return false;
    }
    return true;
}

/* EQ composition */
void sigma_eq_prove(sigma_cp_transcript *t,
                    const sigma_schnorr_witness *wit,
                    const sigma_eq_public *pub,
                    const sigma_scalar *randomness) {
    (void)pub;
    sigma_group_exp_g(&t->a1, randomness);
    sigma_group_exp_g(&t->a2, randomness);
    sigma_scalar ex;
    sigma_scalar_mul(&ex, &t->challenge, &wit->x);
    sigma_scalar_add(&t->response, randomness, &ex);
}

bool sigma_eq_verify(const sigma_cp_transcript *t,
                     const sigma_eq_public *pub) {
    sigma_group_elem lhs1, rhs1, rhs1_term;
    sigma_group_exp_g(&lhs1, &t->response);
    sigma_group_exp(&rhs1_term, &pub->pk1.y, &t->challenge);
    sigma_group_mul(&rhs1, &t->a1, &rhs1_term);
    if (!sigma_group_eq(&lhs1, &rhs1)) return false;
    sigma_group_elem lhs2, rhs2, rhs2_term;
    sigma_group_exp_g(&lhs2, &t->response);
    sigma_group_exp(&rhs2_term, &pub->pk2.y, &t->challenge);
    sigma_group_mul(&rhs2, &t->a2, &rhs2_term);
    return sigma_group_eq(&lhs2, &rhs2);
}

const sigma_protocol *sigma_compose_and(const sigma_protocol *proto1,
                                         const sigma_protocol *proto2) {
    (void)proto2;
    return proto1;
}

const sigma_protocol *sigma_compose_or(const sigma_protocol *proto1,
                                        const sigma_protocol *proto2) {
    (void)proto2;
    return proto1;
}

void sigma_ring_proof_serialize(uint8_t *out, const sigma_ring_proof *p) {
    int N = p->num_keys;
    for (int j = 0; j < N; j++) {
        sigma_group_serialize(out + j * 256, &p->commitments[j]);
        sigma_scalar_serialize(out + N * 256 + j * 32, &p->challenges[j]);
        sigma_scalar_serialize(out + N * 288 + j * 32, &p->responses[j]);
    }
}

bool sigma_ring_proof_deserialize(sigma_ring_proof *p, const uint8_t *in) {
    int N = p->num_keys;
    for (int j = 0; j < N; j++) {
        memcpy(p->commitments[j].limbs, in + j * 256, 256);
        sigma_scalar_deserialize(&p->challenges[j], in + N * 256 + j * 32);
        sigma_scalar_deserialize(&p->responses[j], in + N * 288 + j * 32);
    }
    return true;
}
