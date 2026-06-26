#include "commitments.h"
#include <stdio.h>
#include <assert.h>

/* commitments.c -- Pedersen, ElGamal, bit, string, trapdoor commitments */

void pedersen_commit(pedersen_commitment_t *pc, uint64_t m,
                      const random_tape_t *rng, const group_params_t *gp) {
    if (!pc || !rng || !gp) return;
    pc->m = m;
    pc->r = pull_random_mod_q((random_tape_t *)rng, gp->q);
    uint64_t gm = mod_pow(gp->g, m, gp->p);
    uint64_t hr = mod_pow(gp->h, pc->r, gp->p);
    pc->C = mod_mul(gm, hr, gp->p);
    pc->gp = gp;
}

int pedersen_open(const pedersen_commitment_t *pc, uint64_t *m_out, uint64_t *r_out) {
    if (!pc || !m_out || !r_out) return -1;
    *m_out = pc->m; *r_out = pc->r;
    return 0;
}

int pedersen_verify_opening(uint64_t C, uint64_t m, uint64_t r,
                              const group_params_t *gp) {
    if (!gp) return 0;
    uint64_t gm = mod_pow(gp->g, m, gp->p);
    uint64_t hr = mod_pow(gp->h, r, gp->p);
    return (C == mod_mul(gm, hr, gp->p)) ? 1 : 0;
}

void pedersen_homomorphic_add(const pedersen_commitment_t *pc1,
                               const pedersen_commitment_t *pc2,
                               pedersen_commitment_t *out,
                               const group_params_t *gp) {
    if (!pc1 || !pc2 || !out || !gp) return;
    out->m = mod_add(pc1->m, pc2->m, gp->q);
    out->r = mod_add(pc1->r, pc2->r, gp->q);
    out->C = mod_mul(pc1->C, pc2->C, gp->p);
    out->gp = gp;
}

void elgamal_commit(elgamal_commitment_t *ec, uint64_t m,
                     const random_tape_t *rng, const group_params_t *gp) {
    if (!ec || !rng || !gp) return;
    ec->m = m;
    ec->r = pull_random_mod_q((random_tape_t *)rng, gp->q);
    ec->A = mod_pow(gp->g, ec->r, gp->p);
    ec->B = mod_mul(m % gp->p, mod_pow(gp->h, ec->r, gp->p), gp->p);
    ec->gp = gp;
}

int elgamal_open(const elgamal_commitment_t *ec, uint64_t *m_out, uint64_t *r_out) {
    if (!ec || !m_out || !r_out) return -1;
    *m_out = ec->m; *r_out = ec->r;
    return 0;
}

int elgamal_verify_opening(uint64_t A, uint64_t B, uint64_t m, uint64_t r,
                              const group_params_t *gp) {
    if (!gp) return 0;
    if (mod_pow(gp->g, r, gp->p) != A) return 0;
    return (B == mod_mul(m % gp->p, mod_pow(gp->h, r, gp->p), gp->p)) ? 1 : 0;
}

void bit_commit(bit_commitment_t *bc, int bit,
                 const random_tape_t *rng, const group_params_t *gp) {
    if (!bc || !rng || !gp) return;
    bc->bit = (bit != 0) ? 1 : 0;
    bc->r = pull_random_mod_q((random_tape_t *)rng, gp->q);
    uint64_t hr = mod_pow(gp->h, bc->r, gp->p);
    bc->C = (bc->bit == 0) ? hr : mod_mul(gp->g % gp->p, hr, gp->p);
    bc->gp = gp;
}

int bit_verify_opening(const bit_commitment_t *bc) {
    if (!bc || !bc->gp) return 0;
    uint64_t hr = mod_pow(bc->gp->h, bc->r, bc->gp->p);
    uint64_t expected = (bc->bit == 0) ? hr : mod_mul(bc->gp->g % bc->gp->p, hr, bc->gp->p);
    return (bc->C == expected) ? 1 : 0;
}

void string_commit(string_commitment_t *sc, const uint8_t *data, size_t len,
                    const random_tape_t *rng, const group_params_t *gp) {
    if (!sc || !data || !rng || !gp) return;
    if (len > MAX_STRING_LEN) len = MAX_STRING_LEN;
    sc->len = len; sc->gp = gp;
    random_tape_t rng_local = *rng;
    for (size_t i = 0; i < len; i++) {
        sc->data[i] = data[i];
        sc->randomness[i] = pull_random_mod_q(&rng_local, gp->q);
        sc->commitments[i] = mod_mul(mod_pow(gp->g, data[i], gp->p),
                                      mod_pow(gp->h, sc->randomness[i], gp->p), gp->p);
    }
}

int string_open(const string_commitment_t *sc, uint8_t *data_out, size_t *len_out) {
    if (!sc || !data_out || !len_out) return -1;
    *len_out = sc->len;
    for (size_t i = 0; i < sc->len; i++) data_out[i] = sc->data[i];
    return 0;
}

int string_verify_opening(const string_commitment_t *sc) {
    if (!sc || !sc->gp) return 0;
    for (size_t i = 0; i < sc->len; i++) {
        uint64_t expected = mod_mul(mod_pow(sc->gp->g, sc->data[i], sc->gp->p),
                                     mod_pow(sc->gp->h, sc->randomness[i], sc->gp->p), sc->gp->p);
        if (sc->commitments[i] != expected) return 0;
    }
    return 1;
}

void trapdoor_equivocate(const trapdoor_t *td,
                          uint64_t C, uint64_t old_m, uint64_t old_r,
                          uint64_t new_m, uint64_t *new_r_out) {
    if (!td || !new_r_out) return;
    uint64_t m_diff = mod_sub(old_m, new_m, td->gp->q);
    uint64_t t_inv = mod_inv(td->trapdoor, td->gp->q);
    *new_r_out = mod_add(old_r, mod_mul(m_diff, t_inv, td->gp->q), td->gp->q);
    assert(pedersen_verify_opening(C, new_m, *new_r_out, td->gp));
    (void)C;
}

int commitments_self_test(void) {
    group_params_t gp = {23, 2, 11, 8};
    random_tape_t rng;
    init_random_tape(&rng, 1111);
    pedersen_commitment_t pc;
    pedersen_commit(&pc, 5, &rng, &gp);
    assert(pedersen_verify_opening(pc.C, pc.m, pc.r, &gp) == 1);
    pedersen_commitment_t pc2, pc_sum;
    pedersen_commit(&pc2, 3, &rng, &gp);
    pedersen_homomorphic_add(&pc, &pc2, &pc_sum, &gp);
    assert(pc_sum.m == mod_add(5, 3, gp.q));
    elgamal_commitment_t ec;
    elgamal_commit(&ec, 7, &rng, &gp);
    assert(elgamal_verify_opening(ec.A, ec.B, ec.m, ec.r, &gp) == 1);
    bit_commitment_t bc0, bc1;
    bit_commit(&bc0, 0, &rng, &gp); bit_commit(&bc1, 1, &rng, &gp);
    assert(bit_verify_opening(&bc0) == 1 && bit_verify_opening(&bc1) == 1);
    uint8_t test_str[5] = {1,2,3,4,5};
    string_commitment_t sc;
    string_commit(&sc, test_str, 5, &rng, &gp);
    assert(string_verify_opening(&sc) == 1);
    trapdoor_t td = {3, &gp};
    uint64_t new_r;
    trapdoor_equivocate(&td, pc.C, pc.m, pc.r, 9, &new_r);
    assert(pedersen_verify_opening(pc.C, 9, new_r, &gp) == 1);
    return 0;
}
