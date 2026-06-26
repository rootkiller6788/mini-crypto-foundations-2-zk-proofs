#include "sigma_protocols.h"
#include <stdio.h>
#include <assert.h>

/* sigma_protocols.c -- Schnorr, Chaum-Pedersen, GQ, AND/OR, parallel repetition */

void schnorr_prover_init(schnorr_prover_t *sp, uint64_t x, const group_params_t *gp) {
    if (!sp || !gp) return;
    sp->x = x; sp->r = 0; sp->a = 0; sp->gp = gp;
}

uint64_t schnorr_prover_commit(schnorr_prover_t *sp, const random_tape_t *rng) {
    if (!sp || !rng) return 0;
    sp->r = pull_random_mod_q((random_tape_t *)rng, sp->gp->q);
    sp->a = mod_pow(sp->gp->g, sp->r, sp->gp->p);
    return sp->a;
}

uint64_t schnorr_prover_respond(schnorr_prover_t *sp, uint64_t challenge) {
    if (!sp) return 0;
    uint64_t c_mod = challenge % sp->gp->q;
    return mod_add(sp->r, mod_mul(c_mod, sp->x, sp->gp->q), sp->gp->q);
}

void schnorr_verifier_init(schnorr_verifier_t *sv, uint64_t y, const group_params_t *gp) {
    if (!sv || !gp) return;
    sv->y = y; sv->a = 0; sv->c = 0; sv->s = 0; sv->gp = gp;
}

void schnorr_verifier_set_commitment(schnorr_verifier_t *sv, uint64_t a) {
    if (!sv) return;
    sv->a = a;
}

uint64_t schnorr_verifier_pick_challenge(schnorr_verifier_t *sv, const random_tape_t *rng) {
    if (!sv || !rng) return 0;
    sv->c = pull_random_mod_q((random_tape_t *)rng, sv->gp->q);
    return sv->c;
}

int schnorr_verifier_verify(schnorr_verifier_t *sv, uint64_t s) {
    if (!sv) return 0;
    sv->s = s;
    return schnorr_verify(sv->a, sv->c, sv->s, sv->y, sv->gp);
}

void schnorr_transcript_to_transcript(const schnorr_transcript_t *st, transcript_t *out) {
    if (!st || !out) return;
    transcript_init(out);
    transcript_start_round(out); transcript_append_u64(out, st->a);
    transcript_start_round(out); transcript_append_u64(out, st->c);
    transcript_start_round(out); transcript_append_u64(out, st->s);
}

/* AND-composition */
void and_compose_commit(uint64_t *a1, uint64_t *a2,
                         const schnorr_prover_t *p1, const schnorr_prover_t *p2,
                         const random_tape_t *rng) {
    if (!a1 || !a2 || !p1 || !p2 || !rng) return;
    random_tape_t rng_copy = *rng;
    uint64_t r1 = pull_random_mod_q(&rng_copy, p1->gp->q);
    *a1 = mod_pow(p1->gp->g, r1, p1->gp->p);
    uint64_t r2 = pull_random_mod_q(&rng_copy, p2->gp->q);
    *a2 = mod_pow(p2->gp->g, r2, p2->gp->p);
}
int and_compose_verify(uint64_t a1, uint64_t a2, uint64_t c, uint64_t s1, uint64_t s2,
                        uint64_t y1, uint64_t y2, const group_params_t *gp) {
    if (!gp) return 0;
    return (schnorr_verify(a1, c, s1, y1, gp) && schnorr_verify(a2, c, s2, y2, gp)) ? 1 : 0;
}

/* OR-composition (Cramer-Damgard-Schoenmakers 1994) */

void or_compose_prover_init(or_composition_prover_t *op, int real_side, uint64_t x,
                             uint64_t y1, uint64_t y2, const group_params_t *gp) {
    if (!op || !gp) return;
    assert(real_side == 1 || real_side == 2);
    op->real_side = real_side; op->x = x;
    op->y1 = y1; op->y2 = y2; op->gp = gp;
}
void or_compose_prover_execute(or_composition_prover_t *op, const random_tape_t *rng,
                                or_composition_transcript_t *out, uint64_t vc) {
    if (!op || !rng || !out) return;
    uint64_t a1, a2, c1, c2, s1, s2;
    if (op->real_side == 1) {
        uint64_t r1 = pull_random_mod_q((random_tape_t *)rng, op->gp->q);
        a1 = mod_pow(op->gp->g, r1, op->gp->p);
        c2 = pull_random_mod_q((random_tape_t *)rng, op->gp->q);
        s2 = pull_random_mod_q((random_tape_t *)rng, op->gp->q);
        uint64_t inv = mod_pow(op->y2, ((c2 % op->gp->q) == 0 ? 0 : op->gp->q - (c2 % op->gp->q)), op->gp->p);
        a2 = mod_mul(mod_pow(op->gp->g, s2, op->gp->p), inv, op->gp->p);
        c1 = (vc >= c2) ? ((vc - c2) % op->gp->q) : (op->gp->q - ((c2 - vc) % op->gp->q));
        s1 = mod_add(r1, mod_mul(c1, op->x, op->gp->q), op->gp->q);
    } else {
        uint64_t r2 = pull_random_mod_q((random_tape_t *)rng, op->gp->q);
        a2 = mod_pow(op->gp->g, r2, op->gp->p);
        c1 = pull_random_mod_q((random_tape_t *)rng, op->gp->q);
        s1 = pull_random_mod_q((random_tape_t *)rng, op->gp->q);
        uint64_t inv = mod_pow(op->y1, ((c1 % op->gp->q) == 0 ? 0 : op->gp->q - (c1 % op->gp->q)), op->gp->p);
        a1 = mod_mul(mod_pow(op->gp->g, s1, op->gp->p), inv, op->gp->p);
        c2 = (vc >= c1) ? ((vc - c1) % op->gp->q) : (op->gp->q - ((c1 - vc) % op->gp->q));
        s2 = mod_add(r2, mod_mul(c2, op->x, op->gp->q), op->gp->q);
    }
    out->a1 = a1; out->c1 = c1; out->s1 = s1;
    out->a2 = a2; out->c2 = c2; out->s2 = s2;
    out->c  = vc;
}
int or_compose_verify(const or_composition_transcript_t *t, uint64_t y1, uint64_t y2,
                       const group_params_t *gp) {
    if (!t || !gp) return 0;
    int l = schnorr_verify(t->a1, t->c1, t->s1, y1, gp);
    int r = schnorr_verify(t->a2, t->c2, t->s2, y2, gp);
    int x = (((t->c1 + t->c2) % gp->q) == (t->c % gp->q)) ? 1 : 0;
    return (l && r && x) ? 1 : 0;
}

/* Parallel repetition */

int parallel_sigma_prover(const schnorr_prover_t *sp, const random_tape_t *rng,
                           int k, uint64_t *a_out, uint64_t *c_in, uint64_t *s_out) {
    if (!sp || !rng || !a_out || !c_in || !s_out || k <= 0) return -1;
    random_tape_t rng_local = *rng;
    for (int i = 0; i < k; i++) {
        uint64_t ri = pull_random_mod_q(&rng_local, sp->gp->q);
        a_out[i] = mod_pow(sp->gp->g, ri, sp->gp->p);
        uint64_t ci = c_in[i] % sp->gp->q;
        s_out[i] = mod_add(ri, mod_mul(ci, sp->x, sp->gp->q), sp->gp->q);
    }
    return 0;
}
int parallel_sigma_verify(const uint64_t *a, const uint64_t *c, const uint64_t *s,
                           int k, uint64_t y, const group_params_t *gp) {
    if (!a || !c || !s || !gp || k <= 0) return 0;
    for (int i = 0; i < k; i++)
        if (!schnorr_verify(a[i], c[i], s[i], y, gp)) return 0;
    return 1;
}

int generic_sigma_simulate(sigma_simulate_fn sim, uint64_t y, const group_params_t *gp,
                            const random_tape_t *rng, uint64_t *a, uint64_t *c, uint64_t *s) {
    if (!sim || !gp || !rng || !a || !c || !s) return -1;
    int ret = sim(y, gp, rng, a, c, s);
    if (ret != 0 || !schnorr_verify(*a, *c, *s, y, gp)) return -1;
    return 0;
}

int sigma_protocols_self_test(void) {
    group_params_t gp = {23, 2, 11, 8};
    uint64_t x = 4, y = mod_pow(2, 4, 23), B = mod_pow(gp.h, x, gp.p);
    random_tape_t rng;
    schnorr_prover_t sp;
    schnorr_prover_init(&sp, x, &gp);
    init_random_tape(&rng, 9999);
    uint64_t a = schnorr_prover_commit(&sp, &rng);
    schnorr_verifier_t sv;
    schnorr_verifier_init(&sv, y, &gp);
    schnorr_verifier_set_commitment(&sv, a);
    uint64_t c = schnorr_verifier_pick_challenge(&sv, &rng);
    uint64_t s = schnorr_prover_respond(&sp, c);
    assert(schnorr_verifier_verify(&sv, s) == 1);

    chaum_pedersen_prover_t cp;
    chaum_pedersen_prover_init(&cp, x, y, B, &gp);
    init_random_tape(&rng, 8888);
    uint64_t a1, a2;
    chaum_pedersen_prover_commit(&cp, &rng, &a1, &a2);
    c = pull_random_mod_q(&rng, gp.q);
    s = chaum_pedersen_prover_respond(&cp, c);
    assert(chaum_pedersen_verify(a1, a2, c, s, y, B, &gp) == 1);

    gq_prover_t gq;
    gq_prover_init(&gq, 5, 69, 77, 3);
    init_random_tape(&rng, 7777);
    a = gq_prover_commit(&gq, &rng);
    c = pull_random_mod_q(&rng, 100);
    s = gq_prover_respond(&gq, c);
    assert(gq_verify(a, c, s, 69, 77, 3) == 1);

    uint64_t y2 = mod_pow(2, 7, 23);
    or_composition_prover_t op;
    or_compose_prover_init(&op, 1, x, y, y2, &gp);
    or_composition_transcript_t ot;
    init_random_tape(&rng, 6666);
    uint64_t vc = pull_random_mod_q(&rng, gp.q);
    or_compose_prover_execute(&op, &rng, &ot, vc);
    assert(or_compose_verify(&ot, y, y2, &gp) == 1);

    uint64_t pa[3], pc[3] = {1, 2, 3}, ps[3];
    init_random_tape(&rng, 5555);
    assert(parallel_sigma_prover(&sp, &rng, 3, pa, pc, ps) == 0);
    assert(parallel_sigma_verify(pa, pc, ps, 3, y, &gp) == 1);

    return 0;
}
/* Chaum-Pedersen protocol implementations */
void chaum_pedersen_prover_init(chaum_pedersen_prover_t *cp, uint64_t x,
                                 uint64_t A, uint64_t B, const group_params_t *gp) {
    if (!cp || !gp) return;
    cp->x = x; cp->r = 0; cp->a1 = 0; cp->a2 = 0;
    cp->A = A; cp->B = B; cp->gp = gp;
}
void chaum_pedersen_prover_commit(chaum_pedersen_prover_t *cp,
                                   const random_tape_t *rng,
                                   uint64_t *a1_out, uint64_t *a2_out) {
    if (!cp || !rng || !a1_out || !a2_out) return;
    cp->r = pull_random_mod_q((random_tape_t *)rng, cp->gp->q);
    cp->a1 = mod_pow(cp->gp->g, cp->r, cp->gp->p);
    cp->a2 = mod_pow(cp->gp->h, cp->r, cp->gp->p);
    *a1_out = cp->a1; *a2_out = cp->a2;
}
uint64_t chaum_pedersen_prover_respond(chaum_pedersen_prover_t *cp, uint64_t challenge) {
    if (!cp) return 0;
    uint64_t c_mod = challenge % cp->gp->q;
    return mod_add(cp->r, mod_mul(c_mod, cp->x, cp->gp->q), cp->gp->q);
}
int chaum_pedersen_verify(uint64_t a1, uint64_t a2, uint64_t c, uint64_t s,
                           uint64_t A, uint64_t B, const group_params_t *gp) {
    if (!gp) return 0;
    uint64_t gs = mod_pow(gp->g, s, gp->p);
    uint64_t hs = mod_pow(gp->h, s, gp->p);
    return (gs == mod_mul(a1, mod_pow(A, c, gp->p), gp->p) &&
            hs == mod_mul(a2, mod_pow(B, c, gp->p), gp->p)) ? 1 : 0;
}

/* Guillou-Quisquater protocol implementations */
void gq_prover_init(gq_prover_t *gq, uint64_t x, uint64_t y, uint64_t N, uint64_t e) {
    if (!gq) return;
    gq->N = N; gq->e = e; gq->x = x; gq->y = y; gq->r = 0; gq->a = 0;
}
uint64_t gq_prover_commit(gq_prover_t *gq, const random_tape_t *rng) {
    if (!gq || !rng) return 0;
    gq->r = 1 + pull_random_mod_q((random_tape_t *)rng, gq->N - 1);
    gq->a = mod_pow(gq->r, gq->e, gq->N);
    return gq->a;
}
uint64_t gq_prover_respond(gq_prover_t *gq, uint64_t challenge) {
    if (!gq) return 0;
    return mod_mul(gq->r, mod_pow(gq->x, challenge, gq->N), gq->N);
}
int gq_verify(uint64_t a, uint64_t c, uint64_t s, uint64_t y, uint64_t N, uint64_t e) {
    if (N == 0) return 0;
    /* Verification: s^e * y^c == a mod N */
    uint64_t se = mod_pow(s, e, N);
    uint64_t yc = mod_pow(y, c, N);
    uint64_t lhs = mod_mul(se, yc, N);
    return (lhs == a) ? 1 : 0;
}
