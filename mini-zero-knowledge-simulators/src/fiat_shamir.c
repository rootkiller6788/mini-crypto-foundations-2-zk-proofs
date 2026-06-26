#include "fiat_shamir.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

/* fiat_shamir.c -- Fiat-Shamir transform: interactive to non-interactive ZK */

/* Simple didactic hash function (Merkle-Damgard-like) */

void hash_init(hash_state_t *hs, uint64_t seed) {
    if (!hs) return;
    for (int i = 0; i < 8; i++)
        hs->state[i] = seed + (uint64_t)(i * 0x9E3779B97F4A7C15ULL);
    memset(hs->buffer, 0, HASH_BLOCK_BYTES);
    hs->buffer_len = 0; hs->total_bits = 0;
}

static void hash_compress(hash_state_t *hs) {
    uint64_t w[8];
    memcpy(w, hs->state, sizeof(w));
    for (int round = 0; round < 16; round++) {
        for (int i = 0; i < 8; i++) {
            w[i] = w[i] ^ (w[(i+1)%8] + w[(i+3)%8]);
            w[i] = (w[i] << 7) | (w[i] >> 57);
        }
    }
    for (int i = 0; i < 8; i++)
        hs->state[i] ^= w[i];
}

void hash_update(hash_state_t *hs, const uint8_t *data, size_t len) {
    if (!hs || !data) return;
    hs->total_bits += len * 8;
    for (size_t i = 0; i < len; i++) {
        hs->buffer[hs->buffer_len++] = data[i];
        if (hs->buffer_len == HASH_BLOCK_BYTES) {
            hash_compress(hs);
            hs->buffer_len = 0;
        }
    }
}

void hash_update_u64(hash_state_t *hs, uint64_t val) {
    uint8_t buf[8];
    for (int i = 0; i < 8; i++) buf[i] = (uint8_t)(val >> (8*i));
    hash_update(hs, buf, 8);
}

void hash_finalize(hash_state_t *hs, hash_digest_t *out) {
    if (!hs || !out) return;
    hs->buffer[hs->buffer_len++] = 0x80;
    if (hs->buffer_len > HASH_BLOCK_BYTES - 8) {
        while (hs->buffer_len < HASH_BLOCK_BYTES)
            hs->buffer[hs->buffer_len++] = 0;
        hash_compress(hs); hs->buffer_len = 0;
    }
    while (hs->buffer_len < HASH_BLOCK_BYTES - 8)
        hs->buffer[hs->buffer_len++] = 0;
    for (int i = 0; i < 8; i++)
        hs->buffer[HASH_BLOCK_BYTES-8+i]=(uint8_t)(hs->total_bits>>(8*i));
    hash_compress(hs);
    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 8; j++)
            out->digest[i*4+j]=(uint8_t)(hs->state[i]>>(8*j));
}

uint64_t hash_to_mod_q(const hash_digest_t *d, uint64_t q) {
    if (!d || q == 0) return 0;
    uint64_t val = 0;
    for (int i = 0; i < 8 && i < HASH_OUTPUT_BYTES; i++)
        val = (val << 8) | d->digest[i];
    return val % q;
}

/* Schnorr NIZK via Fiat-Shamir */

int schnorr_nizk_prove(uint64_t x, uint64_t y,
    const group_params_t *gp, const random_tape_t *rng,
    const uint8_t *context, size_t ctx_len,
    schnorr_nizk_proof_t *out) {
    if (!gp || !rng || !out) return -1;
    uint64_t r = pull_random_mod_q((random_tape_t *)rng, gp->q);
    uint64_t a = mod_pow(gp->g, r, gp->p);
    hash_state_t hs; hash_init(&hs, 0);
    hash_update_u64(&hs, a); hash_update_u64(&hs, y);
    hash_update_u64(&hs, gp->p);
    if (context) hash_update(&hs, context, ctx_len);
    hash_digest_t d; hash_finalize(&hs, &d);
    uint64_t e = hash_to_mod_q(&d, gp->q);
    uint64_t s = mod_add(r, mod_mul(e, x, gp->q), gp->q);
    out->a = a; out->s = s;
    return 0;
}

int schnorr_nizk_verify(const schnorr_nizk_proof_t *proof,
    uint64_t y, const group_params_t *gp,
    const uint8_t *context, size_t ctx_len) {
    if (!proof || !gp) return 0;
    hash_state_t hs; hash_init(&hs, 0);
    hash_update_u64(&hs, proof->a); hash_update_u64(&hs, y);
    hash_update_u64(&hs, gp->p);
    if (context) hash_update(&hs, context, ctx_len);
    hash_digest_t d; hash_finalize(&hs, &d);
    uint64_t e = hash_to_mod_q(&d, gp->q);
    return schnorr_verify(proof->a, e, proof->s, y, gp);
}

/* OR-NIZK via Fiat-Shamir */

int or_nizk_prove(int real_side, uint64_t x, uint64_t y1, uint64_t y2,
    const group_params_t *gp, const random_tape_t *rng,
    const uint8_t *context, size_t ctx_len, or_nizk_proof_t *out) {
    if (!gp || !rng || !out) return -1;
    uint64_t a1, a2, c1, c2, s1, s2;
    if (real_side == 1) {
        uint64_t r1 = pull_random_mod_q((random_tape_t *)rng, gp->q);
        a1 = mod_pow(gp->g, r1, gp->p);
        c2 = pull_random_mod_q((random_tape_t *)rng, gp->q);
        s2 = pull_random_mod_q((random_tape_t *)rng, gp->q);
        uint64_t inv = mod_pow(y2, ((c2 % gp->q) == 0 ? 0 : gp->q - (c2 % gp->q)), gp->p);
        a2 = mod_mul(mod_pow(gp->g, s2, gp->p), inv, gp->p);
        hash_state_t hs; hash_init(&hs, 0);
        hash_update_u64(&hs, a1); hash_update_u64(&hs, a2);
        hash_update_u64(&hs, y1); hash_update_u64(&hs, y2);
        if (context) hash_update(&hs, context, ctx_len);
        hash_digest_t d; hash_finalize(&hs, &d);
        uint64_t e = hash_to_mod_q(&d, gp->q);
        c1 = (e >= c2) ? ((e - c2) % gp->q) : (gp->q - ((c2 - e) % gp->q));
        s1 = mod_add(r1, mod_mul(c1, x, gp->q), gp->q);
    } else {
        uint64_t r2 = pull_random_mod_q((random_tape_t *)rng, gp->q);
        a2 = mod_pow(gp->g, r2, gp->p);
        c1 = pull_random_mod_q((random_tape_t *)rng, gp->q);
        s1 = pull_random_mod_q((random_tape_t *)rng, gp->q);
        uint64_t inv = mod_pow(y1, ((c1 % gp->q) == 0 ? 0 : gp->q - (c1 % gp->q)), gp->p);
        a1 = mod_mul(mod_pow(gp->g, s1, gp->p), inv, gp->p);
        hash_state_t hs; hash_init(&hs, 0);
        hash_update_u64(&hs, a1); hash_update_u64(&hs, a2);
        hash_update_u64(&hs, y1); hash_update_u64(&hs, y2);
        if (context) hash_update(&hs, context, ctx_len);
        hash_digest_t d; hash_finalize(&hs, &d);
        uint64_t e = hash_to_mod_q(&d, gp->q);
        c2 = (e >= c1) ? ((e - c1) % gp->q) : (gp->q - ((c1 - e) % gp->q));
        s2 = mod_add(r2, mod_mul(c2, x, gp->q), gp->q);
    }
    out->a1=a1;out->c1=c1;out->s1=s1;
    out->a2=a2;out->c2=c2;out->s2=s2;
    return 0;
}

int or_nizk_verify(const or_nizk_proof_t *proof,
    uint64_t y1, uint64_t y2, const group_params_t *gp,
    const uint8_t *context, size_t ctx_len) {
    if (!proof || !gp) return 0;
    hash_state_t hs; hash_init(&hs, 0);
    hash_update_u64(&hs, proof->a1); hash_update_u64(&hs, proof->a2);
    hash_update_u64(&hs, y1); hash_update_u64(&hs, y2);
    if (context) hash_update(&hs, context, ctx_len);
    hash_digest_t d; hash_finalize(&hs, &d);
    uint64_t e = hash_to_mod_q(&d, gp->q);
    int ok1 = schnorr_verify(proof->a1, proof->c1, proof->s1, y1, gp);
    int ok2 = schnorr_verify(proof->a2, proof->c2, proof->s2, y2, gp);
    int xor_ok = (((proof->c1 + proof->c2) % gp->q) == (e % gp->q)) ? 1 : 0;
    return (ok1 && ok2 && xor_ok) ? 1 : 0;
}

/* CRS (Common Reference String) setup */
void crs_setup(crs_t *crs, const random_tape_t *rng) {
    if(!crs||!rng)return;
    crs->gp.p=23;crs->gp.g=2;crs->gp.q=11;crs->gp.h=8;
    crs->trapdoor=0;
    hash_state_t hs;hash_init(&hs,next_random_u64((random_tape_t*)rng));
    hash_finalize(&hs,(hash_digest_t*)crs->crs_hash);
}
void crs_setup_with_trapdoor(crs_t *crs, uint64_t trapdoor) {
    if(!crs)return;
    crs->gp.p=23;crs->gp.g=2;crs->gp.q=11;crs->gp.h=8;
    crs->trapdoor=trapdoor;
    memset(crs->crs_hash,0,HASH_OUTPUT_BYTES);
}

/* Forking Lemma demonstration */
int forking_lemma_extract(
    schnorr_nizk_proof_t (*adversary)(uint64_t,const group_params_t*,
        const random_tape_t*),
    uint64_t y, const group_params_t *gp, uint64_t *witness_out) {
    if(!adversary||!gp||!witness_out)return -1;
    random_tape_t rng1,rng2;
    init_random_tape(&rng1,12345);
    init_random_tape(&rng2,54321);
    schnorr_nizk_proof_t p1=adversary(y,gp,&rng1);
    schnorr_nizk_proof_t p2=adversary(y,gp,&rng2);
    if(p1.a==p2.a){
        hash_state_t hs;hash_init(&hs,0);
        hash_update_u64(&hs,p1.a);hash_update_u64(&hs,y);
        hash_update_u64(&hs,gp->p);
        hash_digest_t d1,d2;hash_finalize(&hs,&d1);
        hash_init(&hs,0);
        hash_update_u64(&hs,p2.a);hash_update_u64(&hs,y);
        hash_update_u64(&hs,gp->p);
        hash_finalize(&hs,&d2);
        uint64_t e1=hash_to_mod_q(&d1,gp->q);
        uint64_t e2=hash_to_mod_q(&d2,gp->q);
        if(e1!=e2)
            return schnorr_extract_witness(p1.a,e1,p1.s,e2,p2.s,gp,witness_out);
    }
    return -1;
}

/* Self-test */
int fiat_shamir_self_test(void) {
    group_params_t gp={23,2,11,8};
    uint64_t x=4,y=mod_pow(2,4,23);
    random_tape_t rng;init_random_tape(&rng,3333);
    uint8_t ctx[4]={1,2,3,4};
    schnorr_nizk_proof_t proof;
    int ret=schnorr_nizk_prove(x,y,&gp,&rng,ctx,4,&proof);
    assert(ret==0);
    assert(schnorr_nizk_verify(&proof,y,&gp,ctx,4)==1);
    or_nizk_proof_t or_proof;
    uint64_t y2=mod_pow(2,7,23);
    ret=or_nizk_prove(1,x,y,y2,&gp,&rng,ctx,4,&or_proof);
    assert(ret==0);
    assert(or_nizk_verify(&or_proof,y,y2,&gp,ctx,4)==1);
    crs_t crs;
    crs_setup(&crs,&rng);
    assert(crs.gp.p==23);
    crs_setup_with_trapdoor(&crs,3);
    assert(crs.trapdoor==3);
    return 0;
}
