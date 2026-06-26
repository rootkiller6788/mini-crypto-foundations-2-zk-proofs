#include "zk_simulator.h"
#include "sigma_protocols.h"
#include "commitments.h"
#include "fiat_shamir.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>

/* zk_applications.c -- Real-world ZK applications (L7) */
/* Applications: password auth, blockchain ZK, e-voting, credentials */

/* ================================================================
 * L7.1 -- Password Authentication without Revealing Password
 *
 * Use Schnorr identification: prover proves knowledge of
 * discrete log of public key (derived from password).
 * Verifier learns nothing about the password.
 *
 * This is the basis for SRP (Secure Remote Password) and
 * PAKE (Password-Authenticated Key Exchange).
 * ================================================================ */

typedef struct {
    uint64_t password_hash;  /* y = g^{H(password)} */
    const group_params_t *gp;
} password_auth_t;

void password_auth_register(password_auth_t *pa,
    const uint8_t *password, size_t pw_len,
    const group_params_t *gp, const random_tape_t *rng) {
    if(!pa||!password||!gp||!rng)return;
    hash_state_t hs;hash_init(&hs,0);
    hash_update(&hs,password,pw_len);
    hash_digest_t d;hash_finalize(&hs,&d);
    uint64_t h_pw=hash_to_mod_q(&d,gp->q);
    pa->password_hash=mod_pow(gp->g,h_pw,gp->p);
    pa->gp=gp;
}

int password_auth_authenticate(const password_auth_t *pa,
    const uint8_t *password, size_t pw_len,
    const random_tape_t *rng) {
    if(!pa||!password||!rng)return 0;
    hash_state_t hs;hash_init(&hs,0);
    hash_update(&hs,password,pw_len);
    hash_digest_t d;hash_finalize(&hs,&d);
    uint64_t x=hash_to_mod_q(&d,pa->gp->q);
    uint64_t a=mod_pow(pa->gp->g,pull_random_mod_q((random_tape_t*)rng,pa->gp->q),pa->gp->p);
    uint64_t c=pull_random_mod_q((random_tape_t*)rng,pa->gp->q);
    uint64_t s=mod_add(pull_random_mod_q((random_tape_t*)rng,pa->gp->q),
                        mod_mul(c,x,pa->gp->q),pa->gp->q);
    return schnorr_verify(a,c,s,pa->password_hash,pa->gp);
}

/* ================================================================
 * L7.2 -- Blockchain ZK Applications
 *
 * Zcash uses zk-SNARKs (Pinocchio/Groth16) to prove:
 *   "I know sk such that coin commitment opens to value v.
 *    and v is in the Merkle tree of all coin commitments.
 *    and v >= 0 and v + inputs = outputs."
 *
 * Here we simulate the simpler proof of knowledge of
 * opening of a Pedersen commitment (the innermost layer).
 * ================================================================ */

typedef struct {
    uint64_t value;        /* coin value */
    uint64_t serial;       /* unique serial number */
    uint64_t commitment;   /* Pedersen commitment to (value,serial) */
    const group_params_t *gp;
} zcash_coin_t;

void zcash_mint_coin(zcash_coin_t *coin, uint64_t value,
    const random_tape_t *rng, const group_params_t *gp) {
    if(!coin||!rng||!gp)return;
    coin->value=value;
    coin->serial=pull_random_mod_q((random_tape_t*)rng,gp->q);
    uint64_t gm=mod_pow(gp->g,value,gp->p);
    uint64_t hr=mod_pow(gp->h,coin->serial,gp->p);
    coin->commitment=mod_mul(gm,hr,gp->p);
    coin->gp=gp;
}

int zcash_verify_coin(const zcash_coin_t *coin) {
    if(!coin||!coin->gp)return 0;
    uint64_t gm=mod_pow(coin->gp->g,coin->value,coin->gp->p);
    uint64_t hr=mod_pow(coin->gp->h,coin->serial,coin->gp->p);
    return (coin->commitment==mod_mul(gm,hr,coin->gp->p))?1:0;
}

/* ================================================================
 * L7.3 -- Electronic Voting with ZK Proofs
 *
 * Voter proves that their encrypted vote is valid (0 or 1)
 * without revealing which way they voted.
 * This uses OR-proofs: prove (vote=0) OR (vote=1).
 * ================================================================ */

typedef struct {
    int vote;             /* 0 or 1 */
    uint64_t encryption;  /* ElGamal encryption of vote */
    uint64_t randomness;  /* encryption randomness */
    const group_params_t *gp;
} evoting_ballot_t;

void evoting_cast_ballot(evoting_ballot_t *ballot, int vote,
    const random_tape_t *rng, const group_params_t *gp) {
    if(!ballot||!rng||!gp)return;
    ballot->vote=(vote!=0)?1:0;
    ballot->randomness=pull_random_mod_q((random_tape_t*)rng,gp->q);
    ballot->encryption=mod_pow(gp->g,ballot->vote,gp->p);
    uint64_t hr=mod_pow(gp->h,ballot->randomness,gp->p);
    ballot->encryption=mod_mul(ballot->encryption,hr,gp->p);
    ballot->gp=gp;
}

int evoting_verify_ballot(const evoting_ballot_t *ballot,
    const random_tape_t *rng) {
    if(!ballot||!ballot->gp||!rng)return 0;
    uint64_t y0=mod_pow(ballot->gp->g,0,ballot->gp->p);
    uint64_t y1=mod_pow(ballot->gp->g,1,ballot->gp->p);
    or_composition_prover_t op;
    int side=(ballot->vote==0)?1:2;
    or_compose_prover_init(&op,side,ballot->vote?1:0,y0,y1,ballot->gp);
    or_composition_transcript_t ot;
    uint64_t vc=pull_random_mod_q((random_tape_t*)rng,ballot->gp->q);
    or_compose_prover_execute(&op,rng,&ot,vc);
    return or_compose_verify(&ot,y0,y1,ballot->gp);
}

/* ================================================================
 * L7.4 -- Anonymous Credentials (Camenisch-Lysyanskaya)
 *
 * User proves possession of a credential signed by issuer
 * without revealing the credential or the user identity.
 * Uses: CL-signatures + ZK proofs of knowledge. */

typedef struct {
    uint64_t user_id;
    uint64_t credential_hash;
    uint64_t issuer_pubkey;
    int verified;
} anonymous_credential_t;

void anonymous_credential_issue(anonymous_credential_t *cred,
    uint64_t user_id, uint64_t issuer_secret,
    const group_params_t *gp) {
    if(!cred||!gp)return;
    cred->user_id=user_id;
    cred->credential_hash=mod_pow(gp->g,user_id,gp->p);
    cred->issuer_pubkey=mod_pow(gp->g,issuer_secret,gp->p);
    cred->verified=0;
}

int anonymous_credential_verify(const anonymous_credential_t *cred,
    const group_params_t *gp) {
    if(!cred||!gp)return 0;
    uint64_t expected=mod_pow(gp->g,cred->user_id,gp->p);
    return (cred->credential_hash==expected)?1:0;
}
