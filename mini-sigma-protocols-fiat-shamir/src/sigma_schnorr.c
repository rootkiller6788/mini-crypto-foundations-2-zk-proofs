/**
 * sigma_schnorr.c ！ Schnorr Sigma Protocol Implementation
 *
 * Implements the canonical 3-move sigma protocol for proving knowledge
 * of a discrete logarithm: Prover knows x such that y = g^x (mod p).
 *
 * L1 Definitions:
 *   - Schnorr Protocol: Prove knowledge of dlog x for public key y = g^x
 *   - (a, e, z) transcript format: commitment, challenge, response
 *
 * L4 Theorems:
 *   - Special Soundness: from (a,e,z) and (a,e',z'), extract x = (z-z')/(e-e')
 *   - SHVZK: simulated transcript (g^z * y^{-e}, e, z) is identically distributed
 *   - Knowledge Error: κ = 1/q (negligible for 256-bit q)
 *
 * L5 Algorithms:
 *   - Schnorr key generation: x ○ Z_q^*, y = g^x mod p
 *   - Commitment: a = g^r for random r
 *   - Response: z = r + e，x (mod q)
 *   - Verification: g^z 《 a ， y^e (mod p)
 *   - Extraction: x = (z - z') ， (e - e')^{-1} mod q
 *   - Simulation: pick z ○ Z_q, compute a = g^z ， y^{-e}
 *
 * References:
 *   - Schnorr (1991) "Efficient Signature Generation by Smart Cards",
 *     Journal of Cryptology 4(3):161-174
 *   - Goldreich (2004) Foundations of Cryptography I, ′4.7.2
 *   - Katz & Lindell (2014) Introduction to Modern Cryptography, ′13.3
 */

#include "sigma_schnorr.h"
#include <string.h>
#include <stdio.h>

/* ========================================================================
 *  Key Generation
 * ======================================================================== */

void sigma_schnorr_keygen(sigma_schnorr_witness *sk,
                          sigma_schnorr_public  *pk) {
    /* sk = random non-zero scalar in Z_q^* */
    sigma_random_nonzero_scalar(&sk->x);

    /* pk.y = g^{sk.x} mod p */
    sigma_group_exp_g(&pk->y, &sk->x);

    /* pk.generator = standard generator g */
    sigma_group_copy(&pk->generator, &SIGMA_GENERATOR_G);
}

void sigma_schnorr_keygen_seeded(sigma_schnorr_witness *sk,
                                 sigma_schnorr_public  *pk,
                                 uint64_t seed) {
    sigma_random_seed(seed);
    sigma_schnorr_keygen(sk, pk);
}

/* ========================================================================
 *  Protocol: Commit ★ Challenge ★ Response ★ Verify
 * ======================================================================== */

void sigma_schnorr_commit(sigma_group_elem *commitment,
                          const sigma_scalar *randomness) {
    /* a = g^r mod p */
    sigma_group_exp_g(commitment, randomness);
}

void sigma_schnorr_respond(sigma_scalar *response,
                            const sigma_scalar *randomness,
                            const sigma_scalar *challenge,
                            const sigma_scalar *secret_key) {
    /* z = r + e，x mod q */
    sigma_scalar ex;
    sigma_scalar_mul(&ex, challenge, secret_key);
    sigma_scalar_add(response, randomness, &ex);
}

bool sigma_schnorr_verify(const sigma_group_elem *commitment,
                           const sigma_scalar *challenge,
                           const sigma_scalar *response,
                           const sigma_group_elem *public_key) {
    /* Check: g^z 《 a ， y^e (mod p) */
    sigma_group_elem lhs, rhs_term, rhs;

    /* lhs = g^z */
    sigma_group_exp_g(&lhs, response);

    /* rhs_term = y^e */
    sigma_group_exp(&rhs_term, public_key, challenge);

    /* rhs = a * rhs_term = a ， y^e */
    sigma_group_mul(&rhs, commitment, &rhs_term);

    return sigma_group_eq(&lhs, &rhs);
}

/* ========================================================================
 *  Knowledge Extraction (Special Soundness)
 * ======================================================================== */

bool sigma_schnorr_extract(sigma_scalar *witness_out,
                            const sigma_transcript *t1,
                            const sigma_transcript *t2,
                            const sigma_group_elem *public_key) {
    /* Must have same commitment a */
    if (!sigma_group_eq(&t1->commitment, &t2->commitment))
        return false;

    /* Must have different challenges e 』 e' */
    if (sigma_scalar_cmp(&t1->challenge, &t2->challenge) == 0)
        return false;

    /* x = (z - z') ， (e - e')^{-1} mod q */
    sigma_scalar dz, de, de_inv;

    /* dz = z - z' */
    sigma_scalar_sub(&dz, &t1->response, &t2->response);

    /* de = e - e' */
    sigma_scalar_sub(&de, &t1->challenge, &t2->challenge);

    /* de_inv = (e - e')^{-1} mod q */
    if (!sigma_scalar_inv(&de_inv, &de))
        return false;

    /* x = dz * de_inv mod q */
    sigma_scalar_mul(witness_out, &dz, &de_inv);

    /* Verify extracted witness: g^x 《 y (mod p) */
    sigma_group_elem check;
    sigma_group_exp_g(&check, witness_out);
    return sigma_group_eq(&check, public_key);
}

/* ========================================================================
 *  Simulation (Special Honest-Verifier Zero-Knowledge)
 * ======================================================================== */

void sigma_schnorr_simulate(sigma_transcript *transcript,
                             const sigma_scalar *challenge,
                             const sigma_group_elem *public_key) {
    sigma_scalar z;
    sigma_group_elem y_neg_e, a;

    /* Pick random z （ Z_q */
    sigma_random_scalar(&z);

    /* Compute y^{-e} mod p: first y^e, then invert */
    sigma_group_elem y_e;
    sigma_group_exp(&y_e, public_key, challenge);

    /* a = g^z ， y^{-e} mod p */
    sigma_group_div(&a, &y_e, &y_e); /* This is wrong ！ need proper inverse */
    /* Correct: a = g^z * y^{-e} mod p */
    {
        sigma_group_elem gz, y_inv_e;
        sigma_biguint inv;
        sigma_mod_inv(&inv, (const sigma_biguint*)&y_e, &SIGMA_PRIME_P);
        sigma_group_exp_g(&gz, &z);
        sigma_mod_mul((sigma_biguint*)&a, (const sigma_biguint*)&gz, &inv, &SIGMA_PRIME_P);
    }

    sigma_group_copy(&transcript->commitment, &a);
    sigma_scalar_copy(&transcript->challenge, challenge);
    sigma_scalar_copy(&transcript->response, &z);
}

/* ========================================================================
 *  Full Interactive Run
 * ======================================================================== */

void sigma_schnorr_prove(sigma_transcript *transcript,
                          const sigma_schnorr_witness *witness,
                          const sigma_schnorr_public *public_input,
                          const sigma_scalar *randomness) {
    /* Phase 1: commitment a = g^r */
    sigma_schnorr_commit(&transcript->commitment, randomness);

    /* Phase 2: verifier would send challenge e ... (caller provides) */
    /* transcript->challenge must be set by caller */

    /* Phase 3: response z = r + e，x */
    sigma_schnorr_respond(&transcript->response, randomness,
                           &transcript->challenge, &witness->x);
}

bool sigma_schnorr_verify_transcript(const sigma_transcript *t,
                                      const sigma_schnorr_public *pk) {
    /* Verify: g^z 《 a ， y^e */
    return sigma_schnorr_verify(&t->commitment, &t->challenge,
                                 &t->response, &pk->y);
}

/* ========================================================================
 *  VTable Construction
 * ======================================================================== */

/* Static vtable instance ！ thread-unsafe singleton for simplicity */
static sigma_protocol g_schnorr_proto;

/* Forward declarations of vtable adapters */
static void schnorr_prove_commit(sigma_group_elem *c, const sigma_scalar *r,
                                  const void *w, const void *pub) {
    (void)w;
    const sigma_schnorr_public *p = (const sigma_schnorr_public*)pub;
    sigma_schnorr_commit(c, r);
}

static void schnorr_prove_response(sigma_scalar *resp, const sigma_scalar *r,
                                    const sigma_scalar *chall,
                                    const void *w, const void *pub) {
    (void)pub;
    const sigma_schnorr_witness *wit = (const sigma_schnorr_witness*)w;
    sigma_schnorr_respond(resp, r, chall, &wit->x);
}

static bool schnorr_verify(const sigma_group_elem *c, const sigma_scalar *chall,
                            const sigma_scalar *resp, const void *pub) {
    const sigma_schnorr_public *p = (const sigma_schnorr_public*)pub;
    return sigma_schnorr_verify(c, chall, resp, &p->y);
}

static bool schnorr_extract(void *wout, const sigma_transcript *t1,
                             const sigma_transcript *t2, const void *pub) {
    sigma_schnorr_witness *w = (sigma_schnorr_witness*)wout;
    const sigma_schnorr_public *p = (const sigma_schnorr_public*)pub;
    return sigma_schnorr_extract(&w->x, t1, t2, &p->y);
}

static void schnorr_simulate(sigma_transcript *t, const sigma_scalar *c,
                              const void *pub) {
    const sigma_schnorr_public *p = (const sigma_schnorr_public*)pub;
    sigma_schnorr_simulate(t, c, &p->y);
}

static int proto_initialized = 0;

const sigma_protocol *sigma_schnorr_get_protocol(void) {
    if (!proto_initialized) {
        g_schnorr_proto.name = "Schnorr";
        g_schnorr_proto.prove_commit    = schnorr_prove_commit;
        g_schnorr_proto.prove_response  = schnorr_prove_response;
        g_schnorr_proto.verify          = schnorr_verify;
        g_schnorr_proto.extract         = schnorr_extract;
        g_schnorr_proto.simulate        = schnorr_simulate;
        g_schnorr_proto.public_input_size = sizeof(sigma_schnorr_public);
        g_schnorr_proto.witness_size      = sizeof(sigma_schnorr_witness);
        proto_initialized = 1;
    }
    return &g_schnorr_proto;
}
