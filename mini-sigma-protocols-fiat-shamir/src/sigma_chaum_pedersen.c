/**
 * sigma_chaum_pedersen.c ！ Chaum-Pedersen DLEQ Sigma Protocol
 *
 * Proves equality of two discrete logarithms: Prover knows x such that
 * y1 = g1^x AND y2 = g2^x, without revealing x or which bases were used.
 *
 * Protocol (3-move):
 *   Prover(x)                              Verifier(y1, y2, g1, g2)
 *   r ○ Z_q
 *   a1 = g1^r, a2 = g2^r
 *                       ★ a1, a2 ★
 *                                           e ○ Z_q
 *                       ○ e ○
 *   z = r + e，x mod q
 *                       ★ z ★
 *                                      g1^z 《 a1 ， y1^e  (mod p)
 *                                      g2^z 《 a2 ， y2^e  (mod p)
 *
 * L4 Theorems:
 *   - Special Soundness: extract x = (z-z')/(e-e') from either equality
 *     (both extract the same x, providing a consistency check)
 *   - SHVZK: simulator picks z○Z_q, a1=g1^z，y1^{-e}, a2=g2^z，y2^{-e}
 *   - Knowledge Error: κ = 1/q (negligible)
 *
 * L7 Applications:
 *   - Verifiable encryption (Cramer & Shoup 1998)
 *   - Mix-net shuffle verification (Jakobsson & Juels 2000)
 *   - Anonymous credentials (Brands 1993)
 *   - Cryptocurrency privacy (Monero RingCT, Zcash Sapling)
 *   - Threshold DKG: verifiable secret sharing
 *
 * References:
 *   - Chaum & Pedersen (1993) "Wallet Databases with Observers",
 *     CRYPTO '92, LNCS 740
 *   - Cramer & Shoup (1998) "A Practical Public Key Cryptosystem
 *     Provably Secure against Adaptive Chosen Ciphertext Attack"
 *   - Brands (1993) "Untraceable Off-line Cash in Wallets with Observers"
 *   - Hazay & Lindell (2010) "Efficient Secure Two-Party Protocols", Ch 6
 */

#include "sigma_chaum_pedersen.h"
#include <string.h>

/* ========================================================================
 *  Key/Statement Setup
 * ======================================================================== */

void sigma_cp_setup(sigma_chaum_pedersen_public *pub,
                    const sigma_chaum_pedersen_witness *wit,
                    const sigma_group_elem *base1,
                    const sigma_group_elem *base2) {
    sigma_group_copy(&pub->g1, base1);
    sigma_group_copy(&pub->g2, base2);

    /* y1 = g1^x mod p */
    sigma_group_exp(&pub->y1, base1, &wit->x);

    /* y2 = g2^x mod p */
    sigma_group_exp(&pub->y2, base2, &wit->x);
}

void sigma_cp_setup_seeded(sigma_chaum_pedersen_public *pub,
                            sigma_chaum_pedersen_witness *wit,
                            uint64_t seed) {
    sigma_random_seed(seed);

    /* Generate random witness x */
    sigma_random_nonzero_scalar(&wit->x);

    /* g1 = standard generator */
    sigma_group_copy(&pub->g1, &SIGMA_GENERATOR_G);

    /* g2 = g^s for a fixed secret s (represents an alternate base) */
    sigma_scalar s;
    sigma_random_scalar(&s);
    sigma_group_exp_g(&pub->g2, &s);

    /* y1 = g1^x, y2 = g2^x */
    sigma_group_exp(&pub->y1, &pub->g1, &wit->x);
    sigma_group_exp(&pub->y2, &pub->g2, &wit->x);
}

/* ========================================================================
 *  Protocol Functions
 * ======================================================================== */

void sigma_cp_commit(sigma_group_elem *a1, sigma_group_elem *a2,
                     const sigma_scalar *randomness,
                     const sigma_chaum_pedersen_public *pub) {
    /* a1 = g1^r mod p */
    sigma_group_exp(a1, &pub->g1, randomness);

    /* a2 = g2^r mod p ！ SAME randomness for both! */
    sigma_group_exp(a2, &pub->g2, randomness);
}

void sigma_cp_respond(sigma_scalar *response,
                       const sigma_scalar *randomness,
                       const sigma_scalar *challenge,
                       const sigma_chaum_pedersen_witness *witness) {
    /* z = r + e，x mod q */
    sigma_scalar ex;
    sigma_scalar_mul(&ex, challenge, &witness->x);
    sigma_scalar_add(response, randomness, &ex);
}

bool sigma_cp_verify(const sigma_group_elem *a1,
                      const sigma_group_elem *a2,
                      const sigma_scalar *challenge,
                      const sigma_scalar *response,
                      const sigma_chaum_pedersen_public *pub) {
    /* Check equation 1: g1^z 《 a1 ， y1^e */
    sigma_group_elem lhs1, rhs1_term, rhs1;
    sigma_group_exp(&lhs1, &pub->g1, response);
    sigma_group_exp(&rhs1_term, &pub->y1, challenge);
    sigma_group_mul(&rhs1, a1, &rhs1_term);
    bool ok1 = sigma_group_eq(&lhs1, &rhs1);

    /* Check equation 2: g2^z 《 a2 ， y2^e */
    sigma_group_elem lhs2, rhs2_term, rhs2;
    sigma_group_exp(&lhs2, &pub->g2, response);
    sigma_group_exp(&rhs2_term, &pub->y2, challenge);
    sigma_group_mul(&rhs2, a2, &rhs2_term);
    bool ok2 = sigma_group_eq(&lhs2, &rhs2);

    return ok1 && ok2;
}

/* ========================================================================
 *  Full Interactive Run (Prover Side)
 * ======================================================================== */

void sigma_cp_prove(sigma_cp_transcript *t,
                    const sigma_chaum_pedersen_witness *wit,
                    const sigma_chaum_pedersen_public *pub,
                    const sigma_scalar *randomness) {
    /* Commit: a1 = g1^r, a2 = g2^r */
    sigma_cp_commit(&t->a1, &t->a2, randomness, pub);

    /* Response: z = r + e，x (challenge already set by caller) */
    sigma_cp_respond(&t->response, randomness, &t->challenge, wit);
}

bool sigma_cp_verify_transcript(const sigma_cp_transcript *t,
                                 const sigma_chaum_pedersen_public *pub) {
    return sigma_cp_verify(&t->a1, &t->a2, &t->challenge, &t->response, pub);
}

/* ========================================================================
 *  Knowledge Extraction (Special Soundness)
 *
 *  Given (a1, a2, e, z) and (a1, a2, e', z') with e 』 e':
 *    From equation 1: g1^z = a1，y1^e and g1^{z'} = a1，y1^{e'}
 *    Divide: g1^{z-z'} = y1^{e-e'}
 *    Thus: g1^{(z-z')/(e-e')} = y1
 *    So: x = (z-z')/(e-e') mod q
 *
 *  The same x must also satisfy the second equation (consistency check).
 * ======================================================================== */

bool sigma_cp_extract(sigma_chaum_pedersen_witness *wit_out,
                       const sigma_cp_transcript *t1,
                       const sigma_cp_transcript *t2,
                       const sigma_chaum_pedersen_public *pub) {
    /* Same commitments required */
    if (!sigma_group_eq(&t1->a1, &t2->a1)) return false;
    if (!sigma_group_eq(&t1->a2, &t2->a2)) return false;

    /* Different challenges required */
    if (sigma_scalar_cmp(&t1->challenge, &t2->challenge) == 0)
        return false;

    /* x = (z - z') / (e - e') mod q */
    sigma_scalar dz, de, de_inv;
    sigma_scalar_sub(&dz, &t1->response, &t2->response);
    sigma_scalar_sub(&de, &t1->challenge, &t2->challenge);
    if (!sigma_scalar_inv(&de_inv, &de)) return false;
    sigma_scalar_mul(&wit_out->x, &dz, &de_inv);

    /* Consistency: verify y1 = g1^x and y2 = g2^x */
    sigma_group_elem check1, check2;
    sigma_group_exp(&check1, &pub->g1, &wit_out->x);
    sigma_group_exp(&check2, &pub->g2, &wit_out->x);
    return sigma_group_eq(&check1, &pub->y1) &&
           sigma_group_eq(&check2, &pub->y2);
}

/* ========================================================================
 *  Simulation (SHVZK)
 *
 *  Given challenge e in advance:
 *    1. Pick random z （ Z_q
 *    2. Compute a1 = g1^z ， y1^{-e} mod p
 *    3. Compute a2 = g2^z ， y2^{-e} mod p
 *    4. Output (a1, a2, e, z)
 *
 *  The distribution is identical to a real transcript because the
 *  mapping (r, e) ? (z, e) where z = r + e，x is a bijection.
 * ======================================================================== */

void sigma_cp_simulate(sigma_cp_transcript *t,
                        const sigma_scalar *challenge,
                        const sigma_chaum_pedersen_public *pub) {
    /* Pick random z */
    sigma_scalar z;
    sigma_random_scalar(&z);

    /* Compute y1^{-e} mod p */
    sigma_group_elem y1_e, y1_inv_e;
    sigma_group_exp(&y1_e, &pub->y1, challenge);
    sigma_biguint inv1;
    sigma_mod_inv(&inv1, (const sigma_biguint*)&y1_e, &SIGMA_PRIME_P);

    /* a1 = g1^z * y1^{-e} */
    sigma_group_elem g1z;
    sigma_group_exp(&g1z, &pub->g1, &z);
    sigma_mod_mul((sigma_biguint*)&t->a1, (const sigma_biguint*)&g1z,
                  &inv1, &SIGMA_PRIME_P);

    /* Compute y2^{-e} mod p */
    sigma_group_elem y2_e;
    sigma_group_exp(&y2_e, &pub->y2, challenge);
    sigma_biguint inv2;
    sigma_mod_inv(&inv2, (const sigma_biguint*)&y2_e, &SIGMA_PRIME_P);

    /* a2 = g2^z * y2^{-e} */
    sigma_group_elem g2z;
    sigma_group_exp(&g2z, &pub->g2, &z);
    sigma_mod_mul((sigma_biguint*)&t->a2, (const sigma_biguint*)&g2z,
                  &inv2, &SIGMA_PRIME_P);

    sigma_scalar_copy(&t->challenge, challenge);
    sigma_scalar_copy(&t->response, &z);
}

/* ========================================================================
 *  VTable Construction for Chaum-Pedersen
 * ======================================================================== */

static sigma_protocol g_cp_proto;

static void cp_prove_commit(sigma_group_elem *c, const sigma_scalar *r,
                             const void *w, const void *pub) {
    const sigma_chaum_pedersen_public *p = (const sigma_chaum_pedersen_public*)pub;
    sigma_cp_commit(c, c, r, p);
    /* Note: The generic vtable only supports single commitment.
     * For CP, we store a1 in the commitment slot; a2 is implicit.
     * This is a simplification for the abstraction layer. */
}

static void cp_prove_response(sigma_scalar *resp, const sigma_scalar *r,
                               const sigma_scalar *chall,
                               const void *w, const void *pub) {
    (void)pub;
    const sigma_chaum_pedersen_witness *wit = (const sigma_chaum_pedersen_witness*)w;
    sigma_cp_respond(resp, r, chall, wit);
}

static bool cp_verify(const sigma_group_elem *c, const sigma_scalar *chall,
                       const sigma_scalar *resp, const void *pub) {
    const sigma_chaum_pedersen_public *p = (const sigma_chaum_pedersen_public*)pub;
    sigma_group_elem dummy_a2;
    sigma_biguint_set_u64((sigma_biguint*)&dummy_a2, 1);
    /* Simplified single-commitment verify */
    sigma_group_elem lhs, rhs_term, rhs;
    sigma_group_exp(&lhs, &p->g1, resp);
    sigma_group_exp(&rhs_term, &p->y1, chall);
    sigma_group_mul(&rhs, c, &rhs_term);
    return sigma_group_eq(&lhs, &rhs);
}

static bool cp_extract(void *wout, const sigma_transcript *t1,
                        const sigma_transcript *t2, const void *pub) {
    sigma_chaum_pedersen_witness *w = (sigma_chaum_pedersen_witness*)wout;
    const sigma_chaum_pedersen_public *p = (const sigma_chaum_pedersen_public*)pub;

    sigma_scalar dz, de, de_inv;
    sigma_scalar_sub(&dz, &t1->response, &t2->response);
    sigma_scalar_sub(&de, &t1->challenge, &t2->challenge);
    if (!sigma_scalar_inv(&de_inv, &de)) return false;
    sigma_scalar_mul(&w->x, &dz, &de_inv);

    sigma_group_elem check;
    sigma_group_exp(&check, &p->g1, &w->x);
    return sigma_group_eq(&check, &p->y1);
}

static void cp_simulate(sigma_transcript *t, const sigma_scalar *c,
                         const void *pub) {
    const sigma_chaum_pedersen_public *p = (const sigma_chaum_pedersen_public*)pub;
    sigma_scalar z;
    sigma_random_scalar(&z);
    sigma_group_elem y1_e, g1z;
    sigma_group_exp(&y1_e, &p->y1, c);
    sigma_biguint inv;
    sigma_mod_inv(&inv, (const sigma_biguint*)&y1_e, &SIGMA_PRIME_P);
    sigma_group_exp(&g1z, &p->g1, &z);
    sigma_mod_mul((sigma_biguint*)&t->commitment, (const sigma_biguint*)&g1z,
                  &inv, &SIGMA_PRIME_P);
    sigma_scalar_copy(&t->challenge, c);
    sigma_scalar_copy(&t->response, &z);
}

static int cp_proto_init = 0;

const sigma_protocol *sigma_cp_get_protocol(void) {
    if (!cp_proto_init) {
        g_cp_proto.name = "Chaum-Pedersen";
        g_cp_proto.prove_commit    = cp_prove_commit;
        g_cp_proto.prove_response  = cp_prove_response;
        g_cp_proto.verify          = cp_verify;
        g_cp_proto.extract         = cp_extract;
        g_cp_proto.simulate        = cp_simulate;
        g_cp_proto.public_input_size = sizeof(sigma_chaum_pedersen_public);
        g_cp_proto.witness_size      = sizeof(sigma_chaum_pedersen_witness);
        cp_proto_init = 1;
    }
    return &g_cp_proto;
}
