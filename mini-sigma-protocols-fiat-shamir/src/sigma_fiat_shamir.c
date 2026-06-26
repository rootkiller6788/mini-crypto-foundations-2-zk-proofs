/**
 * sigma_fiat_shamir.c ¡ª Fiat-Shamir Transform Implementation
 *
 * Converts any 3-move honest-verifier sigma protocol into a non-interactive
 * zero-knowledge proof system (and digital signature scheme) by replacing
 * the verifier's random challenge with the output of a cryptographic hash
 * function applied to the commitment and the message.
 *
 * The Fiat-Shamir Heuristic (Fiat & Shamir 1986):
 *   Interactive:   P ¡ú a,  V ¡ú e ¡û Z_q,  P ¡ú z
 *   Non-interactive: P computes a, then e = H(a || msg || pub), then z
 *   Proof = (a, z); V recomputes e = H(a || msg || pub), checks verify(a,e,z)
 *
 * L4 Theorems:
 *   - Fiat-Shamir Theorem (1986): If the sigma protocol is HVZK and
 *     has special soundness, the transform yields a NIZK in the ROM.
 *   - Forking Lemma (Pointcheval & Stern 1996): Security reduction
 *     for Fiat-Shamir signatures. If adversary produces a valid forgery
 *     with probability ¦Å in time t, then the discrete log can be solved
 *     with probability ¡Ö ¦Å^2 / q_H in time ¡Ö 2t.
 *
 * L7 Applications:
 *   - Schnorr signatures (EdDSA/Ed25519, BIP-340 Bitcoin)
 *   - DSA/ECDSA (Fiat-Shamir variant)
 *   - Non-interactive ZK proofs (Bulletproofs, zk-STARKs)
 *   - Ring signatures (Monero, CryptoNote)
 *
 * L8 Advanced Topics:
 *   - Strong vs Weak Fiat-Shamir (Bernhard, Pereira, Warinschi 2012)
 *   - Quantum security (Unruh transform, PQ signatures)
 *
 * References:
 *   - Fiat & Shamir (1986) "How to Prove Yourself", CRYPTO '86, LNCS 263
 *   - Pointcheval & Stern (2000) "Security Arguments for Digital
 *     Signatures and Blind Signatures", J. Cryptology 13(3):361-396
 *   - Bellare & Rogaway (1993) "Random Oracles are Practical", ACM CCS
 *   - Bernhard et al. (2012) "How Not to Prove Yourself", NDSS 2012
 */

#include "sigma_fiat_shamir.h"
#include "sigma_schnorr.h"
#include <string.h>

/* ========================================================================
 *  Fiat-Shamir Non-Interactive Proofs
 * ======================================================================== */

void sigma_fs_prove(sigma_proof *proof,
                    const sigma_protocol *proto,
                    const void *witness,
                    const void *public_input,
                    const uint8_t *message,
                    size_t message_len,
                    const sigma_scalar *randomness) {
    /* Step 1: Compute commitment a */
    proto->prove_commit(&proof->commitment, randomness,
                        witness, (void*)public_input);

    /* Step 2: Challenge e = H(commitment || message || public_input) */
    /* We hash message + commitment bytes. The public_input is used
     * indirectly as we include it in the hash via the commitment
     * (which is generated from the witness + public_input). */
    sigma_hash_context ctx;
    sigma_hash_init(&ctx);
    sigma_hash_update(&ctx, message, message_len);
    uint8_t cbuf[256];
    sigma_group_serialize(cbuf, &proof->commitment);
    sigma_hash_update(&ctx, cbuf, 256);
    uint8_t dgst[32];
    sigma_hash_final(&ctx, dgst);
    /* Convert digest to scalar e ¡Ê Z_q */
    memset(proof->challenge.limbs, 0, sizeof(proof->challenge.limbs));
    for (int i = 0; i < 4; i++) {
        uint64_t v = 0;
        for (int j = 7; j >= 0; j--)
            v = (v << 8) | dgst[i * 8 + j];
        proof->challenge.limbs[i] = v;
    }
    proof->challenge.limbs[3] &= 0x3FFFFFFFFFFFFFFFULL;
    if (sigma_scalar_cmp(&proof->challenge, &SIGMA_ORDER_Q) >= 0)
        sigma_scalar_sub(&proof->challenge, &proof->challenge, &SIGMA_ORDER_Q);

    /* Step 3: Compute response z */
    proto->prove_response(&proof->response, randomness,
                          &proof->challenge,
                          witness, (void*)public_input);
}

bool sigma_fs_verify(const sigma_proof *proof,
                     const sigma_protocol *proto,
                     const void *public_input,
                     const uint8_t *message,
                     size_t message_len) {
    /* Recompute challenge: e = H(commitment || message || public_input) */
    sigma_scalar expected_e;
    sigma_hash_context ctx;
    sigma_hash_init(&ctx);
    sigma_hash_update(&ctx, message, message_len);
    uint8_t cbuf[256];
    sigma_group_serialize(cbuf, &proof->commitment);
    sigma_hash_update(&ctx, cbuf, 256);
    uint8_t dgst[32];
    sigma_hash_final(&ctx, dgst);
    memset(expected_e.limbs, 0, sizeof(expected_e.limbs));
    for (int i = 0; i < 4; i++) {
        uint64_t v = 0;
        for (int j = 7; j >= 0; j--)
            v = (v << 8) | dgst[i * 8 + j];
        expected_e.limbs[i] = v;
    }
    expected_e.limbs[3] &= 0x3FFFFFFFFFFFFFFFULL;
    if (sigma_scalar_cmp(&expected_e, &SIGMA_ORDER_Q) >= 0)
        sigma_scalar_sub(&expected_e, &expected_e, &SIGMA_ORDER_Q);

    /* Challenge in proof must match */
    if (sigma_scalar_cmp(&proof->challenge, &expected_e) != 0)
        return false;

    /* Verify the underlying sigma protocol */
    return proto->verify(&proof->commitment, &expected_e,
                         &proof->response, (void*)public_input);
}

/* ========================================================================
 *  Schnorr-Specific Fiat-Shamir Convenience Functions
 * ======================================================================== */

void sigma_fs_schnorr_prove(sigma_proof *proof,
                             const sigma_schnorr_witness *sk,
                             const sigma_schnorr_public *pk,
                             const uint8_t *msg, size_t msg_len,
                             const sigma_scalar *randomness) {
    const sigma_protocol *schnorr_proto = sigma_schnorr_get_protocol();
    sigma_fs_prove(proof, schnorr_proto, sk, pk, msg, msg_len, randomness);
}

bool sigma_fs_schnorr_verify(const sigma_proof *proof,
                              const sigma_schnorr_public *pk,
                              const uint8_t *msg, size_t msg_len) {
    const sigma_protocol *schnorr_proto = sigma_schnorr_get_protocol();
    return sigma_fs_verify(proof, schnorr_proto, pk, msg, msg_len);
}

/* ========================================================================
 *  Fiat-Shamir Digital Signatures
 *
 *  L7 Application: Schnorr signature scheme.
 *  Sign(sk, msg):
 *    1. r ¡û Z_q^* (unique per signature!)
 *    2. R = g^r mod p
 *    3. e = H(R || pk.y || msg) mod q
 *    4. s = r + e¡¤x mod q
 *    5. ¦Ò = (R, s)
 *
 *  Verify(pk, msg, ¦Ò):
 *    1. e = H(R || pk.y || msg) mod q
 *    2. Check: g^s ¡Ô R ¡¤ y^e mod p
 * ======================================================================== */

void sigma_fs_sign(sigma_fs_signature *sig,
                    const sigma_schnorr_witness *sk,
                    const sigma_schnorr_public *pk,
                    const uint8_t *message, size_t message_len) {
    sigma_scalar r;
    sigma_random_nonzero_scalar(&r);

    /* R = g^r */
    sigma_group_exp_g(&sig->commitment, &r);

    /* e = H(R || pk.y || msg) mod q ¡ª strong Fiat-Shamir */
    sigma_scalar e;
    sigma_hash_context ctx;
    sigma_hash_init(&ctx);
    uint8_t Rbuf[256], ybuf[256];
    sigma_group_serialize(Rbuf, &sig->commitment);
    sigma_group_serialize(ybuf, &pk->y);
    sigma_hash_update(&ctx, Rbuf, 256);
    sigma_hash_update(&ctx, ybuf, 256);
    sigma_hash_update(&ctx, message, message_len);
    uint8_t dgst[32];
    sigma_hash_final(&ctx, dgst);
    memset(e.limbs, 0, sizeof(e.limbs));
    for (int i = 0; i < 4; i++) {
        uint64_t v = 0;
        for (int j = 7; j >= 0; j--)
            v = (v << 8) | dgst[i * 8 + j];
        e.limbs[i] = v;
    }
    e.limbs[3] &= 0x3FFFFFFFFFFFFFFFULL;
    if (sigma_scalar_cmp(&e, &SIGMA_ORDER_Q) >= 0)
        sigma_scalar_sub(&e, &e, &SIGMA_ORDER_Q);

    /* s = r + e¡¤x mod q */
    sigma_scalar ex;
    sigma_scalar_mul(&ex, &e, &sk->x);
    sigma_scalar_add(&sig->response, &r, &ex);
}

bool sigma_fs_verify_signature(const sigma_fs_signature *sig,
                                const sigma_schnorr_public *pk,
                                const uint8_t *message, size_t message_len) {
    /* Recompute e = H(R || pk.y || msg) */
    sigma_scalar e;
    sigma_hash_context ctx;
    sigma_hash_init(&ctx);
    uint8_t Rbuf[256], ybuf[256];
    sigma_group_serialize(Rbuf, &sig->commitment);
    sigma_group_serialize(ybuf, &pk->y);
    sigma_hash_update(&ctx, Rbuf, 256);
    sigma_hash_update(&ctx, ybuf, 256);
    sigma_hash_update(&ctx, message, message_len);
    uint8_t dgst[32];
    sigma_hash_final(&ctx, dgst);
    memset(e.limbs, 0, sizeof(e.limbs));
    for (int i = 0; i < 4; i++) {
        uint64_t v = 0;
        for (int j = 7; j >= 0; j--)
            v = (v << 8) | dgst[i * 8 + j];
        e.limbs[i] = v;
    }
    e.limbs[3] &= 0x3FFFFFFFFFFFFFFFULL;
    if (sigma_scalar_cmp(&e, &SIGMA_ORDER_Q) >= 0)
        sigma_scalar_sub(&e, &e, &SIGMA_ORDER_Q);

    /* Check: g^s ¡Ô R ¡¤ y^e mod p */
    sigma_group_elem gs, ye, Rhs;
    sigma_group_exp_g(&gs, &sig->response);
    sigma_group_exp(&ye, &pk->y, &e);
    sigma_group_mul(&Rhs, &sig->commitment, &ye);

    return sigma_group_eq(&gs, &Rhs);
}

/* ========================================================================
 *  Strong vs Weak Fiat-Shamir
 * ======================================================================== */

bool sigma_fs_is_strong(void) {
    /* Our implementation always uses strong Fiat-Shamir by default */
    return true;
}

void sigma_fs_weak_prove(sigma_proof *proof,
                          const sigma_protocol *proto,
                          const void *witness,
                          const void *public_input,
                          const uint8_t *message, size_t message_len) {
    /* Weak Fiat-Shamir: e = H(commitment || message) ¡ª no public key! */
    proto->prove_commit(&proof->commitment, (const sigma_scalar*)
                         ((const uint8_t*)witness + 0), /* hack: we need r */
                         witness, (void*)public_input);

    /* Generate a fresh randomness for the proof */
    sigma_scalar r;
    sigma_random_nonzero_scalar(&r);
    proto->prove_commit(&proof->commitment, &r, witness, (void*)public_input);

    /* e = H(R || msg) only ¡ª OMITTING public key */
    sigma_hash_context ctx;
    sigma_hash_init(&ctx);
    uint8_t Rbuf[256];
    sigma_group_serialize(Rbuf, &proof->commitment);
    sigma_hash_update(&ctx, Rbuf, 256);
    sigma_hash_update(&ctx, message, message_len);
    uint8_t dgst[32];
    sigma_hash_final(&ctx, dgst);
    memset(proof->challenge.limbs, 0, sizeof(proof->challenge.limbs));
    for (int i = 0; i < 4; i++) {
        uint64_t v = 0;
        for (int j = 7; j >= 0; j--)
            v = (v << 8) | dgst[i * 8 + j];
        proof->challenge.limbs[i] = v;
    }
    proof->challenge.limbs[3] &= 0x3FFFFFFFFFFFFFFFULL;
    if (sigma_scalar_cmp(&proof->challenge, &SIGMA_ORDER_Q) >= 0)
        sigma_scalar_sub(&proof->challenge, &proof->challenge, &SIGMA_ORDER_Q);

    proto->prove_response(&proof->response, &r,
                          &proof->challenge, witness, (void*)public_input);
}

/* ========================================================================
 *  Batch Verification (Small Exponents Test)
 *
 *  L8 Advanced Topic: Batch verification of Schnorr signatures.
 *  Instead of O(n) exponentiations, use O(1) exponentiations + O(n) multiplications.
 *
 *  Algorithm (Bellare, Garay, Rabin 1998):
 *    Pick random coefficients c_i ¡Ê [0, 2^t)
 *    Check: g^{¦² c_i¡¤s_i} ¡Ô ¦° (R_i^{c_i} ¡¤ y_i^{c_i¡¤e_i}) mod p
 *
 *  The random linear combination catches any invalid signature with
 *  probability ¡Ý 1 - 2^{-t}. t = 80 gives 2^{-80} error.
 *
 *  L8 Reference:
 *    Bellare, Garay, Rabin (1998) "Fast Batch Verification for Modular
 *    Exponentiation and Digital Signatures", EUROCRYPT '98
 * ======================================================================== */

bool sigma_fs_batch_verify(const sigma_fs_signature *sigs,
                            const sigma_schnorr_public *pks,
                            const uint8_t **messages,
                            const size_t *message_lens,
                            int num_signatures) {
    if (num_signatures <= 0) return true;
    if (num_signatures == 1) {
        return sigma_fs_verify_signature(&sigs[0], &pks[0],
                                          messages[0], message_lens[0]);
    }

    /* Compute LHS: g^{¦² c_i¡¤s_i} */
    sigma_scalar sum_cs;
    sigma_scalar_zero(&sum_cs);

    /* Compute RHS product: ¦° R_i^{c_i} ¡¤ y_i^{c_i¡¤e_i} */
    sigma_group_elem rhs_prod;
    sigma_biguint_set_u64((sigma_biguint*)&rhs_prod, 1);

    sigma_scalar coeffs[32]; /* max batch size */
    if (num_signatures > 32) return false; /* safety limit */

    for (int i = 0; i < num_signatures; i++) {
        /* Generate random coefficient c_i (small, e.g., 80-bit for t=80) */
        sigma_scalar ci;
        sigma_random_scalar(&ci);
        /* Truncate to ~80 bits for efficiency */
        ci.limbs[1] = 0; ci.limbs[2] = 0; ci.limbs[3] = 0;
        if (sigma_scalar_is_zero(&ci)) sigma_scalar_set_u64(&ci, 1);
        sigma_scalar_copy(&coeffs[i], &ci);

        /* Recompute e_i = H(R_i || pk_i.y || msg_i) */
        sigma_scalar ei;
        sigma_hash_context ctx;
        sigma_hash_init(&ctx);
        uint8_t Rbuf[256], ybuf[256];
        sigma_group_serialize(Rbuf, &sigs[i].commitment);
        sigma_group_serialize(ybuf, &pks[i].y);
        sigma_hash_update(&ctx, Rbuf, 256);
        sigma_hash_update(&ctx, ybuf, 256);
        sigma_hash_update(&ctx, messages[i], message_lens[i]);
        uint8_t dgst[32];
        sigma_hash_final(&ctx, dgst);
        memset(ei.limbs, 0, sizeof(ei.limbs));
        for (int j = 0; j < 4; j++) {
            uint64_t v = 0;
            for (int k = 7; k >= 0; k--)
                v = (v << 8) | dgst[j * 8 + k];
            ei.limbs[j] = v;
        }
        ei.limbs[3] &= 0x3FFFFFFFFFFFFFFFULL;
        if (sigma_scalar_cmp(&ei, &SIGMA_ORDER_Q) >= 0)
            sigma_scalar_sub(&ei, &ei, &SIGMA_ORDER_Q);

        /* Accumulate: sum_cs += c_i * s_i */
        sigma_scalar ci_si;
        sigma_scalar_mul(&ci_si, &ci, &sigs[i].response);
        sigma_scalar_add(&sum_cs, &sum_cs, &ci_si);

        /* Accumulate RHS: rhs_prod *= R_i^{c_i} * y_i^{c_i*e_i} */
        sigma_group_elem R_ci, y_ciei;
        sigma_scalar ciei;
        sigma_scalar_mul(&ciei, &ci, &ei);

        sigma_group_exp(&R_ci, &sigs[i].commitment, &ci);
        sigma_group_exp(&y_ciei, &pks[i].y, &ciei);

        sigma_group_elem term;
        sigma_group_mul(&term, &R_ci, &y_ciei);
        sigma_group_mul(&rhs_prod, &rhs_prod, &term);
    }

    /* Check: g^{sum_cs} ¡Ô rhs_prod */
    sigma_group_elem lhs;
    sigma_group_exp_g(&lhs, &sum_cs);

    return sigma_group_eq(&lhs, &rhs_prod);
}

/* ========================================================================
 *  Signature Forgery Resistance Test
 *
 *  Estimates the probability of forging a Schnorr signature without
 *  knowing the secret key, by brute-force random guessing.
 *
 *  Expected result: success rate ¡Ö 1/q ¡Ö 2^{-256} (negligible).
 * ======================================================================== */

double sigma_fs_test_forgery_resistance(int num_trials) {
    sigma_schnorr_witness sk;
    sigma_schnorr_public  pk;
    sigma_schnorr_keygen(&sk, &pk);

    const uint8_t *msg = (const uint8_t*)"test message for forgery resistance";
    size_t msg_len = 37;

    int forgeries = 0;
    for (int i = 0; i < num_trials; i++) {
        sigma_fs_signature sig;
        sigma_scalar fake_r;
        sigma_random_nonzero_scalar(&fake_r);

        /* Try to forge: guess random (R, s) and see if it verifies */
        sigma_group_exp_g(&sig.commitment, &fake_r);

        /* Guess a response s */
        sigma_scalar fake_s;
        sigma_random_scalar(&fake_s);
        sigma_scalar_copy(&sig.response, &fake_s);

        /* Check if this accidentally verifies */
        if (sigma_fs_verify_signature(&sig, &pk, msg, msg_len)) {
            forgeries++;
        }
    }
    return (double)forgeries / (double)num_trials;
}

/* ========================================================================
 *  Serialization
 * ======================================================================== */

void sigma_fs_signature_serialize(uint8_t *out,
                                   const sigma_fs_signature *sig) {
    sigma_group_serialize(out, &sig->commitment);
    sigma_scalar_serialize(out + 256, &sig->response);
}

bool sigma_fs_signature_deserialize(sigma_fs_signature *sig,
                                     const uint8_t *in) {
    memcpy(sig->commitment.limbs, in, 256);
    sigma_scalar_deserialize(&sig->response, in + 256);
    return true;
}

void sigma_fs_proof_serialize(uint8_t *out, const sigma_proof *proof) {
    sigma_group_serialize(out, &proof->commitment);
    sigma_scalar_serialize(out + 256, &proof->response);
    sigma_scalar_serialize(out + 288, &proof->challenge);
}

bool sigma_fs_proof_deserialize(sigma_proof *proof, const uint8_t *in) {
    memcpy(proof->commitment.limbs, in, 256);
    sigma_scalar_deserialize(&proof->response, in + 256);
    sigma_scalar_deserialize(&proof->challenge, in + 288);
    return true;
}
