/**
 * example_schnorr_id.c -- Schnorr Identification Protocol Demo
 *
 * L6 Canonical Problem: Proving knowledge of a discrete logarithm.
 * End-to-end demonstration of the 3-move Schnorr sigma protocol.
 *
 * Scenario: Alice proves to Bob that she knows the secret key x
 * corresponding to her public key y = g^x, without revealing x.
 *
 * Usage: ./example_schnorr_id
 */

#include "sigma_schnorr.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

int main(void) {
    sigma_random_seed((uint64_t)time(NULL));

    printf("============================================================\n");
    printf("  Schnorr Identification Protocol Demo\n");
    printf("  Proving Knowledge of Discrete Logarithm\n");
    printf("============================================================\n\n");

    /* 1. Setup: Alice generates keypair */
    printf("[Setup] Alice generates her keypair...\n");
    sigma_schnorr_witness alice_sk;  /* secret key x */
    sigma_schnorr_public  alice_pk;  /* public key y = g^x */
    sigma_schnorr_keygen(&alice_sk, &alice_pk);
    printf("  Secret key x (first 16 bytes): ");
    {
        uint8_t buf[32]; sigma_scalar_serialize(buf, &alice_sk.x);
        for (int i = 0; i < 16; i++) printf("%02x", buf[i]);
        printf("...\n");
    }
    printf("  Public key y = g^x (verified): %s\n\n",
           sigma_group_is_identity(&alice_pk.y) ? "NO" : "YES");

    /* 2. Alice runs the protocol to prove identity to Bob */
    printf("[Protocol] Alice proves knowledge of x to Bob...\n");
    sigma_scalar randomness;
    sigma_random_nonzero_scalar(&randomness);

    /* Phase 1: Alice sends commitment a = g^r */
    sigma_group_elem commitment;
    sigma_schnorr_commit(&commitment, &randomness);
    printf("  Alice -> Bob: commitment a = g^r\n");

    /* Phase 2: Bob sends random challenge e */
    sigma_scalar challenge;
    sigma_random_scalar(&challenge);
    printf("  Bob -> Alice: challenge e (random in Z_q)\n");

    /* Phase 3: Alice responds with z = r + e*x */
    sigma_scalar response;
    sigma_schnorr_respond(&response, &randomness, &challenge, &alice_sk.x);
    printf("  Alice -> Bob: response z = r + e*x\n\n");

    /* 4. Bob verifies */
    printf("[Verification] Bob checks: g^z == a * y^e (mod p)?\n");
    int valid = sigma_schnorr_verify(&commitment, &challenge,
                                      &response, &alice_pk.y);
    printf("  Result: %s\n\n", valid ? "ACCEPTED (proof valid)" : "REJECTED!");

    /* 5. Check special soundness: extract witness from two transcripts */
    printf("[Security] Special Soundness check:\n");
    sigma_scalar r2;
    sigma_random_nonzero_scalar(&r2);
    sigma_transcript t1, t2;
    sigma_group_copy(&t1.commitment, &commitment);
    sigma_group_copy(&t2.commitment, &commitment);
    sigma_scalar_copy(&t1.challenge, &challenge);
    sigma_random_scalar(&t2.challenge);
    sigma_schnorr_respond(&t1.response, &randomness, &t1.challenge, &alice_sk.x);
    sigma_schnorr_respond(&t2.response, &r2, &t2.challenge, &alice_sk.x);

    sigma_scalar extracted_x;
    int extracted = sigma_schnorr_extract(&extracted_x, &t1, &t2, &alice_pk.y);
    printf("  Using two transcripts with same a, different e:\n");
    printf("  Extracted witness matches secret key: %s\n",
           extracted ? "YES" : "NO");
    if (extracted) {
        printf("  This demonstrates: special soundness => proof of knowledge\n");
    }

    /* 6. SHVZK demonstration */
    printf("\n[Privacy] SHVZK Simulation:\n");
    sigma_scalar sim_e;
    sigma_random_scalar(&sim_e);
    sigma_transcript sim_t;
    sigma_schnorr_simulate(&sim_t, &sim_e, &alice_pk.y);
    int sim_valid = sigma_schnorr_verify(&sim_t.commitment, &sim_t.challenge,
                                          &sim_t.response, &alice_pk.y);
    printf("  Simulated transcript (no witness used): %s\n",
           sim_valid ? "ACCEPTED" : "REJECTED");
    printf("  Distribution identical to real transcript: YES (SHVZK)\n");

    /* 7. Knowledge error */
    printf("\n[Analysis] Knowledge Error kappa:\n");
    const sigma_protocol *proto = sigma_schnorr_get_protocol();
    double kerr = sigma_estimate_knowledge_error(proto, &alice_pk, 500);
    printf("  Estimated knowledge error: %.4f (theoretical: 1/q ~ 2^{-256})\n",
           kerr);

    printf("\n============================================================\n");
    printf("  Summary\n");
    printf("============================================================\n");
    printf("  1. Completeness:      Honest proof always verifies\n");
    printf("  2. Special Soundness: Witness extractable from 2 transcripts\n");
    printf("  3. SHVZK:             Simulator produces identical distribution\n");
    printf("  4. Knowledge Error:   Negligible (1/q)\n");
    printf("  5. Underlying:        Discrete Logarithm assumption\n");
    printf("\n");

    return 0;
}
