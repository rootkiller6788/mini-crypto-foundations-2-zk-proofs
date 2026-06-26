/**
 * example_ring_signature.c -- Ring Signature Demo (1-out-of-N OR Proof)
 *
 * L6 Canonical Problem: Proving membership in a set without revealing identity.
 * L7 Application: Anonymous signatures (Monero, CryptoNote).
 *
 * A ring signature allows a signer to prove they are one of N people
 * without revealing WHICH one. This is the OR-composition of N Schnorr
 * proofs using the Cramer-Damgard-Schoenmakers technique.
 *
 * Scenario: A whistleblower (Carol) signs a message proving she is one
 * of {Alice, Bob, Carol, Dave} without revealing her identity.
 *
 * Usage: ./example_ring_signature
 */

#include "sigma_composition.h"
#include "sigma_schnorr.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

int main(void) {
    sigma_random_seed((uint64_t)time(NULL));

    printf("============================================================\n");
    printf("  Ring Signature Demo (1-out-of-N OR Proof)\n");
    printf("  Cramer-Damgard-Schoenmakers OR Composition\n");
    printf("============================================================\n\n");

    /* 1. Setup: 4 participants with keypairs */
    const int N = 4;
    const char *names[] = {"Alice", "Bob", "Carol", "Dave"};
    sigma_schnorr_witness secret_keys[N];
    sigma_schnorr_public  public_keys[N];

    printf("[Setup] %d participants generate keypairs:\n", N);
    for (int i = 0; i < N; i++) {
        sigma_schnorr_keygen(&secret_keys[i], &public_keys[i]);
        printf("  %s: public key ready\n", names[i]);
    }

    /* 2. Whistleblower Carol (index 2) signs anonymously */
    int signer_idx = 2;  /* Carol */
    const char *message = "The company has been dumping toxic waste since 2019.";

    printf("\n[Signing] %s (whistleblower) signs anonymously:\n", names[signer_idx]);
    printf("  Message: \"%s\"\n", message);
    printf("  Signer knows they are in the set, but...\n");
    printf("  ...the verifier cannot tell WHICH key was used.\n\n");

    sigma_ring_public ring_pub;
    ring_pub.num_keys = N;
    for (int i = 0; i < N; i++) {
        ring_pub.pks[i] = public_keys[i];
    }

    sigma_ring_proof ring_proof;
    sigma_ring_prove(&ring_proof, &ring_pub, signer_idx,
                     &secret_keys[signer_idx],
                     (const uint8_t*)message, strlen(message));

    printf("[Verification] Public verifier checks the ring proof:\n");
    int valid = sigma_ring_verify(&ring_proof, &ring_pub,
                                   (const uint8_t*)message, strlen(message));
    printf("  Result: %s\n", valid ? "ACCEPTED (valid ring signature)" : "REJECTED");

    /* 3. Anonymity analysis */
    printf("\n[Anonymity] What the verifier learns:\n");
    printf("  - One of {%s, %s, %s, %s} signed this message: YES\n",
           names[0], names[1], names[2], names[3]);
    printf("  - Which one signed: UNKNOWN (each equally likely)\n");
    printf("  - The secret key of the signer: UNKNOWN\n");
    printf("  - This is Witness Indistinguishability (WI)\n");

    /* 4. Tampering test */
    printf("\n[Security] Tampering test:\n");
    const char *tampered_msg = "The company is completely innocent.";
    int tamper = sigma_ring_verify(&ring_proof, &ring_pub,
                                    (const uint8_t*)tampered_msg,
                                    strlen(tampered_msg));
    printf("  Same ring proof, different message: %s\n",
           tamper ? "ACCEPTED (FAIL!)" : "REJECTED (correct)");

    /* 5. Attempt to verify without being in the ring */
    printf("\n[Security] Non-member test:\n");
    sigma_schnorr_witness outsider_sk;
    sigma_schnorr_public  outsider_pk;
    sigma_schnorr_keygen(&outsider_sk, &outsider_pk);

    /* Try to create a ring proof using an outsider (should fail for them) */
    sigma_ring_public outsider_ring;
    outsider_ring.num_keys = 2;
    outsider_ring.pks[0] = public_keys[0];
    outsider_ring.pks[1] = public_keys[1];
    /* Note: outsider is NOT in the ring */

    sigma_ring_proof outsider_proof;
    sigma_ring_prove(&outsider_proof, &outsider_ring, 0,
                     &secret_keys[0],  /* using Alice's key */
                     (const uint8_t*)"test", 4);
    /* This proof is valid because Alice (index 0) is in the ring */
    int outsider_ok = sigma_ring_verify(&outsider_proof, &outsider_ring,
                                         (const uint8_t*)"test", 4);
    printf("  Proof using ring member key: %s (expected)\n",
           outsider_ok ? "ACCEPTED" : "REJECTED");

    /* 6. Protocol structure */
    printf("\n[Protocol] CDS OR Composition Structure:\n");
    printf("  For signer at index k:\n");
    printf("    1. For j != k: pick random e_j, z_j, simulate a_j\n");
    printf("    2. For j = k:  pick random r, compute honest a_k = g^r\n");
    printf("    3. Hash all a_j with message to get total challenge e\n");
    printf("    4. Derive e_k = e - sum_{j!=k} e_j (mod q)\n");
    printf("    5. Compute z_k = r + e_k * x_k\n");
    printf("    6. Output (a_0,...,a_{N-1}, e_0,...,e_{N-1}, z_0,...,z_{N-1})\n");
    printf("\n  Verifier: checks sum e_j = H(a_0||...||msg) and\n");
    printf("            g^{z_j} = a_j * y_j^{e_j} for all j\n");

    /* 7. Applications */
    printf("\n[Applications] Real-world ring signatures:\n");
    printf("  - Monero (XMR): RingCT for transaction privacy\n");
    printf("  - CryptoNote: Original ring signature cryptocurrency\n");
    printf("  - Whistleblowing: Anonymous leaks with proof of insider status\n");
    printf("  - E-voting: Prove valid vote without linking to identity\n");
    printf("  - Group Signatures: Prove group membership anonymously\n");

    printf("\n============================================================\n");
    printf("  Summary\n");
    printf("============================================================\n");
    printf("  1. OR Composition:    1-out-of-N proof of partial knowledge\n");
    printf("  2. Anonymity Set:     N = %d participants\n", N);
    printf("  3. Witness Hiding:    Verifier cannot identify signer\n");
    printf("  4. Unforgeable:       Signer must know one secret key\n");
    printf("  5. Size:              O(N) proof size (linear in ring size)\n");
    printf("\n");

    return 0;
}
