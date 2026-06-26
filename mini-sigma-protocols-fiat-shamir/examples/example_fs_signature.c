/**
 * example_fs_signature.c -- Fiat-Shamir Schnorr Signature Demo
 *
 * L6 Canonical Problem: Digital signatures from identification protocols.
 * L7 Application: EdDSA-like Schnorr signatures used in Bitcoin (BIP-340).
 *
 * Demonstrates the complete sign/verify lifecycle:
 *   1. Key generation
 *   2. Sign a message (non-interactive via Fiat-Shamir)
 *   3. Verify the signature
 *   4. Test tampering resistance
 *   5. Batch verification
 *
 * Usage: ./example_fs_signature
 */

#include "sigma_fiat_shamir.h"
#include "sigma_schnorr.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

int main(void) {
    sigma_random_seed((uint64_t)time(NULL));

    printf("============================================================\n");
    printf("  Fiat-Shamir Schnorr Signature Demo\n");
    printf("  (Bitcoin BIP-340 / EdDSA ancestor)\n");
    printf("============================================================\n\n");

    /* 1. Key generation */
    sigma_schnorr_witness sk;
    sigma_schnorr_public  pk;
    sigma_schnorr_keygen(&sk, &pk);
    printf("[KeyGen] Secret key and public key generated.\n");
    printf("  Public key size: %d bytes (2048-bit group element)\n\n",
           (int)sizeof(pk.y));

    /* 2. Sign three messages */
    const char *messages[] = {
        "Transfer 100 BTC to Alice",
        "Transfer 50 BTC to Bob",
        "Approve smart contract #42"
    };

    sigma_fs_signature sigs[3];
    printf("[Signing] Alice signs three messages:\n");
    for (int i = 0; i < 3; i++) {
        sigma_fs_sign(&sigs[i], &sk, &pk,
                       (const uint8_t*)messages[i], strlen(messages[i]));
        printf("  Message %d: \"%s\"\n", i + 1, messages[i]);
        printf("    Signature valid (self-check): %s\n",
               sigma_fs_verify_signature(&sigs[i], &pk,
                   (const uint8_t*)messages[i], strlen(messages[i]))
               ? "YES" : "NO");
    }

    /* 3. Tampering detection */
    printf("\n[Security] Tampering detection:\n");
    const char *tampered = "Transfer 100 BTC to Mallory";
    int tamper_ok = sigma_fs_verify_signature(&sigs[0], &pk,
        (const uint8_t*)tampered, strlen(tampered));
    printf("  Sign(\"Transfer 100 BTC to Alice\") verified with\n");
    printf("  \"Transfer 100 BTC to Mallory\": %s\n",
           tamper_ok ? "ACCEPTED (FAIL!)" : "REJECTED (correct)");

    /* 4. Wrong key */
    sigma_schnorr_witness sk2;
    sigma_schnorr_public  pk2;
    sigma_schnorr_keygen(&sk2, &pk2);
    int wrongkey_ok = sigma_fs_verify_signature(&sigs[1], &pk2,
        (const uint8_t*)messages[1], strlen(messages[1]));
    printf("  Signature verified with wrong public key: %s\n",
           wrongkey_ok ? "ACCEPTED (FAIL!)" : "REJECTED (correct)");

    /* 5. Batch verification */
    printf("\n[Optimization] Batch verification (n=3):\n");
    sigma_schnorr_public pks_arr[3] = {pk, pk, pk};
    const uint8_t *msg_ptrs[3] = {
        (const uint8_t*)messages[0],
        (const uint8_t*)messages[1],
        (const uint8_t*)messages[2]
    };
    size_t msg_lens[3] = {
        strlen(messages[0]), strlen(messages[1]), strlen(messages[2])
    };
    int batch_ok = sigma_fs_batch_verify(sigs, pks_arr, msg_ptrs, msg_lens, 3);
    printf("  Batch result (all 3 valid): %s\n",
           batch_ok ? "ACCEPTED" : "REJECTED");
    printf("  Complexity: O(n) vs O(k*n) for individual verification\n");

    /* 6. Strong Fiat-Shamir */
    printf("\n[Protocol] Strong vs Weak Fiat-Shamir:\n");
    printf("  Implementation uses STRONG Fiat-Shamir by default.\n");
    printf("  Challenge: e = H(R || pk || msg)  [includes public key]\n");
    printf("  This prevents key-substitution attacks.\n");

    /* 7. Forgery resistance */
    printf("\n[Security] Forgery resistance test (500 trials):\n");
    double forgery_rate = sigma_fs_test_forgery_resistance(500);
    printf("  Successful forgeries: %.0f / 500 (rate: %.4f)\n",
           forgery_rate * 500, forgery_rate);
    printf("  Security level: ~256 bits (discrete log)\n");

    /* 8. Sony PS3 vulnerability reminder */
    printf("\n[WARNING] Critical security rule:\n");
    printf("  The randomness r MUST be unique per signature.\n");
    printf("  Reusing r with different messages LEAKS the secret key.\n");
    printf("  This is the exact vulnerability in:\n");
    printf("    - Sony PS3 ECDSA hack (2010)\n");
    printf("    - Android Bitcoin wallet bug (2013)\n");
    printf("    - Blockchain.info repeated r (2014)\n");

    printf("\n============================================================\n");
    printf("  Summary\n");
    printf("============================================================\n");
    printf("  1. Non-interactive:  Fiat-Shamir removes interaction\n");
    printf("  2. Unforgeable:      Under discrete log assumption (ROM)\n");
    printf("  3. Strong FS:        Public key in hash prevents attacks\n");
    printf("  4. Batch verify:     O(n) cost for n signatures\n");
    printf("  5. Production basis: Ed25519, BIP-340 (Schnorr/Taproot)\n");
    printf("\n");

    return 0;
}
