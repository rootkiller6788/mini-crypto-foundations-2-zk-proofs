/*
 * example_snark.c — Groth16 SNARK: Full Pipeline Demonstration
 *
 * Walks through the complete Groth16 SNARK construction:
 *   1. Define computation: y = x * x (multiplication gate)
 *   2. Build R1CS constraint system
 *   3. Convert R1CS to QAP via Lagrange interpolation
 *   4. Generate Common Reference String (CRS) via trusted setup
 *   5. Prover generates 3-element proof
 *   6. Verifier checks pairing equation
 *   7. Extract witness via KEA-based extraction
 *   8. Verify security properties (completeness, soundness, ZK)
 *
 * L6: SNARK as canonical ZK proof problem
 * L7: Foundation for Zcash, zk-rollups, verifiable computation
 *
 * (C) Mini-Theory-of-Computation — mini-knowledge-of-exponent
 */
#include "snark_kea.h"
#include "pairing.h"
#include "discrete_log.h"
#include "kea.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main(void) {
    printf("\n╔══════════════════════════════════════════════════╗\n");
    printf("║   Groth16 SNARK — Full Pipeline Demo           ║\n");
    printf("║   Proving knowledge of y = x * x               ║\n");
    printf("╚══════════════════════════════════════════════════╝\n\n");

    /* Step 1: Define computation */
    printf("── Step 1: R1CS for y = x * x ──\n");
    R1CS* r1cs = r1cs_from_multiplication();
    assert(r1cs);
    r1cs_print(r1cs);

    printf("\n── Step 2: R1CS → QAP ──\n");
    QAP* qap = qap_from_r1cs(r1cs, 107);
    assert(qap);
    qap_print(qap);
    printf("QAP polynomials constructed via Lagrange interpolation.\n");
    printf("Target Z(x) = (x-1) for m=1 constraint.\n");

    printf("\n── Step 3: Trusted Setup ──\n");
    BilinearPairing* bp = pairing_create_simulated();
    assert(bp);
    Groth16ToxicWaste* waste = NULL;
    Groth16ProvingKey* pk = NULL;
    Groth16VerificationKey* vk = NULL;
    int setup_ok = groth16_setup(qap, bp, &waste, &pk, &vk);
    assert(setup_ok);
    printf("CRS generated:\n");
    printf("  Proving key:  %d A-poly, %d B1-poly, %d B2-poly, %d K-poly\n",
           qap->n, qap->n, qap->n, qap->n);
    printf("  Verification key: alpha_g1, beta_g2, gamma_g2, delta_g2\n");
    printf("  Toxic waste: tau=%llu, alpha=%llu, beta=%llu\n",
           (unsigned long long)waste->tau,
           (unsigned long long)waste->alpha,
           (unsigned long long)waste->beta);

    printf("\n── Step 4: Prover ──\n");
    /* Witness: [1, x=5, y=3, out=15] → 5*3=15 */
    uint64_t witness[4] = {1, 5, 3, 15};
    Groth16Proof* pf = groth16_prove(pk, qap, witness, bp);
    assert(pf);
    printf("Proof computed:\n");
    printf("  A (G1): g1^%llu\n", (unsigned long long)pf->A_g1->value);
    printf("  B (G2): g2^%llu\n", (unsigned long long)pf->B_g2->value);
    printf("  C (G1): g1^%llu\n", (unsigned long long)pf->C_g1->value);

    printf("\n── Step 5: Verifier ──\n");
    printf("Verification equation:\n");
    printf("  e(A, B) ?= e(alpha, beta) * e(C, delta)\n");
    int verified = groth16_verify(vk, pf, witness, bp);
    printf("Result: %s\n\n", verified ? "ACCEPTED ✓" : "REJECTED ✗");

    if (verified) {
        printf("Proof properties:\n");
        printf("  • Succinct: 3 group elements (constant size)\n");
        printf("  • Non-interactive: single message prover→verifier\n");
        printf("  • Argument: computationally sound\n");
        printf("  • of Knowledge: KEA ensures witness extraction\n");
    }

    printf("\n── Step 6: Witness Extraction (KEA) ──\n");
    uint64_t extracted[4] = {0};
    int extr_ok = groth16_extract_witness(pf, pk, qap, extracted);
    printf("Extraction: %s\n", extr_ok ? "succeeded (GGM)" : "failed");
    printf("  In the Generic Group Model, the extractor reads\n");
    printf("  the discrete-log representations from the adversary's\n");
    printf("  group element outputs to recover the witness.\n");

    printf("\n── Step 7: Security Verification ──\n");
    snark_check_completeness(qap, bp, witness);

    /* Soundness: try to verify with wrong witness */
    printf("\nSoundness check (wrong witness): ");
    uint64_t wrong_w[4] = {1, 6, 3, 15};  /* 6*3=18, not 15 */
    Groth16ToxicWaste* w2 = NULL; Groth16ProvingKey* pk2 = NULL; Groth16VerificationKey* vk2 = NULL;
    groth16_setup(qap, bp, &w2, &pk2, &vk2);
    Groth16Proof* bad_pf = groth16_prove(pk2, qap, wrong_w, bp);
    int bad_verify = groth16_verify(vk2, bad_pf, witness, bp);
    printf("%s\n", bad_verify ? "VERIFIED (FAIL!)" : "REJECTED (PASS)");
    groth16_proof_free(bad_pf);
    groth16_toxic_waste_free(w2); groth16_pk_free(pk2); groth16_vk_free(vk2);

    /* KEA in Groth16 */
    groth16_kea_demonstration(bp);

    /* Summary Table */
    printf("\n─── Groth16 SNARK Summary ───\n");
    printf("| Property          | Value                         |\n");
    printf("|-------------------|-------------------------------|\n");
    printf("| R1CS constraints  | %-30d|\n", r1cs->n_constraints);
    printf("| QAP degree        | %-30d|\n", qap->m);
    printf("| Proof size        | 3 group elements              |\n");
    printf("| Proof elements    | 2 in G1 + 1 in G2           |\n");
    printf("| Verifier pairings | 3 (or 1 with product)        |\n");
    printf("| CRS model         | Trusted setup                 |\n");
    printf("| Knowledge extract | KEA-based (GGM/AGM)          |\n");
    printf("| Zero-knowledge    | Via blinding (r, s)          |\n");
    printf("| Assumption         | q-KEA + q-PDH               |\n");
    printf("|-------------------|-------------------------------|\n\n");

    printf("Applications of Groth16 SNARK:\n");
    printf("  • Zcash: shielded transactions (since 2016)\n");
    printf("  • zk-Rollups: Ethereum L2 scaling\n");
    printf("  • Verifiable computation outsourcing\n");
    printf("  • Anonymous credentials\n");
    printf("  • Private smart contracts\n");

    /* Cleanup */
    groth16_proof_free(pf);
    groth16_toxic_waste_free(waste);
    groth16_pk_free(pk); groth16_vk_free(vk);
    pairing_free(bp); qap_free(qap); r1cs_free(r1cs);

    printf("\n═══ Groth16 SNARK Demo Complete ═══\n\n");
    return 0;
}
