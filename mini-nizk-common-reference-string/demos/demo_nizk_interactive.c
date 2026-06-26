/**
 * demo_nizk_interactive.c - Interactive NIZK Demonstration
 *
 * Demonstrates: CRS setup, key generation, proof creation,
 * verification, zero-knowledge simulation, serialization roundtrip.
 */

#include "nizk_group.h"
#include "nizk_crs.h"
#include "nizk_sigma.h"
#include "nizk_proof.h"
#include "nizk_simulator.h"
#include <stdio.h>
#include <string.h>

static void print_scalar(const char *name, const nizk_scalar_t *s) {
    printf("  %-15s = 0x%016llx...\n", name,
           (unsigned long long)s->val.limbs[0]);
}

static void print_elem_valid(const char *name, const nizk_group_elem_t *e,
                              const nizk_group_params_t *p) {
    printf("  %-15s = 0x%016llx... (valid=%d)\n", name,
           (unsigned long long)e->elem.limbs[0],
           nizk_group_elem_is_valid(e, p));
}

int main(void) {
    printf("+----------------------------------------------------------+\n");
    printf("|   NIZK Proof System - Interactive Demonstration          |\n");
    printf("|   Proving Knowledge of Discrete Logarithm                |\n");
    printf("+----------------------------------------------------------+\n\n");

    /* Step 1: Initialize group parameters */
    printf("--- Step 1: Group Parameter Initialization ---\n");
    nizk_group_params_t params;
    nizk_group_params_init_256bit(&params);
    printf("  Group modulus p: %d bits\n", params.p_bits);
    printf("  Group order q:   %d bits\n", params.q_bits);
    printf("  Generator g:     %d\n", (int)params.g.limbs[0]);

    /* Step 2: CRS Setup */
    printf("\n--- Step 2: CRS Setup ---\n");
    uint8_t seed[] = "demo-crs-seed";
    nizk_crs_t crs_sound, crs_zk;
    nizk_crs_setup_soundness(&crs_sound, &params, seed, sizeof(seed));
    printf("  Soundness CRS: has_trapdoor=%d\n", crs_sound.has_trapdoor);
    nizk_crs_setup_zk(&crs_zk, &params, NULL);
    printf("  ZK-mode CRS:   has_trapdoor=%d\n", crs_zk.has_trapdoor);
    printf("  CRS validation: sound=%d, zk=%d\n",
           nizk_crs_validate(&crs_sound, &params),
           nizk_crs_validate(&crs_zk, &params));

    /* Step 3: Key Generation */
    printf("\n--- Step 3: Schnorr Key Generation ---\n");
    nizk_scalar_t sk;
    nizk_scalar_rand(&sk, &params);
    nizk_group_elem_t gen, pk;
    nizk_bigint_copy(&gen.elem, &params.g);
    nizk_group_exp(&pk, &gen, &sk, &params);
    print_scalar("Secret key (sk)", &sk);
    print_elem_valid("Public key (pk)", &pk, &params);
    printf("  Relationship: pk = g^sk\n");

    /* Step 4: Generate NIZK Proof */
    printf("\n--- Step 4: NIZK Proof Generation ---\n");
    nizk_proof_t proof;
    uint8_t label[] = "demo-proof-label";
    nizk_prove_dlog(&proof, &crs_sound, &pk, &sk, label, sizeof(label), &params);
    printf("  Proof type: DLOG_KNOWLEDGE\n");
    printf("  Commitment t: valid=%d\n",
           nizk_group_elem_is_valid(&proof.commitment.t, &params));
    printf("  Response s:   0x%016llx...\n",
           (unsigned long long)proof.response.s.val.limbs[0]);

    /* Step 5: Verify NIZK Proof */
    printf("\n--- Step 5: NIZK Proof Verification ---\n");
    int valid = nizk_verify_dlog(&proof, &crs_sound, &pk,
                                  label, sizeof(label), &params);
    printf("  Verification result: %s\n", valid ? "ACCEPT [OK]" : "REJECT [FAIL]");

    /* Verify with wrong label */
    uint8_t wrong_label[] = "wrong-label";
    int invalid = nizk_verify_dlog(&proof, &crs_sound, &pk,
                                    wrong_label, sizeof(wrong_label), &params);
    printf("  Wrong label test:     %s\n", invalid ? "ACCEPT (BUG!)" : "REJECT [OK]");

    /* Step 6: Simulate (Zero-Knowledge Demo) */
    printf("\n--- Step 6: Zero-Knowledge Simulation ---\n");
    nizk_simulator_state_t sim;
    nizk_simulator_init(&sim, &crs_zk);
    nizk_proof_t sim_proof;
    nizk_simulate_dlog(&sim_proof, &sim, &crs_zk, &pk,
                        label, sizeof(label), &params);
    int sim_valid = nizk_verify_dlog(&sim_proof, &crs_zk, &pk,
                                      label, sizeof(label), &params);
    printf("  Simulated proof: %s\n", sim_valid ? "Valid [OK]" : "Invalid [FAIL]");
    printf("  Proofs simulated: %llu\n",
           (unsigned long long)sim.proof_count);

    /* Step 7: Serialization */
    printf("\n--- Step 7: Proof Serialization ---\n");
    size_t len = nizk_proof_serialize(NULL, 0, &proof, &params);
    printf("  Serialized proof size: %zu bytes\n", len);
    uint8_t buf[4096];
    nizk_proof_serialize(buf, len, &proof, &params);
    nizk_proof_t deserialized;
    nizk_proof_deserialize(&deserialized, buf, len, &params);
    int deser_valid = nizk_verify_dlog(&deserialized, &crs_sound, &pk,
                                        label, sizeof(label), &params);
    printf("  Roundtrip verification: %s\n",
           deser_valid ? "ACCEPT [OK]" : "REJECT [FAIL]");

    /* Step 8: Distinguisher test */
    printf("\n--- Step 8: Real vs Simulated Indistinguishability ---\n");
    nizk_crs_t crs_sound2;
    nizk_crs_setup_soundness(&crs_sound2, &params, seed, sizeof(seed));
    nizk_proof_t real_proofs[5], sim_proofs[5];
    nizk_distinguisher_test(real_proofs, sim_proofs, 5,
                             &crs_zk, &crs_sound2, &pk, &sk, &params);
    double similarity = nizk_compare_proofs(real_proofs, sim_proofs, 5, &params);
    printf("  Similarity score: %.3f (0=identical, 1=different)\n", similarity);
    for (int i = 0; i < 5; i++) {
        nizk_proof_clear(&real_proofs[i]);
        nizk_proof_clear(&sim_proofs[i]);
    }
    nizk_crs_clear(&crs_sound2);

    /* Cleanup */
    nizk_proof_clear(&proof);
    nizk_proof_clear(&sim_proof);
    nizk_proof_clear(&deserialized);
    nizk_simulator_clear(&sim);
    nizk_crs_clear(&crs_sound);
    nizk_crs_clear(&crs_zk);
    nizk_group_params_clear(&params);

    printf("\n+----------------------------------------------------------+\n");
    printf("|   Demonstration Complete - NIZK Proof System Works!      |\n");
    printf("+----------------------------------------------------------+\n");
    return 0;
}
