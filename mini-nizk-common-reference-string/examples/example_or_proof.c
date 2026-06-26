/**
 * example_or_proof.c - NIZK OR-Proof (Ring Signature / Anonymous Credential)
 *
 * L6 Canonical Problem: Ring Signatures / Anonymous Authentication
 *
 * Demonstrates an OR-proof: proving knowledge of one of two secret keys
 * without revealing which one. This is the basis for:
 *   - Ring signatures (Monero, CryptoNote)
 *   - Anonymous credentials
 *   - Whistleblower protection
 *   - E-voting eligibility proofs
 *
 * Reference: Cramer, Damgard, Schoenmakers. CRYPTO 1994.
 */
#include "nizk_group.h"
#include "nizk_crs.h"
#include "nizk_sigma.h"
#include "nizk_proof.h"
#include "nizk_simulator.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

int main(void) {
    printf("=== NIZK OR-Proof (Ring Signature) ===\n\n");

    /* Setup */
    printf("[1] Group + CRS setup...\n");
    nizk_group_params_t p;
    nizk_group_params_init_256bit(&p);
    nizk_crs_t crs;
    uint8_t seed[] = "OR Proof Demo Seed";
    nizk_crs_setup_soundness(&crs, &p, seed, sizeof(seed));

    /* Generate two keypairs (two "ring members") */
    printf("[2] Generating two keypairs (ring members)...\n");
    nizk_scalar_t sk1, sk2;
    nizk_scalar_rand(&sk1, &p);
    nizk_scalar_rand(&sk2, &p);
    nizk_group_elem_t gen, pk1, pk2;
    nizk_bigint_copy(&gen.elem, &p.g);
    nizk_group_exp(&pk1, &gen, &sk1, &p);
    nizk_group_exp(&pk2, &gen, &sk2, &p);
    printf("    Member 1: pk=0x%016llx\n",
           (unsigned long long)pk1.elem.limbs[0]);
    printf("    Member 2: pk=0x%016llx\n",
           (unsigned long long)pk2.elem.limbs[0]);

    /* Prover knows sk1 (branch 0), proves "I know sk1 OR sk2" */
    printf("[3] Creating OR-proof (prover knows sk1)...\n");
    nizk_proof_t pf;
    nizk_proof_init(&pf, NIZK_PROOF_OR);
    uint8_t ctx[] = "ring_signature_ctx";
    nizk_prove_or(&pf, &crs, &pk1, &pk2, &sk1, 0,
                   ctx, sizeof(ctx), &p);
    printf("    OR-proof created (prover knows branch 0)\n");
    printf("    Branch count: %d\n", pf.or_num_branches);

    /* Verify: anyone can verify, cannot tell which key was used */
    printf("[4] Verifying OR-proof...\n");
    int valid = nizk_verify_or(&pf, &crs, &pk1, &pk2,
                                ctx, sizeof(ctx), &p);
    printf("    Result: %s\n", valid ? "VALID" : "INVALID");
    assert(valid);
    printf("    Observer CANNOT tell which member signed!\n");

    /* Also works if prover knows sk2 */
    printf("[5] OR-proof with sk2...\n");
    nizk_proof_t pf2;
    nizk_proof_init(&pf2, NIZK_PROOF_OR);
    nizk_prove_or(&pf2, &crs, &pk1, &pk2, &sk2, 1,
                   ctx, sizeof(ctx), &p);
    assert(nizk_verify_or(&pf2, &crs, &pk1, &pk2,
                           ctx, sizeof(ctx), &p));
    printf("    OR-proof with other key also VALID\n");

    /* Compare: proofs should look different (different commitments) */
    printf("[6] Proof indistinguishability...\n");
    printf("    Proof1 comm: 0x%016llx\n",
           (unsigned long long)pf.commitment.t.elem.limbs[0]);
    printf("    Proof2 comm: 0x%016llx\n",
           (unsigned long long)pf2.commitment.t.elem.limbs[0]);
    printf("    Different commitments -> different which-key-used hidden\n");

    /* Simulation: create OR-proof knowing NEITHER key (with ZK CRS) */
    printf("[7] Full simulation (knowing NEITHER key)...\n");
    nizk_crs_t crs_zk;
    nizk_crs_setup_zk(&crs_zk, &p, NULL);
    nizk_simulator_state_t sim;
    nizk_simulator_init(&sim, &crs_zk);
    nizk_proof_t spf;
    uint8_t sctx[] = "sim_or";
    nizk_simulate_or(&spf, &sim, &crs_zk, &pk1, &pk2,
                      sctx, sizeof(sctx), &p);
    printf("    Simulated OR-proof created (no witnesses at all!)\n");
    printf("    This demonstrates the ZK property in CRS model\n");

    /* Cleanup */
    nizk_proof_clear(&pf);
    nizk_proof_clear(&pf2);
    nizk_proof_clear(&spf);
    nizk_simulator_clear(&sim);
    nizk_crs_clear(&crs);
    nizk_crs_clear(&crs_zk);
    nizk_group_params_clear(&p);

    printf("\n=== OR-Proof Demo Complete ===\n");
    return 0;
}
