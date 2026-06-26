/**
 * example_dlog.c - NIZK Proof of Discrete Log Knowledge (Schnorr + Fiat-Shamir)
 *
 * L6 Canonical Problem: Schnorr Identification / Digital Signature
 * Demonstrates complete NIZK DLOG proof flow with simulation and serialization.
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
    printf("=== NIZK Proof of Discrete Log Knowledge ===\n\n");

    /* 1. Group parameters (256-bit for educational demo) */
    printf("[1] 256-bit group parameters...\n");
    nizk_group_params_t params;
    nizk_group_params_init_256bit(&params);

    /* 2. CRS in soundness mode */
    printf("[2] CRS (soundness mode)...\n");
    nizk_crs_t crs;
    uint8_t seed[] = "NIZK DLOG Demo v1.0";
    nizk_crs_setup_soundness(&crs, &params, seed, sizeof(seed));
    assert(nizk_crs_validate(&crs, &params));
    printf("    CRS valid, no trapdoor\n");

    /* 3. Key generation */
    printf("[3] Keypair generation...\n");
    nizk_scalar_t sk;
    nizk_scalar_rand(&sk, &params);
    nizk_group_elem_t gen, pk;
    nizk_bigint_copy(&gen.elem, &params.g);
    nizk_group_exp(&pk, &gen, &sk, &params);
    printf("    pk = g^sk, sk kept secret\n");

    /* 4. Create NIZK proof (prove knowledge of sk without revealing it) */
    printf("[4] Creating NIZK proof...\n");
    nizk_proof_t proof;
    nizk_proof_init(&proof, NIZK_PROOF_DLOG_KNOWLEDGE);
    uint8_t ctx[] = "auth_session_001";
    nizk_prove_dlog(&proof, &crs, &pk, &sk, ctx, sizeof(ctx), &params);
    printf("    Proof: type=%d, comm=0x%016llx, resp=0x%016llx\n",
           proof.type,
           (unsigned long long)proof.commitment.t.elem.limbs[0],
           (unsigned long long)proof.response.s.val.limbs[0]);

    /* 5. Verify proof */
    printf("[5] Verifying...\n");
    int valid = nizk_verify_dlog(&proof, &crs, &pk, ctx, sizeof(ctx), &params);
    printf("    Result: %s\n", valid ? "VALID" : "INVALID");
    assert(valid);

    /* 6. Tampered context fails */
    printf("[6] Tampered context test...\n");
    uint8_t bad[] = "auth_session_002";
    assert(!nizk_verify_dlog(&proof, &crs, &pk, bad, sizeof(bad), &params));
    printf("    Tampered: INVALID (correctly rejected)\n");

    /* 7. ZK Simulation (with trapdoor CRS) */
    printf("[7] ZK Simulation...\n");
    nizk_crs_t crs_zk;
    nizk_crs_setup_zk(&crs_zk, &params, NULL);
    nizk_simulator_state_t sim;
    nizk_simulator_init(&sim, &crs_zk);
    nizk_proof_t sproof;
    uint8_t sctx[] = "sim_session";
    nizk_simulate_dlog(&sproof, &sim, &crs_zk, &pk, sctx, sizeof(sctx), &params);
    printf("    Simulated proof created (no witness used)\n");

    /* 8. Serialization */
    printf("[8] Serialization...\n");
    size_t len = nizk_proof_serialize(NULL, 0, &proof, &params);
    printf("    Serialized size: %zu bytes\n", len);

    /* 9. Distinguisher test */
    printf("[9] Distinguisher test (N=5)...\n");
    nizk_proof_t rp[5], sp[5];
    nizk_crs_t crs_s;
    nizk_crs_setup_soundness(&crs_s, &params, seed, sizeof(seed));
    nizk_distinguisher_test(rp, sp, 5, &crs_zk, &crs_s, &pk, &sk, &params);
    double sim_score = nizk_compare_proofs(rp, sp, 5, &params);
    printf("    Similarity: %.3f (1.0 = indistinguishable)\n", sim_score);
    for (int i = 0; i < 5; i++) {
        nizk_proof_clear(&rp[i]);
        nizk_proof_clear(&sp[i]);
    }

    /* Cleanup */
    nizk_proof_clear(&proof);
    nizk_proof_clear(&sproof);
    nizk_simulator_clear(&sim);
    nizk_crs_clear(&crs);
    nizk_crs_clear(&crs_zk);
    nizk_crs_clear(&crs_s);
    nizk_group_params_clear(&params);

    printf("\n=== DLOG NIZK Proof Demo Complete ===\n");
    return 0;
}
