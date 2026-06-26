// example_demo.c - End-to-end SNARK pipeline demonstration
// Shows: R1CS -> QAP -> Setup -> Prove -> Verify for a simple circuit.
// Demonstrates the core SNARK property: honest proof verifies.
#include <stdio.h>
#include <assert.h>
#include "r1cs.h"
#include "qap.h"
#include "snark.h"
#include "setup.h"

int main(void) {
    printf("=== zkSNARK Demo: x * y = z ===");    printf("Proving knowledge of (x, y) such that x * y = z");
    FieldParams fp = FIELD_BN254;

    // Step 1: Build R1CS
    printf("Step 1: Building R1CS...");    R1CS* r = r1cs_create(1, 4, 2);
    int va[] = {1}; fe_t ca[1]; fe_from_uint64(ca[0], 1);
    int vb[] = {2}; fe_t cb[1]; fe_from_uint64(cb[0], 1);
    int vc[] = {3}; fe_t cc[1]; fe_from_uint64(cc[0], 1);
    r1cs_add_full_constraint(r, 0, va, ca, 1, vb, cb, 1, vc, cc, 1, &fp);
    r1cs_print_summary(r);

    // Step 2: Create witness (x=3, y=4, z=12)
    printf("Step 2: Creating witness...");    fe_t witness[4];
    fe_one(witness[0]);
    fe_from_uint64(witness[1], 3);
    fe_from_uint64(witness[2], 4);
    fe_from_uint64(witness[3], 12);
    printf("Witness: 1 (constant), x=3, y=4, z=12");
    // Verify R1CS
    int r1cs_ok = r1cs_verify(r, witness, &fp);
    printf("R1CS verification: %s", r1cs_ok ? "PASS" : "FAIL");    assert(r1cs_ok);

    // Step 3: R1CS -> QAP
    printf("Step 3: Converting R1CS to QAP...");    fe_t roots[1]; fe_from_uint64(roots[0], 0);
    QAP* q = qap_from_r1cs(r, roots, &fp);
    assert(q != NULL);
    qap_print_summary(q);

    // Step 4: QAP check
    printf("Step 4: Verifying QAP satisfiability...");    int qap_ok_poly = qap_verify_poly(q, witness, &fp);
    int qap_ok_sz = qap_verify_sz(q, witness, &fp);
    printf("QAP poly check: %s", qap_ok_poly ? "PASS" : "FAIL");    printf("QAP S-Z check: %s", qap_ok_sz ? "PASS" : "FAIL");
    // Step 5: Setup
    printf("Step 5: Running trusted setup...");    GroupParams* gp = group_params_create_small();
    assert(gp != NULL);
    fe_t tau, alpha, beta, gamma, delta;
    fe_random(tau, gp->fp);
    fe_random(alpha, gp->fp);
    fe_random(beta, gp->fp);
    fe_random(gamma, gp->fp);
    fe_random(delta, gp->fp);
    ProvingKey pk = {0};
    VerifyingKey vk = {0};
    int setup_ok = snark_setup(&pk, &vk, q, gp, tau, alpha, beta, gamma, delta);
    printf("Setup: %s", setup_ok ? "OK" : "FAIL");    assert(setup_ok);

    // Step 6: Prove
    printf("Step 6: Generating proof...");    Proof proof;
    int prove_ok = snark_prove(&proof, &pk, q, witness, gp, 0);
    printf("Proof generation: %s", prove_ok ? "OK" : "FAIL");    assert(prove_ok);

    // Step 7: Verify
    printf("Step 7: Verifying proof...");    fe_t pub_inputs[2];
    fe_from_uint64(pub_inputs[0], 3); // public x
    fe_from_uint64(pub_inputs[1], 4); // public y
    int verify_ok = snark_verify(&proof, &vk, pub_inputs, gp);
    printf("Proof verification: %s", verify_ok ? "PASS" : "FAIL");    assert(verify_ok);

    // Step 8: Demo ZK property
    printf("Step 8: Zero-knowledge demonstration...");    Proof proof_zk;
    int prove_zk_ok = snark_prove(&proof_zk, &pk, q, witness, gp, 1);
    assert(prove_zk_ok);
    int verify_zk_ok = snark_verify(&proof_zk, &vk, pub_inputs, gp);
    printf("ZK proof verification: %s", verify_zk_ok ? "PASS" : "FAIL");
    printf("=== All demo steps completed successfully! ===");
    // Cleanup
    pk_free(&pk);
    vk_free(&vk);
    group_params_free(gp);
    qap_free(q);
    r1cs_free(r);

    return 0;
}
