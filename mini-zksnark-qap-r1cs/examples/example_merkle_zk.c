// example_merkle_zk.c - Merkle Tree Zero-Knowledge Inclusion Proof
//
// Demonstrates a SNARK proof for Merkle tree inclusion: the prover knows
// a valid Merkle path proving that a leaf belongs to a committed tree root,
// without revealing the leaf or the path.
//
// Knowledge: L6 Canonical Problem (Merkle inclusion), L7 Application (ZK verification)
//
// Circuit: hash(left, right) = (L + R)^2 (simplified pedersen-style hash)
// For a tree of depth d, the circuit has 2d gates per verification.
//
// References:
//   - Merkle (1987) "A Digital Signature Based on a Conventional Encryption Function"
//   - Ben-Sasson et al. (2014) "Scalable Zero Knowledge via Cycles of Elliptic Curves"

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include "circuit_to_r1cs.h"
#include "qap.h"
#include "snark.h"
#include "setup.h"

// Build a depth-3 Merkle tree inclusion proof circuit
// The prover knows leaf and path, verifier only sees root
static void demo_merkle_zk_path(void) {
    printf("\n--- Merkle ZK Inclusion Demo (depth=3) ---\n");
    FieldParams fp = FIELD_BN254;
    int depth = 3;

    // Step 1: Build the circuit for Merkle path verification
    printf("Building Merkle circuit (depth %d)...\n", depth);
    ArithmeticCircuit* circ = circuit_build_merkle_verify(depth, &fp);
    assert(circ != NULL);
    circuit_print(circ);
    printf("  Mul gates: %d\n", circuit_count_mul_gates(circ));

    // Step 2: Evaluate the circuit with a concrete input
    fe_t inputs[10];
    // Leaf value (secret)
    fe_from_uint64(inputs[0], 7);
    // Sibling values along the path
    fe_from_uint64(inputs[1], 3);
    fe_from_uint64(inputs[2], 5);
    fe_from_uint64(inputs[3], 11);
    int n_inputs = 1 + depth; // leaf + siblings
    circuit_evaluate(circ, inputs, n_inputs, &fp);

    // Step 3: Convert to R1CS
    printf("Converting to R1CS...\n");
    R1CS* r1cs = circuit_to_r1cs(circ, &fp);
    assert(r1cs != NULL);
    r1cs_print_summary(r1cs);

    // Step 4: Build witness from circuit evaluation
    // witness layout: [1 (constant), leaf, sibling0, sibling1, sibling2,
    //                  intermediate wires..., output]
    int nv = r1cs->n_vars;
    fe_t* witness = (fe_t*)calloc((size_t)nv, sizeof(fe_t));
    fe_one(witness[0]); // constant
    // Copy computed wire values from circuit
    for (int i = 0; i < circ->n_wires && i < nv - 1; i++) {
        if (circ->wires[i].is_assigned) {
            fe_set(witness[i + 1], circ->wires[i].value);
        }
    }

    // Step 5: Verify R1CS
    printf("Verifying R1CS...\n");
    int r1cs_ok = r1cs_verify(r1cs, witness, &fp);
    printf("  R1CS: %s\n", r1cs_ok ? "PASS" : "FAIL");
    assert(r1cs_ok);

    // Step 6: QAP conversion
    printf("Converting to QAP...\n");
    int m = r1cs->n_constraints;
    fe_t* roots = (fe_t*)malloc((size_t)m * sizeof(fe_t));
    for (int i = 0; i < m; i++) fe_from_uint64(roots[i], (uint64_t)i);
    QAP* q = qap_from_r1cs(r1cs, roots, &fp);
    assert(q != NULL);
    qap_print_summary(q);

    // Step 7: QAP satisfiability check (polynomial + Schwartz-Zippel)
    printf("Checking QAP satisfiability...\n");
    int qap_poly_ok = qap_verify_poly(q, witness, &fp);
    int qap_sz_ok = qap_verify_sz(q, witness, &fp);
    printf("  QAP poly check: %s\n", qap_poly_ok ? "PASS" : "FAIL");
    printf("  QAP S-Z check:  %s\n", qap_sz_ok ? "PASS" : "FAIL");

    // Step 8: Setup + Prove + Verify
    printf("Running SNARK pipeline...\n");
    GroupParams* gp = group_params_create_small();
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
    printf("  Setup: %s\n", setup_ok ? "OK" : "FAIL");
    assert(setup_ok);

    // Generate proof (non-ZK first)
    Proof proof;
    int prove_ok = snark_prove(&proof, &pk, q, witness, gp, 0);
    printf("  Prove: %s\n", prove_ok ? "OK" : "FAIL");
    assert(prove_ok);

    // Public input: just the expected root value
    fe_t pub_inputs[1];
    // The root is the last variable in the witness
    int root_var = nv - 1;
    fe_set(pub_inputs[0], witness[root_var]);

    int verify_ok = snark_verify(&proof, &vk, pub_inputs, gp);
    printf("  Verify: %s\n", verify_ok ? "PASS" : "FAIL");
    assert(verify_ok);

    // ZK version: verify again, proof should be different
    Proof proof_zk;
    snark_prove(&proof_zk, &pk, q, witness, gp, 1);
    int verify_zk_ok = snark_verify(&proof_zk, &vk, pub_inputs, gp);
    printf("  ZK Verify: %s\n", verify_zk_ok ? "PASS" : "FAIL");
    printf("  (ZK proof A.x differs: %s)\n",
           fe_equal(proof.A.x, proof_zk.A.x) ? "same (non-ZK)" : "different (ZK)");

    printf("\nMerkle ZK inclusion proof: SUCCESS\n");

    // Cleanup
    pk_free(&pk); vk_free(&vk);
    group_params_free(gp);
    qap_free(q);
    free(roots);
    r1cs_free(r1cs);
    free(witness);
    circuit_free(circ);
}

// Build a SHA256-like circuit and verify it
static void demo_sha256_circuit(void) {
    printf("\n--- SHA256 Round Circuit Demo ---\n");
    FieldParams fp = FIELD_BN254;

    // Build simplified SHA256 round circuit
    ArithmeticCircuit* circ = circuit_build_sha256_round(&fp);
    assert(circ != NULL);
    circuit_print(circ);

    // Evaluate with test inputs
    fe_t inputs[9]; // h[4]=prev, m[4]=message, nonce
    fe_from_uint64(inputs[0], 0x6a09e667ULL); // h0
    fe_from_uint64(inputs[1], 0xbb67ae85ULL); // h1
    fe_from_uint64(inputs[2], 0x3c6ef372ULL); // h2
    fe_from_uint64(inputs[3], 0xa54ff53aULL); // h3
    fe_from_uint64(inputs[4], 0x510e527fULL); // m0
    fe_from_uint64(inputs[5], 0x9b05688cULL); // m1
    fe_from_uint64(inputs[6], 0x1f83d9abULL); // m2
    fe_from_uint64(inputs[7], 0x5be0cd19ULL); // m3
    fe_from_uint64(inputs[8], 12345);         // nonce

    circuit_evaluate(circ, inputs, 9, &fp);
    printf("Circuit evaluated with SHA256-like inputs\n");

    // Convert to R1CS and verify
    R1CS* r1cs = circuit_to_r1cs(circ, &fp);
    assert(r1cs != NULL);
    r1cs_print_summary(r1cs);

    // Build witness
    int nv = r1cs->n_vars;
    fe_t* witness = (fe_t*)calloc((size_t)nv, sizeof(fe_t));
    fe_one(witness[0]);
    for (int i = 0; i < circ->n_wires && i < nv - 1; i++) {
        if (circ->wires[i].is_assigned) {
            fe_set(witness[i + 1], circ->wires[i].value);
        }
    }

    int ok = r1cs_verify(r1cs, witness, &fp);
    printf("SHA256 R1CS: %s\n", ok ? "PASS" : "FAIL");
    assert(ok);

    free(witness);
    r1cs_free(r1cs);
    circuit_free(circ);
}

int main(void) {
    printf("=== Merkle Tree & SHA256 ZK Demos ===\n");
    printf("These demos show how zkSNARKs prove knowledge of:\n");
    printf("1. A valid Merkle inclusion path (without revealing it)\n");
    printf("2. Satisfying a SHA256-like circuit\n\n");

    demo_merkle_zk_path();
    demo_sha256_circuit();

    printf("\n=== All demos passed! ===\n");
    return 0;
}
