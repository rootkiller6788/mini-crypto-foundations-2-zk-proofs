// visual_proof.c - Visualize zkSNARK Proof Structure
// Prints the structure of a Groth16 proof showing witness compression.
// Knowledge: L7 Application (proof visualization)

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "snark.h"
#include "qap.h"
#include "r1cs.h"
#include "setup.h"
#include "dlog.h"

static void print_proof_structure(const Proof* p, const char* label) {
    printf("\n=== %s ===\n", label);
    printf("Proof (3 group elements):\n");
    printf("  A (G1): x[3]=0x%016llx y[3]=0x%016llx inf=%d\n",
           (unsigned long long)p->A.x[3], (unsigned long long)p->A.y[3], p->A.is_infinity);
    printf("  B (G2): x0[3]=0x%016llx y0[3]=0x%016llx inf=%d\n",
           (unsigned long long)p->B.x[0][3], (unsigned long long)p->B.y[0][3], p->B.is_infinity);
    printf("  C (G1): x[3]=0x%016llx y[3]=0x%016llx inf=%d\n",
           (unsigned long long)p->C.x[3], (unsigned long long)p->C.y[3], p->C.is_infinity);
    printf("  Total: ~256 bytes (A:64+B:128+C:64)\n");
}

int main(void) {
    printf("=== zkSNARK Proof Structure Visualization ===\n\n");
    FieldParams fp = FIELD_BN254;
    GroupParams* gp = group_params_create_small();
    assert(gp != NULL);

    printf("Circuit: x * y = z\n");
    R1CS* r = r1cs_create(1, 4, 2);
    int va[] = {1}; fe_t ca[1]; fe_from_uint64(ca[0], 1);
    int vb[] = {2}; fe_t cb[1]; fe_from_uint64(cb[0], 1);
    int vc[] = {3}; fe_t cc[1]; fe_from_uint64(cc[0], 1);
    r1cs_add_full_constraint(r, 0, va, ca, 1, vb, cb, 1, vc, cc, 1, &fp);
    r1cs_print_summary(r);

    fe_t roots[1]; fe_from_uint64(roots[0], 0);
    QAP* q = qap_from_r1cs(r, roots, &fp);
    assert(q != NULL);
    qap_print_summary(q);

    printf("\nGenerating keys via setup...\n");
    fe_t tau, alpha, beta, gamma, delta;
    fe_random(tau, gp->fp); fe_random(alpha, gp->fp);
    fe_random(beta, gp->fp); fe_random(gamma, gp->fp);
    fe_random(delta, gp->fp);

    ProvingKey pk = {0}; VerifyingKey vk = {0};
    int so = snark_setup(&pk, &vk, q, gp, tau, alpha, beta, gamma, delta);
    printf("  Proving key: %d vars, %d pub\n", pk.n_vars, pk.n_pub_inputs);
    assert(so);

    fe_t witness[4];
    fe_one(witness[0]);
    fe_from_uint64(witness[1], 3);
    fe_from_uint64(witness[2], 4);
    fe_from_uint64(witness[3], 12);

    printf("\nWitness (secret): 1, x=3, y=4, z=12\n");
    printf("Public inputs: x=3, y=4\n");

    Proof proof;
    snark_prove(&proof, &pk, q, witness, gp, 0);
    print_proof_structure(&proof, "Non-ZK Proof");
    printf("Structure: A=witness_A, B=witness_B, C=witness_C\n");

    Proof proof_zk;
    snark_prove(&proof_zk, &pk, q, witness, gp, 1);
    print_proof_structure(&proof_zk, "ZK Proof");
    printf("Structure: A=witness_A+r*delta, B=witness_B+s*delta\n");
    printf("Blinding factors r,s make proofs differ.\n");

    printf("\n--- Comparison ---\n");
    printf("A differs: %s\n", fe_equal(proof.A.x, proof_zk.A.x) ? "NO" : "YES");

    fe_t pub_in[2];
    fe_from_uint64(pub_in[0], 3); fe_from_uint64(pub_in[1], 4);
    printf("Non-ZK verify: %s\n", snark_verify(&proof, &vk, pub_in, gp) ? "PASS" : "FAIL");
    printf("ZK verify: %s\n", snark_verify(&proof_zk, &vk, pub_in, gp) ? "PASS" : "FAIL");

    printf("\n=== Key Insight ===\n");
    printf("256-byte proof replaces gigabyte witness.\n");
    printf("The verifier checks a single pairing equation.\n");

    pk_free(&pk); vk_free(&vk);
    group_params_free(gp); qap_free(q); r1cs_free(r);
    return 0;
}