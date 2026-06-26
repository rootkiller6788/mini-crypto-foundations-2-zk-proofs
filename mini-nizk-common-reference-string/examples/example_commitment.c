/**
 * example_commitment.c - Pedersen Commitments & NIZK Opening Proof
 *
 * L6 Canonical Problem: Confidential Transactions / Verifiable Commitments
 *
 * Demonstrates:
 *   1. Pedersen commitment creation and verification
 *   2. Homomorphic addition/subtraction of commitments
 *   3. NIZK proof of commitment opening knowledge
 *   4. Vector commitment to multiple values
 */
#include "nizk_group.h"
#include "nizk_crs.h"
#include "nizk_commitment.h"
#include "nizk_proof.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

int main(void) {
    printf("=== Pedersen Commitments & NIZK Opening Proofs ===\n\n");

    /* Setup */
    printf("[1] Group + Pedersen CRS...\n");
    nizk_group_params_t p;
    nizk_group_params_init_256bit(&p);
    nizk_crs_t crs;
    uint8_t seed[] = "Pedersen Demo Seed";
    nizk_crs_setup_pedersen(&crs, &p, seed, sizeof(seed));
    assert(nizk_crs_validate(&crs, &p));

    /* Basic Pedersen commitment */
    printf("[2] Basic Pedersen commitment...\n");
    nizk_scalar_t m, r;
    nizk_scalar_set_u64(&m, 42);
    nizk_scalar_set_u64(&r, 12345);
    nizk_commitment_t com;
    nizk_commitment_opening_t open;
    nizk_pedersen_commit(&com, &open, &m, &r, &crs, &p);
    printf("    Committed to m=42, C=0x%016llx\n",
           (unsigned long long)com.C.elem.limbs[0]);

    /* Verify opening */
    printf("[3] Verify opening...\n");
    assert(nizk_pedersen_verify(&com, &open, &crs, &p));
    printf("    Opening verified: VALID\n");

    /* Binding: wrong opening fails */
    nizk_commitment_opening_t fake;
    nizk_scalar_set_u64(&fake.m, 99);
    nizk_scalar_copy(&fake.r, &open.r);
    assert(!nizk_pedersen_verify(&com, &fake, &crs, &p));
    printf("    Wrong opening: INVALID (binding holds)\n");

    /* Homomorphic addition: commit(10) + commit(20) = commit(30) */
    printf("[4] Homomorphic addition...\n");
    nizk_scalar_t m1, r1, m2, r2;
    nizk_scalar_set_u64(&m1, 10); nizk_scalar_set_u64(&r1, 100);
    nizk_scalar_set_u64(&m2, 20); nizk_scalar_set_u64(&r2, 200);
    nizk_commitment_t c1, c2;
    nizk_commitment_opening_t o1, o2;
    nizk_pedersen_commit(&c1, &o1, &m1, &r1, &crs, &p);
    nizk_pedersen_commit(&c2, &o2, &m2, &r2, &crs, &p);
    nizk_commitment_t c_sum;
    nizk_commitment_add(&c_sum, &c1, &c2, &p);
    nizk_commitment_opening_t o_sum;
    nizk_scalar_add(&o_sum.m, &m1, &m2, &p);
    nizk_scalar_add(&o_sum.r, &r1, &r2, &p);
    assert(nizk_pedersen_verify(&c_sum, &o_sum, &crs, &p));
    printf("    Commit(10) + Commit(20) = Commit(30): VALID\n");

    /* NIZK proof of commitment opening */
    printf("[5] NIZK proof of opening knowledge...\n");
    nizk_proof_t pf;
    nizk_proof_init(&pf, NIZK_PROOF_COMMITMENT);
    uint8_t label[] = "com_proof";
    nizk_prove_commitment(&pf, &crs, &com, &open, label, sizeof(label), &p);
    assert(nizk_verify_commitment(&pf, &crs, &com, label, sizeof(label), &p));
    printf("    Proof valid: proves knowledge of (m, r) without revealing them\n");

    /* Vector commitment */
    printf("[6] Vector commitment (3 values)...\n");
    nizk_scalar_t msgs[3];
    nizk_scalar_set_u64(&msgs[0], 1);
    nizk_scalar_set_u64(&msgs[1], 2);
    nizk_scalar_set_u64(&msgs[2], 3);
    nizk_scalar_t vr;
    nizk_scalar_set_u64(&vr, 999);
    nizk_commitment_t vcom;
    nizk_vector_commit(&vcom, msgs, 3, &vr, &crs, &p);
    assert(nizk_vector_verify(&vcom, msgs, 3, &vr, &crs, &p));
    printf("    Vector commitment to [1,2,3]: VALID (single group element)\n");

    nizk_commitment_opening_clear(&open);
    nizk_proof_clear(&pf);
    nizk_crs_clear(&crs);
    nizk_group_params_clear(&p);
    printf("\n=== Commitment Demo Complete ===\n");
    return 0;
}
