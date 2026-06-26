// test_r1cs.c - Tests for R1CS constraint system
#include <stdio.h>
#include <assert.h>
#include "r1cs.h"

int main(void) {
    FieldParams fp = FIELD_BN254;
    
    // Create R1CS: single constraint x*y = z
    R1CS* r = r1cs_create(1, 4, 2);
    assert(r != NULL);
    assert(r->n_constraints == 1);
    assert(r->n_vars == 4);
    assert(r->n_pub_inputs == 2);
    
    // Add constraint: (1*x) * (1*y) = (1*z)
    // Variables: 0=constant(1), 1=x, 2=y, 3=z
    int varsA[] = {1}; fe_t coeffsA[1]; fe_from_uint64(coeffsA[0], 1);
    int varsB[] = {2}; fe_t coeffsB[1]; fe_from_uint64(coeffsB[0], 1);
    int varsC[] = {3}; fe_t coeffsC[1]; fe_from_uint64(coeffsC[0], 1);
    r1cs_add_full_constraint(r, 0, varsA, coeffsA, 1, varsB, coeffsB, 1, varsC, coeffsC, 1, &fp);
    
    // Valid witness: x=3, y=4, z=12 => 3*4=12
    fe_t witness[4];
    fe_one(witness[0]);        // constant = 1
    fe_from_uint64(witness[1], 3);   // x = 3
    fe_from_uint64(witness[2], 4);   // y = 4
    fe_from_uint64(witness[3], 12);  // z = 12
    
    int ok = r1cs_verify(r, witness, &fp);
    assert(ok == 1);
    
    // Invalid witness: x=3, y=5, z=12 => 3*5=15 != 12
    fe_from_uint64(witness[2], 5);
    ok = r1cs_verify(r, witness, &fp);
    assert(ok == 0);
    
    // Test witness management
    Witness* w = witness_create(4);
    assert(w != NULL);
    witness_set(w, 0, (const fe_t){1,0,0,0}, &fp);
    witness_set(w, 1, (const fe_t){3,0,0,0}, &fp);
    assert(!fe_is_zero(w->values[0]));
    
    // Test copy
    R1CS* r2 = r1cs_copy(r);
    assert(r2 != NULL);
    assert(r2->n_constraints == r->n_constraints);
    ok = r1cs_verify(r2, witness, &fp);
    assert(ok == 0); // still invalid witness
    
    // Cleanup
    witness_free(w);
    r1cs_free(r2);
    r1cs_free(r);
    
    printf("All R1CS tests passed!");    return 0;
}
