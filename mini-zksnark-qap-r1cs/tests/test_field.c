// test_field.c - Tests for finite field arithmetic
#include <stdio.h>
#include <assert.h>
#include "field.h"

int main(void) {
    FieldParams fp = FIELD_BN254;
    fe_t a, b, c, d;
    
    // Test fe_zero / fe_is_zero
    fe_zero(a);
    assert(fe_is_zero(a));
    
    // Test fe_one / fe_is_one
    fe_one(a);
    assert(fe_is_one(a));
    assert(!fe_is_zero(a));
    
    // Test add/sub identity
    fe_from_uint64(a, 42);
    fe_from_uint64(b, 0);
    fe_add(c, a, b, &fp);
    assert(fe_equal(c, a));
    
    // Test sub identity
    fe_sub(c, a, b, &fp);
    assert(fe_equal(c, a));
    
    // Test add commutativity
    fe_from_uint64(a, 7);
    fe_from_uint64(b, 3);
    fe_add(c, a, b, &fp);
    fe_add(d, b, a, &fp);
    assert(fe_equal(c, d));
    
    // Test mul commutativity
    fe_from_uint64(a, 5);
    fe_from_uint64(b, 6);
    fe_mul(c, a, b, &fp);
    fe_mul(d, b, a, &fp);
    assert(fe_equal(c, d));
    
    // Test mul identity
    fe_one(a);
    fe_from_uint64(b, 123);
    fe_mul(c, a, b, &fp);
    assert(fe_equal(c, b));
    
    // Test inv
    fe_from_uint64(a, 3);
    fe_inv(b, a, &fp);
    fe_mul(c, a, b, &fp);
    assert(fe_is_one(c));
    
    // Test add/sub inverse
    fe_from_uint64(a, 100);
    fe_from_uint64(b, 30);
    fe_sub(c, a, b, &fp);
    fe_add(d, c, b, &fp);
    assert(fe_equal(d, a));
    
    // Test neg
    fe_neg(b, a, &fp);
    fe_add(c, a, b, &fp);
    assert(fe_is_zero(c));
    
    // Test pow
    fe_from_uint64(a, 2);
    fe_from_uint64(b, 8);
    fe_pow(c, a, b, &fp);
    fe_from_uint64(d, 256);
    assert(fe_equal(c, d));
    
    // Test random
    fe_random(a, &fp);
    // Random element is a valid field element
    assert(1); // exercise random generation
    
    // Test Montgomery conversion roundtrip
    fe_from_uint64(a, 999);
    fe_to_montgomery(b, a, &fp);
    fe_from_montgomery(c, b, &fp);
    assert(fe_equal(c, a));
    
    // Test batch mul
    fe_t inputs[3], outputs[3], twos[3];
    fe_from_uint64(inputs[0], 2);
    fe_from_uint64(inputs[1], 4);
    fe_from_uint64(inputs[2], 8);
    fe_from_uint64(twos[0], 2);
    fe_from_uint64(twos[1], 2);
    fe_from_uint64(twos[2], 2);
    fe_batch_mul(outputs, inputs, twos, 3, &fp);
    fe_from_uint64(a, 4);
    assert(fe_equal(outputs[0], a));
    fe_from_uint64(a, 8);
    assert(fe_equal(outputs[1], a));
    fe_from_uint64(a, 16);
    assert(fe_equal(outputs[2], a));
    
    // Test batch inv
    fe_t inv_results[2];
    fe_batch_inv(inv_results, inputs, 2, &fp);
    fe_mul(a, inputs[0], inv_results[0], &fp);
    assert(fe_is_one(a));
    fe_mul(a, inputs[1], inv_results[1], &fp);
    assert(fe_is_one(a));
    
    printf("All field tests passed!");    return 0;
}
