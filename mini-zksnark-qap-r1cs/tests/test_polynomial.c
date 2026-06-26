// test_polynomial.c - Tests for polynomial operations
#include <stdio.h>
#include <assert.h>
#include "polynomial.h"

int main(void) {
    FieldParams fp = FIELD_BN254;
    fe_t coeff_a, x, result;

    // Test poly_create and basic operations
    Polynomial* p = poly_create(3);
    assert(p != NULL);
    assert(poly_degree(p) == 0);

    // Set p(x) = 3 + 2x + x^2
    fe_from_uint64(coeff_a, 3);
    poly_set_constant(p, coeff_a);
    fe_from_uint64(coeff_a, 2); 
    fe_set(p->coeffs[1], coeff_a);
    fe_from_uint64(coeff_a, 1);
    fe_set(p->coeffs[2], coeff_a);
    p->degree = 2;
    assert(poly_degree(p) == 2);

    // Evaluate p(2) = 3 + 2*2 + 1*4 = 11
    fe_from_uint64(x, 2);
    poly_eval(result, p, x, &fp);
    fe_t expected; fe_from_uint64(expected, 11);
    assert(fe_equal(result, expected));

    // Test poly_add
    Polynomial* q = poly_create(1);
    fe_from_uint64(coeff_a, 5);
    poly_set_constant(q, coeff_a);
    fe_from_uint64(coeff_a, 3);
    fe_set(q->coeffs[1], coeff_a);
    q->degree = 1;

    Polynomial* sum = poly_create(3);
    poly_add(sum, p, q, &fp);
    assert(poly_degree(sum) == 2);
    // sum(x) = 8 + 5x + x^2

    // Test poly_mul
    Polynomial* prod = poly_create(5);
    poly_mul(prod, p, q, &fp);
    assert(poly_degree(prod) == 3);
    // prod(x) = 15 + 19x + 11x^2 + 3x^3

    // Test poly_mul_scalar
    fe_from_uint64(coeff_a, 2);
    Polynomial* scaled = poly_create(3);
    poly_mul_scalar(scaled, p, coeff_a, &fp);
    // scaled(x) = 6 + 4x + 2x^2

    // Test poly_copy
    Polynomial* copy = poly_copy(p);
    assert(copy != NULL);
    assert(poly_degree(copy) == poly_degree(p));

    // Test poly_trim
    p->coeffs[2][0] = 0; p->coeffs[2][1] = 0;
    p->coeffs[2][2] = 0; p->coeffs[2][3] = 0;
    poly_trim(p);
    assert(poly_degree(p) == 1);

    // Test vanishing polynomial
    fe_t domain[2];
    fe_from_uint64(domain[0], 0);
    fe_from_uint64(domain[1], 1);
    Polynomial* z = vanishing_polynomial(domain, 2, &fp);
    assert(z != NULL);
    // Z(x) = (x-0)*(x-1) = x^2 - x
    fe_from_uint64(x, 0);
    poly_eval(result, z, x, &fp);
    assert(fe_is_zero(result));
    fe_from_uint64(x, 1);
    poly_eval(result, z, x, &fp);
    assert(fe_is_zero(result));

    // Cleanup
    poly_free(p); poly_free(q); poly_free(sum);
    poly_free(prod); poly_free(scaled); poly_free(copy);
    poly_free(z);

    printf("All polynomial tests passed!");    return 0;
}
