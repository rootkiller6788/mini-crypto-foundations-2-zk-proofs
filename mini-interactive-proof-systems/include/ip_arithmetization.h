#ifndef MINI_IP_ARITHMETIZATION_H
#define MINI_IP_ARITHMETIZATION_H
#include "ip_system.h"

/* Arithmetization of Boolean formulas to low-degree polynomials.
 * Gate identities over GF(p): NOT(x)=1-x, AND(x,y)=x*y, OR(x,y)=x+y-xy.
 * Shamir (1992): IP = PSPACE via arithmetization + sumcheck. */

#define GATE_INPUT 0
#define GATE_AND   1
#define GATE_OR    2
#define GATE_NOT   3
#define GATE_NAND  4
#define GATE_XOR   5
#define GATE_MAJ3  6

typedef struct { int type; size_t input_a, input_b, input_c; } ArithGate;
typedef struct {
    ArithGate *gates;
    size_t num_gates, num_inputs, output_gate;
    uint64_t prime;
} ArithCircuit;

uint64_t ip_arith_not(uint64_t input, uint64_t prime);
uint64_t ip_arith_and(uint64_t x1, uint64_t x2, uint64_t prime);
uint64_t ip_arith_or(uint64_t x1, uint64_t x2, uint64_t prime);
uint64_t ip_arith_xor(uint64_t x1, uint64_t x2, uint64_t prime);
uint64_t ip_arith_nand(uint64_t x1, uint64_t x2, uint64_t prime);
uint64_t ip_arith_maj3(uint64_t x1, uint64_t x2, uint64_t x3, uint64_t prime);

int arith_circuit_create(ArithCircuit *circ, size_t num_inputs, uint64_t prime);
void arith_circuit_free(ArithCircuit *circ);
size_t arith_circuit_add_and(ArithCircuit *circ, size_t a, size_t b);
size_t arith_circuit_add_or(ArithCircuit *circ, size_t a, size_t b);
size_t arith_circuit_add_not(ArithCircuit *circ, size_t a);
size_t arith_circuit_add_nand(ArithCircuit *circ, size_t a, size_t b);
size_t arith_circuit_add_xor(ArithCircuit *circ, size_t a, size_t b);
size_t arith_circuit_add_clause(ArithCircuit *circ, const size_t *literals, size_t len);
size_t arith_circuit_from_3cnf(ArithCircuit *circ, const size_t **clauses,
                                const size_t *clause_lens, size_t num_clauses);
int arith_circuit_eval(ArithCircuit *circ, const uint64_t *inputs,
                        size_t n, uint64_t *output);
int arith_circuit_eval_field(ArithCircuit *circ, const uint64_t *point,
                              size_t n, uint64_t *output);
int ip_tqbf_quantify(uint64_t *evaluations, size_t k, int is_forall,
                      uint64_t prime, uint64_t *out);
int ip_tqbf_arithmetize(size_t num_vars, const int *quantifiers,
                         const size_t **clauses, const size_t *clause_lens,
                         size_t num_clauses, uint64_t prime, uint64_t *result);
uint64_t ip_lagrange_basis(size_t i, uint64_t x, const uint64_t *points,
                            size_t d, uint64_t prime);
size_t ip_product_degree(size_t deg_a, size_t deg_b);
size_t ip_individual_degree(size_t circuit_size);

#endif /* MINI_IP_ARITHMETIZATION_H */