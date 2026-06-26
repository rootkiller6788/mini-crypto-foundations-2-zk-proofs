/*======================================================================
 * ip_arithmetization.c -- Arithmetization of Boolean Formulas
 *
 * Implements the full arithmetization pipeline: converting Boolean
 * formulas and circuits into low-degree polynomials over finite
 * fields. This is the essential bridge between logic and algebra
 * that enables interactive proofs to verify computation.
 *
 * Knowledge mapping:
 *   L1: Arithmetization definition -- Boolean-to-algebraic conversion
 *   L2: polynomial extensions, low-degree representations
 *   L3: multivariate polynomials over GF(p), circuit-to-polynomial
 *   L4: Cook-Levin via arithmetization leads to IP=PSPACE
 *   L5: Gate arithmetization (AND/OR/NOT -> algebraic identities)
 *   L6: 3SAT arithmetization, TQBF arithmetization for #SAT
 *   L7: Verification of computation via algebraic methods
 *
 * Gate arithmetization:
 *   NOT(x)   -> 1 - x
 *   AND(x,y) -> x * y
 *   OR(x,y)  -> x + y - x*y
 *   XOR(x,y) -> x + y - 2*x*y (over GF(p) with p > 2)
 *
 * For a Boolean formula phi with gates g_1,...,g_m and inputs
 * x_1,...,x_n, we assign a variable to each gate output and
 * enforce algebraic identities at each gate.
 *
 * Reference:
 *   Shamir. "IP = PSPACE." J. ACM 39(4), 1992.
 *   Babai, Fortnow. "Arithmetization: A new method in structural
 *   complexity theory." Computational Complexity 1, 1991.
 *======================================================================*/

#include "ip_system.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*======================================================================
 * Basic gate arithmetization (L2: Core Concepts, L5: Methods)
 *
 * Each Boolean gate is converted to an algebraic identity over GF(p):
 *   identity == 0 when the gate is correctly evaluated.
 *======================================================================*/

/* Arithmetize a single NOT gate:
 * output = NOT(input)  <==>  output = 1 - input
 * Constraint polynomial: C(x,y) = y - (1 - x) where x=input, y=output
 * Satisfied when C(x,y) = 0.
 */
uint64_t ip_arith_not(uint64_t input, uint64_t prime) {
    return (prime + 1 - (input % prime)) % prime;
}

/* Arithmetize AND gate:
 * output = AND(x1, x2)  <==>  output = x1 * x2
 * Constraint polynomial: C(x1,x2,y) = y - x1*x2
 */
uint64_t ip_arith_and(uint64_t x1, uint64_t x2, uint64_t prime) {
    return ((x1 % prime) * (x2 % prime)) % prime;
}

/* Arithmetize OR gate:
 * output = OR(x1, x2)  <==>  output = x1 + x2 - x1*x2
 * Constraint polynomial: C(x1,x2,y) = y - (x1+x2-x1*x2)
 */
uint64_t ip_arith_or(uint64_t x1, uint64_t x2, uint64_t prime) {
    uint64_t p = prime;
    return (((x1 % p) + (x2 % p)) % p + p - ((x1 % p) * (x2 % p)) % p) % p;
}

/* Arithmetize XOR gate (prime > 2):
 * output = XOR(x1, x2)  <==>  output = x1 + x2 - 2*x1*x2
 */
uint64_t ip_arith_xor(uint64_t x1, uint64_t x2, uint64_t prime) {
    uint64_t p = prime;
    uint64_t term = (2 * ((x1 % p) * (x2 % p)) % p) % p;
    return (((x1 % p) + (x2 % p)) % p + p - term) % p;
}

/* Arithmetize NAND gate (universal gate):
 * output = NAND(x1, x2)  <==>  output = 1 - x1*x2
 */
uint64_t ip_arith_nand(uint64_t x1, uint64_t x2, uint64_t prime) {
    uint64_t p = prime;
    uint64_t prod = ((x1 % p) * (x2 % p)) % p;
    return (p + 1 - prod) % p;
}

/* Arithmetize MAJ3 (majority of 3):
 * output = (x1 AND x2) OR (x2 AND x3) OR (x1 AND x3)
 */
uint64_t ip_arith_maj3(uint64_t x1, uint64_t x2, uint64_t x3, uint64_t prime) {
    uint64_t p = prime;
    uint64_t t12 = ((x1 % p) * (x2 % p)) % p;
    uint64_t t23 = ((x2 % p) * (x3 % p)) % p;
    uint64_t t13 = ((x1 % p) * (x3 % p)) % p;
    /* OR of three terms */
    uint64_t s1 = (t12 + t23) % p;
    uint64_t s1_term = (t12 * t23) % p;
    s1 = (s1 + p - s1_term) % p;
    return (s1 + t13 + p - ((s1 * t13) % p)) % p;
}

/*======================================================================
 * Circuit arithmetization (L3: Mathematical Structures)
 *
 * A Boolean circuit is a DAG where:
 *   - Input gates are labeled with variables x_1,...,x_n
 *   - Internal gates are labeled with AND/OR/NOT
 *   - Output gate gives the circuit value
 *
 * Arithmetization assigns a polynomial to each gate:
 *   - Input gate i: variable X_i (degree 1)
 *   - NOT gate with input a: 1 - A(X)
 *   - AND gate with inputs a,b: A(X) * B(X)
 *   - OR gate with inputs a,b: A(X) + B(X) - A(X)*B(X)
 *
 * The circuit output is a polynomial P(X_1,...,X_n) of degree
 * at most size(C) over GF(p).
 *======================================================================*/

/* Circuit gate types */
#define GATE_INPUT 0
#define GATE_AND   1
#define GATE_OR    2
#define GATE_NOT   3
#define GATE_NAND  4
#define GATE_XOR   5
#define GATE_MAJ3  6

/* Single gate in an arithmetized circuit */
typedef struct {
    int    type;       /* Gate type */
    size_t input_a;    /* First input gate index */
    size_t input_b;    /* Second input gate index (-1 for NOT) */
    size_t input_c;    /* Third input gate index (-1 for MAJ3) */
} ArithGate;

/* Arithmetized circuit */
typedef struct {
    ArithGate *gates;
    size_t     num_gates;
    size_t     num_inputs;
    size_t     output_gate;
    uint64_t   prime;
} ArithCircuit;

int arith_circuit_create(ArithCircuit *circ, size_t num_inputs,
                          uint64_t prime) {
    if (!circ) return -1;
    circ->gates = (ArithGate *)calloc(256, sizeof(ArithGate));
    if (!circ->gates) return -1;
    circ->num_gates = 0;
    circ->num_inputs = num_inputs;
    circ->output_gate = 0;
    circ->prime = prime;

    /* Create input gates */
    for (size_t i = 0; i < num_inputs; i++) {
        circ->gates[i].type = GATE_INPUT;
        circ->gates[i].input_a = i;
        circ->gates[i].input_b = (size_t)-1;
        circ->gates[i].input_c = (size_t)-1;
        circ->num_gates++;
    }
    return 0;
}

void arith_circuit_free(ArithCircuit *circ) {
    if (circ && circ->gates) {
        free(circ->gates);
        circ->gates = NULL;
        circ->num_gates = 0;
    }
}

/* Add a binary gate to the circuit. Returns gate index. */
static size_t add_gate(ArithCircuit *circ, int type,
                        size_t a, size_t b) {
    if (!circ || a >= circ->num_gates || (b != (size_t)-1 && b >= circ->num_gates))
        return (size_t)-1;
    size_t idx = circ->num_gates++;
    circ->gates[idx].type = type;
    circ->gates[idx].input_a = a;
    circ->gates[idx].input_b = b;
    circ->gates[idx].input_c = (size_t)-1;
    return idx;
}

size_t arith_circuit_add_and(ArithCircuit *circ, size_t a, size_t b) {
    return add_gate(circ, GATE_AND, a, b);
}

size_t arith_circuit_add_or(ArithCircuit *circ, size_t a, size_t b) {
    return add_gate(circ, GATE_OR, a, b);
}

size_t arith_circuit_add_not(ArithCircuit *circ, size_t a) {
    return add_gate(circ, GATE_NOT, a, (size_t)-1);
}

size_t arith_circuit_add_nand(ArithCircuit *circ, size_t a, size_t b) {
    return add_gate(circ, GATE_NAND, a, b);
}

size_t arith_circuit_add_xor(ArithCircuit *circ, size_t a, size_t b) {
    return add_gate(circ, GATE_XOR, a, b);
}

/* Evaluate the arithmetized circuit on a Boolean input assignment.
 *
 * For input assignment x in {0,1}^n, compute the polynomial value
 * at each gate and return the output value.
 *
 * The evaluation traverses the circuit in topological order
 * (gates are assumed to be in topologically sorted order).
 */
int arith_circuit_eval(ArithCircuit *circ, const uint64_t *inputs,
                        size_t n, uint64_t *output) {
    if (!circ || !inputs || !output || n != circ->num_inputs) return -1;

    uint64_t p = circ->prime;
    uint64_t *values = (uint64_t *)calloc(circ->num_gates, sizeof(uint64_t));
    if (!values) return -1;

    for (size_t i = 0; i < circ->num_gates; i++) {
        ArithGate *g = &circ->gates[i];
        switch (g->type) {
            case GATE_INPUT:
                values[i] = inputs[g->input_a] % p;
                break;
            case GATE_AND:
                values[i] = ip_arith_and(values[g->input_a],
                                          values[g->input_b], p);
                break;
            case GATE_OR:
                values[i] = ip_arith_or(values[g->input_a],
                                         values[g->input_b], p);
                break;
            case GATE_NOT:
                values[i] = ip_arith_not(values[g->input_a], p);
                break;
            case GATE_NAND:
                values[i] = ip_arith_nand(values[g->input_a],
                                           values[g->input_b], p);
                break;
            case GATE_XOR:
                values[i] = ip_arith_xor(values[g->input_a],
                                          values[g->input_b], p);
                break;
            default:
                free(values); return -1;
        }
    }

    *output = values[circ->output_gate];
    free(values);
    return 0;
}

/*======================================================================
 * Boolean formula to circuit conversion (L6: 3SAT arithmetization)
 *
 * Converts a 3CNF formula to an arithmetized circuit.
 * Each clause (l1 OR l2 OR l3) becomes:
 *   OR(OR(lit(l1), lit(l2)), lit(l3))
 *
 * The full formula (AND of clauses) becomes a tree of AND gates.
 *======================================================================*/

/* Convert one clause to gates. Returns the gate index of clause output.
 *
 * Each literal is encoded as (var << 1) | neg, where neg=1 means negated.
 * For literal (var,neg=0): gate is input var
 * For literal (var,neg=1): gate is NOT(input var)
 */
static size_t build_literal_gate(ArithCircuit *circ, size_t encoded,
                                  size_t num_vars) {
    size_t var = encoded >> 1;
    int neg = (int)(encoded & 1);
    if (var >= num_vars) return (size_t)-1;
    if (neg) {
        return arith_circuit_add_not(circ, var);
    }
    return var; /* Input gate index = var */
}

size_t arith_circuit_add_clause(ArithCircuit *circ,
                                 const size_t *literals, size_t len) {
    if (!circ || !literals || len == 0) return (size_t)-1;

    /* Build literal gates */
    size_t lit_gates[3];
    for (size_t i = 0; i < len && i < 3; i++) {
        lit_gates[i] = build_literal_gate(circ, literals[i],
                                           circ->num_inputs);
        if (lit_gates[i] == (size_t)-1) return (size_t)-1;
    }

    /* OR chain: OR(OR(l1,l2), l3) for 3 literals */
    size_t cur = lit_gates[0];
    for (size_t i = 1; i < len && i < 3; i++) {
        cur = arith_circuit_add_or(circ, cur, lit_gates[i]);
    }
    return cur;
}

/* Build a 3CNF formula as an arithmetized circuit.
 * Returns the index of the output gate (AND of all clauses).
 */
size_t arith_circuit_from_3cnf(ArithCircuit *circ,
                                const size_t **clauses,
                                const size_t *clause_lens,
                                size_t num_clauses) {
    if (!circ || !clauses || !clause_lens) return (size_t)-1;
    if (num_clauses == 0) return (size_t)-1;

    size_t *clause_gates = (size_t *)calloc(num_clauses, sizeof(size_t));
    if (!clause_gates) return (size_t)-1;

    for (size_t i = 0; i < num_clauses; i++) {
        clause_gates[i] = arith_circuit_add_clause(circ,
                                                     clauses[i],
                                                     clause_lens[i]);
        if (clause_gates[i] == (size_t)-1) {
            free(clause_gates);
            return (size_t)-1;
        }
    }

    /* AND chain: all clauses */
    size_t output = clause_gates[0];
    for (size_t i = 1; i < num_clauses; i++) {
        output = arith_circuit_add_and(circ, output, clause_gates[i]);
    }

    circ->output_gate = output;
    free(clause_gates);
    return output;
}

/*======================================================================
 * Multilinear extension from circuit (L4: IP = PSPACE)
 *
 * Given a circuit C with output polynomial P(X_1,...,X_n), the
 * multilinear extension of the Boolean function f(x) = C(x) is
 * precisely P itself when restricted to {0,1}^n.
 *
 * For IP = PSPACE, we need the full polynomial extension to
 * arbitrary field elements. The circuit arithmetization naturally
 * provides this: evaluating the circuit on field elements uses the
 * same algebraic identities, yielding P(r_1,...,r_n) for any
 * r_i in GF(p).
 *
 * This is the key insight of Shamir (1992): the arithmetized
 * circuit IS the low-degree polynomial extension.
 *======================================================================*/

/* Evaluate the arithmetized circuit on arbitrary field elements
 * (not just Boolean values). This gives the polynomial extension
 * value P(r_1,...,r_n) for any r_i in GF(p).
 *
 * The constraint is that inputs must still be treated as variables
 * that can take any field value, while gates must maintain their
 * algebraic identities.
 */
int arith_circuit_eval_field(ArithCircuit *circ, const uint64_t *point,
                              size_t n, uint64_t *output) {
    /* Same as arith_circuit_eval -- the polynomial formulas work
     * for any field elements, not just {0,1}. This is the beauty
     * of arithmetization. */
    return arith_circuit_eval(circ, point, n, output);
}

/*======================================================================
 * TQBF Arithmetization (L4: IP = PSPACE)
 *
 * Given a Quantified Boolean Formula:
 *   Phi = Q_1 x_1 Q_2 x_2 ... Q_n x_n phi(x_1,...,x_n)
 *
 * where Q_i in {exists, forall} and phi is a 3CNF formula,
 * we construct a polynomial identity:
 *
 *   Phi is true  <=>  (Op_1)_{x1} (Op_2)_{x2} ... (Op_n)_{xn} A_phi(x) != 0
 *
 * where:
 *   exists x_i:  Op_i = sum over x_i in {0,1}
 *   forall x_i:  Op_i = product over x_i in {0,1}
 *
 * This gives an arithmetic expression of degree <= size(phi) * n
 * that can be verified using the sumcheck protocol.
 *======================================================================*/

/* Compute one quantifier step:
 * For exists: sum_{x_i in {0,1}} f(x_i, ...)
 * For forall: prod_{x_i in {0,1}} f(x_i, ...)
 *
 * Input: evaluations array of size 2^k (k = n - i + 1)
 * Output: evaluations array of size 2^{k-1} after quantifying variable i
 */
int ip_tqbf_quantify(uint64_t *evaluations, size_t k, int is_forall,
                      uint64_t prime, uint64_t *out) {
    if (!evaluations || !out || k == 0) return -1;

    size_t half = 1ULL << (k - 1);
    uint64_t p = prime;

    for (size_t b = 0; b < half; b++) {
        uint64_t v0 = evaluations[b] % p;
        uint64_t v1 = evaluations[half + b] % p;

        if (is_forall) {
            /* forall: product over x_i in {0,1} */
            out[b] = (v0 * v1) % p;
        } else {
            /* exists: sum over x_i in {0,1} */
            out[b] = (v0 + v1) % p;
        }
    }
    return 0;
}

/* Evaluate a quantified Boolean formula by arithmetization.
 *
 * Input:
 *   num_vars: n
 *   quantifiers: array of 0/1 (0=exists, 1=forall) for each variable
 *   clause data: 3CNF formula phi
 *   prime: field prime
 *
 * Output:
 *   result: non-zero if Phi is true, 0 if false (with high probability)
 *
 * The algorithm:
 *   1. Build evaluation table of phi over all 2^n assignments
 *   2. Apply quantifiers from inner to outer (x_n to x_1)
 *   3. Return final value
 */
int ip_tqbf_arithmetize(size_t num_vars, const int *quantifiers,
                         const size_t **clauses, const size_t *clause_lens,
                         size_t num_clauses, uint64_t prime,
                         uint64_t *result) {
    if (!quantifiers || !clauses || !clause_lens || !result) return -1;

    size_t total = 1ULL << num_vars;
    uint64_t *evals = (uint64_t *)calloc(total, sizeof(uint64_t));
    if (!evals) return -1;

    /* Step 1: evaluate phi on all 2^n assignments */
    for (size_t x = 0; x < total; x++) {
        /* Convert x to bit assignment */
        uint64_t assignment[64] = {0};
        for (size_t i = 0; i < num_vars && i < 64; i++) {
            assignment[i] = (x >> i) & 1;
        }

        uint64_t phi_val;
        if (ip_arithmetize_3cnf(clauses, clause_lens, num_clauses,
                                 assignment, num_vars, prime,
                                 &phi_val) != 0) {
            free(evals); return -1;
        }
        evals[x] = phi_val;
    }

    /* Step 2: apply quantifiers from inner to outer */
    uint64_t *current = evals;
    uint64_t *next = (uint64_t *)calloc(total / 2, sizeof(uint64_t));
    if (!next) { free(evals); return -1; }

    size_t k = num_vars;
    for (size_t step = 0; step < num_vars; step++) {
        int q = quantifiers[num_vars - 1 - step]; /* inner to outer */
        if (ip_tqbf_quantify(current, k, q == 1, prime, next) != 0) {
            free(evals); free(next); return -1;
        }
        k--;
        /* Swap buffers */
        uint64_t *tmp = current;
        current = next;
        next = tmp;
    }

    *result = current[0] % prime;

    /* Point current to correct buffer before freeing */
    if (current == next) {
        /* next was the final buffer; evals is the other one */
        free(evals);
        free(next);
    } else {
        free(evals);
        free(next);
    }
    return 0;
}

/*======================================================================
 * Low-degree extension construction (L5: Methods, L8: PCP connection)
 *
 * A low-degree extension (LDE) of a function f: H^m -> F is a
 * polynomial P: F^m -> F of individual degree < |H| that agrees
 * with f on H^m. LDEs are fundamental to PCP constructions and
 * the GKR protocol.
 *
 * For the Boolean hypercube H = {0,1}, the multilinear extension
 * is precisely the unique LDE with individual degree 1.
 *
 * For larger domains H, we use Lagrange interpolation over H
 * to construct the LDE.
 *======================================================================*/

/* Lagrange basis polynomial L_i(x) over evaluation points x_0,...,x_{d-1}.
 *
 * L_i(x) = product_{j != i} (x - x_j) / (x_i - x_j)
 *
 * For the Boolean hypercube H = {0,1}, L_0(x) = 1-x, L_1(x) = x.
 */
uint64_t ip_lagrange_basis(size_t i, uint64_t x, const uint64_t *points,
                            size_t d, uint64_t prime) {
    uint64_t p = prime;
    uint64_t num = 1, den = 1;

    for (size_t j = 0; j < d; j++) {
        if (j == i) continue;
        /* numerator: (x - x_j) mod p */
        uint64_t xj = points[j] % p;
        if (x >= xj) {
            num = (num * ((x - xj) % p)) % p;
        } else {
            num = (num * ((p - ((xj - x) % p)) % p)) % p;
        }
        /* denominator: (x_i - x_j) mod p */
        uint64_t xi = points[i] % p;
        if (xi >= xj) {
            den = (den * ((xi - xj) % p)) % p;
        } else {
            den = (den * ((p - ((xj - xi) % p)) % p)) % p;
        }
    }

    /* Multiply by den^{-1} */
    uint64_t inv_den = 1;
    /* Simple modular inverse for small primes */
    for (uint64_t k = 1; k < p; k++) {
        if ((den * k) % p == 1) { inv_den = k; break; }
    }
    return (num * inv_den) % p;
}

/*======================================================================
 * Polynomial degree reduction (L5: Methods)
 *
 * In the sumcheck protocol for non-multilinear polynomials, the
 * prover sends a degree-d univariate polynomial in each round
 * (where d is the degree in the current variable).
 *
 * For multilinear polynomials, d=1 (simple). For higher-degree
 * polynomials (as in PCP constructions), the prover must send
 * d+1 coefficients.
 *======================================================================*/

/* Compute the degree of the product of two multilinear polynomials.
 * Since multilinear * multilinear = degree 2 in each variable,
 * the total degree is at most 2n.
 */
size_t ip_product_degree(size_t deg_a, size_t deg_b) {
    return deg_a + deg_b;
}

/* Compute the individual degree in variable i of a polynomial.
 * For a multilinear polynomial, this is 1 for all variables.
 * For an arithmetized circuit of size s, the degree can be as
 * high as size(C).
 */
size_t ip_individual_degree(size_t circuit_size) {
    /* Worst-case: chain of AND gates doubles degree each step */
    /* In practice, for multilinear arithmetization, degree <= size */
    return circuit_size;
}