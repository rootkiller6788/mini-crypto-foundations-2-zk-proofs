/* circuit_to_r1cs.h — arithmetic circuit → R1CS conversion
 *
 * Converts arithmetic circuits (directed acyclic graphs of add/mul gates)
 * into R1CS form. This is the standard compilation pipeline used by all
 * modern SNARK toolchains (libsnark, Circom, ZoKrates, etc.).
 *
 * Arithmetic circuit definition:
 *   - Nodes: constant inputs, variable inputs, add gates, mul gates
 *   - Edges: wires carrying values
 *   - Constraints: each mul gate ⇒ one R1CS constraint
 *   - Add gates are "free" (absorbed into linear combinations)
 *
 * Key concepts:
 *   - Circuit flattening: convert nested expressions to flat gates
 *   - R1CS variable assignment: one variable per wire
 *   - Signal flow: forward propagation from inputs to outputs
 *   - Gate → constraint mapping: one-to-one for mul gates
 *
 * References:
 *   - Ben-Sasson et al. (2013) "SNARKs for C" (Pinocchio compilation)
 *   - Parno, Howell, Gentry, Raykova (2013) "Pinocchio: Nearly Practical VC"
 *   - circom language: https://docs.circom.io/
 */
#ifndef CIRCUIT_TO_R1CS_H
#define CIRCUIT_TO_R1CS_H
#include "r1cs.h"
#include "field.h"
#include <stdint.h>

/* ─── Gate types ─── */
typedef enum {
    GATE_INPUT,       /* wire from external input */
    GATE_CONSTANT,    /* fixed constant value */
    GATE_ADD,         /* a + b */
    GATE_MUL,         /* a * b (generates one R1CS constraint) */
    GATE_OUTPUT       /* designated output wire */
} GateType;

/* ─── Arithmetic circuit ─── */
typedef struct ArithmeticCircuit ArithmeticCircuit;

/* ─── Gate ─── */
typedef struct {
    GateType type;
    int      id;
    int      input_a;     /* wire id of first input (-1 for constant gate) */
    int      input_b;     /* wire id of second input */
    int      output_wire; /* assigned wire id */
    fe_t     constant;    /* for GATE_CONSTANT */
} Gate;

/* ─── Wire ─── */
typedef struct {
    int    id;
    fe_t   value;
    int    is_assigned;
} Wire;

/* ─── Circuit ─── */
struct ArithmeticCircuit {
    Gate*  gates;
    Wire*  wires;
    int    n_gates;
    int    n_wires;
    int    n_inputs;
    int    n_outputs;
    int    gate_capacity;
    int    wire_capacity;
};

/* ─── Lifecycle ─── */
ArithmeticCircuit* circuit_create(int max_gates, int max_wires);
void               circuit_free(ArithmeticCircuit* c);

/* ─── Gate/wire creation ─── */
int  circuit_add_input(ArithmeticCircuit* c);          /* returns wire id */
int  circuit_add_constant(ArithmeticCircuit* c, const fe_t val,
                          const FieldParams* fp);      /* returns wire id */
int  circuit_add_wire(ArithmeticCircuit* c);           /* intermediate wire */
int  circuit_add_gate(ArithmeticCircuit* c, GateType type,
                      int input_a, int input_b);       /* returns output wire id */
void circuit_mark_output(ArithmeticCircuit* c, int wire_id);

/* ─── Evaluation ─── */
int  circuit_evaluate(ArithmeticCircuit* c, const fe_t* inputs,
                      int n_inputs, const FieldParams* fp);

/* ─── Circuit → R1CS ─── */
/* Each multiplication gate produces one R1CS constraint.
   Addition/subtraction gates are handled as linear combinations.
   Returns a new R1CS instance. */
R1CS* circuit_to_r1cs(const ArithmeticCircuit* c, const FieldParams* fp);

/* ─── Circuit construction helpers ─── */
/* Build a circuit for: y = x^3 + x + 5 (the classic SNARK demo) */
ArithmeticCircuit* circuit_build_demo_x3_plus_x_plus_5(const FieldParams* fp);

/* Build a circuit for: SHA256 compression (simplified) */
ArithmeticCircuit* circuit_build_sha256_round(const FieldParams* fp);

/* Build a circuit for: Merkle tree inclusion proof */
ArithmeticCircuit* circuit_build_merkle_verify(int depth, const FieldParams* fp);

/* Build a circuit for: matrix multiplication C = A × B (n×n) */
ArithmeticCircuit* circuit_build_matrix_mul(int n, const FieldParams* fp);

/* ─── Circuit analysis ─── */
int  circuit_count_mul_gates(const ArithmeticCircuit* c);
int  circuit_count_add_gates(const ArithmeticCircuit* c);
int  circuit_total_wires(const ArithmeticCircuit* c);
void circuit_print(const ArithmeticCircuit* c);

#endif /* CIRCUIT_TO_R1CS_H */
