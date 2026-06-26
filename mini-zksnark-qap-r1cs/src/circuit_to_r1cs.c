// circuit_to_r1cs.c - Arithmetic circuit to R1CS compiler
// Converts arithmetic circuits (DAG of add/mul gates) to R1CS constraints.
// Standard compilation pipeline for all modern SNARK toolchains.
// Knowledge: L5 Algorithm (circuit flattening, gate-to-constraint mapping)

#include "circuit_to_r1cs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

ArithmeticCircuit* circuit_create(int max_gates, int max_wires) {
 ArithmeticCircuit* c=(ArithmeticCircuit*)malloc(sizeof(ArithmeticCircuit));
 if(!c)return 0;
 c->gates=(Gate*)calloc((size_t)max_gates,sizeof(Gate));
 c->wires=(Wire*)calloc((size_t)max_wires,sizeof(Wire));
 c->n_gates=0;c->n_wires=0;c->n_inputs=0;c->n_outputs=0;
 c->gate_capacity=max_gates;c->wire_capacity=max_wires;return c;}
void circuit_free(ArithmeticCircuit* c){if(c){free(c->gates);free(c->wires);free(c);}}
int circuit_add_input(ArithmeticCircuit* c){
 int w=c->n_wires++;c->wires[w].id=w;c->wires[w].is_assigned=0;
 c->n_inputs++;return w;}
int circuit_add_constant(ArithmeticCircuit* c, const fe_t val, const FieldParams* fp){
 int w=c->n_wires++;c->wires[w].id=w;fe_set(c->wires[w].value,val);
 c->wires[w].is_assigned=1;(void)fp;
 Gate g;g.type=GATE_CONSTANT;g.id=c->n_gates++;g.input_a=-1;g.input_b=-1;
 g.output_wire=w;fe_set(g.constant,val);c->gates[g.id]=g;return w;}
int circuit_add_wire(ArithmeticCircuit* c){
 int w=c->n_wires++;c->wires[w].id=w;c->wires[w].is_assigned=0;return w;}

int circuit_add_gate(ArithmeticCircuit* c, GateType type, int a, int b) {
    Gate g; g.type = type; g.id = c->n_gates++;
    g.input_a = a; g.input_b = b;
    g.output_wire = c->n_wires;
    c->wires[g.output_wire].id = g.output_wire;
    c->wires[g.output_wire].is_assigned = 0;
    fe_zero(g.constant);
    c->gates[g.id] = g;
    c->n_wires++;
    return g.output_wire;
}

void circuit_mark_output(ArithmeticCircuit* c, int wire_id) {
    c->n_outputs++;
    Gate g; g.type = GATE_OUTPUT; g.id = c->n_gates++;
    g.input_a = wire_id; g.input_b = -1; g.output_wire = wire_id;
    fe_zero(g.constant); c->gates[g.id] = g;
}

int circuit_evaluate(ArithmeticCircuit* c, const fe_t* inputs, int n_inputs, const FieldParams* fp) {
    /* Assign input values */
    for (int i = 0; i < n_inputs && i < c->n_inputs; i++) {
        fe_set(c->wires[i].value, inputs[i]);
        c->wires[i].is_assigned = 1;
    }
    /* Evaluate gates in topological order (assumes gates are sorted) */
    for (int i = 0; i < c->n_gates; i++) {
        Gate* g = &c->gates[i];
        if (g->type == GATE_CONSTANT) {
            fe_set(c->wires[g->output_wire].value, g->constant);
            c->wires[g->output_wire].is_assigned = 1;
        } else if (g->type == GATE_ADD) {
            fe_add(c->wires[g->output_wire].value,
                   c->wires[g->input_a].value,
                   c->wires[g->input_b].value, fp);
            c->wires[g->output_wire].is_assigned = 1;
        } else if (g->type == GATE_MUL) {
            fe_mul(c->wires[g->output_wire].value,
                   c->wires[g->input_a].value,
                   c->wires[g->input_b].value, fp);
            c->wires[g->output_wire].is_assigned = 1;
        }
    }
    return c->n_wires > 0 ? 0 : -1;
}

R1CS* circuit_to_r1cs(const ArithmeticCircuit* c, const FieldParams* fp) {
    int m = 0;
    /* Count multiplication gates */
    for (int i = 0; i < c->n_gates; i++)
        if (c->gates[i].type == GATE_MUL) m++;
    R1CS* r = r1cs_create(m, c->n_wires + 1, c->n_inputs);
    if (!r) return NULL;
    int c_idx = 0;
    fe_t one; fe_one(one);
    for (int i = 0; i < c->n_gates; i++) {
        Gate* g = &c->gates[i];
        if (g->type == GATE_MUL) {
            /* A: left input, B: right input, C: output */
            int varsA[] = {g->input_a}; fe_t coeffsA[1]; fe_one(coeffsA[0]);
            int varsB[] = {g->input_b}; fe_t coeffsB[1]; fe_one(coeffsB[0]);
            int varsC[] = {g->output_wire}; fe_t coeffsC[1]; fe_one(coeffsC[0]);
            r1cs_add_constraint_A(r, c_idx, varsA, coeffsA, 1, fp);
            r1cs_add_constraint_B(r, c_idx, varsB, coeffsB, 1, fp);
            r1cs_add_constraint_C(r, c_idx, varsC, coeffsC, 1, fp);
            c_idx++;
        }
    }
    return r;
}

ArithmeticCircuit* circuit_build_demo_x3_plus_x_plus_5(const FieldParams* fp) {
    /* y = x^3 + x + 5
     * Gates: w0=x(input), w1=5(constant), w2=w0*w0, w3=w2*w0, w4=w3+w0, w5=w4+w1(output) */
    ArithmeticCircuit* c = circuit_create(10, 20);
    if (!c) return NULL;
    int x   = circuit_add_input(c);
    /* Add constant 5 as a wire */
    { fe_t five; fe_from_uint64(five, 5);
      int c5_wire = circuit_add_constant(c, five, fp);
      (void)c5_wire; /* wire id tracked by circuit */
    }
    /* x^2 */
    int x2  = circuit_add_gate(c, GATE_MUL, x, x);
    /* x^3 */
    int x3  = circuit_add_gate(c, GATE_MUL, x2, x);
    /* x^3 + x */
    int t1  = circuit_add_gate(c, GATE_ADD, x3, x);
    /* (x^3+x) + 5 */
    int y   = circuit_add_gate(c, GATE_ADD, t1, 1); /* 1 = constant wire id */
    circuit_mark_output(c, y);
    return c;
}

ArithmeticCircuit* circuit_build_sha256_round(const FieldParams* fp) {
    /* Simplified SHA256 round: 2 additions + 2 multiplications per path */
    ArithmeticCircuit* c = circuit_create(50, 100);
    if (!c) return NULL;
    /* Inputs: prev_hash[4], message[4], nonce */
    int h[4], m[4], nonce;
    for (int i = 0; i < 4; i++) h[i] = circuit_add_input(c);
    for (int i = 0; i < 4; i++) m[i] = circuit_add_input(c);
    nonce = circuit_add_input(c);
    /* Simple round: tmp = (h+nonce)*(m+nonce) then add back */
    int t1 = circuit_add_gate(c, GATE_ADD, h[0], nonce);
    int t2 = circuit_add_gate(c, GATE_ADD, m[0], nonce);
    int mul1 = circuit_add_gate(c, GATE_MUL, t1, t2);
    int out = circuit_add_gate(c, GATE_ADD, mul1, h[1]);
    circuit_mark_output(c, out);
    (void)fp;
    return c;
}

ArithmeticCircuit* circuit_build_merkle_verify(int depth, const FieldParams* fp) {
    /* Merkle tree: hash(left, right) = (L+R)^2 simplified */
    ArithmeticCircuit* c = circuit_create(depth * 4, depth * 8);
    if (!c) return NULL;
    int leaf = circuit_add_input(c);
    int cur = leaf;
    for (int i = 0; i < depth; i++) {
        int sibling = circuit_add_input(c);
        int sum = circuit_add_gate(c, GATE_ADD, cur, sibling);
        cur = circuit_add_gate(c, GATE_MUL, sum, sum);
    }
    circuit_mark_output(c, cur);
    (void)fp;
    return c;
}

ArithmeticCircuit* circuit_build_matrix_mul(int n, const FieldParams* fp) {
    int total_muls = n * n * n;
    int total_adds = n * n * (n - 1);
    ArithmeticCircuit* c = circuit_create(total_muls + total_adds + n, 4*n*n);
    if (!c) return NULL;
    int* a_wires = (int*)malloc((size_t)(n*n) * sizeof(int));
    int* b_wires = (int*)malloc((size_t)(n*n) * sizeof(int));
    for (int i = 0; i < n*n; i++) a_wires[i] = circuit_add_input(c);
    for (int i = 0; i < n*n; i++) b_wires[i] = circuit_add_input(c);
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {
            int accum = -1;
            for (int k = 0; k < n; k++) {
                int prod = circuit_add_gate(c, GATE_MUL, a_wires[i*n+k], b_wires[k*n+j]);
                accum = (accum < 0) ? prod : circuit_add_gate(c, GATE_ADD, accum, prod);
            }
            circuit_mark_output(c, accum);
        }
    }
    free(a_wires); free(b_wires); (void)fp; return c;
}
int circuit_count_mul_gates(const ArithmeticCircuit* c) {
    int cnt=0; for(int i=0;i<c->n_gates;i++) if(c->gates[i].type==GATE_MUL)cnt++; return cnt; }
int circuit_count_add_gates(const ArithmeticCircuit* c) {
    int cnt=0; for(int i=0;i<c->n_gates;i++) if(c->gates[i].type==GATE_ADD)cnt++; return cnt; }
int circuit_total_wires(const ArithmeticCircuit* c) { return c->n_wires; }
void circuit_print(const ArithmeticCircuit* c) {
    printf("Circuit: %d gates (%d mul %d add), %d wires, %d in, %d out\n",
           c->n_gates,circuit_count_mul_gates(c),circuit_count_add_gates(c),
           c->n_wires,c->n_inputs,c->n_outputs); }
