#ifndef MINI_IP_GKR_H
#define MINI_IP_GKR_H
#include "ip_system.h"

/* GKR Protocol (Goldwasser-Kalai-Rothblum 2008/2015)
 * Doubly-efficient interactive proofs for layered circuits.
 * Verifier: O(d log |C|) time. Prover: poly(|C|) time. */

#define GKR_MAX_LAYERS    32
#define GKR_MAX_LAYER_SIZE 12

typedef enum {
    GKR_GATE_PLUS  = 0,
    GKR_GATE_TIMES = 1,
    GKR_GATE_XOR   = 2,
    GKR_GATE_ID    = 3,
    GKR_GATE_CONST = 4
} GKRGateType;

typedef struct {
    size_t layer_idx, num_inputs, num_outputs, num_layers;
    size_t layer_sizes[GKR_MAX_LAYERS];
    size_t *left_inputs, *right_inputs, *layer_offsets;
    GKRGateType *gate_types;
    uint64_t prime;
} GKRLayeredCircuit;

int gkr_circuit_init(GKRLayeredCircuit *circ, const size_t *layer_sizes,
                      size_t num_layers, uint64_t prime);
void gkr_circuit_free(GKRLayeredCircuit *circ);
int gkr_circuit_set_gate(GKRLayeredCircuit *circ, size_t layer,
                          size_t gate_idx, size_t left, size_t right,
                          GKRGateType type);
uint64_t gkr_evaluate_layer(const GKRLayeredCircuit *circ, size_t layer,
                             const uint64_t *gate_values, const uint64_t *point_z,
                             uint64_t prime);
int gkr_verify(const GKRLayeredCircuit *circ, const uint64_t *input_values,
               uint64_t claimed_output, int *accepted);
uint64_t gkr_prover_evaluate(const GKRLayeredCircuit *circ, size_t layer,
                              const uint64_t *gate_values, const uint64_t *point);

#endif /* MINI_IP_GKR_H */