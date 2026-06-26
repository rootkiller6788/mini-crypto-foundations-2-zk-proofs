#ifndef MINI_IP_PROTOCOLS_H
#define MINI_IP_PROTOCOLS_H
#include "ip_system.h"
typedef struct { int n; uint64_t adj[64]; } IPGraph;
typedef struct { int n; int mapping[64]; } IPPermutation;
typedef struct { IPGraph G0, G1, H; int b, b_prime; IPPermutation pi; } IPGNIState;
typedef struct { uint64_t N, x, s, r, sqrt_x, z; int b; } IPQRState;
int ip_graph_init(IPGraph *g, int n, const int *edges, size_t num_edges);
int ip_graph_is_isomorphic(const IPGraph *g0, const IPGraph *g1, IPPermutation *witness);
int ip_graph_permute(const IPGraph *g, const IPPermutation *pi, IPGraph *out);
int ip_permutation_random(IPPermutation *pi, int n);
int ip_gni_prover_strategy(const char *input, size_t input_len, const char *witness, size_t witness_len, const IPTranscript *transcript, const IPMessage *challenge, IPMessage *response);
int ip_gni_verifier_challenge(const char *input, size_t input_len, const IPTranscript *transcript, IPRandomTape *tape, IPMessage *challenge);
int ip_gni_verifier_decide(const char *input, size_t input_len, const IPTranscript *transcript, IPVerdict *verdict);
int ip_gni_proof_system_create(IPProofSystem *psys, const IPGraph *g0, const IPGraph *g1);
int ip_qr_prover_strategy(const char *input, size_t input_len, const char *witness, size_t witness_len, const IPTranscript *transcript, const IPMessage *challenge, IPMessage *response);
int ip_qr_verifier_challenge(const char *input, size_t input_len, const IPTranscript *transcript, IPRandomTape *tape, IPMessage *challenge);
int ip_qr_verifier_decide(const char *input, size_t input_len, const IPTranscript *transcript, IPVerdict *verdict);
int ip_qr_proof_system_create(IPProofSystem *psys, uint64_t N, uint64_t x, uint64_t sqrt_x);
int ip_graph_serialize(const IPGraph *g, uint8_t *buf, size_t *len);
int ip_graph_deserialize(const uint8_t *buf, size_t len, IPGraph *g);
#endif
