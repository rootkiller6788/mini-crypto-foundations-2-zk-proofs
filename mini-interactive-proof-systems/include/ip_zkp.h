#ifndef MINI_IP_ZK_PROOFS_H
#define MINI_IP_ZK_PROOFS_H
#include "ip_system.h"
#include "ip_protocols.h"

/* Zero-Knowledge Interactive Proof Systems (L7)
 * Goldwasser-Micali-Rackoff 1985/89, Goldreich-Micali-Wigderson 1991.
 */

typedef enum {
    ZK_PERFECT      = 0,
    ZK_STATISTICAL   = 1,
    ZK_COMPUTATIONAL = 2
} ZKType;

typedef struct {
    int (*simulate)(const char *input, size_t input_len,
                    IPTranscript *output,
                    IPRandomTape *tape);
    void *state;
    ZKType zk_type;
    int    is_initialized;
} ZKSimulator;

/* GNI Zero-Knowledge Simulator (GMW 1991, L7)
 * The GNI protocol is perfect ZK. Simulator picks b'' and pi'',
 * computes H'' = pi''(G_{b''}), outputs transcript (H'', b'').
 * When G0,G1 are non-isomorphic, distributions are identical.
 */
int zk_gni_simulate(const char *input, size_t input_len,
                    IPTranscript *output, IPRandomTape *tape);

int zk_simulator_init(ZKSimulator *sim,
    int (*simulate_fn)(const char*, size_t, IPTranscript*, IPRandomTape*),
    ZKType zk_type);
void zk_simulator_free(ZKSimulator *sim);
int zk_simulator_run(ZKSimulator *sim, const char *input,
                     size_t input_len, IPTranscript *output);

/* ZK for Quadratic Residuosity (L7)
 * Computational ZK under QRA. Simulator picks random s, r.
 */
int zk_qr_simulate(const char *input, size_t input_len,
                   IPTranscript *output, IPRandomTape *tape);

/* Fiat-Shamir Heuristic (L7)
 * Transforms Sigma protocol into NIZK in ROM.
 */
typedef struct {
    uint8_t  *commitments;
    uint8_t  *responses;
    size_t    num_rounds;
    size_t    commitment_size;
    size_t    response_size;
} FiatShamirProof;

int fs_hash_challenge(const uint8_t *data, size_t len, uint64_t *challenge);
int fs_generate_proof(const char *input, size_t input_len,
                      const char *witness, size_t wit_len,
                      FiatShamirProof *proof);
int fs_verify_proof(const char *input, size_t input_len,
                    const FiatShamirProof *proof, int *accepted);

/* Statistical ZK -- Graph Isomorphism (L7)
 * 3-move protocol: commit H=pi(G0), challenge b, respond psi.
 */
int zk_graph_iso_prove(const IPGraph *G0, const IPGraph *G1,
                       const IPPermutation *witness,
                       IPRandomTape *tape, IPTranscript *transcript);
int zk_graph_iso_verify(const IPGraph *G0, const IPGraph *G1,
                        const IPTranscript *transcript,
                        IPVerdict *verdict);

/* Sigma Protocols (L7, L8)
 * 3-move public-coin with special soundness.
 */
typedef struct {
    int (*commit)(void *state, const char *witness, size_t wit_len,
                  uint8_t *commitment, size_t *commit_len);
    int (*respond)(void *state, const char *witness, size_t wit_len,
                   uint64_t challenge, uint8_t *response, size_t *resp_len);
    int (*verify)(void *state, const uint8_t *commitment, size_t commit_len,
                  uint64_t challenge, const uint8_t *response, size_t resp_len,
                  int *accepted);
    void *state;
} SigmaProtocol;

int sigma_protocol_init(SigmaProtocol *sp,
    int (*commit)(void*, const char*, size_t, uint8_t*, size_t*),
    int (*respond)(void*, const char*, size_t, uint64_t, uint8_t*, size_t*),
    int (*verify)(void*, const uint8_t*, size_t, uint64_t, const uint8_t*, size_t, int*),
    void *state);
int sigma_protocol_run(SigmaProtocol *sp, const char *witness, size_t wit_len,
                       IPRandomTape *tape, int *accepted);
int sigma_extract_witness(SigmaProtocol *sp,
    const uint8_t *commit, size_t commit_len,
    uint64_t c1, const uint8_t *resp1, size_t r1_len,
    uint64_t c2, const uint8_t *resp2, size_t r2_len,
    void *extracted_witness, size_t *wit_len);

#endif
