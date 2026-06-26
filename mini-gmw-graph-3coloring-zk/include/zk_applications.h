/*
 * zk_applications.h - Applications of Zero-Knowledge Proofs
 *
 * L7 Applications:
 *   - Zero-Knowledge Authentication: prove knowledge of password without revealing it
 *   - Zero-Knowledge Identity: prove identity without revealing secret key
 *   - ZK Graph Isomorphism: ZK proof for graph isomorphism
 *   - ZK Hamiltonian Cycle: ZK proof that a graph has a Hamiltonian cycle
 *   - Credential systems: prove attributes without revealing identity
 *
 * L8 Advanced Topics:
 *   - Sigma protocols: 3-move ZK proofs with special soundness
 *   - Non-interactive ZK (NIZK): Fiat-Shamir transform
 *   - zkSNARK connection: GMW as pre-cursor to modern SNARKs
 *
 * Reference:
 *   Goldreich (2004) FOC I, Ch.4
 *   Fiat, Shamir (1986) - How to Prove Yourself
 *   Blum, Feldman, Micali (1988) - Non-Interactive ZK
 *
 * Courses: MIT 6.876, Stanford CS255
 */
#ifndef ZK_APPLICATIONS_H
#define ZK_APPLICATIONS_H

#include "gmw_protocol.h"
#include "simulator.h"

/* -- ZK Authentication ------------------------------------- */
/*
 * ZK Password Proof:
 * Prover knows password p. Instead of sending p, prover constructs
 * a graph coloring problem encoding p, then runs GMW to prove knowledge.
 *
 * Protocol:
 * 1. Setup: hash password to derive graph G and 3-coloring psi
 * 2. Prover proves knowledge of psi for G using GMW protocol
 * 3. Verifier accepts if GMW protocol succeeds in all rounds
 */
typedef struct {
    char*   username;
    Graph3Col*  challenge_graph;
    Coloring3*  secret_coloring;  /* derived from password hash */
    int     n_rounds;
    double  security_level;      /* 2^{-security_level} soundness */
} ZKAuthCredential;

ZKAuthCredential* zk_auth_setup(const char* username, const char* password, int n_rounds);
void              zk_auth_free(ZKAuthCredential* cred);
int               zk_auth_prove(ZKAuthCredential* cred, uint64_t seed);
int               zk_auth_verify(ZKAuthCredential* cred, uint64_t seed);

/* -- ZK Graph Isomorphism Protocol ------------------------- */
/*
 * Graph Isomorphism: G1 ~= G2 iff there exists a permutation pi
 * such that (u,v) in E1 iff (pi(u), pi(v)) in E2.
 *
 * ZK Proof for Graph Isomorphism (GMW-style):
 * 1. P picks random permutation sigma, sends H = sigma(G1)
 * 2. V sends random bit b in {0,1}
 * 3. If b=0: P reveals sigma (shows H = sigma(G1))
 *    If b=1: P reveals sigma o pi^{-1} (shows H = sigma o pi^{-1}(G2))
 * 4. V checks consistency
 *
 * Soundness: 1/2 per round -> amplify by repetition
 * ZK: V only sees random isomorphic copy, learns nothing about pi
 */
typedef struct {
    int     n_vertices;
    int*    permutation;   /* pi[v] = image of v under isomorphism */
} GraphIsomorphism;

int zk_graph_iso_prove(const Graph3Col* G1, const Graph3Col* G2,
                        const GraphIsomorphism* iso, int n_rounds, uint64_t seed);
int zk_graph_iso_verify(const Graph3Col* G1, const Graph3Col* G2,
                         int n_rounds, uint64_t seed);

/* -- ZK Hamiltonian Cycle ---------------------------------- */
/*
 * ZK Proof for Hamiltonian Cycle:
 * 1. P commits to adjacency matrix of a random isomorphic copy of G
 * 2. V challenges: show cycle edges OR show isomorphism
 * 3. P reveals accordingly
 *
 * This shows a different NP-complete problem with a ZK proof,
 * illustrating the general technique.
 */
typedef struct {
    int     n_vertices;
    int*    cycle;  /* cycle[0], cycle[1], ..., cycle[n-1], cycle[0] */
    int     cycle_len;
} HamiltonianCycle;

int zk_hamcycle_prove(const Graph3Col* G, const HamiltonianCycle* cycle,
                       int n_rounds, uint64_t seed);
int zk_hamcycle_verify(const Graph3Col* G, int n_rounds, uint64_t seed);

/* -- Fiat-Shamir Transform (NIZK) -------------------------- */
/*
 * Convert interactive ZK proof to non-interactive using random oracle.
 * Instead of V sending random challenge, P computes:
 *   challenge = H(commitments || instance)
 *
 * This is the Fiat-Shamir heuristic (Fiat, Shamir 1986).
 * Security holds in the random oracle model.
 */
typedef struct {
    HashDigest*  commitments;
    int          n_commitments;
    int          challenge_edge_u;
    int          challenge_edge_v;
    int          revealed_color_u;
    int          revealed_color_v;
    CommitNonce  nonce_u;
    CommitNonce  nonce_v;
} NIZKProof;

NIZKProof* nizk_gmw_prove(const Graph3Col* graph, const Coloring3* coloring,
                           uint64_t seed);
int        nizk_gmw_verify(const Graph3Col* graph, const NIZKProof* proof);

/* -- Credential / Anonymous Credential System --------------- */
/*
 * Simple demonstration of anonymous credentials using ZK.
 * User proves possession of a valid credential without revealing
 * which credential (among many possible).
 */
typedef struct {
    char*   issuer;
    int     credential_id;
    int     attributes[4];  /* up to 4 attributes encoded */
} ZKCredential;

int zk_credential_prove_attribute(const ZKCredential* cred, int attr_index,
                                   int threshold, int n_rounds, uint64_t seed);
int zk_credential_verify_attribute(int attr_index, int threshold,
                                    int n_rounds, uint64_t seed);

/* -- Sigma Protocol Integration ---------------------------- */
/*
 * Sigma Protocol: 3-move protocol (commit, challenge, response)
 * with special soundness and honest-verifier ZK.
 * GMW 3-COLORING is a Sigma-like protocol with |E| possible challenges.
 */

typedef enum { SIGMA_COMMIT, SIGMA_CHALLENGE, SIGMA_RESPONSE } SigmaPhase;

typedef struct {
    SigmaPhase  phase;
    HashDigest  commitment;     /* a = commitment from prover */
    int         challenge;      /* e = random challenge from verifier */
    int         response;       /* z = response from prover */
    int         accepted;
} SigmaRound;

#endif
