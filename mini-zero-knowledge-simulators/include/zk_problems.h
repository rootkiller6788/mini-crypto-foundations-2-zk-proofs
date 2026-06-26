#ifndef ZK_PROBLEMS_H
#define ZK_PROBLEMS_H

#include "zk_simulator.h"
#include "commitments.h"

/*
 * mini-zero-knowledge-simulators -- zk_problems.h
 * Canonical NP-complete problems and their ZK proofs.
 * Covers L6 (Canonical Problems).
 *
 * The GMW theorem shows that ALL of NP has computational ZK proofs
 * by reducing to GRAPH-3-COLORING. We implement the three canonical
 * ZK proofs for NP-complete problems:
 *
 *  1. GRAPH-3-COLORING (G3C) -- the original GMW proof
 *  2. GRAPH ISOMORPHISM (GI) -- a perfect ZK proof
 *  3. HAMILTONIAN CYCLE (HC) -- a constant-round ZK proof
 *
 * Reference: Goldreich-Micali-Wigderson (STOC 1991)
 *            Goldreich-Micali-Wigderson (JACM 1991)
 *            Blum (1986) "How to Prove a Theorem So No One Else Can Claim It"
 * Courses: MIT 6.875, Stanford CS355, Berkeley CS276, Princeton COS 561
 */

/* ================================================================
 * L6 -- Canonical Problems
 * ================================================================ */

/* -----------------------------------------------------------------
 * L6.1 -- GRAPH-3-COLORING (NP-Complete)
 *
 * Input: undirected graph G = (V, E)
 * Question: does there exist psi: V -> {1,2,3} s.t. forall (u,v) in E,
 *            psi(u) != psi(v)?
 *
 * This is the ANCHOR NP-complete problem for ZK. Every other
 * NP problem reduces to G3C via Cook-Levin -> 3SAT -> G3C.
 *
 * GMW Protocol for G3C (basic round, soundness error 1 - 1/|E|):
 *   P: Knows 3-colouring psi.
 *   1. Pick random permutation pi of {1,2,3}.
 *   2. For each v in V: commit to pi(psi(v)).
 *   3. Send all commitments to V.
 *   V:
 *   4. Pick random edge (u,v) in E. Send to P.
 *   P:
 *   5. Open commitments for u and v.
 *   V:
 *   6. Accept iff opened colours differ.
 *
 * After k repetitions (sequential), soundness error = (1-1/|E|)^k.
 *
 * ZK property: simulator guesses edge (u,v), commits to colours
 * that differ on (u,v) and are the SAME colour elsewhere. If V
 * picks that edge, great. Otherwise, rewind. Expected O(|E|) tries.
 * ----------------------------------------------------------------- */

#define MAX_VERTICES 64
#define MAX_EDGES    256

typedef struct {
    int num_vertices;           /* |V| */
    int num_edges;              /* |E| */
    int edges[MAX_EDGES][2];    /* edge list: (u, v) pairs, 0-indexed */
    int adjacency[MAX_VERTICES][MAX_VERTICES]; /* adjacency matrix (0/1) */
} graph_t;

/* A 3-colouring: colour[v] in {0, 1, 2} */
typedef struct {
    int num_vertices;
    int colours[MAX_VERTICES];
} three_colouring_t;

/* G3C ZK Protocol Data Structures */

/* Prover state for one round of GMW G3C protocol */
typedef struct {
    int                num_vertices;
    int                perm[3];    /* permutation of colours */
    bit_commitment_t   commitments[MAX_VERTICES];
    int                permuted_colours[MAX_VERTICES];
    const group_params_t *gp;
} g3c_prover_round_t;

/* Verifier state for one round */
typedef struct {
    int                num_edges;
    int                challenge_edge[2];  /* the edge V asks to reveal */
} g3c_verifier_round_t;

/* Full GMW G3C protocol (k rounds) */
void g3c_prover_init_round(g3c_prover_round_t *pr,
                            const three_colouring_t *colouring,
                            const random_tape_t *rng,
                            const group_params_t *gp);
void g3c_verifier_pick_edge(g3c_verifier_round_t *vr,
                              const graph_t *G,
                              const random_tape_t *rng);
int  g3c_verifier_verify(const g3c_prover_round_t *pr,
                           const g3c_verifier_round_t *vr);

/*
 * G3C Simulator
 *
 * Algorithm (one round):
 *   1. Guess edge (u*, v*) that V will challenge.
 *   2. For v in V:
 *     - if v == u*: commit to colour 0
 *     - if v == v*: commit to colour 1
 *     - else:        commit to colour 2
 *   3. If V challenges (u*,v*): reveal 0 and 1 -> accept.
 *      Otherwise: rewind and try again.
 *
 * Expected rewinds per round = |E|.
 */
int g3c_simulate_round(const graph_t *G,
                         const random_tape_t *rng,
                         bit_commitment_t *commitments_out,
                         int *challenged_edge_out,
                         int *revealed_colours_out);

/* Full G3C simulator (k rounds) */
int g3c_simulate_protocol(const graph_t *G, int k,
                            const random_tape_t *rng,
                            transcript_t *out);

/* -----------------------------------------------------------------
 * L6.2 -- GRAPH ISOMORPHISM (in NP, not known NP-complete unless PH collapses)
 *
 * Input: two graphs G0 = (V, E0), G1 = (V, E1)
 * Question: does there exist permutation pi: V -> V s.t.
 *            (u,v) in E0 iff (pi(u), pi(v)) in E1?
 *
 * GI has a PERFECT ZK proof (Goldreich-Micali-Wigderson 1987):
 *
 * Protocol (one round, soundness error 1/2):
 *   P: Knows isomorphism pi: G0 -> G1.
 *   1. Pick random permutation sigma of V.
 *   2. Compute H = sigma(G0). Send H to V.
 *   V:
 *   3. Pick random bit b in {0,1}. Send b to P.
 *   P:
 *   4. If b=0: send sigma.
 *      If b=1: send sigma compose pi^{-1}.
 *   V:
 *   5. If b=0: check H = sigma(G0).
 *      If b=1: check H = (sigma compose pi^{-1})(G1).
 *
 * Perfect ZK: simulator picks b in advance. If b=0, picks random
 * sigma, sends H=sigma(G0). If b=1, picks random tau, sends
 * H=tau(G1). V's challenge matches exactly half the time.
 * Expected rewinds = 2 per round.
 *
 * After k rounds, soundness error = (1/2)^k.
 * ----------------------------------------------------------------- */
typedef struct {
    int n;                          /* number of vertices */
    int adjacency[MAX_VERTICES][MAX_VERTICES]; /* for G0 */
} gi_graph_t;

typedef struct {
    int perm[MAX_VERTICES];         /* sigma: V -> V, a permutation */
} gi_permutation_t;

typedef struct {
    int n;
    int permuted_adj[MAX_VERTICES][MAX_VERTICES]; /* H = sigma(G) */
} gi_permuted_graph_t;

/* Apply permutation sigma to graph G: produces sigma(G) */
void gi_apply_permutation(const gi_graph_t *G,
                           const gi_permutation_t *sigma,
                           gi_permuted_graph_t *H_out);

/* Compose two permutations: sigma compose tau */
void gi_compose_permutations(const gi_permutation_t *sigma,
                               const gi_permutation_t *tau,
                               gi_permutation_t *out);

/* Graph isomorphism ZK prover */
typedef struct {
    int                n;
    gi_permutation_t   sigma;        /* random permutation for this round */
    gi_permuted_graph_t H;           /* H = sigma(G0) */
    gi_permutation_t   pi;           /* witness: G0 -> G1 isomorphism */
} gi_prover_round_t;

void gi_prover_init_round(gi_prover_round_t *pr,
                            const gi_graph_t *G0,
                            const gi_permutation_t *pi,
                            const random_tape_t *rng);
void gi_prover_respond(gi_prover_round_t *pr, int b,
                         gi_permutation_t *response_out);

/* GI Simulator (one round) */
int gi_simulate_round(const gi_graph_t *G0, const gi_graph_t *G1,
                        const random_tape_t *rng,
                        gi_permuted_graph_t *H_out,
                        int *b_out, gi_permutation_t *resp_out);

/* -----------------------------------------------------------------
 * L6.3 -- HAMILTONIAN CYCLE (NP-Complete)
 *
 * Input: directed graph G = (V, E)
 * Question: does there exist a cycle visiting each vertex exactly once?
 *
 * HC has a ZK proof via the Blum protocol (1986):
 *
 * Protocol (one round, soundness error 1/2):
 *   P: Knows Hamilton cycle C = (v1, v2, ..., vn, v1).
 *   1. Pick random permutation pi.
 *   2. Compute adjacency matrix A' of pi(G).
 *   3. Commit to all n^2 entries of A'.
 *   V:
 *   4. Pick random bit b.
 *   P:
 *   5. If b=0: open ALL commitments (reveal A') and reveal pi.
 *      V checks that A' = pi(G).
 *      If b=1: open only entries corresponding to cycle C' = pi(C).
 *      V checks these n entries form a cycle.
 *
 * Perfect ZK: simulator guesses b=0 or b=1. If b=0, picks random pi,
 * commits to pi(G) honestly. If b=1, commits to matrix that is 0
 * everywhere except a random cycle of 1s. V's challenge matches
 * half the time. Expected rewinds = 2.
 * ----------------------------------------------------------------- */

typedef struct {
    int n;                          /* number of vertices */
    int adjacency[MAX_VERTICES][MAX_VERTICES]; /* directed adjacency matrix */
} hc_graph_t;

typedef struct {
    int vertices[MAX_VERTICES];     /* cycle: v0, v1, ..., v_{n-1}, v0 */
    int n;
} hamiltonian_cycle_t;

/* HC ZK Prover (one round) */
typedef struct {
    int                n;
    gi_permutation_t   pi;          /* random permutation */
    int                permuted_adj[MAX_VERTICES][MAX_VERTICES];
    bit_commitment_t   commitments[MAX_VERTICES][MAX_VERTICES];
    const group_params_t *gp;
} hc_prover_round_t;

void hc_prover_init_round(hc_prover_round_t *pr,
                            const hc_graph_t *G,
                            const hamiltonian_cycle_t *cycle,
                            const random_tape_t *rng,
                            const group_params_t *gp);
void hc_prover_reveal_all(hc_prover_round_t *pr,
                            gi_permutation_t *pi_out,
                            int adj_out[MAX_VERTICES][MAX_VERTICES]);
void hc_prover_reveal_cycle(hc_prover_round_t *pr,
                              int cycle_out[MAX_VERTICES]);

int hc_verifier_verify_graph(const hc_graph_t *G,
                               const gi_permutation_t *pi,
                               int adj[MAX_VERTICES][MAX_VERTICES]);
int hc_verifier_verify_cycle(const bit_commitment_t commits[MAX_VERTICES][MAX_VERTICES],
                               const int *cycle, int n);

/* HC Simulator (one round) */
int hc_simulate_round(const hc_graph_t *G,
                        const random_tape_t *rng,
                        const group_params_t *gp,
                        transcript_t *out);

#endif /* ZK_PROBLEMS_H */

