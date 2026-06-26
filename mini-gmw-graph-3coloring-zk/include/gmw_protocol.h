/*
 * gmw_protocol.h - GMW Graph 3-Coloring Zero-Knowledge Protocol
 *
 * L1 Definitions:
 *   - GMW Protocol: Interactive proof for Graph 3-Colorability
 *     Goldreich, Micali, Wigderson (STOC 1986, JACM 1991)
 *   - Protocol flow (one round):
 *     1. P permutes colors with random pi in S3
 *     2. P commits to pi(psi(v)) for each v in V
 *     3. V chooses random edge e = (u,v) in E
 *     4. P reveals pi(psi(u)) and pi(psi(v))
 *     5. V checks colors are different and valid
 *
 * L2 Core Concepts:
 *   - Completeness: if graph is 3-colorable, honest P always convinces V
 *   - Soundness: if graph NOT 3-colorable, P cheats with prob <= 1 - 1/|E|
 *   - Zero-Knowledge: V learns nothing beyond graph 3-colorability
 *   - Soundness amplification: repeat k rounds -> error <= (1 - 1/|E|)^k
 *
 * L3 Mathematical Structures:
 *   - Protocol transcript: commitments + challenge + decommitments
 *   - Color permutation: S3 acting on {0,1,2}, represented as int[3]
 *   - Round state machine with 5 phases
 *
 * L4 Fundamental Theorems:
 *   - GMW Theorem: every L in NP has a computational ZK proof system
 *   - Reduction: NP <=p 3-COLORING, then apply GMW 3-COLORING protocol
 *   - Soundness error bound: epsilon <= (1 - 1/|E|)
 *
 * L5 Algorithms:
 *   - GMW prover algorithm (commit + respond to challenge)
 *   - GMW verifier algorithm (choose challenge + verify)
 *   - Multi-round sequential composition
 *
 * Reference:
 *   Goldreich, Micali, Wigderson (1986/1991) - Proofs that Yield Nothing
 *   Goldreich (2004) - Foundations of Cryptography I, sec4.4
 *
 * Courses: MIT 6.876, Stanford CS255, Princeton COS 551
 */
#ifndef GMW_PROTOCOL_H
#define GMW_PROTOCOL_H

#include "graph_3coloring.h"
#include "commitment.h"

/* -- Round State Machine ------------------------------------ */
typedef enum {
    GMW_PHASE_INIT = 0,
    GMW_PHASE_COMMIT,       /* P has sent commitments */
    GMW_PHASE_CHALLENGE,    /* V has sent challenge edge */
    GMW_PHASE_REVEAL,       /* P has revealed edge endpoint colors */
    GMW_PHASE_VERIFY,       /* V has verified */
    GMW_PHASE_COMPLETE
} GMWPhase;

/* -- Color Permutation -------------------------------------- */
typedef struct {
    int perm[NUM_COLORS];   /* perm[c] = permuted color, a bijection on {0,1,2} */
    int inv[NUM_COLORS];    /* inverse permutation */
} ColorPermutation;

/* -- GMW Round Data ---------------------------------------- */
typedef struct {
    int             round_index;
    GMWPhase        phase;
    /* Prover-side */
    ColorPermutation perm;
    HashDigest*      commitments;   /* |V| commitments */
    CommitNonce*     nonces;        /* |V| nonces */
    int              revealed_u;
    int              revealed_v;
    int              revealed_color_u;
    int              revealed_color_v;
    /* Verifier-side */
    int              challenge_u;
    int              challenge_v;
    int              verifier_accept;
    /* Soundness tracking */
    double           soundness_error; /* current per-round error bound */
} GMWRound;

/* -- GMW Protocol Session ---------------------------------- */
typedef struct {
    Graph3Col*          graph;
    Coloring3*          coloring;        /* P's secret 3-coloring (NULL if V) */
    int                 is_prover;       /* 1 = P, 0 = V */
    int                 n_rounds;        /* total rounds planned */
    int                 current_round;
    GMWRound**          rounds;
    int                 rounds_capacity;
    /* Pedersen commitment support (optional) */
    PedersenParams*     pedersen_params;
    int                 use_pedersen;    /* 0 = hash-based, 1 = Pedersen */
    /* Protocol statistics */
    int                 total_rounds_completed;
    int                 verifier_accepts;
    int                 verifier_rejects;
    double              final_soundness_error;
} GMWSession;

/* -- Session Management ------------------------------------ */
GMWSession* gmw_session_create(Graph3Col* graph, Coloring3* coloring,
                                int is_prover, int n_rounds);
void        gmw_session_free(GMWSession* session);

/* -- Round Operations -------------------------------------- */
GMWRound*   gmw_round_create(int index, int n_vertices);
void        gmw_round_free(GMWRound* round, int n_vertices);

/* -- Prover Operations ------------------------------------- */
/*
 * Step 1: Prover generates random color permutation and
 * commits to permuted colors for all vertices.
 * Complexity: O(|V|) commitments.
 */
int gmw_prover_commit(GMWSession* session, GMWRound* round);

/*
 * Step 2: Prover receives challenge edge (u,v) from verifier.
 * Step 3: Prover reveals decommitments for vertices u and v.
 * Complexity: O(1) reveal.
 */
int gmw_prover_reveal(GMWSession* session, GMWRound* round,
                       int challenge_u, int challenge_v);

/* -- Verifier Operations ----------------------------------- */
/*
 * Step 1: Verifier receives all commitments (stored in round).
 * Step 2: Verifier selects random edge (u,v) as challenge.
 * Complexity: O(1) random edge selection.
 */
int gmw_verifier_challenge(const GMWSession* session, GMWRound* round);

/*
 * Step 3: Verifier checks revealed colors for edge (u,v):
 *   - Both colors are valid (in {0,1,2})
 *   - Colors are different
 *   - Commitments match
 * Returns: 1 = accept, 0 = reject
 */
int gmw_verifier_verify(const GMWSession* session, GMWRound* round);

/* -- Full Round Execution ---------------------------------- */
/*
 * Execute one complete round of the GMW protocol.
 * Handles both prover and verifier roles.
 * Returns: 1 = round accepted, 0 = round rejected, -1 = error
 */
int gmw_execute_round(GMWSession* session);

/* -- Multi-Round Execution --------------------------------- */
/*
 * Execute all planned rounds of the GMW protocol.
 * Returns: 1 = all rounds accepted, 0 = at least one rejection
 */
int gmw_execute_all_rounds(GMWSession* session);

/* -- Soundness Analysis ------------------------------------ */
/*
 * Calculate soundness error for k rounds of the GMW protocol.
 * epsilon_k = (1 - 1/|E|)^k
 * For desired security level (e.g., 2^{-80}), compute required rounds:
 * k >= 80 / log2(|E|/(|E|-1))
 */
double gmw_soundness_error(const GMWSession* session, int k_rounds);

/*
 * Calculate minimum number of rounds needed for given soundness target.
 */
int gmw_rounds_for_soundness(const GMWSession* session, double target_error);

/* -- Transcript ------------------------------------------- */
typedef struct {
    int             n_vertices;
    int             n_edges;
    int             n_rounds;
    GMWRound**      rounds;
    int             verifier_accept;
} GMWTranscript;

GMWTranscript* gmw_transcript_create(const GMWSession* session);
void           gmw_transcript_free(GMWTranscript* transcript);
void           gmw_transcript_print(const GMWTranscript* transcript);

/* -- Utility ---------------------------------------------- */
void gmw_print_round(const GMWRound* round, int n_vertices);
void gmw_print_session_stats(const GMWSession* session);

#endif
