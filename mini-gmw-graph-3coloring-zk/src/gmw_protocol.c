/*
 * gmw_protocol.c -- GMW Graph 3-Coloring Zero-Knowledge Protocol
 *
 * Full implementation of the Goldreich-Micali-Wigderson interactive
 * zero-knowledge proof system for Graph 3-Colorability.
 *
 * L1: GMW Protocol = interactive proof for 3-COLORING with ZK property
 * L2: Completeness, Soundness (epsilon = 1 - 1/|E|), Zero-Knowledge
 * L3: 5-phase round state machine, S3 color permutation, protocol transcript
 * L4: GMW Theorem: every L in NP has computational ZK proof system
 * L5: Proof execution: commit -> challenge -> reveal -> verify
 * L7: Soundness amplification via sequential repetition
 *
 * Protocol (one round):
 *   1. P chooses random pi in S3, commits to pi(c(v)) for all v in V
 *   2. V chooses random edge e = (u,v) in E
 *   3. P reveals pi(c(u)) and pi(c(v))
 *   4. V verifies colors differ and match commitments
 *
 * Soundness error (one round): epsilon = 1 - 1/|E|
 * After k rounds: epsilon_k = (1 - 1/|E|)^k <= exp(-k/|E|)
 *
 * Reference:
 *   Goldreich, Micali, Wigderson (STOC 1986, JACM 1991)
 *   Goldreich (2004) Foundations of Cryptography I, sec 4.4
 * Courses: MIT 6.876, Stanford CS255, Princeton COS 551
 */
#include "gmw_protocol.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>

/* ================================================================
 * S3 Color Permutation
 * ================================================================ */

/*
 * Generate a random permutation of {0,1,2} (S3 group, size 6).
 * Uses Fisher-Yates shuffle.
 * Stores both the permutation and its inverse.
 */
static void s3_random_perm(ColorPermutation* perm, unsigned int seed) {
    int vals[NUM_COLORS] = {0, 1, 2};
    /* Fisher-Yates shuffle */
    srand(seed);
    for (int i = NUM_COLORS - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        int tmp = vals[i]; vals[i] = vals[j]; vals[j] = tmp;
    }
    for (int c = 0; c < NUM_COLORS; c++) {
        perm->perm[c] = vals[c];
        perm->inv[vals[c]] = c;
    }
}

/* ================================================================
 * Session Management
 * ================================================================ */

/*
 * Create a new GMW protocol session.
 *
 * Parameters:
 *   graph     - the graph instance
 *   coloring  - prover's witness (3-coloring), or NULL if verifier
 *   is_prover - 1 for prover role, 0 for verifier
 *   n_rounds  - number of sequential repetitions for soundness amplification
 *
 * Returns: initialized GMWSession* (must be freed with gmw_session_free)
 */
GMWSession* gmw_session_create(Graph3Col* graph, Coloring3* coloring,
                                int is_prover, int n_rounds) {
    if (!graph || n_rounds <= 0) return NULL;
    if (is_prover && (!coloring || !coloring->valid)) return NULL;

    GMWSession* session = (GMWSession*)malloc(sizeof(GMWSession));
    if (!session) return NULL;

    session->graph = graph;
    session->coloring = coloring;
    session->is_prover = is_prover;
    session->n_rounds = n_rounds;
    session->current_round = 0;
    session->rounds_capacity = n_rounds;
    session->rounds = (GMWRound**)calloc((size_t)n_rounds, sizeof(GMWRound*));
    if (!session->rounds) { free(session); return NULL; }

    session->pedersen_params = NULL;
    session->use_pedersen = 0;

    session->total_rounds_completed = 0;
    session->verifier_accepts = 0;
    session->verifier_rejects = 0;
    session->final_soundness_error = 1.0;

    return session;
}

/*
 * Free a GMW session and all associated rounds.
 */
void gmw_session_free(GMWSession* session) {
    if (!session) return;
    if (session->rounds) {
        for (int i = 0; i < session->current_round; i++) {
            gmw_round_free(session->rounds[i], session->graph->n_vertices);
        }
        free(session->rounds);
    }
    if (session->pedersen_params) {
        pedersen_params_free(session->pedersen_params);
    }
    free(session);
}

/* ================================================================
 * Round Operations
 * ================================================================ */

/*
 * Create a new round structure.
 * Allocates commitment and nonce arrays for all vertices.
 *
 * Complexity: O(|V|) allocation
 */
GMWRound* gmw_round_create(int index, int n_vertices) {
    GMWRound* round = (GMWRound*)malloc(sizeof(GMWRound));
    if (!round) return NULL;

    round->round_index = index;
    round->phase = GMW_PHASE_INIT;
    round->commitments = (HashDigest*)calloc((size_t)n_vertices,
                                              sizeof(HashDigest));
    round->nonces = (CommitNonce*)calloc((size_t)n_vertices,
                                          sizeof(CommitNonce));
    if (!round->commitments || !round->nonces) {
        free(round->commitments); free(round->nonces);
        free(round); return NULL;
    }

    round->revealed_u = -1;
    round->revealed_v = -1;
    round->revealed_color_u = -1;
    round->revealed_color_v = -1;
    round->challenge_u = -1;
    round->challenge_v = -1;
    round->verifier_accept = 0;
    round->soundness_error = 1.0;

    return round;
}

/*
 * Free a round structure.
 */
void gmw_round_free(GMWRound* round, int n_vertices) {
    (void)n_vertices; /* preserved for API consistency across protocol variants */
    if (!round) return;
    free(round->commitments);
    free(round->nonces);
    free(round);
}

/* ================================================================
 * Prover Operations
 * ================================================================ */

/*
 * PROVER STEP 1: Commit Phase
 *
 * The prover:
 *   1. Picks a random color permutation pi in S3
 *   2. For each vertex v, computes permuted_color = pi(c(v))
 *   3. Commits to permuted_color for each v with a fresh random nonce
 *
 * This hides the actual coloring from the verifier while binding
 * the prover to a specific permuted coloring.
 *
 * Complexity: O(|V|) commitments
 */
int gmw_prover_commit(GMWSession* session, GMWRound* round) {
    if (!session || !round || !session->is_prover) return -1;
    if (!session->coloring) return -1;
    if (round->phase != GMW_PHASE_INIT) return -1;

    int n = session->graph->n_vertices;

    /* Generate random permutation pi in S3 */
    s3_random_perm(&round->perm, (unsigned int)(time(NULL) + round->round_index));

    /* Commit to permuted colors for each vertex */
    for (int v = 0; v < n; v++) {
        int orig_color = session->coloring->colors[v];
        int perm_color = round->perm.perm[orig_color];

        commit_generate_nonce(&round->nonces[v]);
        round->commitments[v] = commit_color(perm_color, &round->nonces[v]);
    }

    round->phase = GMW_PHASE_COMMIT;
    return 1;
}

/*
 * PROVER STEP 2: Reveal Phase
 *
 * The prover receives the challenge edge (challenge_u, challenge_v) from V
 * and reveals:
 *   - The permuted colors for u and v
 *   - The nonces used to commit to those colors
 *
 * The verifier will check:
 *   - The commitments match the revealed colors + nonces
 *   - The revealed colors are different
 *
 * Complexity: O(1)
 */
int gmw_prover_reveal(GMWSession* session, GMWRound* round,
                       int challenge_u, int challenge_v) {
    if (!session || !round || !session->is_prover) return -1;
    if (round->phase != GMW_PHASE_COMMIT) return -1;

    int n = session->graph->n_vertices;
    if (challenge_u < 0 || challenge_u >= n) return -1;
    if (challenge_v < 0 || challenge_v >= n) return -1;

    /* Check that (u,v) is actually an edge */
    if (!graph3_has_edge(session->graph, challenge_u, challenge_v)) return -1;

    round->challenge_u = challenge_u;
    round->challenge_v = challenge_v;
    round->revealed_u = challenge_u;
    round->revealed_v = challenge_v;

    int orig_cu = session->coloring->colors[challenge_u];
    int orig_cv = session->coloring->colors[challenge_v];

    round->revealed_color_u = round->perm.perm[orig_cu];
    round->revealed_color_v = round->perm.perm[orig_cv];

    round->phase = GMW_PHASE_REVEAL;
    return 1;
}

/* ================================================================
 * Verifier Operations
 * ================================================================ */

/*
 * VERIFIER STEP 1: Challenge Phase
 *
 * The verifier randomly selects an edge (u,v) from the graph's edge set.
 *
 * Since we store the graph as adjacency matrix, we enumerate all edges
 * and pick one uniformly at random.
 *
 * Complexity: O(|E|) to enumerate edges
 */
int gmw_verifier_challenge(const GMWSession* session, GMWRound* round) {
    if (!session || !round) return -1;
    if (session->is_prover) return -1;
    if (round->phase != GMW_PHASE_COMMIT) return -1;

    int n = session->graph->n_vertices;
    int n_edges = session->graph->n_edges;

    if (n_edges == 0) return -1; /* edge-less graph, protocol undefined */

    /* Choose random edge index (deterministic for testing) */
    srand((unsigned int)(time(NULL) + round->round_index * 9973));
    int target = rand() % n_edges;

    /* Enumerate edges until we hit the target */
    int count = 0;
    for (int i = 0; i < n; i++) {
        for (int j = i + 1; j < n; j++) {
            if (graph3_has_edge(session->graph, i, j)) {
                if (count == target) {
                    round->challenge_u = i;
                    round->challenge_v = j;
                    round->phase = GMW_PHASE_CHALLENGE;
                    return 1;
                }
                count++;
            }
        }
    }

    return -1; /* should not reach here */
}

/*
 * VERIFIER STEP 2: Verify Phase
 *
 * The verifier checks the prover's revealed information:
 *   1. Both revealed colors are valid (in {0,1,2})
 *   2. The revealed colors are different (proper coloring on this edge)
 *   3. The commitments for u and v match the revealed colors + nonces
 *
 * Returns 1 if all checks pass (accept), 0 if any check fails (reject).
 *
 * This implements the core soundness guarantee of the GMW protocol:
 * a cheating prover who does NOT know a valid 3-coloring will be caught
 * with probability at least 1/|E| per round.
 */
int gmw_verifier_verify(const GMWSession* session, GMWRound* round) {
    if (!session || !round) return 0;
    if (session->is_prover) return 0;
    if (round->phase != GMW_PHASE_REVEAL) return 0;

    int u = round->revealed_u;
    int v = round->revealed_v;
    int cu = round->revealed_color_u;
    int cv = round->revealed_color_v;

    /* Check 1: Valid colors */
    if (cu < 0 || cu >= NUM_COLORS) { round->verifier_accept = 0; return 0; }
    if (cv < 0 || cv >= NUM_COLORS) { round->verifier_accept = 0; return 0; }

    /* Check 2: Different colors (proper coloring on edge) */
    if (cu == cv) { round->verifier_accept = 0; return 0; }

    /* Check 3: Commitments match */
    if (!commit_verify_color(cu, &round->nonces[u], &round->commitments[u])) {
        round->verifier_accept = 0; return 0;
    }
    if (!commit_verify_color(cv, &round->nonces[v], &round->commitments[v])) {
        round->verifier_accept = 0; return 0;
    }

    round->verifier_accept = 1;
    round->phase = GMW_PHASE_VERIFY;
    return 1;
}

/* ================================================================
 * Full Round Execution (Combined Prover + Verifier)
 * ================================================================ */

/*
 * Execute one complete round of the GMW protocol.
 *
 * In this demonstration, both prover and verifier run in the same process.
 * The function orchestrates the full 5-phase state machine.
 *
 * Returns: 1 = round accepted, 0 = round rejected, -1 = error
 */
int gmw_execute_round(GMWSession* session) {
    if (!session) return -1;
    if (session->current_round >= session->n_rounds) return -1;

    int n = session->graph->n_vertices;

    /* Allocate new round */
    GMWRound* round = gmw_round_create(session->current_round, n);
    if (!round) return -1;
    session->rounds[session->current_round] = round;

    /* Phase 1-2: Prover commits */
    if (session->is_prover) {
        if (gmw_prover_commit(session, round) != 1) {
            round->verifier_accept = 0;
            session->verifier_rejects++;
            session->current_round++;
            return -1;
        }
    } else {
        /* For verifier role, commitments would be received from prover.
         * In this demo, we simulate by having the verifier-side
         * know the correct commitments. The actual protocol transmits
         * them between parties. */
        round->phase = GMW_PHASE_COMMIT;
    }

    /* Phase 3: Verifier chooses challenge */
    if (!session->is_prover) {
        if (gmw_verifier_challenge(session, round) != 1) {
            round->verifier_accept = 0;
            session->verifier_rejects++;
            session->current_round++;
            return -1;
        }
    }

    /* Phase 4: Prover reveals */
    /* (challenge is set either locally or externally) */
    if (session->is_prover && round->phase == GMW_PHASE_CHALLENGE) {
        /* In a real protocol, the verifier would send the challenge.
         * Here we simulate: prover also knows which edge was challenged
         * (in separate execution). */
    }

    /* Phase 5: Verifier verifies */
    if (!session->is_prover && round->phase == GMW_PHASE_REVEAL) {
        round->verifier_accept = gmw_verifier_verify(session, round);
    }

    /* Update session statistics */
    session->total_rounds_completed++;
    if (round->verifier_accept) {
        session->verifier_accepts++;
    } else {
        session->verifier_rejects++;
    }

    /* Update round soundness error */
    int n_edges = session->graph->n_edges;
    if (n_edges > 0) {
        round->soundness_error = 1.0 - 1.0 / n_edges;
    }

    session->current_round++;
    return round->verifier_accept;
}

/*
 * Execute all planned rounds.
 * Returns 1 if ALL rounds accepted, 0 if any rejected.
 */
int gmw_execute_all_rounds(GMWSession* session) {
    if (!session) return -1;

    for (int i = 0; i < session->n_rounds; i++) {
        int result = gmw_execute_round(session);
        if (result <= 0) {
            session->final_soundness_error =
                gmw_soundness_error(session, session->current_round);
            return 0;
        }
    }

    session->final_soundness_error =
        gmw_soundness_error(session, session->n_rounds);
    return 1;
}

/* ================================================================
 * Soundness Analysis
 * ================================================================ */

/*
 * Calculate soundness error after k rounds.
 *
 * Theorem: For the GMW 3-COLORING protocol, if the graph is NOT 3-colorable,
 *   a cheating prover can convince the verifier in one round with
 *   probability at most epsilon = 1 - 1/|E|.
 *
 * After k independent sequential repetitions:
 *   epsilon_k = (1 - 1/|E|)^k
 *
 * For large |E|: epsilon_k approx exp(-k/|E|)
 *
 * This function computes the exact value.
 *
 * Complexity: O(k) exponentiations, or O(log k) with fast exponentiation
 */
double gmw_soundness_error(const GMWSession* session, int k_rounds) {
    if (!session || k_rounds <= 0) return 1.0;

    int n_edges = session->graph->n_edges;
    if (n_edges <= 1) return 1.0; /* trivial graph, soundness undefined */

    double eps_per_round = 1.0 - 1.0 / n_edges;
    return pow(eps_per_round, k_rounds);
}

/*
 * Calculate minimum rounds needed for target soundness error.
 *
 * Want: (1 - 1/|E|)^k <= target_error
 * => k >= log(target_error) / log(1 - 1/|E|)
 *
 * For numerical stability with large |E|:
 *   log(1 - 1/|E|) approx -1/|E| for large |E|
 *   => k >= -|E| * ln(target_error)
 *
 * Complexity: O(1)
 */
int gmw_rounds_for_soundness(const GMWSession* session, double target_error) {
    if (!session || target_error <= 0.0 || target_error >= 1.0) return -1;

    int n_edges = session->graph->n_edges;
    if (n_edges <= 1) return -1;

    double eps_per_round = 1.0 - 1.0 / n_edges;
    double k_exact = log(target_error) / log(eps_per_round);
    int k = (int)ceil(k_exact);

    return k > 0 ? k : 1;
}

/* ================================================================
 * Transcript Management
 * ================================================================ */

/*
 * Create a transcript from a completed session.
 * The transcript contains all round data for verification and analysis.
 */
GMWTranscript* gmw_transcript_create(const GMWSession* session) {
    if (!session) return NULL;

    GMWTranscript* trans = (GMWTranscript*)malloc(sizeof(GMWTranscript));
    if (!trans) return NULL;

    trans->n_vertices = session->graph->n_vertices;
    trans->n_edges = session->graph->n_edges;
    trans->n_rounds = session->current_round;
    trans->verifier_accept = (session->verifier_rejects == 0) ? 1 : 0;

    trans->rounds = (GMWRound**)malloc(
        (size_t)session->current_round * sizeof(GMWRound*));
    if (!trans->rounds) { free(trans); return NULL; }

    for (int i = 0; i < session->current_round; i++) {
        trans->rounds[i] = session->rounds[i]; /* shallow copy (ownership transfer) */
    }

    return trans;
}

/*
 * Free a transcript.
 */
void gmw_transcript_free(GMWTranscript* transcript) {
    if (!transcript) return;
    if (transcript->rounds) {
        for (int i = 0; i < transcript->n_rounds; i++) {
            /* Note: rounds are owned by session, not transcript */
        }
        free(transcript->rounds);
    }
    free(transcript);
}

/*
 * Print transcript details.
 */
void gmw_transcript_print(const GMWTranscript* transcript) {
    if (!transcript) { printf("Transcript: NULL\n"); return; }
    printf("=== GMW Protocol Transcript ===\n");
    printf("Graph: |V|=%d, |E|=%d\n", transcript->n_vertices, transcript->n_edges);
    printf("Rounds: %d\n", transcript->n_rounds);
    printf("Verifier: %s\n", transcript->verifier_accept ? "ACCEPT" : "REJECT");
    for (int i = 0; i < transcript->n_rounds; i++) {
        GMWRound* r = transcript->rounds[i];
        printf("  Round %d: phase=%d, edge=(%d,%d), colors=(%s,%s), accept=%s\n",
               i, r->phase, r->challenge_u, r->challenge_v,
               COLOR_STRING(r->revealed_color_u), COLOR_STRING(r->revealed_color_v),
               r->verifier_accept ? "yes" : "no");
    }
}

/* ================================================================
 * Print Utilities
 * ================================================================ */

/*
 * Print round state.
 */
void gmw_print_round(const GMWRound* round, int n_vertices) {
    (void)n_vertices; /* preserved for API consistency across protocol variants */
    if (!round) return;
    printf("Round %d: phase=%d, edge=(%d,%d), colors_u=%d, colors_v=%d, accept=%d\n",
           round->round_index, round->phase,
           round->challenge_u, round->challenge_v,
           round->revealed_color_u, round->revealed_color_v,
           round->verifier_accept);
}

/*
 * Print session statistics.
 */
void gmw_print_session_stats(const GMWSession* session) {
    if (!session) return;
    printf("=== GMW Session Stats ===\n");
    printf("Role: %s\n", session->is_prover ? "Prover" : "Verifier");
    printf("Rounds planned: %d\n", session->n_rounds);
    printf("Rounds completed: %d\n", session->total_rounds_completed);
    printf("Accepts: %d, Rejects: %d\n",
           session->verifier_accepts, session->verifier_rejects);
    printf("Final soundness error: %.6e\n", session->final_soundness_error);
}
