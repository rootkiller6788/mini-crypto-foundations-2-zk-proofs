/*
 * simulator.h - Zero-Knowledge Simulator for GMW Protocol
 *
 * L1 Definitions:
 *   - Zero-Knowledge: for every PPT verifier V*, there exists a PPT simulator S
 *     such that for all x in L, the output distributions are computationally
 *     indistinguishable:  {View_{V*}(P,V*)(x)} ~_c {S(x)}
 *
 *   - View of V*: all messages received from P + V*'s random tape
 *
 *   - Three variants of ZK:
 *     (a) Perfect ZK: distributions are identical
 *     (b) Statistical ZK: distributions are statistically close
 *     (c) Computational ZK: distributions are computationally indistinguishable
 *
 * L2 Core Concepts:
 *   - Simulator paradigm: S internally runs V*, rewinds it, and produces
 *     a transcript that looks like a real interaction
 *   - Honest-Verifier ZK (HVZK): ZK only against the honest V
 *   - Malicious-Verifier ZK: ZK against any V* (stronger notion)
 *
 * L3 Mathematical Structures:
 *   - GMW Simulator strategy:
 *     S works as follows (for honest-verifier GMW 3-COLORING):
 *       1. Pick random edge e = (u,v)
 *       2. Pick random distinct colors c_u, c_v in {0,1,2}
 *       3. For all other vertices w != u,v: commit to random color
 *       4. For u,v: commit to c_u, c_v
 *       5. Output transcript: (all_commitments, e, c_u, c_v, nonces_for_u,v)
 *
 * L4 Fundamental Theorems:
 *   - GMW protocol is computational ZK (under commitment hiding)
 *   - Every L in NP has CZK proof system (GMW Theorem)
 *   - If OWF exist, every L in NP has CZK proof (via GMW + Naor commitment)
 *
 * Reference:
 *   Goldreich, Micali, Wigderson (1986/1991)
 *   Goldreich (2004) - FOC I, sec4.4.2-4.4.3
 *   Goldreich, Oren (1994) - Definitions and Properties of ZK Proof Systems
 *
 * Courses: MIT 6.876, Stanford CS255
 */
#ifndef SIMULATOR_H
#define SIMULATOR_H

#include "gmw_protocol.h"
#include "commitment.h"

/* -- Simulator for GMW 3-COLORING Protocol ----------------- */
/*
 * Simulated transcript produced by the ZK simulator.
 * This should be computationally indistinguishable from
 * a real GMW protocol transcript.
 */
typedef struct {
    int              n_vertices;
    int              n_edges;
    /* Simulated commitments (one per vertex) */
    HashDigest*      commitments;
    CommitNonce*     nonces;
    /* Simulated challenge edge */
    int              edge_u;
    int              edge_v;
    /* Simulated revealed colors */
    int              color_u;
    int              color_v;
    /* For the two revealed vertices, we need proper nonces */
    CommitNonce      nonce_u;
    CommitNonce      nonce_v;
    /* Simulator random tape (for reproducibility) */
    uint64_t         sim_seed;
} SimulatedTranscript;

/* -- Simulator Operations ---------------------------------- */
/*
 * Create a simulated transcript for the GMW 3-COLORING protocol.
 *
 * Strategy (HVZK simulator):
 * 1. Randomly choose an edge e = (u,v) in E
 * 2. Randomly choose two distinct colors c_u != c_v
 * 3. Generate commitments:
 *    - For u,v: commit to c_u, c_v with fresh nonces
 *    - For all other vertices: commit to random colors
 * 4. Output the simulated transcript
 *
 * This transcript is indistinguishable from a real one because:
 * - In the real protocol, colors are permuted randomly
 * - The verifier only sees TWO colors (which are always different
 *   because the graph is 3-colorable)
 * - All commitments are hiding, so unopened commitments reveal nothing
 *
 * Complexity: O(|V|) commitments
 */
SimulatedTranscript* simulator_generate_transcript(const Graph3Col* graph,
                                                    uint64_t seed);

/*
 * Generate multiple simulated transcripts.
 */
SimulatedTranscript** simulator_generate_transcripts(const Graph3Col* graph,
                                                      int n_transcripts,
                                                      uint64_t base_seed);

/*
 * Free a simulated transcript.
 */
void simulator_free_transcript(SimulatedTranscript* transcript);

/*
 * Generate a real GMW transcript (for comparison with simulated).
 * Uses the actual prover with the given 3-coloring.
 */
GMWTranscript* simulator_generate_real_transcript(const Graph3Col* graph,
                                                   const Coloring3* coloring,
                                                   int n_rounds,
                                                   uint64_t seed);

/* -- Distinguisher / Indistinguishability Tests ------------ */
/*
 * Simple statistical comparison between simulated and real transcripts.
 * Compares distributions of observed colors.
 * In a real ZK proof, these should be indistinguishable.
 * (This is a heuristic test, not a cryptographic proof of ZK.)
 */
typedef struct {
    double color_dist_sim[NUM_COLORS][NUM_COLORS]; /* joint distribution in simulated */
    double color_dist_real[NUM_COLORS][NUM_COLORS]; /* joint distribution in real */
    double total_variation_distance;
    int    samples_compared;
} ZKDistinguisherReport;

/*
 * Run a distinguisher test comparing simulated vs real transcripts.
 * Computes total variation distance between the two distributions.
 * If ZK holds, TVD should be negligible (close to 0).
 */
ZKDistinguisherReport* zk_distinguisher_run(const Graph3Col* graph,
                                              const Coloring3* coloring,
                                              int n_samples,
                                              uint64_t seed);

void zk_distinguisher_report_free(ZKDistinguisherReport* report);
void zk_distinguisher_report_print(const ZKDistinguisherReport* report);

/* -- ZK Property Verification ------------------------------ */
/*
 * Verify that the simulator produces transcripts that are
 * consistent (i.e., would be accepted by the honest verifier).
 * This is a necessary condition for ZK (but not sufficient).
 */
int simulator_verify_consistency(const SimulatedTranscript* transcript,
                                  const Graph3Col* graph);

/*
 * Check that simulated transcripts have the same structure
 * as real transcripts: same challenge distribution, same
 * color difference property.
 */
int simulator_structural_test(const Graph3Col* graph,
                               const Coloring3* coloring,
                               int n_trials, uint64_t seed);

/* -- Simulator for General NP via 3-COLORING Reduction ----- */
/*
 * Given an NP-witness for any NP language L, and the reduction
 * from L to 3-COLORING, produce a simulated GMW transcript.
 *
 * This demonstrates the GMW Theorem: every L in NP has a
 * computational ZK proof system.
 */
SimulatedTranscript* simulator_np_language(const char* language_name,
                                            const void* np_witness,
                                            int (*reduction_to_3col)(const void*, Graph3Col**, Coloring3**),
                                            uint64_t seed);

#endif
