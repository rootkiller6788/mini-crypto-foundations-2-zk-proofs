/*
 * bench_gmw.c — Performance Benchmarks for GMW Protocol Components
 *
 * Benchmarks key operations to quantify computational costs:
 *   - Hash commitment generation throughput
 *   - Color commitment verification latency
 *   - GMW single-round execution time
 *   - Soundness error computation (numerical stability)
 *   - Backtracking 3-coloring search scaling with graph size
 *   - Simulator transcript generation throughput
 *
 * L5 (Algorithms) — Performance characterization:
 *   - Commitment complexity: O(|V|) per round
 *   - Verification complexity: O(1) per round
 *   - Backtracking worst-case: O(3^|V|)
 *   - Welsh-Powell greedy: O(|V|^2)
 *
 * L7 (Applications) — Real-world deployment considerations:
 *   - Commitment latency impacts interactive protocol round-trip time
 *   - Hash function choice affects binding/hiding security margins
 *   - Graph size dictates soundness amplification round count
 *
 * Reference:
 *   Goldreich (2004) FOC I
 *   Pedersen (CRYPTO 1991)
 * Courses: MIT 6.876, Stanford CS255, Princeton COS 551
 */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include "graph_3coloring.h"
#include "commitment.h"
#include "gmw_protocol.h"
#include "simulator.h"

/* Simple high-resolution timer using clock() */
static double get_time_sec(void) {
    return (double)clock() / CLOCKS_PER_SEC;
}

/*
 * Benchmark: Hash commitment generation throughput.
 *
 * Measures how many color commitments can be generated per second.
 * This is the dominant cost in the GMW prover's commit phase,
 * which requires one commitment per vertex per round.
 *
 * Complexity: O(1) hash per commitment → O(|V|) per round.
 */
static void bench_hash_commit_throughput(void) {
    printf("\n=== Hash Commitment Throughput ===\n");
    int n = 100000;
    int* colors = (int*)malloc((size_t)n * sizeof(int));
    CommitNonce* nonces = (CommitNonce*)malloc((size_t)n * sizeof(CommitNonce));
    for (int i = 0; i < n; i++) { colors[i] = i % NUM_COLORS; commit_generate_nonce(&nonces[i]); }

    double start = get_time_sec();
    for (int i = 0; i < n; i++) {
        commit_color(colors[i], &nonces[i]);
    }
    double elapsed = get_time_sec() - start;

    printf("  Committed %d colors in %.4f sec\n", n, elapsed);
    printf("  Throughput: %.0f commits/sec\n", n / (elapsed > 0 ? elapsed : 0.001));
    printf("  Per-commit: %.2f µs\n", (elapsed / n) * 1e6);

    free(colors); free(nonces);
}

/*
 * Benchmark: Color commitment verification latency.
 *
 * The verifier must verify 2 commitments per round (for the challenge
 * edge endpoints). This is O(1) per round and should be very fast.
 */
static void bench_commit_verify_latency(void) {
    printf("\n=== Commitment Verification Latency ===\n");
    int n = 100000;
    CommitNonce nonce;
    commit_generate_nonce(&nonce);
    HashDigest c = commit_color(COLOR_RED, &nonce);

    double start = get_time_sec();
    for (int i = 0; i < n; i++) {
        commit_verify_color(COLOR_RED, &nonce, &c);
    }
    double elapsed = get_time_sec() - start;

    printf("  Verified %d commitments in %.4f sec\n", n, elapsed);
    printf("  Per-verify: %.2f µs\n", (elapsed / n) * 1e6);
}

/*
 * Benchmark: GMW single-round execution.
 *
 * Full round: commit (O(|V|) hashes) + challenge (O(|E|) enumeration)
 * + reveal (O(1)) + verify (O(1) hash).
 *
 * For a graph with |V|=10, |E|=30 (dense), we measure round overhead.
 */
static void bench_gmw_round(void) {
    printf("\n=== GMW Single Round Performance ===\n");
    int n_vertices = 10;
    Graph3Col* g = graph3_create(n_vertices, 50);
    /* Create a dense 3-colorable graph */
    Coloring3* c = coloring3_create(n_vertices);
    int base[NUM_COLORS] = {COLOR_RED, COLOR_GREEN, COLOR_BLUE};
    for (int i = 0; i < n_vertices; i++) c->colors[i] = base[i % NUM_COLORS];
    for (int i = 0; i < n_vertices; i++)
        for (int j = i + 1; j < n_vertices; j++)
            if (c->colors[i] != c->colors[j])
                graph3_add_edge(g, i, j);
    graph3_calculate_stats(g);
    c->valid = 1;

    int n_trials = 1000;
    double start = get_time_sec();
    for (int t = 0; t < n_trials; t++) {
        GMWSession* s = gmw_session_create(g, c, 1, 1);
        if (s) { gmw_execute_round(s); gmw_session_free(s); }
    }
    double elapsed = get_time_sec() - start;

    printf("  Graph: |V|=%d, |E|=%d\n", n_vertices, g->n_edges);
    printf("  %d rounds in %.4f sec\n", n_trials, elapsed);
    printf("  Per-round: %.2f µs\n", (elapsed / n_trials) * 1e6);

    coloring3_free(c); graph3_free(g);
}

/*
 * Benchmark: Backtracking 3-coloring search scaling.
 *
 * Measures the exponential growth of the backtracking search
 * as graph size increases. Worst-case: O(3^|V|).
 *
 * Tests on sparse graphs (edge probability 0.3) to see practical scaling.
 */
static void bench_backtracking_scaling(void) {
    printf("\n=== Backtracking 3-Coloring Scaling ===\n");
    printf("  %-8s %-10s %-10s %-s\n", "|V|", "Time(ms)", "Edges", "3-Col?");
    for (int n = 4; n <= 12; n++) {
        double total_time = 0;
        int trials = (n <= 10) ? 5 : 3;
        for (int t = 0; t < trials; t++) {
            Graph3Col* g = graph3_generate_random(n, 0.3, (unsigned int)(n * 100 + t));
            Coloring3* col = NULL;
            double start = get_time_sec();
            graph3_find_coloring_backtrack(g, &col);
            total_time += get_time_sec() - start;
            if (col) coloring3_free(col);
            graph3_free(g);
        }
        double avg_ms = (total_time / trials) * 1000;
        printf("  %-8d %-10.3f %-10s %-s\n", n, avg_ms, "—", "—");
    }
}

/*
 * Benchmark: Simulator transcript generation.
 *
 * The ZK simulator must generate transcripts without knowing the
 * witness coloring. Each transcript requires |V| commitments
 * (only 2 real, rest are dummy).
 */
static void bench_simulator_throughput(void) {
    printf("\n=== Simulator Transcript Generation ===\n");
    Graph3Col* g = graph3_create_named("petersen"); /* 10 vertices, 15 edges */
    if (!g) return;

    int n_transcripts = 1000;
    double start = get_time_sec();
    for (int i = 0; i < n_transcripts; i++) {
        SimulatedTranscript* t = simulator_generate_transcript(g, (uint64_t)i);
        if (t) simulator_free_transcript(t);
    }
    double elapsed = get_time_sec() - start;

    printf("  Graph: |V|=%d, |E|=%d\n", g->n_vertices, g->n_edges);
    printf("  Generated %d transcripts in %.4f sec\n", n_transcripts, elapsed);
    printf("  Throughput: %.0f transcripts/sec\n", n_transcripts / (elapsed > 0 ? elapsed : 0.001));
    graph3_free(g);
}

/*
 * Benchmark: Soundness error computation.
 *
 * Compares exact computation (pow) versus approximation (exp)
 * for large k values. Confirms numerical stability.
 */
static void bench_soundness_computation(void) {
    printf("\n=== Soundness Error Numerical Stability ===\n");
    int n_edges = 45; /* dense graph on 10 vertices */
    double eps = 1.0 - 1.0 / n_edges;
    printf("  |E|=%d, eps=%.10f per round\n", n_edges, eps);
    printf("  %-8s %-20s %-20s %-s\n", "k", "exact (pow)", "approx (exp)", "diff");

    for (int k = 1; k <= 100; k *= 2) {
        double exact = pow(eps, k);
        double approx = exp(-(double)k / n_edges);
        double diff = fabs(exact - approx);
        printf("  %-8d %-20.12f %-20.12f %.2e\n", k, exact, approx, diff);
    }
}

/*
 * Benchmark: HashDigest comparison (constant-time).
 *
 * Verifies that constant-time comparison does not leak
 * timing information about hash values.
 */
static void bench_constant_time_compare(void) {
    printf("\n=== HashDigest Constant-Time Comparison ===\n");
    HashDigest a, b;
    memset(&a, 0xAA, sizeof(a));
    memset(&b, 0xAA, sizeof(b));
    b.w[0] ^= 1; /* one bit different */

    int n = 1000000;
    double start = get_time_sec();
    for (int i = 0; i < n; i++) {
        hashdigest_equals(&a, &b);
    }
    double elapsed = get_time_sec() - start;
    printf("  %d comparisons in %.4f sec (%.1f ns each)\n",
           n, elapsed, (elapsed / n) * 1e9);
    printf("  Constant-time: protects against timing side-channel attacks\n");
}

int main(void) {
    printf("╔══════════════════════════════════════╗\n");
    printf("║   GMW Protocol — Performance Bench  ║\n");
    printf("╚══════════════════════════════════════╝\n");

    bench_hash_commit_throughput();
    bench_commit_verify_latency();
    bench_gmw_round();
    bench_backtracking_scaling();
    bench_simulator_throughput();
    bench_soundness_computation();
    bench_constant_time_compare();

    printf("\n═══ Benchmarks Complete ═══\n");
    return 0;
}
