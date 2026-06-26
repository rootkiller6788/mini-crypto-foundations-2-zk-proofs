#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "graph_3coloring.h"
#include "commitment.h"
#include "gmw_protocol.h"

int main(void) {
    printf("=== GMW 3-Coloring ZK Proof Demo ===\n\n");
    printf("1. Creating graph...\n");
    Graph3Col* g = graph3_create_named("house");
    graph3_print(g);

    printf("\n2. Finding 3-coloring...\n");
    Coloring3* c = NULL;
    if (graph3_find_coloring_backtrack(g, &c)) {
        printf("   Found valid 3-coloring:\n");
        coloring3_print(c);
    } else {
        printf("   No 3-coloring found!\n");
        graph3_free(g);
        return 1;
    }

    int n = g->n_vertices;
    int n_edges = g->n_edges;
    printf("\n3. GMW protocol (1 round):\n");
    printf("   Graph: |V|=%d, |E|=%d\n", n, n_edges);

    GMWRound* round = gmw_round_create(0, n);
    GMWSession* session = gmw_session_create(g, c, 1, 1);
    gmw_prover_commit(session, round);

    srand(12345);
    int target = rand() % n_edges;
    int cnt = 0, cu = 0, cv = 0;
    for (int i = 0; i < n; i++) {
        for (int j = i + 1; j < n; j++) {
            if (graph3_has_edge(g, i, j)) {
                if (cnt == target) { cu = i; cv = j; }
                cnt++;
            }
        }
    }
    printf("   Challenge edge: (%d,%d)\n", cu, cv);

    gmw_prover_reveal(session, round, cu, cv);
    printf("   Revealed colors: %s, %s\n",
           COLOR_STRING(round->revealed_color_u),
           COLOR_STRING(round->revealed_color_v));

    int accept = (round->revealed_color_u != round->revealed_color_v) ? 1 : 0;
    printf("   Verifier: %s\n", accept ? "ACCEPT" : "REJECT");

    printf("\n4. Soundness analysis:\n");
    double eps1 = 1.0 - 1.0 / n_edges;
    printf("   Per-round error: %.4f\n", eps1);
    for (int k = 1; k <= 100; k *= 10) {
        printf("   After %3d rounds: %.2e\n", k, pow(eps1, k));
    }

    gmw_round_free(round, n);
    gmw_session_free(session);
    coloring3_free(c);
    graph3_free(g);

    printf("\n=== Demo Complete ===\n");
    return 0;
}
