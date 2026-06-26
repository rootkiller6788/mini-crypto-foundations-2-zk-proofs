#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "graph_3coloring.h"
#include "commitment.h"
#include "gmw_protocol.h"
#include "simulator.h"

int main(void) {
    printf("=== ZK Simulator Demo ===\n\n");
    Graph3Col* g = graph3_create_named("triangle");
    printf("Graph: "); graph3_print_compact(g); printf("\n\n");

    printf("1. Simulated transcript (NO coloring knowledge):\n");
    SimulatedTranscript* sim = simulator_generate_transcript(g, 42);
    printf("   Edge: (%d,%d)\n", sim->edge_u, sim->edge_v);
    printf("   Colors: %s, %s\n",
           COLOR_STRING(sim->color_u), COLOR_STRING(sim->color_v));
    printf("   Consistent: %s\n",
           simulator_verify_consistency(sim, g) ? "yes" : "no");
    simulator_free_transcript(sim);

    printf("\n2. Real transcript (WITH coloring):\n");
    Coloring3* c = coloring3_create(3);
    c->colors[0] = COLOR_RED;
    c->colors[1] = COLOR_GREEN;
    c->colors[2] = COLOR_BLUE;
    c->valid = coloring3_verify(g, c);

    GMWTranscript* real = simulator_generate_real_transcript(g, c, 5, 123);
    printf("   Rounds: %d\n", real->n_rounds);
    printf("   Verdict: %s\n", real->verifier_accept ? "ACCEPT" : "REJECT");
    if (real->rounds) {
        for (int i = 0; i < real->n_rounds; i++)
            gmw_round_free(real->rounds[i], g->n_vertices);
        free(real->rounds);
    }
    free(real);

    printf("\n3. Distinguisher test:\n");
    ZKDistinguisherReport* r = zk_distinguisher_run(g, c, 30, 555);
    printf("   Samples: %d\n", r->samples_compared);
    printf("   TVD: %.4f (0 => indistinguishable => ZK holds)\n",
           r->total_variation_distance);
    zk_distinguisher_report_free(r);

    printf("\n4. Key insight:\n");
    printf("   Simulator works WITHOUT the 3-coloring.\n");
    printf("   Output indistinguishable from real transcripts.\n");
    printf("   => Verifier learns NOTHING beyond validity.\n");

    coloring3_free(c);
    graph3_free(g);
    printf("\n=== Demo Complete ===\n");
    return 0;
}
