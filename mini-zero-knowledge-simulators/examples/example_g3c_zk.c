/*
 * example_g3c_zk.c -- End-to-End: Graph 3-Coloring ZK Proof (GMW Protocol)
 *
 * Demonstrates the GMW ZK proof for Graph 3-Coloring:
 *   Prover (knows 3-colouring) commits to permuted colours of each vertex.
 *   Verifier challenges one random edge.
 *   Prover opens commitments for both endpoints.
 *   Verifier checks colours differ.
 *
 * After k rounds, soundness error = (1 - 1/|E|)^k.
 *
 * Reference: Goldreich-Micali-Wigderson (STOC 1986, JACM 1991)
 * Courses: MIT 6.875, Berkeley CS276, Stanford CS355
 */

#include "zk_simulator.h"
#include "zk_problems.h"
#include "commitments.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(void) {
    printf("=== G3C (Graph 3-Coloring) GMW ZK Protocol ===\n\n");

    /* Build a triangle graph (3 vertices, 3 edges) */
    graph_t G;
    G.num_vertices = 3;
    G.num_edges = 3;
    G.edges[0][0] = 0; G.edges[0][1] = 1;
    G.edges[1][0] = 1; G.edges[1][1] = 2;
    G.edges[2][0] = 2; G.edges[2][1] = 0;
    memset(G.adjacency, 0, sizeof(G.adjacency));
    G.adjacency[0][1] = G.adjacency[1][0] = 1;
    G.adjacency[1][2] = G.adjacency[2][1] = 1;
    G.adjacency[2][0] = G.adjacency[0][2] = 1;

    printf("Graph: triangle K3 with |V|=3, |E|=3\n");
    printf("3-colouring: v0=Red(0), v1=Green(1), v2=Blue(2)\n\n");

    /* Known 3-colouring */
    three_colouring_t colouring;
    colouring.num_vertices = 3;
    colouring.colours[0] = 0;  /* red */
    colouring.colours[1] = 1;  /* green */
    colouring.colours[2] = 2;  /* blue */

    /* Group parameters for bit commitments */
    group_params_t gp = {23, 2, 11, 8};

    random_tape_t rng;
    init_random_tape(&rng, (uint64_t)time(NULL));

    /* Run k rounds of the GMW G3C protocol */
    int k = 10;
    int accepted = 0;

    printf("Running %d rounds (soundness error = (2/3)^%d = %.6f)\n",
           k, k, powf(2.0f/3.0f, (float)k));

    for (int round = 0; round < k; round++) {
        /* Prover: commit to permuted colours */
        g3c_prover_round_t pr;
        g3c_prover_init_round(&pr, &colouring, &rng, &gp);

        printf("  Round %2d: commitments sent (all %d vertices)\n",
               round + 1, G.num_vertices);

        /* Verifier: pick a random edge */
        g3c_verifier_round_t vr;
        g3c_verifier_pick_edge(&vr, &G, &rng);
        printf("            challenge edge = (%d, %d)\n",
               vr.challenge_edge[0], vr.challenge_edge[1]);

        /* Prover: open both endpoints */
        /* Verifier: verify */
        int ok = g3c_verifier_verify(&pr, &vr);
        if (ok) {
            printf("            verified: colours differ OK\n");
            accepted++;
        } else {
            printf("            FAILED: colours same!\n");
        }
    }

    printf("\nResult: %d/%d rounds accepted\n", accepted, k);
    printf("When prover knows the 3-colouring: all rounds should accept.\n");
    printf("When prover does NOT know: expected %d accepts (cheat detection).\n",
           (int)(k * 1.0 / 3.0));

    /* Simulator demonstration */
    printf("\n=== G3C Simulator (One Round) ===\n");
    init_random_tape(&rng, 1234567);
    bit_commitment_t sim_commits[MAX_VERTICES];
    int sim_edge[2], sim_colours[MAX_VERTICES];
    if (g3c_simulate_round(&G, &rng, sim_commits, sim_edge, sim_colours) == 0) {
        printf("  Simulator guessed edge: (%d, %d)\n", sim_edge[0], sim_edge[1]);
        printf("  Simulated colours on edge: %d != %d\n",
               sim_colours[sim_edge[0]], sim_colours[sim_edge[1]]);
        printf("  Expected success rate: 1/|E| = 1/%d per attempt\n", G.num_edges);
    }

    printf("\n=== G3C Demo Complete ===\n");
    return 0;
}
