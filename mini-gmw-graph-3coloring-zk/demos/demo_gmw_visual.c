/*
 * demo_gmw_visual.c — Visual Demonstration of GMW Protocol Rounds
 *
 * Annotated walkthrough of the GMW 3-COLORING ZK protocol showing:
 *   1. Graph construction with known 3-coloring
 *   2. Prover's commitment phase (hiding the coloring)
 *   3. Verifier's random edge challenge
 *   4. Prover's selective reveal (only 2 vertex colors)
 *   5. Verifier's consistency check
 *   6. Soundness amplification via sequential repetition
 *
 * Demonstrates L5 (Algorithms) and L6 (Canonical Problems):
 *   - GMW protocol state machine visualization
 *   - Soundness error computation across rounds
 *   - ZK simulator comparison side-by-side
 *
 * Reference:
 *   Goldreich, Micali, Wigderson (1986/1991)
 *   Goldreich (2004) FOC I, sec 4.4
 * Courses: MIT 6.876, Stanford CS255, Princeton COS 551
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "graph_3coloring.h"
#include "commitment.h"
#include "gmw_protocol.h"
#include "simulator.h"
#include "interactive_proof.h"
#include "zk_applications.h"

/* Print a color with ANSI escape codes for visual clarity */
static void print_color_ansi(int color) {
    switch (color) {
    case COLOR_RED:    printf("\033[31mRED\033[0m"); break;
    case COLOR_GREEN:  printf("\033[32mGREEN\033[0m"); break;
    case COLOR_BLUE:   printf("\033[34mBLUE\033[0m"); break;
    default:           printf("???"); break;
    }
}

/* Print a graph as an ASCII adjacency matrix with coloring overlay */
static void print_graph_with_coloring(const Graph3Col* g, const Coloring3* c) {
    printf("    ");
    for (int i = 0; i < g->n_vertices; i++) printf(" v%-2d", i);
    printf("\n");
    for (int i = 0; i < g->n_vertices; i++) {
        printf("v%-2d ", i);
        print_color_ansi(c ? c->colors[i] : -1);
        for (int j = 0; j < g->n_vertices; j++) {
            if (i == j) { printf(" \\  "); }
            else { printf(" %d  ", graph3_has_edge(g, i, j)); }
        }
        printf("\n");
    }
}

/*
 * Demonstrate one complete round of the GMW protocol step-by-step.
 * Shows the five phases: INIT → COMMIT → CHALLENGE → REVEAL → VERIFY
 */
static void demo_single_round(const Graph3Col* graph, const Coloring3* coloring,
                               int round_num, unsigned int seed) {
    int n = graph->n_vertices;
    srand(seed);

    printf("\n══════ Round %d ══════\n", round_num);
    printf("[Phase 1: INIT] Prover knows a valid 3-coloring:\n    ");
    for (int v = 0; v < n; v++) {
        printf("v%d=", v); print_color_ansi(coloring->colors[v]); printf(" ");
    }
    printf("\n");

    printf("[Phase 2: COMMIT] Prover applies random permutation pi in S3\n");
    ColorPermutation perm;
    int vals[NUM_COLORS] = {0, 1, 2};
    for (int i = NUM_COLORS - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        int t = vals[i]; vals[i] = vals[j]; vals[j] = t;
    }
    for (int c = 0; c < NUM_COLORS; c++) { perm.perm[c] = vals[c]; perm.inv[vals[c]] = c; }
    printf("  Perm: "); for (int c=0;c<NUM_COLORS;c++){print_color_ansi(c);printf("->");print_color_ansi(perm.perm[c]);printf(" ");}
    printf("\n  Committed (permuted) colors:\n    ");

    HashDigest commits[32]; CommitNonce nonces[32];
    for (int v = 0; v < n; v++) {
        int pc = perm.perm[coloring->colors[v]];
        commit_generate_nonce(&nonces[v]);
        commits[v] = commit_color(pc, &nonces[v]);
        printf("v%d=", v); print_color_ansi(pc); printf("[c] ");
    }
    printf("\n");

    printf("[Phase 3: CHALLENGE] Verifier selects random edge\n");
    int n_edges = graph->n_edges;
    int target = rand() % n_edges;
    int cu=-1,cv=-1,cnt=0;
    for (int i=0;i<n&&cu<0;i++) for(int j=i+1;j<n;j++)
        if (graph3_has_edge(graph,i,j)) { if(cnt==target){cu=i;cv=j;} cnt++; }
    printf("  Edge: (v%d, v%d)\n", cu, cv);

    printf("[Phase 4: REVEAL] Prover opens ONLY two vertices\n");
    int ru=perm.perm[coloring->colors[cu]], rv=perm.perm[coloring->colors[cv]];
    printf("  v%d=",cu);print_color_ansi(ru);printf(" v%d=",cv);print_color_ansi(rv);
    printf("\n  (All other vertices remain hidden — ZK property!)\n");

    printf("[Phase 5: VERIFY] Verifier checks:\n");
    int c1=(ru!=rv), c2=(ru>=0&&ru<NUM_COLORS&&rv>=0&&rv<NUM_COLORS);
    int c3=commit_verify_color(ru,&nonces[cu],&commits[cu]);
    int c4=commit_verify_color(rv,&nonces[cv],&commits[cv]);
    printf("  Colors differ? %s  Valid? %s  Commit match? %s  %s\n",
           c1?"YES":"NO",c2?"YES":"NO",c3?"YES":"NO",c4?"YES":"NO");
    printf("  Result: %s\n", (c1&&c2&&c3&&c4)?"ACCEPT":"REJECT");
}

/*
 * Demonstrate soundness amplification: epsilon_k = (1 - 1/|E|)^k
 */
static void demo_soundness_amplification(const Graph3Col* graph) {
    printf("\n═══ Soundness Amplification ═══\n");
    int n_edges = graph->n_edges;
    if (n_edges<=1) return;
    double eps = 1.0 - 1.0/n_edges;
    printf("  |E|=%d, eps=%.4f per round\n", n_edges, eps);
    printf("  %-6s %-20s %s\n", "k", "epsilon^k", "Security(bits)");
    int ks[]={1,2,5,10,20,40,80,128};
    for(int i=0;i<8;i++){
        int k=ks[i]; double ek=pow(eps,k);
        double bits=(ek>0)?-log(ek)/log(2.0):INFINITY;
        printf("  %-6d %-20.10f %.1f\n",k,ek,bits);
    }
}

/*
 * Compare real vs simulated transcripts — ZK property demonstration.
 */
static void demo_simulator_comparison(const Graph3Col* graph, const Coloring3* coloring) {
    printf("\n═══ ZK Simulator Comparison ═══\n");
    GMWTranscript* real = simulator_generate_real_transcript(graph,coloring,5,42);
    printf("  Real: %s\n",(real&&real->verifier_accept)?"ACCEPT":"REJECT");
    SimulatedTranscript** sims = simulator_generate_transcripts(graph,5,99);
    if(sims){for(int i=0;i<5;i++)printf("  Sim#%d: edge=(%d,%d) colors=(%d,%d) ok=%d\n",
        i,sims[i]->edge_u,sims[i]->edge_v,sims[i]->color_u,sims[i]->color_v,
        simulator_verify_consistency(sims[i],graph));}
    ZKDistinguisherReport* dr=zk_distinguisher_run(graph,coloring,100,12345);
    if(dr){printf("  TVD=%.6f (close to 0 => ZK holds)\n",dr->total_variation_distance);
           zk_distinguisher_report_free(dr);}
    if(real){if(real->rounds){for(int i=0;i<real->n_rounds;i++)gmw_round_free(real->rounds[i],graph->n_vertices);free(real->rounds);}free(real);}
    if(sims){for(int i=0;i<5;i++)simulator_free_transcript(sims[i]);free(sims);}
}

/*
 * Fiat-Shamir transform: interactive → non-interactive ZK proof.
 */
static void demo_fiat_shamir(const Graph3Col* graph, const Coloring3* coloring) {
    printf("\n═══ Fiat-Shamir NIZK Transform ═══\n");
    NIZKProof* proof = nizk_gmw_prove(graph,coloring,42);
    if(!proof){printf("  FAILED\n");return;}
    printf("  Commitments: %d, Edge: (%d,%d), Colors: (%d,%d)\n",
           proof->n_commitments,proof->challenge_edge_u,proof->challenge_edge_v,
           proof->revealed_color_u,proof->revealed_color_v);
    printf("  Verify: %s\n",nizk_gmw_verify(graph,proof)?"VALID":"INVALID");
    free(proof->commitments); free(proof);
}

/*
 * Anonymous credential: "my attribute >= threshold" ZK proof.
 */
static void demo_anonymous_credential(void) {
    printf("\n═══ Anonymous Credential Demo ═══\n");
    ZKCredential cred;
    cred.issuer="University"; cred.credential_id=12345;
    cred.attributes[0]=25; cred.attributes[1]=80;
    cred.attributes[2]=3;  cred.attributes[3]=100;
    printf("  Cred: [age=%d, score=%d, level=%d, balance=%d]\n",
           cred.attributes[0],cred.attributes[1],cred.attributes[2],cred.attributes[3]);
    printf("  age>=18? %s\n",zk_credential_prove_attribute(&cred,0,18,5,100)?"PROVED":"FAILED");
    printf("  score>=60? %s\n",zk_credential_prove_attribute(&cred,1,60,5,200)?"PROVED":"FAILED");
    printf("  age>=30? %s (correctly rejected)\n",zk_credential_prove_attribute(&cred,0,30,5,300)?"SHOULD FAIL":"REJECTED");
}

int main(void) {
    printf("╔══════════════════════════════════════╗\n");
    printf("║  GMW 3-Coloring ZK — Visual Demo   ║\n");
    printf("╚══════════════════════════════════════╝\n\n");

    Graph3Col* graph = graph3_create_named("house");
    if(!graph){printf("Failed to create graph.\n");return 1;}
    printf("Graph: "); graph3_print(graph);

    Coloring3* coloring=NULL;
    if(!graph3_find_coloring_backtrack(graph,&coloring)||!coloring){
        printf("No 3-coloring found.\n");graph3_free(graph);return 1;
    }
    printf("Found 3-coloring: "); coloring3_print(coloring);

    demo_single_round(graph,coloring,1,12345);
    demo_single_round(graph,coloring,2,67890);
    demo_soundness_amplification(graph);
    demo_simulator_comparison(graph,coloring);
    demo_fiat_shamir(graph,coloring);
    demo_anonymous_credential();

    coloring3_free(coloring); graph3_free(graph);
    printf("\n═══ Demo Complete ═══\n");
    return 0;
}
