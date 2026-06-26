/*======================================================================
 * example_zk_gni.c -- Zero-Knowledge Simulator for GNI
 *
 * Demonstrates the perfect zero-knowledge simulator for the
 * Graph Non-Isomorphism protocol. The simulator produces
 * transcripts that are indistinguishable from real
 * prover-verifier interactions, without needing to solve GI.
 *
 * L7: Zero-Knowledge Proofs ¡ª GNI perfect ZK simulator (GMW 1991)
 *======================================================================*/

#include "ip_system.h"
#include "ip_protocols.h"
#include "ip_zkp.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(void) {
    printf("=== Zero-Knowledge GNI Simulator Example ===\n\n");

    /* Create two non-isomorphic graphs:
     * G0: 4 vertices, path 0-1-2-3
     * G1: 4 vertices, cycle 0-1-2-3-0
     */
    int edges0[] = {0,1, 1,2, 2,3};
    int edges1[] = {0,1, 1,2, 2,3, 3,0};

    IPGraph G0, G1;
    ip_graph_init(&G0, 4, edges0, 3);
    ip_graph_init(&G1, 4, edges1, 4);

    printf("G0: 4-vertex path (0-1-2-3)\n");
    printf("G1: 4-vertex cycle (0-1-2-3-0)\n");

    /* Verify they are non-isomorphic */
    IPPermutation witness;
    int iso = ip_graph_is_isomorphic(&G0, &G1, &witness);
    printf("Are G0 and G1 isomorphic? %s\n\n", iso ? "YES" : "NO");

    /* Serialize input for protocol */
    uint8_t input_buf[2048];
    size_t graph_size = sizeof(int) + sizeof(uint64_t) * 64;
    size_t offset = 0;
    ip_graph_serialize(&G0, input_buf + offset, &graph_size);
    offset += graph_size;
    ip_graph_serialize(&G1, input_buf + offset, &graph_size);
    offset += graph_size;

    /* Part 1: Run real GNI protocol */
    printf("=== Part 1: Real GNI Protocol ===\n");
    IPProofSystem psys;
    ip_gni_proof_system_create(&psys, &G0, &G1);

    IPResult result;
    ip_run(&psys, (const char *)input_buf, offset, NULL, 0, &result);
    printf("Real protocol verdict: %s\n",
           result.verdict == IP_VERDICT_ACCEPT ? "ACCEPT" : "REJECT");
    printf("Real transcript messages: %u\n\n",
           result.transcript.num_messages);

    /* Part 2: Run ZK simulator */
    printf("=== Part 2: ZK Simulator for GNI ===\n");
    ZKSimulator sim;
    zk_simulator_init(&sim, zk_gni_simulate, ZK_PERFECT);

    IPTranscript sim_transcript;
    zk_simulator_run(&sim, (const char *)input_buf, offset,
                     &sim_transcript);

    printf("Simulator produced transcript:\n");
    printf("  Messages: %u\n", sim_transcript.num_messages);
    printf("  Verdict: %s\n",
           sim_transcript.final_verdict == IP_VERDICT_ACCEPT ?
           "ACCEPT" : "REJECT");

    /* Analyze transcripts */
    printf("\n=== Transcript Analysis ===\n");
    printf("Real transcript rounds: %u\n", result.transcript.total_rounds);
    printf("Sim transcript rounds:  %u\n", sim_transcript.total_rounds);

    /* Both have same structure: V challenge + P response = 2 messages */
    printf("Real  msg[0] sender: %s\n",
           result.transcript.messages[0].sender == IP_MESSAGE_VERIFIER ?
           "Verifier" : "Prover");
    printf("Sim   msg[0] sender: %s\n",
           sim_transcript.messages[0].sender == IP_MESSAGE_VERIFIER ?
           "Verifier" : "Prover");

    /* In perfect ZK: both transcripts have identical distribution */
    printf("\n=== Perfect ZK Property ===\n");
    printf("When G0 and G1 are non-isomorphic:\n");
    printf("  - Real: V picks random b, random pi, sends H=pi(G_b).\n");
    printf("          P determines b (by solving GI), responds b.\n");
    printf("  - Sim:  picks random b', random pi', sends H'=pi'(G_{b'}).\n");
    printf("          Responds b'.\n");
    printf("  Both b and b' are uniform on {0,1},\n");
    printf("  pi and pi' are uniform on S_n.\n");
    printf("  => IDENTICAL distributions (perfect ZK).\n");

    /* Cleanup */
    zk_simulator_free(&sim);
    ip_verifier_free(&psys.verifier);
    ip_prover_free(&psys.prover);

    printf("\n=== ZK GNI Simulator Example Complete ===\n");
    return 0;
}
