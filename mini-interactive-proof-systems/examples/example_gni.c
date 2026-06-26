/*======================================================================
 * example_gni.c -- Graph Non-Isomorphism Interactive Proof Example
 *
 * Demonstrates the GNI protocol: proving that two graphs are NOT
 * isomorphic using interactive proof. GNI is in IP but not known
 * to be in NP.
 *
 * L6: Graph Non-Isomorphism -- canonical problem
 *======================================================================*/

#include "ip_system.h"
#include "ip_protocols.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(void) {
    printf("=== GNI Interactive Proof Example ===\n\n");

    /* Create two non-isomorphic graphs:
     * G0: 3 vertices, edges (0-1, 1-2) -- a path of length 2
     * G1: 3 vertices, edges (0-1, 0-2, 1-2) -- a triangle
     */
    int edges0[] = {0, 1, 1, 2};
    int edges1[] = {0, 1, 0, 2, 1, 2};

    IPGraph G0, G1;
    ip_graph_init(&G0, 3, edges0, 2);
    ip_graph_init(&G1, 3, edges1, 3);

    printf("G0: 3 vertices, path 0-1-2\n");
    printf("G1: 3 vertices, triangle 0-1-2-0\n");

    /* Serialize input for the protocol: G0 || G1 */
    uint8_t input_buf[2048];
    size_t graph_size = sizeof(int) + sizeof(uint64_t) * 64;
    size_t offset = 0;
    ip_graph_serialize(&G0, input_buf + offset, &graph_size);
    offset += graph_size;
    ip_graph_serialize(&G1, input_buf + offset, &graph_size);
    offset += graph_size;

    /* Check they are indeed non-isomorphic */
    IPPermutation witness;
    int iso = ip_graph_is_isomorphic(&G0, &G1, &witness);
    printf("G0 isomorphic to G1? %s\n\n", iso ? "YES" : "NO");

    /* Set up GNI proof system */
    IPProofSystem psys;
    if (ip_gni_proof_system_create(&psys, &G0, &G1) != 0) {
        printf("Error: Could not create GNI proof system\n");
        return 1;
    }

    printf("Proof system: %s\n", psys.language_name);
    printf("Rounds: %u, Type: %s\n", psys.num_rounds,
           psys.protocol_type == IP_PROTOCOL_PRIVATE_COIN ?
           "private-coin" : "public-coin");
    printf("Completeness error: %.4f, Soundness error: %.4f\n\n",
           psys.completeness_error, psys.soundness_error);

    /* Run the GNI protocol several times */
    printf("Running GNI protocol with error reduction (k=3):\n");
    IPResult result;
    int ret = ip_run_with_error_reduction(&psys,
        (const char *)input_buf, offset, NULL, 0, 3, &result);
    if (ret != 0) {
        printf("Error: Protocol run failed\n");
        return 1;
    }

    printf("Verdict: %s\n", result.verdict == IP_VERDICT_ACCEPT ?
           "ACCEPT (non-isomorphic)" : "REJECT");
    printf("Error bound: %.6f\n", result.error_bound);
    printf("Rounds executed: %u\n\n", result.rounds_executed);

    /* Experiment with isomorphic graphs */
    printf("Now testing with isomorphic graphs (G1 = permuted G0):\n");
    IPPermutation pi = {.n = 3, .mapping = {2, 1, 0}}; /* Reverse */
    IPGraph G0_prime;
    ip_graph_permute(&G0, &pi, &G0_prime);

    iso = ip_graph_is_isomorphic(&G0, &G0_prime, NULL);
    printf("G0 isomorphic to permuted G0? %s\n", iso ? "YES" : "NO");

    printf("\n=== GNI Example Complete ===\n");
    return 0;
}
