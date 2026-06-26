#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "graph_3coloring.h"
#include "commitment.h"
#include "gmw_protocol.h"
#include "zk_applications.h"

int main(void) {
    printf("=== ZK Authentication Demo ===\n\n");
    printf("1. Setup: Alice registers with password\n");
    ZKAuthCredential* cred = zk_auth_setup("alice", "s3cret!", 5);
    if (!cred) { printf("Setup failed!\n"); return 1; }
    printf("   Graph: ");
    graph3_print_compact(cred->challenge_graph);
    printf("\n");
    printf("   Security: %.1f bits\n", cred->security_level);

    printf("\n2. Authentication...\n");
    int ok = zk_auth_prove(cred, 42);
    printf("   Result: %s\n", ok ? "ACCEPT" : "REJECT");

    printf("\n3. What the verifier sees:\n");
    printf("   - Commitments to permuted colors\n");
    printf("   - One random edge as challenge\n");
    printf("   - Two revealed colors (different)\n");
    printf("   - Learns NOTHING about the password!\n");

    printf("\n4. Security properties:\n");
    printf("   Completeness: Honest prover always succeeds\n");
    printf("   Soundness: False prover caught w.h.p.\n");
    printf("   Zero-Knowledge: Only validity is learned\n");

    zk_auth_free(cred);
    printf("\n=== Demo Complete ===\n");
    return 0;
}
