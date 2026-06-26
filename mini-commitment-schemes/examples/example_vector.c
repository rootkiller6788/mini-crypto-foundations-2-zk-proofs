/**
 * @file example_vector.c
 * @brief Vector commitment (Merkle tree) end-to-end demonstration
 *
 * Demonstrates committing to a vector of values and proving
 * individual positions with Merkle proofs.
 *
 * This pattern is the foundation of:
 *   - Blockchain light clients (Bitcoin SPV)
 *   - Verifiable databases (Certificate Transparency)
 *   - zk-rollup state trees
 *
 * Knowledge Mapping:
 *   L1: Vector commitment definition
 *   L5: Merkle tree construction, proof generation
 *   L6: Membership proof problem
 *   L7: Blockchain application
 */

#include "vector_commit.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    printf("\n");
    printf("¨X¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨[\n");
    printf("¨U   Vector Commitment (Merkle Tree) Demo       ¨U\n");
    printf("¨U   Commitment to a vector with O(log n) proofs ¨U\n");
    printf("¨^¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨a\n\n");

    /* ================================================================
     * Step 1: Setup
     * Create a vector of 8 elements (account balances).
     * ================================================================ */

    printf("[Step 1] Create vector of 8 account balances\n");

    vector_commitment vc;
    vc_init(&vc, 8);

    uint64_t balances[] = {1000, 250, 5000, 75, 3200, 150, 800, 4250};
    for (size_t i = 0; i < 8; i++) {
        bigint val;
        bigint_init_u64(&val, balances[i]);
        vc_set_element(&vc, i, &val);
        printf("  Account[%zu] = %llu\n", i, (unsigned long long)balances[i]);
    }
    printf("\n");

    /* ================================================================
     * Step 2: Commit
     * Build the Merkle tree. The root is the commitment.
     * ================================================================ */

    printf("[Step 2] Build Merkle tree and compute commitment\n");

    vc_commit(&vc);
    const bigint *root = vc_get_commitment(&vc);

    char root_hex[512];
    bigint_to_hex(root, root_hex, sizeof(root_hex));
    printf("  Merkle root (commitment) C = %s\n", root_hex);
    printf("  Tree depth: ceil(log2(8)) = 3\n");
    printf("  The commitment is published (e.g., on blockchain).\n\n");

    /* ================================================================
     * Step 3: Generate Proof
     * Prove that Account[3] = 75 without revealing other balances.
     * ================================================================ */

    printf("[Step 3] Generate Merkle proof for Account[3]\n");
    printf("  Prover claims: Account[3] = 75\n");

    vc_merkle_proof proof;
    vc_open(&vc, 3, &proof);

    printf("  Proof contains %zu sibling hashes:\n", proof.proof_length);
    for (size_t i = 0; i < proof.proof_length; i++) {
        char sib_hex[256];
        bigint_to_hex(&proof.siblings[i], sib_hex, sizeof(sib_hex));
        printf("    Level %zu: %s (direction: %s)\n",
               i, sib_hex,
               proof.directions[i] == 0 ? "right sibling" : "left sibling");
    }
    printf("  Proof size: O(log n) = %zu hashes (vs O(n) for full vector)\n",
           proof.proof_length);
    printf("\n");

    /* ================================================================
     * Step 4: Verify Proof
     * The verifier recomputes the root from the proof and checks equality.
     * ================================================================ */

    printf("[Step 4] Verify the Merkle proof\n");

    bigint claimed_value;
    bigint_init_u64(&claimed_value, 75);
    bool is_valid = vc_verify(&vc, 3, &claimed_value, &proof);
    printf("  Verification result: %s\n", is_valid ? "VALID" : "INVALID");

    /* Try to cheat: claim Account[3] = 1000 */
    bigint fake_value;
    bigint_init_u64(&fake_value, 1000);
    bool is_cheat = vc_verify(&vc, 3, &fake_value, &proof);
    printf("  Cheat attempt (claim 1000): %s\n", is_cheat ? "ACCEPTED" : "REJECTED");
    printf("\n");

    /* ================================================================
     * Step 5: Update
     * Update Account[3] from 75 to 200. Only O(log n) nodes change.
     * ================================================================ */

    printf("[Step 5] Update Account[3] from 75 to 200\n");

    bigint old_root;
    bigint_copy(&old_root, root);

    bigint new_balance;
    bigint_init_u64(&new_balance, 200);
    vc_update(&vc, 3, &new_balance);

    const bigint *new_root = vc_get_commitment(&vc);

    char new_root_hex[512];
    bigint_to_hex(new_root, new_root_hex, sizeof(new_root_hex));

    printf("  Old root: %s\n", root_hex);
    printf("  New root: %s\n", new_root_hex);
    printf("  Root changed: %s\n",
           bigint_cmp(&old_root, new_root) == 0 ? "NO" : "YES");
    printf("  Only 3 internal nodes were recomputed (O(log n)).\n");

    /* Verify the new balance at position 3 */
    vc_merkle_proof new_proof;
    vc_open(&vc, 3, &new_proof);
    bool new_valid = vc_verify(&vc, 3, &new_balance, &new_proof);
    printf("  New balance verification: %s\n", new_valid ? "VALID" : "INVALID");

    /* Unchanged positions should still verify with their old values */
    bigint unchanged_val;
    bigint_init_u64(&unchanged_val, 1000);
    vc_merkle_proof proof_0;
    vc_open(&vc, 0, &proof_0);
    bool unchanged_valid = vc_verify(&vc, 0, &unchanged_val, &proof_0);
    printf("  Unchanged Account[0]=1000 verification: %s\n",
           unchanged_valid ? "VALID" : "INVALID");

    vc_destroy(&vc);

    printf("\n¨X¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨[\n");
    printf("¨U   Vector commitment demo completed!          ¨U\n");
    printf("¨^¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨a\n\n");

    return 0;
}
