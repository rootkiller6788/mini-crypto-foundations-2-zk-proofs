/**
 * @file vector_commit.h
 * @brief Vector commitment scheme via Merkle tree
 *
 * A vector commitment allows committing to a vector (m_1, ..., m_n)
 * and later opening individual positions with concise proofs.
 *
 * Construction (Merkle tree based):
 *   - Build a binary Merkle tree over the vector elements
 *   - Commitment C = root hash of the tree
 *   - Opening proof for position i = Merkle proof (sibling hashes
 *     along the path from leaf i to root)
 *   - Verifier: recomputes root from leaf and proof, checks equality
 *
 * Properties:
 *   - Position binding: Cannot open position i to two different values
 *   - Concise openings: Proof size O(log n) (vs O(n) for naive approach)
 *   - Updateable: Can update one position and recompute commitment in O(log n)
 *
 * This is a fundamental building block for:
 *   - Stateless cryptocurrencies (Bitcoin SPV, Ethereum light clients)
 *   - Verifiable databases
 *   - zk-rollups (validity proofs for batch transactions)
 *   - Polynomial commitment alternatives
 *
 * References:
 *   - Merkle, R.C. "A Digital Signature Based on a Conventional
 *     Encryption Function" (CRYPTO 1987)
 *   - Catalano, D. and Fiore, D. "Vector Commitments and Their
 *     Applications" (PKC 2013)
 *   - Buterin, V. "Merkling in Ethereum" (2015)
 *
 * Knowledge Mapping:
 *   L1: Definitions - vector commitment, Merkle tree, proof
 *   L3: Mathematical Structures - binary tree, hash chain
 *   L5: Algorithms - Merkle tree construction, proof generation
 *   L6: Canonical Problems - membership proof
 *   L7: Applications - lightweight verification, blockchain
 *   L8: Advanced - updatable commitments
 */

#ifndef MINI_VECTOR_COMMIT_H
#define MINI_VECTOR_COMMIT_H

#include "bigint.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/*============================================================================
 * Constants
 *============================================================================*/

/** Maximum vector length supported */
#define VC_MAX_LENGTH 256

/** Maximum depth of Merkle tree (log2(VC_MAX_LENGTH)) */
#define VC_MAX_DEPTH 8

/** Hash output size (in limbs, 256-bit = 4 x 64-bit) */
#define VC_HASH_LIMBS 4

/*============================================================================
 * Merkle tree node (L3: binary tree structure)
 *
 * Each node stores a hash value. Leaves store hash(message_i).
 * Internal nodes store hash(left_child || right_child).
 *============================================================================*/

typedef struct {
    bigint hash;           /**< Hash value at this node */
    bool   is_leaf;        /**< Whether this is a leaf node */
    size_t index;          /**< Position in the vector (leaves only) */
} vc_node;

/*============================================================================
 * Merkle tree (L3: complete binary tree over vector)
 *
 * The tree is stored in array representation for simplicity:
 *   - Root at index 1
 *   - Left child of i: 2*i
 *   - Right child of i: 2*i + 1
 *   - Parent of i: floor(i/2)
 *   - Leaves at indices [VC_MAX_LENGTH, 2*VC_MAX_LENGTH)
 *
 * For a vector of n elements, we build a tree of size 2*n.
 *============================================================================*/

typedef struct {
    vc_node nodes[2 * VC_MAX_LENGTH];  /**< Array-based binary tree */
    size_t  vector_length;             /**< Number of committed elements */
    size_t  tree_size;                 /**< Total nodes in tree */
    bigint  commitment;                /**< Root hash = commitment */
} vc_merkle_tree;

/*============================================================================
 * Merkle proof (L5: proof of inclusion)
 *
 * A Merkle proof for position i contains:
 *   - The leaf value at position i
 *   - The sibling hashes along the path from leaf to root
 *   - The direction (left/right) for each sibling
 *
 * The verifier recomputes: h_0 = hash(leaf_i), then for each sibling:
 *   if left: h_{k+1} = hash(sibling || h_k)
 *   if right: h_{k+1} = hash(h_k || sibling)
 *
 * If the final hash equals the root (commitment), the proof is valid.
 *============================================================================*/

typedef struct {
    bigint  leaf_value;                 /**< The claimed value at position */
    bigint  siblings[VC_MAX_DEPTH];     /**< Sibling hashes along path */
    int     directions[VC_MAX_DEPTH];   /**< 0=left sibling, 1=right sibling */
    size_t  proof_length;              /**< Number of siblings (= tree depth) */
    size_t  position;                   /**< Position in the vector */
} vc_merkle_proof;

/*============================================================================
 * Vector commitment (L1: the commitment itself)
 *============================================================================*/

typedef struct {
    vc_merkle_tree tree;        /**< Underlying Merkle tree */
    bigint        *elements;    /**< Original vector elements */
    size_t         length;      /**< Number of elements */
    bool           committed;   /**< Whether tree has been built */
} vector_commitment;

/*============================================================================
 * Lifecycle
 *============================================================================*/

/** Initialize an empty vector commitment for n elements. */
void vc_init(vector_commitment *vc, size_t n);

/** Free resources associated with a vector commitment. */
void vc_destroy(vector_commitment *vc);

/*============================================================================
 * Set element (before committing)
 *============================================================================*/

/** Set the i-th element of the vector. 0-indexed. */
bool vc_set_element(vector_commitment *vc, size_t i, const bigint *value);

/*============================================================================
 * Commit phase (L5: Merkle tree construction)
 *
 * Builds the Merkle tree from the vector elements.
 * The root hash becomes the commitment.
 *
 * Algorithm:
 *   1. Hash each element: leaf_i = SimpleHash(element_i || i)
 *   2. For each level k from 0 to ceil(log2(n)):
 *      For each pair of adjacent nodes:
 *        parent = SimpleHash(left || right)
 *   3. Root = top-level single node
 *
 * The hash function used is a simple Davies-Meyer-like construction
 * based on bigint modular arithmetic for educational clarity.
 *============================================================================*/

bool vc_commit(vector_commitment *vc);

/** Get the commitment value (root hash). */
const bigint* vc_get_commitment(const vector_commitment *vc);

/*============================================================================
 * Open phase (L5: Merkle proof generation)
 *
 * Generates a Merkle proof that can be used to verify the value
 * at a specific position without revealing other elements.
 *
 * Proof size: O(log n) sibling hashes
 * Verification time: O(log n) hash computations
 *============================================================================*/

bool vc_open(const vector_commitment *vc, size_t position,
             vc_merkle_proof *proof);

/*============================================================================
 * Verify phase (L5: Merkle proof verification)
 *
 * Given a commitment C, a position i, a claimed value v, and a proof pi:
 * Verify(C, i, v, pi) -> true iff v is indeed the i-th element.
 *
 * Algorithm (recomputing root from proof):
 *   h = SimpleHash(v || i)
 *   for each (sibling, direction) in proof:
 *     if direction == LEFT_SIBLING:  h = SimpleHash(sibling || h)
 *     if direction == RIGHT_SIBLING: h = SimpleHash(h || sibling)
 *   return h == C
 *============================================================================*/

bool vc_verify(const vector_commitment *vc, size_t position,
               const bigint *value, const vc_merkle_proof *proof);

/*============================================================================
 * Update (L8: updatable commitment)
 *
 * Update one element in the vector and recompute the commitment
 * in O(log n) time (changing only the path from leaf to root).
 *
 * This enables dynamic commitments where individual positions
 * can be modified without recomputing the entire tree.
 *============================================================================*/

bool vc_update(vector_commitment *vc, size_t position, const bigint *new_value);

/*============================================================================
 * Aggregate proofs (L8: proof aggregation)
 *
 * Combine multiple Merkle proofs for different positions into
 * a single compact proof (using the fact that overlapping paths
 * can be merged).
 *
 * This is a simplified demonstration of proof aggregation,
 * relevant to Verkle trees and modern stateless protocols.
 *============================================================================*/

typedef struct {
    bigint  values[VC_MAX_LENGTH];
    bigint  aggregated_siblings[VC_MAX_DEPTH];
    bool    value_present[VC_MAX_LENGTH];
    size_t  num_positions;
    size_t  positions[VC_MAX_LENGTH];
} vc_aggregate_proof;

bool vc_aggregate_proofs(const vector_commitment *vc,
                         const size_t *positions, size_t num_pos,
                         vc_aggregate_proof *agg_proof);

bool vc_verify_aggregate(const vector_commitment *vc,
                         const vc_aggregate_proof *agg_proof);

/*============================================================================
 * Hash function (L5: simple hash for educational use)
 *
 * SimpleHash(x || aux) = ((x + aux) * PRIME_CONST) mod LARGE_PRIME
 *
 * This is NOT cryptographically secure. It demonstrates the Merkle tree
 * structure without the complexity of real hash functions (SHA-256).
 *============================================================================*/

void vc_simple_hash(const bigint *data, uint64_t aux, bigint *output);

#endif /* MINI_VECTOR_COMMIT_H */
