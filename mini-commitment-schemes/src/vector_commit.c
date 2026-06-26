/**
 * @file vector_commit.c
 * @brief Vector commitment scheme via Merkle tree
 *
 * Implements a vector commitment scheme that allows committing to
 * a vector (m_1, ..., m_n) and opening individual positions with
 * O(log n)-sized proofs.
 *
 * Tree layout: 0-based complete binary tree array
 *   - N = next_power_of_two(n)  (number of leaves, padded)
 *   - Total nodes = 2*N - 1
 *   - Root at index 0
 *   - Left child of i:  2*i + 1
 *   - Right child of i: 2*i + 2
 *   - Leaves at indices N-1 to 2*N-2
 *   - Parent of i: (i-1)/2
 *
 * Knowledge Mapping:
 *   L1: Vector commitment, Merkle proof definitions
 *   L3: Binary tree structure
 *   L5: Merkle tree construction, proof generation, verification
 *   L6: Membership proof problem
 *   L7: Blockchain light client application
 *   L8: Updatable commitments
 */

#include "vector_commit.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* =========================================================================
 * Simple hash function for Merkle tree (L5)
 * ========================================================================= */

static const uint64_t HASH_PRIME_LIMBS[4] = {
    0xFFFFFFFFFFFFFFFFULL,
    0x0000000000000000ULL,
    0x0000000000000000ULL,
    0xFFFEFBFF7EFFFFFFULL
};

static void hash_prime_init(bigint *p) {
    bigint_init(p);
    for (int i = 0; i < 4; i++) {
        p->limbs[i] = HASH_PRIME_LIMBS[i];
    }
    p->nlimbs = 4;
    while (p->nlimbs > 0 && p->limbs[p->nlimbs - 1] == 0) {
        p->nlimbs--;
    }
}

void vc_simple_hash(const bigint *data, uint64_t aux, bigint *output) {
    bigint prime, state, temp;
    hash_prime_init(&prime);

    bigint_init_u64(&state, 0x6A09E667F3BCC908ULL);

    /* Absorb data */
    bigint_init(&temp);
    bigint_init_u64(&temp, 0x9E3779B97F4A7C15ULL);
    bigint_add(&temp, data);
    bigint_mod(&temp, &prime);

    bigint_mul(&state, &state, &temp);
    bigint_mod(&state, &prime);

    /* Absorb aux */
    bigint_init_u64(&temp, aux);
    bigint temp2;
    bigint_init_u64(&temp2, 0xBB67AE8584CAA73BULL);
    bigint_add(&temp, &temp2);

    bigint_mul(&state, &state, &temp);
    bigint_mod(&state, &prime);

    /* Mixing rounds */
    for (int round = 0; round < 3; round++) {
        bigint_mul(&state, &state, &state);
        bigint_mod(&state, &prime);
        bigint temp3;
        bigint_init_u64(&temp3, (uint64_t)(round + 1) * 0x510E527FADE682D1ULL);
        bigint_add(&state, &temp3);
        bigint_mod(&state, &prime);
    }

    bigint_copy(output, &state);
}

/* =========================================================================
 * Vector Commitment Lifecycle
 * ========================================================================= */

void vc_init(vector_commitment *vc, size_t n) {
    if (n > VC_MAX_LENGTH) n = VC_MAX_LENGTH;
    vc->elements = (bigint *)calloc(n, sizeof(bigint));
    for (size_t i = 0; i < n; i++) bigint_init(&vc->elements[i]);
    vc->length = n;
    vc->committed = false;
    memset(vc->tree.nodes, 0, sizeof(vc->tree.nodes));
    for (size_t i = 0; i < 2 * VC_MAX_LENGTH; i++) {
        bigint_init(&vc->tree.nodes[i].hash);
        vc->tree.nodes[i].is_leaf = false;
        vc->tree.nodes[i].index = 0;
    }
    vc->tree.vector_length = n;
    vc->tree.tree_size = 0;
    bigint_init(&vc->tree.commitment);
}

void vc_destroy(vector_commitment *vc) {
    if (vc->elements) { free(vc->elements); vc->elements = NULL; }
    vc->length = 0;
    vc->committed = false;
}

bool vc_set_element(vector_commitment *vc, size_t i, const bigint *value) {
    if (vc == NULL || value == NULL || i >= vc->length || vc->committed)
        return false;
    bigint_copy(&vc->elements[i], value);
    return true;
}

/* =========================================================================
 * Helper: next power of 2, leaf node index
 * ========================================================================= */

static size_t next_power_of_two(size_t n) {
    size_t p = 1;
    while (p < n) p <<= 1;
    return p;
}

static size_t leaf_node_idx(size_t N, size_t pos) {
    return N - 1 + pos;
}

/* =========================================================================
 * Merkle Tree Construction (L5)
 *
 * 0-based complete binary tree:
 *   - N leaves at indices [N-1, 2*N-2]
 *   - Internal nodes at indices [0, N-2]
 *   - Root at index 0
 * ========================================================================= */

bool vc_commit(vector_commitment *vc) {
    if (vc == NULL || vc->length == 0) return false;

    size_t N = next_power_of_two(vc->length);
    size_t total_nodes = 2 * N - 1;
    vc->tree.vector_length = vc->length;
    vc->tree.tree_size = total_nodes;

    /* Step 1: Hash leaves at indices N-1 to 2*N-2 */
    for (size_t i = 0; i < N; i++) {
        size_t idx = leaf_node_idx(N, i);
        const bigint *elem = (i < vc->length)
            ? &vc->elements[i]
            : &vc->elements[vc->length - 1]; /* Duplicate last for padding */

        vc_simple_hash(elem, (uint64_t)i, &vc->tree.nodes[idx].hash);
        vc->tree.nodes[idx].is_leaf = true;
        vc->tree.nodes[idx].index = i;
    }

    /* Step 2: Build internal nodes bottom-up (from N-2 down to 0) */
    for (size_t i = N - 1; i > 0; i--) {
        size_t parent = i - 1;
        size_t left   = 2 * parent + 1;
        size_t right  = 2 * parent + 2;

        bigint combined;
        bigint_init(&combined);
        bigint_copy(&combined, &vc->tree.nodes[left].hash);
        bigint_add(&combined, &vc->tree.nodes[right].hash);

        vc_simple_hash(&combined,
                       (uint64_t)((left << 16) | right),
                       &vc->tree.nodes[parent].hash);
        vc->tree.nodes[parent].is_leaf = false;
        vc->tree.nodes[parent].index = 0;
    }

    /* Step 3: Root at index 0 */
    bigint_copy(&vc->tree.commitment, &vc->tree.nodes[0].hash);
    vc->committed = true;
    return true;
}

const bigint* vc_get_commitment(const vector_commitment *vc) {
    if (vc == NULL || !vc->committed) return NULL;
    return &vc->tree.commitment;
}

/* =========================================================================
 * Merkle Proof Generation (L5)
 *
 * Walk from leaf to root, collecting sibling hashes.
 * direction 0 = current is left child (sibling is right)
 * direction 1 = current is right child (sibling is left)
 * ========================================================================= */

bool vc_open(const vector_commitment *vc, size_t position,
             vc_merkle_proof *proof) {
    if (vc == NULL || proof == NULL || !vc->committed) return false;
    if (position >= vc->length) return false;

    size_t N = next_power_of_two(vc->length);
    size_t node_idx = leaf_node_idx(N, position);

    bigint_copy(&proof->leaf_value, &vc->elements[position]);
    proof->position = position;
    proof->proof_length = 0;

    while (node_idx > 0) {
        size_t parent  = (node_idx - 1) / 2;
        size_t sibling;
        int direction;

        if (node_idx % 2 == 0) {
            /* node_idx is right child ¡ú sibling is left */
            sibling = node_idx - 1;
            direction = 1;
        } else {
            /* node_idx is left child ¡ú sibling is right */
            sibling = node_idx + 1;
            direction = 0;
        }

        size_t p = proof->proof_length;
        if (p >= VC_MAX_DEPTH) return false;

        bigint_copy(&proof->siblings[p], &vc->tree.nodes[sibling].hash);
        proof->directions[p] = direction;
        proof->proof_length++;
        node_idx = parent;
    }
    return true;
}

/* =========================================================================
 * Merkle Proof Verification (L5)
 *
 * Recompute root from proof: hash up using sibling hashes.
 * direction 0 = current was left, sibling on right ¡ú hash(current || sibling)
 * direction 1 = current was right, sibling on left ¡ú hash(sibling || current)
 * ========================================================================= */

bool vc_verify(const vector_commitment *vc, size_t position,
               const bigint *value, const vc_merkle_proof *proof) {
    if (vc == NULL || value == NULL || proof == NULL) return false;
    if (!vc->committed || position >= vc->length) return false;
    if (position != proof->position) return false;

    bigint h;
    bigint_init(&h);
    vc_simple_hash(value, (uint64_t)position, &h);

    for (size_t i = 0; i < proof->proof_length; i++) {
        bigint combined;
        bigint_init(&combined);

        if (proof->directions[i] == 0) {
            /* Current was left, sibling right: hash(current || sibling) */
            bigint_copy(&combined, &h);
            bigint_add(&combined, &proof->siblings[i]);
        } else {
            /* Current was right, sibling left: hash(sibling || current) */
            bigint_copy(&combined, &proof->siblings[i]);
            bigint_add(&combined, &h);
        }

        vc_simple_hash(&combined,
                       (uint64_t)((i << 8) | proof->directions[i]), &h);
    }

    return bigint_cmp(&h, &vc->tree.commitment) == 0;
}

/* =========================================================================
 * Update (L8: Updatable Commitment)
 *
 * Recompute only the path from updated leaf to root (O(log n)).
 * ========================================================================= */

bool vc_update(vector_commitment *vc, size_t position, const bigint *new_value) {
    if (vc == NULL || new_value == NULL || !vc->committed) return false;
    if (position >= vc->length) return false;

    size_t N = next_power_of_two(vc->length);
    bigint_copy(&vc->elements[position], new_value);

    /* Recompute leaf */
    size_t node_idx = leaf_node_idx(N, position);
    vc_simple_hash(new_value, (uint64_t)position,
                   &vc->tree.nodes[node_idx].hash);

    /* Walk up recomputing parents */
    while (node_idx > 0) {
        size_t parent = (node_idx - 1) / 2;
        size_t left   = 2 * parent + 1;
        size_t right  = 2 * parent + 2;

        bigint combined;
        bigint_init(&combined);
        bigint_copy(&combined, &vc->tree.nodes[left].hash);
        bigint_add(&combined, &vc->tree.nodes[right].hash);

        vc_simple_hash(&combined,
                       (uint64_t)((left << 16) | right),
                       &vc->tree.nodes[parent].hash);
        node_idx = parent;
    }

    bigint_copy(&vc->tree.commitment, &vc->tree.nodes[0].hash);
    return true;
}

/* =========================================================================
 * Aggregate Proofs (L8: Proof Aggregation)
 * ========================================================================= */

bool vc_aggregate_proofs(const vector_commitment *vc,
                         const size_t *positions, size_t num_pos,
                         vc_aggregate_proof *agg_proof) {
    if (vc == NULL || positions == NULL || agg_proof == NULL || !vc->committed)
        return false;
    if (num_pos > VC_MAX_LENGTH) return false;

    size_t N = next_power_of_two(vc->length);
    agg_proof->num_positions = num_pos;

    for (size_t p = 0; p < num_pos; p++) {
        size_t pos = positions[p];
        if (pos >= vc->length) return false;

        agg_proof->positions[p] = pos;
        bigint_copy(&agg_proof->values[p], &vc->elements[pos]);
        agg_proof->value_present[p] = true;

        /* Record unique siblings at each depth */
        size_t node_idx = leaf_node_idx(N, pos);
        size_t depth = 0;
        while (node_idx > 0 && depth < VC_MAX_DEPTH) {
            size_t parent  = (node_idx - 1) / 2;
            size_t sibling = (node_idx % 2 == 0) ? (node_idx - 1) : (node_idx + 1);
            bigint_copy(&agg_proof->aggregated_siblings[depth],
                        &vc->tree.nodes[sibling].hash);
            node_idx = parent;
            depth++;
        }
    }
    return true;
}

bool vc_verify_aggregate(const vector_commitment *vc,
                         const vc_aggregate_proof *agg_proof) {
    if (vc == NULL || agg_proof == NULL || !vc->committed) return false;

    size_t N = next_power_of_two(vc->length);

    for (size_t p = 0; p < agg_proof->num_positions; p++) {
        if (!agg_proof->value_present[p]) continue;
        size_t pos = agg_proof->positions[p];
        if (pos >= vc->length) return false;

        bigint h;
        bigint_init(&h);
        vc_simple_hash(&agg_proof->values[p], (uint64_t)pos, &h);

        size_t node_idx = leaf_node_idx(N, pos);
        size_t depth = 0;
        while (node_idx > 0 && depth < VC_MAX_DEPTH) {
            bigint combined;
            bigint_init(&combined);

            if (node_idx % 2 == 0) {
                /* Right child, sibling is left */
                bigint_copy(&combined, &agg_proof->aggregated_siblings[depth]);
                bigint_add(&combined, &h);
            } else {
                /* Left child, sibling is right */
                bigint_copy(&combined, &h);
                bigint_add(&combined, &agg_proof->aggregated_siblings[depth]);
            }

            vc_simple_hash(&combined,
                           (uint64_t)((depth << 8) | (node_idx & 1)), &h);
            node_idx = (node_idx - 1) / 2;
            depth++;
        }

        if (bigint_cmp(&h, &vc->tree.commitment) != 0) return false;
    }
    return true;
}
