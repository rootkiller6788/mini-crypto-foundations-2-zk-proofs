/**
 * @file hash_commit.h
 * @brief Hash-based commitment scheme
 *
 * Hash-based commitments are the simplest form of commitment:
 *   Commit(m, r) = H(m || r)
 *
 * where H is a collision-resistant hash function.
 *
 * Security:
 *   - Hiding: If H is modeled as a random oracle, commitment reveals
 *     no information about m (computational hiding).
 *   - Binding: Finding (m,r) != (m',r') with H(m||r) = H(m'||r')
 *     breaks collision resistance of H (computational binding).
 *
 * While simpler than Pedersen commitments, hash-based commitments:
 *   - Do NOT have perfect hiding
 *   - Do NOT have additive homomorphic properties
 *   - Do NOT support trapdoor equivocation without ROM tricks
 *   - ARE post-quantum secure (if the hash is, e.g., SHA-3)
 *
 * This makes them relevant as a post-quantum alternative (L9).
 *
 * References:
 *   - Damgard, I. "Commitment Schemes and Zero-Knowledge Protocols" (1999)
 *   - Halevi, S. and Micali, S. "Practical and Provably-Secure Commitment
 *     Schemes from Collision-Free Hashing" (CRYPTO 1996)
 *   - Unruh, D. "Computationally Binding Quantum Commitments" (EUROCRYPT 2016)
 *
 * Knowledge Mapping:
 *   L1: Definitions - hash-based commitment
 *   L2: Core Concepts - random oracle model, collision resistance
 *   L4: Fundamental Laws - collision resistance => binding
 *   L5: Algorithms - hash-based commit/open/verify
 *   L7: Applications - post-quantum commitments
 *   L9: Research Frontiers - quantum-secure commitments
 */

#ifndef MINI_HASH_COMMIT_H
#define MINI_HASH_COMMIT_H

#include "bigint.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/*============================================================================
 * Simple hash function (L5: Davies-Meyer inspired)
 *
 * We implement a simplified hash function based on modular arithmetic.
 * This is NOT cryptographically secure but serves to demonstrate the
 * structure of hash-based commitment schemes.
 *
 * The construction uses a sponge-like absorb-squeeze pattern:
 *   - Absorb: state = (state XOR block_i) * PRIME mod LARGE_PRIME
 *   - Squeeze: output = state
 *
 * For real applications: use SHA-256, SHA-3, or BLAKE3.
 *============================================================================*/

/** Output size of the simple hash (256 bits = 4 limbs) */
#define HASH_OUTPUT_LIMBS 4

/** Simple hash state (internal buffer) */
typedef struct {
    bigint   state;
    uint64_t rounds;
    uint64_t absorbed_bytes;
} simple_hash_state;

/** Initialize the hash state. */
void simple_hash_init(simple_hash_state *st);

/** Absorb data into the hash state. */
void simple_hash_absorb(simple_hash_state *st, const uint8_t *data, size_t len);

/** Absorb a bigint into the hash state. */
void simple_hash_absorb_bigint(simple_hash_state *st, const bigint *val);

/** Squeeze: finalize and produce hash output. */
void simple_hash_squeeze(simple_hash_state *st, bigint *output);

/** One-shot hash of data: output = SimpleHash(data, len). */
void simple_hash(const uint8_t *data, size_t len, bigint *output);

/** One-shot hash of a big integer. */
void simple_hash_bigint(const bigint *val, bigint *output);

/*============================================================================
 * Hash commitment
 *============================================================================*/

/**
 * Compute a hash-based commitment: C = H(m || r).
 *
 * This concatenates the message and randomness, then hashes.
 * For perfect hiding in the random oracle model, r must be
 * sufficiently long (recommended: >= 128 bits of entropy).
 *
 * @param m  message to commit
 * @param r  randomness (salt/nonce)
 * @param c  output: commitment value C
 */
void hash_commit(const bigint *m, const bigint *r, bigint *c);

/**
 * Verify a hash-based commitment opening.
 * Recomputes H(m || r) and checks equality.
 */
bool hash_commit_verify(const bigint *c, const bigint *m, const bigint *r);

/*============================================================================
 * Domain separation (L2: preventing cross-scheme attacks)
 *
 * In real protocols, different hash uses must be domain-separated:
 *   H("commit" || m || r) != H("signature" || m || r)
 *
 * This prevents an adversary from reusing a commitment as something else.
 *============================================================================*/

/** Domain-separated hash commitment with a domain tag. */
void hash_commit_domain(const uint8_t *domain, size_t domain_len,
                        const bigint *m, const bigint *r, bigint *c);

/** Domain-separated verification. */
bool hash_commit_domain_verify(const uint8_t *domain, size_t domain_len,
                               const bigint *c, const bigint *m, const bigint *r);

/*============================================================================
 * Multi-round hashing (L7: strengthening for weak hash functions)
 *
 * If the underlying hash is only one-way but not proven collision-resistant,
 * we can apply multiple rounds:
 *
 *   C = H( H(m || r1) || r2 )
 *
 * This increases the security margin. Used in real-world protocols
 * like HMAC-based commitments.
 *============================================================================*/

/** Multi-round hash commitment (2 rounds). */
void hash_commit_double(const bigint *m, const bigint *r1,
                        const bigint *r2, bigint *c);

/** Multi-round verification. */
bool hash_commit_double_verify(const bigint *c,
                               const bigint *m, const bigint *r1,
                               const bigint *r2);

/*============================================================================
 * Comparison of commitment schemes (L6: scheme selection)
 *
 * Different applications require different tradeoffs:
 *
 * Scheme     | Hiding    | Binding   | Homomorphic | Post-Quantum | Setup
 * -----------+-----------+-----------+-------------+--------------+-------
 * Hash       | Comp      | Comp      | No          | Yes          | None
 * Pedersen   | Perfect   | Comp      | Yes (add)   | No           | Trusted
 * Fujisaki-  | Stat      | Comp      | Yes (add)   | No           | RSA mod
 * Okamoto    |           |           |             |              |
 *============================================================================*/

/** Print a comparison table of commitment schemes to buf. */
void hash_commit_compare_schemes(char *buf, size_t buf_size);

#endif /* MINI_HASH_COMMIT_H */
