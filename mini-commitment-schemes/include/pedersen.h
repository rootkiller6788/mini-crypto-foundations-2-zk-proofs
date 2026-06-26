/**
 * @file pedersen.h
 * @brief Pedersen commitment scheme over a prime-order group
 *
 * The Pedersen commitment scheme (CRYPTO 1991):
 *
 *   Setup: Group Z_p^* of prime order q, generators g, h where
 *          log_g(h) is unknown (random oracle setup or trusted setup).
 *
 *   Commit(m, r) = g^m * h^r  (mod p)
 *
 *   Security:
 *     - Perfectly hiding: For any m, the distribution of Commit(m, r)
 *       for random r is uniform over the group. No information about m
 *       is leaked (information-theoretic).
 *     - Computationally binding: Opening to m' != m requires computing
 *       log_g(h), which is the discrete logarithm problem.
 *
 *   Homomorphic property:
 *     Commit(m1, r1) * Commit(m2, r2) = Commit(m1+m2, r1+r2)
 *
 * References:
 *   - Pedersen, T.P. "Non-Interactive and Information-Theoretic Secure
 *     Verifiable Secret Sharing" (CRYPTO 1991)
 *   - Bootle, J. et al. "Efficient Zero-Knowledge Arguments for
 *     Arithmetic Circuits in the Discrete Log Setting" (EUROCRYPT 2016)
 *
 * Knowledge Mapping:
 *   L1: Definitions - Pedersen commitment, homomorphic commitment
 *   L3: Mathematical Structures - Z_p^*, discrete log group
 *   L4: Fundamental Laws - Discrete logarithm hardness assumption
 *   L5: Algorithms - Pedersen commit/open/verify
 *   L8: Advanced - homomorphic properties, trapdoor equivocation
 */

#ifndef MINI_PEDERSEN_H
#define MINI_PEDERSEN_H

#include "commitment.h"
#include "modarith.h"
#include <stdbool.h>

/*============================================================================
 * Pedersen commitment parameters (L3, L4)
 *
 * The security of Pedersen commitments rests on the discrete logarithm
 * assumption: given g and h = g^x, it is computationally infeasible
 * to recover x.
 *
 * For perfect hiding, h must be chosen such that no party knows log_g(h).
 * This can be done via:
 *   - Hash-to-group: h = HashToGroup("Pedersen-h-" || g) ¡ª ROM
 *   - Trusted setup: A trusted party picks x, computes h = g^x, destroys x
 *============================================================================*/

/**
 * Pedersen parameter generation.
 *
 * Given a generator g of a group of prime order q, derive h such that
 * no one knows log_g(h). Uses a deterministic hash-to-group approach.
 *
 * @param ctx  protocol context with group G
 * @param g    generator of the group (must have order q)
 * @return true on success
 *
 * The security of this setup relies on the random oracle model:
 * h = H("Pedersen-h" || g) interpreted as a group element.
 */
bool pedersen_setup(commit_ctx *ctx, const bigint *g);

/**
 * Pedersen setup with a known discrete log relationship h = g^x.
 * This is the "trapdoor setup" variant used in ZK-proof simulation.
 * WARNING: makes the scheme NOT binding for the trapdoor holder.
 *
 * @param ctx  protocol context
 * @param g    generator
 * @param x    trapdoor: discrete log of h base g (h = g^x)
 */
bool pedersen_setup_trapdoor(commit_ctx *ctx, const bigint *g,
                             const bigint *x);

/**
 * Compute a Pedersen commitment: C = g^m * h^r mod p.
 *
 * @param ctx  protocol context with g, h set up
 * @param c    output commitment
 * @param m    message to commit
 * @param r    randomness
 * @return true on success
 *
 * Complexity: O(log(p) * log^2(p)) ¡ª two modular exponentiations
 *   followed by one modular multiplication.
 */
bool pedersen_commit(commit_ctx *ctx, commitment *c,
                     const bigint *m, const bigint *r);

/**
 * Verify a Pedersen commitment opening.
 * Recomputes C' = g^m * h^r and checks C' == C.
 *
 * @return true if opening matches commitment
 */
bool pedersen_verify(const commit_ctx *ctx, const commitment *c);

/**
 * Homomorphically add two Pedersen commitments.
 * c_out = c1 * c2 mod p (interpreted as commitment to m1+m2 with r1+r2)
 *
 * @return true if both commitments are Pedersen
 */
bool pedersen_homomorphic_add(const commit_ctx *ctx,
                              const commitment *c1,
                              const commitment *c2,
                              commitment *c_out);

/**
 * Prove knowledge of opening for a Pedersen commitment
 * without revealing (m, r). This is a Sigma-protocol for
 * discrete log representation.
 *
 * The protocol proves knowledge of (m, r) such that C = g^m * h^r
 * without revealing m or r (zero-knowledge proof of knowledge).
 *
 * @param ctx     protocol context
 * @param c       the commitment to prove knowledge of
 * @param m, r    the secret opening (prover knows this)
 * @param challenge  verifier's random challenge
 * @param response_a output: first response component
 * @param response_b output: second response component
 * @return true if proof was generated
 *
 * Reference: Schnorr identification protocol generalization
 *   (Cramer-Damgard-Schoenmakers, CRYPTO 1994)
 */
bool pedersen_prove_knowledge(const commit_ctx *ctx,
                              const commitment *c,
                              const bigint *m, const bigint *r,
                              const bigint *challenge,
                              bigint *response_a,
                              bigint *response_b);

/**
 * Verify a proof of knowledge for a Pedersen commitment.
 *
 * @return true if the proof is valid
 */
bool pedersen_verify_knowledge(const commit_ctx *ctx,
                               const commitment *c,
                               const bigint *challenge,
                               const bigint *response_a,
                               const bigint *response_b);

#endif /* MINI_PEDERSEN_H */
