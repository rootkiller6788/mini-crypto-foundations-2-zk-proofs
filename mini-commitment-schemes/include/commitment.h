/**
 * @file commitment.h
 * @brief Cryptographic commitment scheme core definitions and framework
 *
 * A commitment scheme is a two-phase cryptographic protocol:
 *   1. Commit phase: Sender locks a message m with randomness r,
 *      producing commitment C = Commit(m, r). C is sent to receiver.
 *   2. Open phase: Sender reveals (m, r). Receiver verifies
 *      Verify(C, m, r) == true.
 *
 * Security properties (L1, L2):
 *   - Hiding: C reveals no information about m
 *   - Binding: Cannot find (m,r) != (m',r') with Commit(m,r) = Commit(m',r')
 *
 * References:
 *   - Blum, M. "Coin Flipping by Telephone" (CRYPTO 1981)
 *   - Goldreich, O. "Foundations of Cryptography, Vol 1" (2001), Ch.4.4
 *   - Pedersen, T.P. "Non-Interactive and Information-Theoretic
 *     Secure Verifiable Secret Sharing" (CRYPTO 1991)
 *   - Damgard, I. "Commitment Schemes and Zero-Knowledge Protocols" (1999)
 *
 * Knowledge Mapping:
 *   L1: Definitions - commitment, hiding, binding, opening
 *   L2: Core Concepts - computational vs statistical security, trapdoor
 *   L4: Fundamental Laws - DL assumption, collision resistance
 */

#ifndef MINI_COMMITMENT_H
#define MINI_COMMITMENT_H

#include "bigint.h"
#include "modarith.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/*============================================================================
 * Commitment scheme types (L1: scheme classification)
 *
 * Different constructions provide different security guarantees:
 *
 *   Scheme Type        | Hiding          | Binding         | Assumption
 *   -------------------+-----------------+-----------------+---------------
 *   Pedersen           | Perfect (info)  | Computational   | Discrete Log
 *   Hash-based (ROM)   | Computational   | Computational   | Collision res
 *   Vector (Merkle)    | Computational   | Computational   | Collision res
 *   Fujisaki-Okamoto   | Statistical     | Computational   | Factoring
 *============================================================================*/

typedef enum {
    COMMIT_SCHEME_PEDERSEN        = 0,
    COMMIT_SCHEME_HASH_SHA256     = 1,
    COMMIT_SCHEME_VECTOR_MERKLE   = 2,
    COMMIT_SCHEME_FUJISAKI_OKAMOTO = 3,
} commit_scheme_type;

/*============================================================================
 * Hiding and Binding property classification (L1, L2)
 *
 * Theorem (Damgard 1999): A commitment scheme cannot be both
 *   perfectly hiding AND perfectly binding simultaneously.
 *   At least one property must be computational.
 *============================================================================*/

typedef enum {
    SECURITY_PERFECT       = 0,
    SECURITY_STATISTICAL   = 1,
    SECURITY_COMPUTATIONAL = 2,
} security_level;

/*============================================================================
 * Commitment data structure (L1, L3)
 *
 * Represents a single commitment instance:
 *   C = Commit(m, r) where m is the message (in Z_p) and r is randomness.
 *
 * Invariants:
 *   - When opened == false: only C is valid
 *   - When opened == true: message and randomness are revealed
 *   - scheme identifies which construction was used
 *============================================================================*/

typedef struct {
    bigint             commitment_val;
    bigint             message;
    bigint             randomness;
    bool               opened;
    commit_scheme_type scheme;
    security_level     hiding_level;
    security_level     binding_level;
} commitment;

/*============================================================================
 * Commitment protocol context (L3: protocol state)
 * Manages the lifecycle of a commitment protocol instance.
 *============================================================================*/

typedef struct {
    modctx            group;
    commit_scheme_type active_scheme;
    bigint            g;
    bigint            h;
    bool              pedersen_setup;
    size_t            hash_security;
    bigint            fujisaki_n;
    bigint            fujisaki_g;
    bool              fujisaki_setup;
    bigint            trapdoor;
    bool              has_trapdoor;
} commit_ctx;

/*============================================================================
 * Lifecycle (L3)
 *============================================================================*/

void commit_ctx_init(commit_ctx *ctx, const bigint *modulus,
                     commit_scheme_type scheme);
void commit_ctx_init_u64(commit_ctx *ctx, uint64_t modulus,
                         commit_scheme_type scheme);
void commit_init(commitment *c, commit_scheme_type scheme);
void commit_ctx_destroy(commit_ctx *ctx);

/*============================================================================
 * Core protocol - Commit phase (L1, L5)
 *
 * C = Commit(m, r)
 *
 * Pedersen scheme: C = g^m * h^r (mod p)
 * Hash scheme:     C = H(m || r) via modular arithmetic simulation
 *============================================================================*/

bool commit_do(commit_ctx *ctx, commitment *c,
               const bigint *m, const bigint *r);
bool commit_do_random(commit_ctx *ctx, commitment *c, const bigint *m);

/*============================================================================
 * Core protocol - Open phase (L1, L5)
 *
 * Sender reveals (m, r). Receiver verifies Verify(C, m, r) == true.
 *============================================================================*/

void commit_open(commitment *c);
bool commit_verify(const commit_ctx *ctx, const commitment *c);

/*============================================================================
 * Security property analysis (L2, L4)
 *============================================================================*/

bool commit_test_hiding(const commit_ctx *ctx,
                        const bigint *m0, const bigint *m1,
                        double *advantage, size_t trials);
bool commit_test_binding(const commit_ctx *ctx, size_t attempt,
                         bigint *m, bigint *r,
                         bigint *m2, bigint *r2);

/*============================================================================
 * Homomorphic property (L8: Advanced - Homomorphic Commitments)
 *
 * Pedersen commitments are additively homomorphic:
 *   (g^{m1} * h^{r1}) * (g^{m2} * h^{r2}) = g^{m1+m2} * h^{r1+r2}
 *
 * Applications: range proofs, verifiable computation, ZK proof systems
 *============================================================================*/

bool commit_homomorphic_combine(const commit_ctx *ctx,
                                const commitment *c1,
                                const commitment *c2,
                                commitment *c_out);
bool commit_verify_homomorphic(const commit_ctx *ctx,
                               const commitment *c1,
                               const commitment *c2,
                               const commitment *c_out);

/*============================================================================
 * Equivocability and Trapdoor (L8: Advanced)
 *
 * If trapdoor x = log_g(h) is known, can open C = g^m * h^r
 * to any m' via r' = r + (m - m')/x.
 * Used in ZK-proof simulation (simulator can equivocate).
 *============================================================================*/

bool commit_set_trapdoor(commit_ctx *ctx, const bigint *trapdoor);
bool commit_equivocate(const commit_ctx *ctx, const commitment *c,
                       const bigint *new_msg, bigint *new_rand);

/*============================================================================
 * Coin-flipping protocol (L7: Application)
 *
 * Two-party coin flipping over a telephone (Blum, 1981):
 *   Alice commits to a, Bob sends b, Alice opens a, result = a XOR b
 *============================================================================*/

bool commit_coin_flip(commit_ctx *ctx, int alice_bit, int bob_bit, int *result);

/*============================================================================
 * Sigma-protocol building block (L7: Application)
 *
 * Prover -> Verifier: a = Commit(randomness)         (commitment)
 * Verifier -> Prover: e = challenge (random)          (challenge)
 * Prover -> Verifier: z = response(witness, e, r)    (response)
 *============================================================================*/

bool commit_sigma_protocol_commit(commit_ctx *ctx, commitment *c,
                                  const bigint *witness);

/*============================================================================
 * Commitment scheme comparison and analysis (L2, L6)
 *============================================================================*/

const char* commit_scheme_name(commit_scheme_type scheme);
const char* security_level_name(security_level level);
void commit_describe(const commit_ctx *ctx, const commitment *c, char *buf, size_t n);

#endif /* MINI_COMMITMENT_H */
