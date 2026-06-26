#ifndef FIAT_SHAMIR_H
#define FIAT_SHAMIR_H

#include "zk_simulator.h"
#include "sigma_protocols.h"
#include <stdio.h>

/*
 * mini-zero-knowledge-simulators -- fiat_shamir.h
 * Fiat-Shamir heuristic: transform interactive ZK proofs into
 * non-interactive ZK proofs (NIZK) in the Random Oracle Model.
 * Covers L4.5 (Fiat-Shamir Theorem) and L5 (Algorithms).
 *
 * Reference: Fiat & Shamir (CRYPTO 1986)
 *            Pointcheval & Stern (EUROCRYPT 1996, J. Cryptology 2000)
 *            Canetti, Goldreich & Halevi (JACM 2004)
 * Courses: MIT 6.875, Stanford CS355, Berkeley CS276
 */

/* ================================================================
 * L4.5 -- Fiat-Shamir Transform
 * ================================================================ */

/*
 * The Fiat-Shamir (FS) transform converts any sigma protocol
 * (3-round public-coin) into a non-interactive proof by
 * replacing the verifier's random challenge c with:
 *
 *   e = H(a || x || aux)
 *
 * where H is a cryptographic hash function modeled as a
 * random oracle (RO). The proof becomes a single message:
 *
 *   pi = (a, e, s)
 *
 * Verification: compute e = H(a || x || aux), check ver(a, e, s).
 *
 * Security in the ROM:
 *   - Soundness: If the sigma protocol has special soundness,
 *     the FS proof is sound (via Forking Lemma).
 *   - Zero-Knowledge: If the sigma protocol is HVZK,
 *     the FS proof is ZK (simulator programs RO).
 *
 * In the standard model, the FS transform is NOT provably secure
 * in general. Counterexamples exist (Goldwasser-Kalai 2003).
 * However, it is widely used in practice (EdDSA, Schnorr sigs).
 */

/*
 * L4.5.1 -- Basic Hash Function (for didactic RO modeling)
 *
 * We implement a simple Merkle-Damgard construction
 * using a compression function based on AES-like rounds.
 * This is for illustration only -- real systems use SHA-256/SHA-3.
 */
#define HASH_OUTPUT_BYTES 32
#define HASH_BLOCK_BYTES  64

typedef struct {
    uint8_t digest[HASH_OUTPUT_BYTES];
} hash_digest_t;

typedef struct {
    uint64_t state[8];       /* internal state (512 bits) */
    uint8_t  buffer[HASH_BLOCK_BYTES];
    size_t   buffer_len;
    uint64_t total_bits;
} hash_state_t;

void hash_init(hash_state_t *hs, uint64_t seed);
void hash_update(hash_state_t *hs, const uint8_t *data, size_t len);
void hash_update_u64(hash_state_t *hs, uint64_t val);
void hash_finalize(hash_state_t *hs, hash_digest_t *out);
uint64_t hash_to_mod_q(const hash_digest_t *d, uint64_t q);

/*
 * L4.5.2 -- Fiat-Shamir Proof (Schnorr, non-interactive)
 *
 * For Schnorr protocol: prover knows x s.t. y = g^x.
 *
 * NIZK proof generation:
 *   1. Pick random r, compute a = g^r
 *   2. Compute e = H(a || y || g || p) mod q
 *   3. Compute s = r + e*x mod q
 *   4. Output pi = (a, s)   [e is recomputed by verifier]
 *
 * NIZK verification:
 *   1. Compute e = H(a || y || g || p) mod q
 *   2. Check g^s == a * y^e
 *
 * This is the basis for Schnorr signatures (EdDSA, etc.).
 */
typedef struct {
    uint64_t a;
    uint64_t s;   /* challenge e is derived via hash */
} schnorr_nizk_proof_t;

int schnorr_nizk_prove(uint64_t x, uint64_t y,
                        const group_params_t *gp,
                        const random_tape_t *rng,
                        const uint8_t *context, size_t ctx_len,
                        schnorr_nizk_proof_t *out);
int schnorr_nizk_verify(const schnorr_nizk_proof_t *proof,
                         uint64_t y, const group_params_t *gp,
                         const uint8_t *context, size_t ctx_len);

/*
 * L4.5.3 -- NIZK from OR-Proof via Fiat-Shamir
 *
 * OR-proof + FS = non-interactive witness-indistinguishable proof.
 * This is the basis for ring signatures and anonymous credentials.
 *
 * Proof generation (know witness for y1):
 *   1. For y2: pick c2,s2 random; compute a2 = g^{s2} * y2^{-c2}
 *   2. For y1: compute a1 = g^{r1} (random r1)
 *   3. Compute e = H(a1 || a2 || y1 || y2 || ctx)
 *   4. Set c1 = e XOR c2
 *   5. Compute s1 = r1 + c1*x
 *   6. Output pi = (a1, c1, s1, a2, c2, s2)
 *
 * Verification:
 *   1. Compute e = H(a1 || a2 || y1 || y2 || ctx)
 *   2. Check c1 XOR c2 == e
 *   3. Check g^{s1} == a1 * y1^{c1}
 *   4. Check g^{s2} == a2 * y2^{c2}
 */
typedef struct {
    uint64_t a1, c1, s1;
    uint64_t a2, c2, s2;
} or_nizk_proof_t;

int or_nizk_prove(int real_side, uint64_t x, uint64_t y1, uint64_t y2,
                   const group_params_t *gp,
                   const random_tape_t *rng,
                   const uint8_t *context, size_t ctx_len,
                   or_nizk_proof_t *out);
int or_nizk_verify(const or_nizk_proof_t *proof,
                    uint64_t y1, uint64_t y2,
                    const group_params_t *gp,
                    const uint8_t *context, size_t ctx_len);

/*
 * L4.5.4 -- Forking Lemma (Pointcheval-Stern 1996)
 *
 * THEOREM (Forking Lemma, informal):
 * Let A be a PPT algorithm that, given public key y and random
 * oracle H, outputs a valid FS proof (a,s) with non-negligible
 * probability epsilon using at most Q queries to H.
 *
 * Then there exists a forking algorithm F that runs A, replays it
 * with fresh random oracle answers after the critical query,
 * and with probability O(epsilon^2/Q) obtains two valid proofs
 * (a, e1, s1) and (a, e2, s2) with e1 != e2.
 *
 * From these two proofs, special soundness extracts the witness.
 *
 * Implication: FS transforms preserve proof-of-knowledge in the ROM.
 *
 * We implement a simplified forking lemma simulation (for fixed q)
 * to demonstrate the extraction principle.
 */
int forking_lemma_extract(schnorr_nizk_proof_t (*adversary)(
                               uint64_t y, const group_params_t *gp,
                               const random_tape_t *rng),
                           uint64_t y, const group_params_t *gp,
                           uint64_t *witness_out);

/*
 * L4.5.5 -- Strong Fiat-Shamir vs Weak Fiat-Shamir
 *
 * Weak FS:   e = H(a)                (original Fiat-Shamir)
 * Strong FS: e = H(a || statement)   (Bernhard et al. 2012)
 *
 * The difference is security against "weak" attackers in the
 * multi-user setting. Strong FS is now standard.
 *
 * For didactic purposes, we implement both and demonstrate the
 * difference in security proofs.
 */
typedef enum {
    FS_WEAK   = 0,  /* e = H(a) */
    FS_STRONG = 1,  /* e = H(a || y || g || p || ctx) */
} fs_mode_t;

/*
 * L4.5.6 -- NIZK in the Common Reference String Model
 *
 * An alternative to ROM: use a CRS generated by a trusted setup.
 * The simulator is given a trapdoor associated with the CRS.
 *
 * This avoids the random oracle heuristic but requires a trusted
 * CRS generation (or multi-party computation for CRS setup).
 *
 * FS in ROM is essentially NIZK with the RO as the CRS.
 */
typedef struct {
    group_params_t  gp;
    uint64_t        trapdoor;    /* log_g(h) for trapdoor CRS */
    uint8_t         crs_hash[HASH_OUTPUT_BYTES];
} crs_t;

void crs_setup(crs_t *crs, const random_tape_t *rng);
void crs_setup_with_trapdoor(crs_t *crs, uint64_t trapdoor);

#endif /* FIAT_SHAMIR_H */

