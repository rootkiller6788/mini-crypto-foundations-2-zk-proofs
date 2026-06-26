/**
 * nizk_simulator.h ！ Zero-Knowledge Simulator for NIZK Proofs
 *
 * L2 Definition: A simulator is an algorithm that can produce proofs
 * indistinguishable from real proofs WITHOUT knowing the witness.
 * The existence of a simulator is what formally defines zero-knowledge:
 *
 *   For every PPT verifier V*, there exists a PPT simulator Sim such that
 *   for all (x,w) in R, the distributions {Prove(x,w)} and {Sim(x)} are
 *   computationally indistinguishable.
 *
 * In the CRS model, the simulator knows the CRS trapdoor (tau where h = g^tau).
 * This trapdoor allows the simulator to "cheat" the verification equation:
 *
 *   Instead of computing s = v + c*w (needs w), the simulator:
 *   1. Picks random s, c
 *   2. Computes t = g^s * h^{-c}
 *   3. Programs the random oracle: H(stmt || t) = c
 *
 * This produces proofs that are INDISTINGUISHABLE from real proofs,
 * establishing the zero-knowledge property.
 *
 * Reference: Goldreich, Micali, Wigderson. "Proofs that Yield Nothing
 *            But Their Validity." JACM 1991.
 *
 * Course Mapping:
 *   MIT 6.875: Zero-knowledge simulation
 *   Stanford CS355: Simulator construction
 *   Princeton COS 551: Simulation in CRS model
 */

#ifndef NIZK_SIMULATOR_H
#define NIZK_SIMULATOR_H

#include "nizk_group.h"
#include "nizk_crs.h"
#include "nizk_proof.h"
#include "nizk_sigma.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------------
 * L2: Simulator State
 * ------------------------------------------------------------------------- */

/**
 * nizk_simulator_state ！ State for the NIZK simulator.
 *
 * The simulator holds the CRS trapdoor tau (where h = g^tau).
 * With tau, it can generate proofs without witnesses by:
 *   1. Choosing random challenge c and response s
 *   2. Computing commitment t = g^s * h^{-c}
 *   3. Outputting proof pi = (t, s) which implicitly defines c = H(stmt||t)
 *
 * This is only secure in the Random Oracle Model (ROM), where the
 * simulator can "program" the random oracle to return the pre-chosen c.
 *
 * In the standard CRS model (no ROM), different techniques are needed
 * (e.g., Groth-Sahai proofs with bilinear pairings).
 */
typedef struct {
    nizk_scalar_t trapdoor;    /* CRS trapdoor: tau where h = g^tau */
    int           is_active;   /* 1 if simulator has trapdoor */
    uint64_t      proof_count; /* number of proofs simulated (for debugging) */
} nizk_simulator_state_t;

/* ---------------------------------------------------------------------------
 * L5: Simulator Construction
 * ------------------------------------------------------------------------- */

/**
 * nizk_simulator_init ！ Initialize simulator with CRS trapdoor.
 *
 * The simulator requires a ZK-mode CRS where the trapdoor is known.
 * If the CRS was generated in soundness mode (no trapdoor), simulation
 * is impossible ！ this models the real-world constraint.
 *
 * Parameters:
 *   sim  ！ simulator state to initialize
 *   crs  ！ CRS with known trapdoor (has_trapdoor == 1)
 *
 * Returns 1 if initialization succeeded (trapdoor available), 0 otherwise.
 */
int  nizk_simulator_init(nizk_simulator_state_t *sim,
                          const nizk_crs_t *crs);

/**
 * nizk_simulate_dlog ！ Simulate a NIZK proof of discrete log knowledge.
 *
 * Generates a proof that "I know w such that h = g^w" WITHOUT actually
 * knowing w. The simulated proof is indistinguishable from a real one
 * by any PPT distinguisher.
 *
 * Algorithm (with trapdoor tau):
 *   1. Pick random s, c <- Z_q
 *   2. Compute t = g^s * pubkey^{-c}
 *   3. The hash H(stmt || t) will be programmed to equal c
 *      (In this implementation, we skip programming and just set c)
 *
 * Note: In a real ROM security proof, the simulator programs the random
 * oracle. Here we model this by directly constructing the transcript
 * and embedding the challenge-response pair.
 *
 * Parameters:
 *   proof   ！ output simulated proof
 *   sim     ！ simulator state (with trapdoor)
 *   crs     ！ common reference string
 *   pubkey  ！ public key (the statement to prove)
 *   label   ！ context label
 *   label_len ！ label length
 *   params  ！ group parameters
 *
 * Theorem (Zero-Knowledge): If the DDH assumption holds in G,
 * simulated proofs are computationally indistinguishable from real proofs.
 */
void nizk_simulate_dlog(nizk_proof_t *proof,
                         const nizk_simulator_state_t *sim,
                         const nizk_crs_t *crs,
                         const nizk_group_elem_t *pubkey,
                         const uint8_t *label, size_t label_len,
                         const nizk_group_params_t *params);

/**
 * nizk_simulate_dlog_eq ！ Simulate proof of equal discrete logs.
 *
 * Generates a proof that "I know w such that u = g^w AND v = h^w"
 * without knowing w.
 */
void nizk_simulate_dlog_eq(nizk_proof_t *proof,
                            const nizk_simulator_state_t *sim,
                            const nizk_crs_t *crs,
                            const nizk_group_elem_t *u,
                            const nizk_group_elem_t *v,
                            const nizk_group_elem_t *base_h,
                            const uint8_t *label, size_t label_len,
                            const nizk_group_params_t *params);

/**
 * nizk_simulate_commitment ！ Simulate proof of commitment opening.
 *
 * Generates a proof of knowledge of opening (m, r) for C = g^m * h^r
 * without knowing the actual opening values.
 */
void nizk_simulate_commitment(nizk_proof_t *proof,
                               const nizk_simulator_state_t *sim,
                               const nizk_crs_t *crs,
                               const nizk_commitment_t *com,
                               const uint8_t *label, size_t label_len,
                               const nizk_group_params_t *params);

/**
 * nizk_simulate_or ！ Simulate an OR proof.
 *
 * Simulates knowledge of one of two secrets without knowing either.
 * This finds a valid challenge split c0 + c1 = c_total for the OR proof.
 */
void nizk_simulate_or(nizk_proof_t *proof,
                       const nizk_simulator_state_t *sim,
                       const nizk_crs_t *crs,
                       const nizk_group_elem_t *pubkey1,
                       const nizk_group_elem_t *pubkey2,
                       const uint8_t *label, size_t label_len,
                       const nizk_group_params_t *params);

/* ---------------------------------------------------------------------------
 * L2: Distinguisher ！ Testing Indistinguishability
 * ------------------------------------------------------------------------- */

/**
 * nizk_distinguisher_test ！ Statistical test for proof indistinguishability.
 *
 * Generates N real proofs and N simulated proofs, then runs a simple
 * statistical test to check if a distinguisher can tell them apart.
 *
 * This is an educational tool to demonstrate the ZK property.
 * In practice, the indistinguishability is computational (based on
 * hardness assumptions) and cannot be tested empirically.
 *
 * Parameters:
 *   real_proofs      ！ array to store real proofs
 *   simulated_proofs ！ array to store simulated proofs
 *   N                ！ number of proofs of each type
 *   crs_zk           ！ CRS with trapdoor (for simulator)
 *   crs_sound        ！ CRS without trapdoor (for real prover)
 *   pubkey           ！ public key
 *   witness          ！ secret key (for real prover)
 *   params           ！ group parameters
 *
 * L8 Advanced Topic: Statistical zero-knowledge vs computational ZK.
 */
void nizk_distinguisher_test(nizk_proof_t *real_proofs,
                              nizk_proof_t *simulated_proofs,
                              int N,
                              const nizk_crs_t *crs_zk,
                              const nizk_crs_t *crs_sound,
                              const nizk_group_elem_t *pubkey,
                              const nizk_scalar_t *witness,
                              const nizk_group_params_t *params);

/**
 * nizk_compare_proofs ！ Compare two proofs for structural similarity.
 *
 * Returns a similarity score in [0.0, 1.0] based on the statistical
 * distribution of proof elements. Used for ZK validation.
 *
 * Note: This is a heuristic！computational ZK cannot be verified
 * empirically. This function is for educational/debugging purposes.
 */
double nizk_compare_proofs(const nizk_proof_t *proofs_a,
                            const nizk_proof_t *proofs_b,
                            int count,
                            const nizk_group_params_t *params);

/** Clean up simulator state. */
void nizk_simulator_clear(nizk_simulator_state_t *sim);

/** Print simulator state for debugging. */
void nizk_simulator_print(const nizk_simulator_state_t *sim);

#ifdef __cplusplus
}
#endif

#endif /* NIZK_SIMULATOR_H */
