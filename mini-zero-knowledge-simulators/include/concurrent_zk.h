#ifndef CONCURRENT_ZK_H
#define CONCURRENT_ZK_H

#include "zk_simulator.h"
#include "simulator_core.h"
#include "sigma_protocols.h"
#include "fiat_shamir.h"

/*
 * mini-zero-knowledge-simulators -- concurrent_zk.h
 * Advanced ZK: Concurrent, Resettable, Non-Black-Box, Straight-line.
 * Covers L8 (Advanced Topics).
 *
 * Reference: Dwork, Naor & Sahai (1998) "Concurrent Zero-Knowledge"
 *            Barak (2001) "How to Go Beyond the Black-Box Simulation Barrier"
 *            Canetti, Goldreich, Goldwasser & Micali (2000) "Resettable ZK"
 * Courses: MIT 6.875, Stanford CS355, Oxford Advanced Crypto
 */

#define MAX_CONCURRENT_SESSIONS 16

typedef struct {
    uint32_t session_id;
    uint32_t state;
    transcript_t partial_transcript;
    int completed;
    int aborted;
} concurrent_session_t;

typedef struct {
    concurrent_session_t sessions[MAX_CONCURRENT_SESSIONS];
    uint32_t num_sessions;
    uint32_t next_session_id;
    uint32_t active_session;
} concurrent_scheduler_t;

void concurrent_scheduler_init(concurrent_scheduler_t *cs);
int  concurrent_scheduler_add_session(concurrent_scheduler_t *cs);
int  concurrent_scheduler_get_active(concurrent_scheduler_t *cs);
void concurrent_scheduler_switch_to(concurrent_scheduler_t *cs, uint32_t idx);
int  concurrent_scheduler_complete_session(concurrent_scheduler_t *cs, uint32_t idx);
int  concurrent_scheduler_all_done(const concurrent_scheduler_t *cs);

/*
 * L8.2 -- Resettable Zero-Knowledge (Dwork-Naor-Sahai 1998)
 * Prover can be reset to initial state by malicious verifier.
 */
typedef struct {
    uint64_t x;
    const group_params_t *gp;
    uint32_t reset_count;
    int state_saved;
    random_tape_t initial_random;
} resettable_prover_t;

void resettable_prover_init(resettable_prover_t *rp, uint64_t x,
                             const group_params_t *gp);
void resettable_prover_reset(resettable_prover_t *rp);
int  resettable_prover_has_been_reset(const resettable_prover_t *rp);

/*
 * L8.3 -- Non-Black-Box Simulation (Barak 2001)
 * Simulator uses the description of V* as a string.
 */
typedef struct {
    uint8_t *verifier_code;
    size_t code_size;
    int non_black_box;
    hash_digest_t code_hash;
} nbb_simulator_t;

void nbb_simulator_init(nbb_simulator_t *ns, simulation_mode_t mode);
void nbb_simulator_set_code(nbb_simulator_t *ns, const uint8_t *code,
                             size_t size);
int  nbb_simulator_hash_code(nbb_simulator_t *ns);
int  nbb_simulator_is_nbb(const nbb_simulator_t *ns);

/*
 * L8.4 -- Straight-Line Simulation
 * No rewinding needed (NIZK or trapdoor-based).
 */
int straight_line_simulate(const uint8_t *x, size_t xlen,
                            const random_tape_t *rng,
                            transcript_t *out);

/*
 * L8.5 -- Bounded Concurrent Simulation Time
 * Worst-case analysis for concurrent composition.
 */
double bounded_concurrent_sim_time(double n, double b);

/*
 * L8.6 -- Recursive Rewinding Strategy (Richardson-Kilian 1999)
 */
typedef struct {
    uint32_t rewind_depth;
    uint32_t max_depth;
    transcript_t saved_prefix;
    uint32_t checkpoint_round;
} recursive_rewind_state_t;

void recursive_rewind_init(recursive_rewind_state_t *rrs,
                            uint32_t max_depth);
int  recursive_rewind_checkpoint(recursive_rewind_state_t *rrs,
                                  const transcript_t *current,
                                  uint32_t round);
int  recursive_rewind_restore(recursive_rewind_state_t *rrs,
                                transcript_t *out);

/*
 * L8.7 -- Timing Constraints on Simulators
 */
typedef struct {
    uint32_t max_time_ms;
    uint32_t elapsed_ms;
    int timeout_occurred;
} timing_constraint_t;

void timing_constraint_set(timing_constraint_t *tc, uint32_t max_ms);
int  timing_constraint_check(timing_constraint_t *tc);
void timing_constraint_advance(timing_constraint_t *tc, uint32_t delta_ms);

/*
 * L8.8 -- UC-style ZK Ideal Functionality
 */
typedef struct {
    uint64_t statement;
    uint64_t witness;
    int is_valid;
    int proof_delivered;
} uc_zk_ideal_functionality_t;

void uc_zk_ideal_init(uc_zk_ideal_functionality_t *f);
int  uc_zk_ideal_prove(uc_zk_ideal_functionality_t *f,
                        uint64_t statement, uint64_t witness,
                        int (*relation)(uint64_t, uint64_t));
int  uc_zk_ideal_verify(const uc_zk_ideal_functionality_t *f);

#endif /* CONCURRENT_ZK_H */

