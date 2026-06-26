#ifndef SIMULATOR_CORE_H
#define SIMULATOR_CORE_H

#include "zk_simulator.h"
#include "sigma_protocols.h"
#include "commitments.h"

/*
 * mini-zero-knowledge-simulators -- simulator_core.h
 * Core simulator algorithms and scheduling framework.
 * Covers L5 (Algorithms/Methods) for simulators.
 *
 * The simulator is THE central object of study in ZK proofs.
 * Understanding how to construct simulators is understanding
 * zero-knowledge itself.
 *
 * Reference: Goldreich (2004) Foundations of Cryptography, Vol.1 Ch.4
 *            Lindell (2016) "How to Simulate It"
 *            Pass (2003) "Simulation in Quasi-Polynomial Time"
 * Courses: MIT 6.875, Stanford CS355, Berkeley CS276, CMU 15-859
 */

/* ================================================================
 * L5 -- Simulator Algorithms and Methods
 * ================================================================ */

/*
 * L5.1 -- Black-Box Rewinding Simulator Framework
 *
 * The fundamental pattern for BB simulation:
 *   1. Initialize V* with random tape r
 *   2. Loop:
 *      a. Run protocol up to challenge point
 *      b. Save V* state
 *      c. Send simulated message, get V* response
 *      d. If response is "favourable", complete simulation
 *      e. Else, rewind V* to saved state, go to (b)
 *   3. Output complete transcript
 *
 * Expected running time: T_sim = poly(|x|) / Pr[favourable event]
 * For most sigma protocols, Pr[favourable] = 1/|C|, so
 * T_sim = |C| * poly(|x|) = O(q * poly(|x|)).
 *
 * If q is exponential in security parameter, this is fine
 * because T_sim IS polynomial. But if q is small (e.g., constant),
 * the simulator might be inefficient. Hence challenges must be
 * taken from a large enough space.
 */

/*
 * Simulator scheduler: controls the rewind order and number of
 * attempts. Different scheduling strategies have different
 * expected running times.
 */
typedef enum {
    SCHED_NAIVE_REWIND,        /* rewind to fixed point, uniform retry */
    SCHED_BINARY_SEARCH,       /* binary search over message tree */
    SCHED_PRECOMPUTE_CHALLENGE,/* precompute all possible challenges */
    SCHED_STRAIGHT_LINE,       /* no rewinding (NIZK or specific protos) */
} scheduler_type_t;

/*
 * A rewind session: the simulator interacts with V* across
 * multiple rewindings.
 */
#define MAX_REWINDS 1024

typedef struct {
    simulator_fn      simulate;        /* the simulation function to use */
    simulation_mode_t mode;
    scheduler_type_t  scheduler;
    uint32_t          max_attempts;
    uint32_t          attempt_count;
    uint32_t          successful_rewinds;
    rewind_state_t    saved_states[MAX_REWINDS];
    uint32_t          num_saved_states;
} rewind_session_t;

void rewind_session_init(rewind_session_t *sess,
                          simulator_fn sim,
                          simulation_mode_t mode,
                          uint32_t max_attempts);
int  rewind_session_run(rewind_session_t *sess,
                         const uint8_t *x, size_t xlen,
                         const random_tape_t *master_rng,
                         transcript_t *out);
void rewind_session_save_state(rewind_session_t *sess,
                                const rewind_state_t *state);
int  rewind_session_restore_state(rewind_session_t *sess,
                                   uint32_t index,
                                   rewind_state_t *state_out);

/*
 * L5.2 -- View Generation vs Transcript Generation
 *
 * A subtle point: the simulator must generate the ENTIRE view,
 * not just the transcript. The view includes V*'s random tape.
 *
 * For black-box simulation, the simulator CHOOSES the random tape
 * r for V* and embeds it in the output view.
 *
 * For non-black-box simulation, the simulator works with V*'s code
 * directly and may not have control over its randomness.
 */

/*
 * Generate a full verifier view via BB simulation.
 * Returns 0 on success, -1 on failure.
 */
int simulate_verifier_view(const uint8_t *x, size_t xlen,
                            simulation_mode_t mode,
                            const random_tape_t *rng,
                            verifier_view_t *view_out);

/*
 * L5.3 -- Expected Running Time Analysis
 *
 * For a black-box simulator that rewinds until a favourable
 * challenge is obtained, the expected number of attempts is
 * geometric with parameter p = Pr[favourable].
 *
 * E[attempts] = 1/p
 * Var[attempts] = (1-p)/p^2
 *
 * Function below computes the expected attempts and variance.
 */
double expected_rewind_attempts(double success_prob);
double rewind_variance(double success_prob);

/*
 * L5.4 -- Simulator Oracle
 *
 * In the BB simulation model, V* is treated as an oracle.
 * The simulator sends messages and receives responses.
 *
 * For didactic purposes, we model V* as a deterministic function
 * of its random tape r, previous messages, and auxiliary input z.
 *
 * This is without loss of generality: any PPT V* can be
 * derandomized by fixing its random tape (which the simulator
 * controls).
 */
typedef int (*verifier_oracle_fn)(const uint8_t *incoming_message,
                                   size_t in_len,
                                   uint8_t *response, size_t *resp_len,
                                   void *oracle_state);

/*
 * L5.5 -- Expected Polynomial Time Simulators
 *
 * THEOREM (Goldreich-Krawczyk-Luby 1991):
 * If a language L has a BB ZK proof with verifier challenge space
 * of size q and the protocol is a sigma protocol, then the
 * expected simulation time is O(q * poly(n)).
 *
 * If q = poly(n), the simulation is expected poly-time.
 * If q is constant (e.g., {0,1}), sequential repetition
 * is needed to make soundness error negligible, but this
 * destroys the simple rewind-based simulation.
 *
 * For constant-round protocols with polynomial-size challenge
 * spaces, sequential repetition with separate rewinding in
 * each round yields expected poly-time simulation.
 */
int is_expected_polynomial(double success_prob, double n);

/*
 * L5.6 -- Simulation Strategies for Different Protocol Structures
 */

/* Strategy for 3-round sigma protocols (Schnorr-type) */
int simulate_3round_sigma(uint64_t y, const group_params_t *gp,
                           const random_tape_t *rng,
                           sigma_simulate_fn hvzk_sim,
                           transcript_t *out);

/* Strategy for constant-round public-coin protocols */
int simulate_constant_round(const uint8_t *x, size_t xlen,
                              int num_rounds,
                              const random_tape_t *rng,
                              transcript_t *out);

/*
 * L5.7 -- Error Handling in Simulation
 *
 * A simulation may fail (e.g., exceed max attempts). In this case,
 * the simulator outputs a special failure indicator.
 *
 * For statistical ZK, the simulator can abort with small probability
 * without compromising the ZK property. For perfect ZK, the
 * simulator must NEVER output a distinguishable transcript.
 *
 * For computational ZK, the simulator can fail with negligible
 * probability (since a PPT distinguisher cannot exploit this).
 */
#define SIM_OK        0
#define SIM_TIMEOUT  -1
#define SIM_ABORT    -2
#define SIM_INVALID  -3

const char *sim_error_string(int error_code);

/*
 * L5.8 -- Simulator Quality Metrics
 *
 * We can measure the "quality" of a simulation in terms of
 * statistical distance between real and simulated distributions.
 *
 * For Perfect ZK: distance = 0 (exactly)
 * For Statistical ZK: distance = negl(n)
 * For Computational ZK: distance = negl(n) against PPT distinguishers
 */
double simulator_statistical_quality(const transcript_t *real_samples,
                                      size_t num_real,
                                      const transcript_t *sim_samples,
                                      size_t num_sim);

#endif /* SIMULATOR_CORE_H */

