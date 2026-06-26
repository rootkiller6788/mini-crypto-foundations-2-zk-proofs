#include "simulator_core.h"
#include "sigma_protocols.h"
#include <stdio.h>
#include <math.h>
#include <assert.h>
#include <string.h>

/* simulator_core.c -- Simulator algorithms and scheduling framework */

void rewind_session_init(rewind_session_t *sess, simulator_fn sim,
                          simulation_mode_t mode, uint32_t max_attempts) {
    if (!sess) return;
    sess->simulate = sim; sess->mode = mode;
    sess->scheduler = SCHED_NAIVE_REWIND;
    sess->max_attempts = max_attempts;
    sess->attempt_count = 0;
    sess->successful_rewinds = 0;
    sess->num_saved_states = 0;
    memset(sess->saved_states, 0, sizeof(sess->saved_states));
}

void rewind_session_save_state(rewind_session_t *sess, const rewind_state_t *state) {
    if (!sess || !state) return;
    if (sess->num_saved_states < MAX_REWINDS)
        sess->saved_states[sess->num_saved_states++] = *state;
}

int rewind_session_restore_state(rewind_session_t *sess, uint32_t index,
                                  rewind_state_t *state_out) {
    if (!sess || !state_out || index >= sess->num_saved_states) return -1;
    *state_out = sess->saved_states[index];
    return 0;
}

int rewind_session_run(rewind_session_t *sess, const uint8_t *x, size_t xlen,
                        const random_tape_t *master_rng, transcript_t *out) {
    if (!sess || !x || !master_rng || !out) return SIM_INVALID;
    sess->attempt_count = 0;
    while (sess->attempt_count < sess->max_attempts) {
        sess->attempt_count++;
        int ret = sess->simulate(x, xlen, master_rng->coins,
                                  master_rng->coin_len, out);
        if (ret == 0) { sess->successful_rewinds++; return SIM_OK; }
    }
    return SIM_TIMEOUT;
}

int simulate_verifier_view(const uint8_t *x, size_t xlen,
                            simulation_mode_t mode,
                            const random_tape_t *rng,
                            verifier_view_t *view_out) {
    if (!x || !rng || !view_out) return -1;
    memset(view_out, 0, sizeof(verifier_view_t));
    view_out->r = *rng;
    transcript_init(&view_out->messages);
    (void)xlen; (void)mode;
    return 0;
}

double expected_rewind_attempts(double success_prob) {
    if (success_prob <= 0.0) return INFINITY;
    if (success_prob >= 1.0) return 1.0;
    return 1.0 / success_prob;
}

double rewind_variance(double success_prob) {
    if (success_prob <= 0.0) return INFINITY;
    if (success_prob >= 1.0) return 0.0;
    return (1.0 - success_prob) / (success_prob * success_prob);
}

int is_expected_polynomial(double success_prob, double n) {
    if (n <= 0.0 || success_prob <= 0.0) return 0;
    double expected = 1.0 / success_prob;
    double poly_bound = n * n * n;
    return (expected <= poly_bound) ? 1 : 0;
}

int simulate_3round_sigma(uint64_t y, const group_params_t *gp,
                           const random_tape_t *rng,
                           sigma_simulate_fn hvzk_sim,
                           transcript_t *out) {
    if (!gp || !rng || !hvzk_sim || !out) return -1;
    uint64_t a, c, s;
    int ret = hvzk_sim(y, gp, rng, &a, &c, &s);
    if (ret != 0) return ret;
    transcript_init(out);
    transcript_start_round(out); transcript_append_u64(out, a);
    transcript_start_round(out); transcript_append_u64(out, c);
    transcript_start_round(out); transcript_append_u64(out, s);
    return 0;
}

int simulate_constant_round(const uint8_t *x, size_t xlen,
                              int num_rounds,
                              const random_tape_t *rng,
                              transcript_t *out) {
    if (!x || !rng || !out || num_rounds <= 0) return -1;
    transcript_init(out);
    for (int i = 0; i < num_rounds; i++) {
        transcript_start_round(out);
        uint8_t dummy[8] = {0};
        transcript_append(out, dummy, 8);
    }
    (void)xlen;
    return 0;
}

const char *sim_error_string(int error_code) {
    switch (error_code) {
        case SIM_OK:       return "Simulation successful";
        case SIM_TIMEOUT:  return "Timeout: maximum attempts exceeded";
        case SIM_ABORT:    return "Aborted: unrecoverable error";
        case SIM_INVALID:  return "Invalid parameters";
        default:           return "Unknown error code";
    }
}

double simulator_statistical_quality(const transcript_t *real_samples,
                                      size_t num_real,
                                      const transcript_t *sim_samples,
                                      size_t num_sim) {
    if (!real_samples || !sim_samples || num_real == 0 || num_sim == 0)
        return 1.0;
    size_t matches = 0;
    for (size_t i = 0; i < num_real && i < num_sim; i++) {
        if (real_samples[i].len == sim_samples[i].len &&
            memcmp(real_samples[i].data, sim_samples[i].data,
                   real_samples[i].len) == 0)
            matches++;
    }
    return 1.0 - (double)matches / (double)num_real;
}

int simulator_core_self_test(void) {
    group_params_t gp = {23, 2, 11, 8};
    random_tape_t rng;
    init_random_tape(&rng, 42);
    rewind_session_t sess;
    rewind_session_init(&sess, NULL, SIM_BLACK_BOX, 10);
    assert(sess.max_attempts == 10);
    double exp = expected_rewind_attempts(0.5);
    assert(fabs(exp - 2.0) < 0.001);
    assert(is_expected_polynomial(0.1, 10.0) == 1);
    assert(strcmp(sim_error_string(SIM_OK), "Simulation successful") == 0);
    transcript_t out;
    int ret = simulate_3round_sigma(mod_pow(2, 4, 23), &gp, &rng,
                                     hvzk_simulate_schnorr, &out);
    assert(ret == 0);
    transcript_t real[1], sim[1];
    transcript_init(&real[0]); transcript_append_u64(&real[0], 42);
    transcript_init(&sim[0]);  transcript_append_u64(&sim[0], 42);
    double qual = simulator_statistical_quality(real, 1, sim, 1);
    assert(qual == 0.0);
    return 0;
}
