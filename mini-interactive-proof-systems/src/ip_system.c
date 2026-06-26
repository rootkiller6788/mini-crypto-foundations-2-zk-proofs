/*======================================================================
 * ip_system.c -- Interactive Proof System: core definitions & runtime
 *
 * Implements the foundational infrastructure for interactive proof
 * systems as defined in Goldwasser-Micali-Rackoff (1985/89).
 *
 * Knowledge mapping:
 *   L1: IP definition -- prover, verifier, completeness, soundness
 *   L2: error reduction, sequential repetition, public/private coins
 *   L3: transcript, random tape, finite field GF(p) arithmetic
 *   L4: Chernoff-bound error reduction, Goldwasser-Sipser equivalence
 *   L5: sequential repetition, multilinear evaluation DP
 *
 * Reference:
 *   Goldwasser, Micali, Rackoff. "The knowledge complexity of
 *   interactive proof-systems." SIAM J. Comput. 18(1), 1989.
 *   Arora & Barak. Computational Complexity: A Modern Approach, Ch.8.
 *   Shamir. "IP = PSPACE." J. ACM 39(4), 1992.
 *======================================================================*/

#include "ip_system.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>

/* Random tape operations (L3: Mathematical Structures)
 * Public-coin vs private-coin: Goldwasser-Sipser (1989): IP[k] = AM[k+2].
 */
static uint64_t ip_prng_state = 0xABCD12345678ULL;

static uint64_t ip_prng_next(void) {
    ip_prng_state ^= ip_prng_state >> 12;
    ip_prng_state ^= ip_prng_state << 25;
    ip_prng_state ^= ip_prng_state >> 27;
    return ip_prng_state * 0x2545F4914F6CDD1DULL;
}

void ip_random_seed(uint64_t seed) {
    if (seed == 0) seed = 1;
    ip_prng_state = seed;
}

int ip_tape_init(IPRandomTape *tape, size_t num_coins, int is_public) {
    if (!tape || num_coins == 0) return -1;
    tape->coins = (uint64_t *)calloc(num_coins, sizeof(uint64_t));
    if (!tape->coins) return -1;
    tape->num_coins = num_coins;
    tape->coins_used = 0;
    tape->is_public = is_public;
    for (size_t i = 0; i < num_coins; i++) {
        tape->coins[i] = ip_prng_next();
    }
    return 0;
}

void ip_tape_free(IPRandomTape *tape) {
    if (tape && tape->coins) {
        free(tape->coins);
        tape->coins = NULL;
        tape->num_coins = 0;
        tape->coins_used = 0;
    }
}

uint64_t ip_tape_consume(IPRandomTape *tape, size_t k) {
    if (!tape || k == 0 || k > 64) return 0;
    uint64_t result = 0;
    for (size_t i = 0; i < k; i++) {
        if (tape->coins_used >= tape->num_coins) {
            uint64_t new_coin = ip_prng_next();
            result = result | ((new_coin & 1) << i);
        } else {
            uint64_t coin = tape->coins[tape->coins_used++];
            result = result | ((coin & 1) << i);
        }
    }
    return result;
}

/* Transcript management (L3: Mathematical Structures)
 *
 * A transcript records all messages exchanged between prover and
 * verifier during an interactive proof. The transcript is the
 * central data structure for:
 *   - Verifier decision (accept/reject based on transcript)
 *   - Zero-knowledge simulation (simulator produces indistinguishable
 *     transcripts without prover interaction)
 */
void ip_transcript_init(IPTranscript *transcript) {
    if (!transcript) return;
    memset(transcript, 0, sizeof(IPTranscript));
    transcript->verdict_is_set = 0;
}

int ip_transcript_add(IPTranscript *transcript, const IPMessage *msg) {
    if (!transcript || !msg) return -1;
    if (transcript->num_messages >= IP_MAX_ROUNDS * 2) return -1;
    if (msg->length > IP_MAX_MESSAGE_SIZE) return -1;
    if (msg->round > IP_MAX_ROUNDS) return -1;
    memcpy(&transcript->messages[transcript->num_messages], msg, sizeof(IPMessage));
    transcript->num_messages++;
    if (msg->round + 1 > transcript->total_rounds) {
        transcript->total_rounds = msg->round + 1;
    }
    return 0;
}

int ip_transcript_to_string(const IPTranscript *transcript,
                            char *buffer, size_t buf_size) {
    if (!transcript || !buffer || buf_size == 0) return -1;
    int offset = 0;
    int n = snprintf(buffer, buf_size,
        "Transcript: rounds=%u messages=%u verdict=%d\n",
        transcript->total_rounds, transcript->num_messages,
        transcript->verdict_is_set ? (int)transcript->final_verdict : -1);
    if (n < 0) return offset;
    offset = n;
    for (uint32_t i = 0; i < transcript->num_messages && (size_t)offset < buf_size; i++) {
        const IPMessage *m = &transcript->messages[i];
        n = snprintf(buffer + offset, buf_size - offset,
            "  round=%u sender=%s len=%zu\n",
            m->round, m->sender == IP_MESSAGE_PROVER ? "P" : "V", m->length);
        if (n < 0) break;
        offset += n;
    }
    return offset;
}

/* Prover / Verifier lifecycle (L1: Core Definitions)
 *
 * Prover (P): computationally unbounded entity trying to convince
 *   the verifier that x in L.
 *
 * Verifier (V): polynomial-time probabilistic Turing machine.
 *
 * Completeness: forall x in L, Pr[<P,V>(x)=accept] >= 2/3
 * Soundness:    forall x not in L, forall P*, Pr[<P*,V>(x)=accept] <= 1/3
 */
int ip_prover_init(IPProver *prover, IPProverStrategy strategy) {
    if (!prover || !strategy) return -1;
    memset(prover, 0, sizeof(IPProver));
    prover->strategy = strategy;
    prover->is_initialized = 1;
    return 0;
}

void ip_prover_free(IPProver *prover) {
    if (prover) {
        if (prover->state) {
            free(prover->state);
            prover->state = NULL;
        }
        prover->state_size = 0;
        prover->is_initialized = 0;
    }
}

int ip_verifier_init(IPVerifier *verifier, IPVerifierStrategy next_challenge,
                     IPVerdictFunction decide, IPProtocolType prot_type,
                     size_t num_coins) {
    if (!verifier || !next_challenge || !decide) return -1;
    memset(verifier, 0, sizeof(IPVerifier));
    verifier->next_challenge = next_challenge;
    verifier->decide = decide;
    verifier->protocol_type = prot_type;
    if (ip_tape_init(&verifier->tape, num_coins,
        prot_type == IP_PROTOCOL_PUBLIC_COIN ? 1 : 0) != 0) {
        return -1;
    }
    verifier->is_initialized = 1;
    return 0;
}

void ip_verifier_free(IPVerifier *verifier) {
    if (verifier) {
        ip_tape_free(&verifier->tape);
        if (verifier->state) {
            free(verifier->state);
            verifier->state = NULL;
        }
        verifier->state_size = 0;
        verifier->is_initialized = 0;
    }
}

int ip_proof_system_init(IPProofSystem *psys, const char *name,
                         IPProver *prover, IPVerifier *verifier,
                         uint32_t rounds, IPProtocolType prot_type) {
    if (!psys || !name || !prover || !verifier) return -1;
    memset(psys, 0, sizeof(IPProofSystem));
    strncpy(psys->language_name, name, sizeof(psys->language_name) - 1);
    psys->prover = *prover;
    psys->verifier = *verifier;
    psys->num_rounds = rounds;
    psys->protocol_type = prot_type;
    psys->completeness_error = 1.0 / 3.0;
    psys->soundness_error = 1.0 / 3.0;
    psys->is_valid = 1;
    return 0;
}

/* Core protocol execution (L5: Algorithms/Methods)
 * ip_run: Execute a single run of the IP protocol.
 * Protocol proceeds in rounds:
 *   V sends challenge -> P sends response
 * After k rounds, V runs decide() on transcript.
 * Implements the general IP[k] framework from GMR'89.
 */
int ip_run(IPProofSystem *psys, const char *input, size_t input_len,
           const char *witness, size_t wit_len, IPResult *result) {
    if (!psys || !psys->is_valid || !input || !result) return -1;
    if (!psys->prover.is_initialized || !psys->verifier.is_initialized) return -1;

    IPTranscript transcript;
    ip_transcript_init(&transcript);
    IPMessage challenge, response;

    for (uint32_t r = 0; r < psys->num_rounds; r++) {
        memset(&challenge, 0, sizeof(challenge));
        challenge.round = r;
        challenge.sender = IP_MESSAGE_VERIFIER;

        int vret = psys->verifier.next_challenge(
            input, input_len, &transcript,
            &psys->verifier.tape, &challenge);
        if (vret < 0) { result->success = 0; return -1; }

        if (ip_transcript_add(&transcript, &challenge) != 0) {
            result->success = 0; return -1;
        }

        memset(&response, 0, sizeof(response));
        response.round = r;
        response.sender = IP_MESSAGE_PROVER;

        int pret = psys->prover.strategy(
            input, input_len, witness, wit_len,
            &transcript, &challenge, &response);
        if (pret < 0) { result->success = 0; return -1; }

        if (ip_transcript_add(&transcript, &response) != 0) {
            result->success = 0; return -1;
        }
    }

    IPVerdict verdict;
    int dret = psys->verifier.decide(input, input_len, &transcript, &verdict);
    if (dret < 0) { result->success = 0; return -1; }

    transcript.final_verdict = verdict;
    transcript.verdict_is_set = 1;

    result->verdict = verdict;
    result->transcript = transcript;
    result->rounds_executed = psys->num_rounds;
    result->success = 1;
    result->error_bound = (verdict == IP_VERDICT_ACCEPT)
        ? psys->completeness_error : psys->soundness_error;
    return 0;
}

/* Error reduction via sequential repetition (L2: Core Concepts)
 *
 * Running the protocol k times independently and accepting iff all
 * runs accept reduces soundness error exponentially:
 *   soundness_error(k) = (soundness_error(1))^k
 *
 * Completeness degrades modestly: by union bound,
 *   completeness_error(k) <= k * completeness_error(1)
 */
int ip_run_with_error_reduction(IPProofSystem *psys, const char *input,
    size_t input_len, const char *witness, size_t wit_len,
    size_t k, IPResult *result) {
    if (!psys || !input || !result || k == 0) return -1;

    size_t accepts = 0;
    IPResult run_result;

    for (size_t rep = 0; rep < k; rep++) {
        ip_tape_free(&psys->verifier.tape);
        if (ip_tape_init(&psys->verifier.tape, IP_MAX_ROUNDS * 2,
            psys->verifier.protocol_type == IP_PROTOCOL_PUBLIC_COIN ? 1 : 0) != 0) {
            result->success = 0; return -1;
        }

        int ret = ip_run(psys, input, input_len, witness, wit_len, &run_result);
        if (ret != 0 || !run_result.success) {
            result->success = 0; return -1;
        }
        if (run_result.verdict == IP_VERDICT_ACCEPT) {
            accepts++;
        }
    }

    result->verdict = (accepts == k) ? IP_VERDICT_ACCEPT : IP_VERDICT_REJECT;

    double reduced_soundness = pow(psys->soundness_error, (double)k);
    double reduced_completeness = 1.0 - pow(1.0 - psys->completeness_error, (double)k);

    result->error_bound = (result->verdict == IP_VERDICT_ACCEPT)
        ? reduced_soundness : reduced_completeness;
    result->transcript = run_result.transcript;
    result->rounds_executed = psys->num_rounds * (uint32_t)k;
    result->success = 1;
    return 0;
}

/* Statistical analysis (L2: probabilistic analysis)
 * Runs protocol num_runs times to estimate acceptance probability.
 */
int ip_collect_statistics(IPProofSystem *psys, const char *input,
    size_t input_len, const char *witness, size_t wit_len,
    size_t num_runs, IPStatistics *stats) {
    if (!psys || !input || !stats || num_runs == 0) return -1;

    memset(stats, 0, sizeof(IPStatistics));
    stats->num_runs = num_runs;
    stats->num_accepts = 0;
    stats->min_error = 1.0;
    stats->max_error = 0.0;

    IPResult run_result;
    double total_rounds = 0.0;

    for (size_t i = 0; i < num_runs; i++) {
        ip_tape_free(&psys->verifier.tape);
        if (ip_tape_init(&psys->verifier.tape, IP_MAX_ROUNDS * 2,
            psys->verifier.protocol_type == IP_PROTOCOL_PUBLIC_COIN ? 1 : 0) != 0) {
            return -1;
        }

        int ret = ip_run(psys, input, input_len, witness, wit_len, &run_result);
        if (ret != 0 || !run_result.success) return -1;

        if (run_result.verdict == IP_VERDICT_ACCEPT) {
            stats->num_accepts++;
        }
        if (run_result.error_bound < stats->min_error)
            stats->min_error = run_result.error_bound;
        if (run_result.error_bound > stats->max_error)
            stats->max_error = run_result.error_bound;
        total_rounds += (double)run_result.rounds_executed;
    }

    stats->accept_rate = (double)stats->num_accepts / (double)num_runs;
    stats->avg_rounds = total_rounds / (double)num_runs;
    return 0;
}

/* Chernoff bound for error reduction (L4: Fundamental Laws)
 *
 * For independent Bernoulli trials X_1,...,X_k with E[X_i] = p:
 *   Pr[Sigma X_i >= (1+delta)kp] <= exp(-delta^2 kp / 3)
 *
 * Sequential repetition: Pr[all k accept] = epsilon^k
 */
double ip_chernoff_bound(size_t k, double per_round_error) {
    if (k == 0) return 1.0;
    if (per_round_error >= 1.0) return 1.0;
    if (per_round_error <= 0.0) return 0.0;

    double exact_bound = pow(per_round_error, (double)k);
    double p = per_round_error;
    double delta = 0.5 / p - 1.0;
    if (delta <= 0.0) return exact_bound;
    double chernoff_upper = exp(-delta * delta * (double)k * p / 3.0);

    return (chernoff_upper < exact_bound) ? chernoff_upper : exact_bound;
}

/* Finite field arithmetic over GF(p) (L3: Mathematical Structures)
 *
 * Essential for arithmetization: converting Boolean formulas into
 * low-degree polynomials over a prime field.
 */
int ip_field_init(IPFiniteField *field, uint64_t prime) {
    if (!field || prime < 2) return -1;
    for (uint64_t d = 2; d * d <= prime && d < 100000; d++) {
        if (prime % d == 0) return -1;
    }
    field->prime = prime;
    field->elements = NULL;
    field->num_elements = 0;
    return 0;
}

void ip_field_free(IPFiniteField *field) {
    if (field) {
        if (field->elements) free(field->elements);
        field->elements = NULL;
        field->num_elements = 0;
    }
}

uint64_t ip_field_add(IPFiniteField *field, uint64_t a, uint64_t b) {
    if (!field) return 0;
    return (a + b) % field->prime;
}

uint64_t ip_field_sub(IPFiniteField *field, uint64_t a, uint64_t b) {
    if (!field) return 0;
    if (a >= b) {
        return (a - b) % field->prime;
    } else {
        return (field->prime - ((b - a) % field->prime)) % field->prime;
    }
}

uint64_t ip_field_mul(IPFiniteField *field, uint64_t a, uint64_t b) {
    if (!field) return 0;
    uint64_t result = 0;
    uint64_t p = field->prime;
    a = a % p;
    b = b % p;
    while (b > 0) {
        if (b & 1) result = (result + a) % p;
        a = (a << 1) % p;
        b >>= 1;
    }
    return result;
}

uint64_t ip_field_pow(IPFiniteField *field, uint64_t a, uint64_t exp) {
    if (!field) return 0;
    uint64_t result = 1;
    a = a % field->prime;
    uint64_t e = exp;
    while (e > 0) {
        if (e & 1) result = ip_field_mul(field, result, a);
        a = ip_field_mul(field, a, a);
        e >>= 1;
    }
    return result;
}

static int64_t egcd(int64_t a, int64_t b, int64_t *x, int64_t *y) {
    if (b == 0) { *x = 1; *y = 0; return a; }
    int64_t x1, y1;
    int64_t g = egcd(b, a % b, &x1, &y1);
    *x = y1;
    *y = x1 - (a / b) * y1;
    return g;
}

uint64_t ip_field_inv(IPFiniteField *field, uint64_t a) {
    if (!field || a == 0 || a % field->prime == 0) return 0;
    int64_t x, y;
    (void)egcd((int64_t)(a % field->prime), (int64_t)field->prime, &x, &y);
    uint64_t inv = (uint64_t)((x % (int64_t)field->prime + (int64_t)field->prime)
                    % (int64_t)field->prime);
    return inv;
}

/* Polynomial operations over GF(p) (L3: Mathematical Structures)
 *
 * Polynomials are core algebraic objects in interactive proofs.
 * The sumcheck protocol and GKR protocol operate on multilinear
 * polynomials and low-degree extensions over finite fields.
 */
int ip_polynomial_init(IPPolynomial *poly, const uint64_t *coeffs,
                       size_t degree, uint64_t prime) {
    if (!poly || !coeffs) return -1;
    poly->coeffs = (uint64_t *)calloc(degree + 1, sizeof(uint64_t));
    if (!poly->coeffs) return -1;
    memcpy(poly->coeffs, coeffs, (degree + 1) * sizeof(uint64_t));
    poly->degree = degree;
    poly->prime = prime;
    poly->is_valid = 1;
    return 0;
}

void ip_polynomial_free(IPPolynomial *poly) {
    if (poly) {
        if (poly->coeffs) free(poly->coeffs);
        poly->coeffs = NULL;
        poly->degree = 0;
        poly->is_valid = 0;
    }
}

/* Evaluate polynomial using Horner method: O(degree) field ops */
uint64_t ip_polynomial_eval(IPPolynomial *poly, uint64_t x) {
    if (!poly || !poly->is_valid) return 0;
    uint64_t p = poly->prime;
    x = x % p;
    uint64_t result = poly->coeffs[poly->degree] % p;
    for (int64_t i = (int64_t)poly->degree - 1; i >= 0; i--) {
        result = ((poly->coeffs[i] % p) + (result * x) % p) % p;
    }
    return result;
}

/* Multilinear extension (L3: Mathematical Structures)
 *
 * Every function f: {0,1}^n -> F has a unique multilinear extension
 * f_tilde: F^n -> F:
 *   f_tilde(x) = sum_{b in {0,1}^n} f(b) * prod_i chi_{b_i}(x_i)
 * where chi_0(x)=1-x, chi_1(x)=x.
 *
 * Fundamental to arithmetization in IP=PSPACE and sumcheck.
 */
int ip_multilinear_init(IPMultilinearExtension *mex, const uint64_t *evals,
                        size_t n, uint64_t prime) {
    if (!mex || !evals) return -1;
    size_t num_evals = 1ULL << n;
    mex->evaluations = (uint64_t *)calloc(num_evals, sizeof(uint64_t));
    if (!mex->evaluations) return -1;
    memcpy(mex->evaluations, evals, num_evals * sizeof(uint64_t));
    mex->num_vars = n;
    mex->prime = prime;
    mex->is_valid = 1;
    return 0;
}

void ip_multilinear_free(IPMultilinearExtension *mex) {
    if (mex) {
        if (mex->evaluations) free(mex->evaluations);
        mex->evaluations = NULL;
        mex->num_vars = 0;
        mex->is_valid = 0;
    }
}

uint64_t ip_multilinear_eval(IPMultilinearExtension *mex,
                             const uint64_t *point) {
    if (!mex || !point || !mex->is_valid) return 0;
    size_t n = mex->num_vars;
    size_t total = 1ULL << n;
    uint64_t p = mex->prime;
    uint64_t result = 0;

    for (size_t b = 0; b < total; b++) {
        uint64_t f_b = mex->evaluations[b] % p;
        uint64_t chi_term = 1;
        for (size_t i = 0; i < n; i++) {
            uint64_t b_i = (b >> i) & 1;
            uint64_t x_i = point[i] % p;
            uint64_t factor;
            if (b_i == 1) {
                factor = x_i;
            } else {
                factor = (x_i == 0) ? 1 : (1 + p - x_i) % p;
            }
            chi_term = (chi_term * factor) % p;
        }
        result = (result + (f_b * chi_term) % p) % p;
    }
    return result;
}

/* DP evaluation: A[b] = (1-x_i)*A[b] + x_i*A[b+2^i], O(n*2^n) */
uint64_t ip_multilinear_eval_dp(IPMultilinearExtension *mex,
                                const uint64_t *point) {
    if (!mex || !point || !mex->is_valid) return 0;
    size_t n = mex->num_vars;
    size_t total = 1ULL << n;
    uint64_t p = mex->prime;

    uint64_t *work = (uint64_t *)malloc(total * sizeof(uint64_t));
    if (!work) return 0;
    memcpy(work, mex->evaluations, total * sizeof(uint64_t));

    for (size_t i = 0; i < n; i++) {
        uint64_t x_i = point[i] % p;
        size_t stride = 1ULL << i;
        size_t pairs = total / (2 * stride);

        for (size_t j = 0; j < pairs; j++) {
            size_t idx0 = 2 * j * stride;
            size_t idx1 = idx0 + stride;
            for (size_t k = 0; k < stride; k++) {
                uint64_t val0 = work[idx0 + k] % p;
                uint64_t val1 = work[idx1 + k] % p;
                uint64_t one_minus_x;
                if (x_i == 0) one_minus_x = 1;
                else one_minus_x = (1 + p - x_i) % p;
                uint64_t term0 = (one_minus_x * val0) % p;
                uint64_t term1 = (x_i * val1) % p;
                work[idx0 + k] = (term0 + term1) % p;
            }
        }
    }
    uint64_t result = work[0];
    free(work);
    return result;
}

int ip_multilinear_restrict(IPMultilinearExtension *mex, size_t var_index,
                            uint64_t value, IPMultilinearExtension *out) {
    if (!mex || !out || !mex->is_valid) return -1;
    if (var_index >= mex->num_vars) return -1;
    if (value > 1) return -1;

    size_t n = mex->num_vars;
    size_t out_size = 1ULL << (n - 1);
    uint64_t *out_evals = (uint64_t *)calloc(out_size, sizeof(uint64_t));
    if (!out_evals) return -1;

    for (size_t b = 0; b < out_size; b++) {
        size_t full_b = 0;
        size_t shift = 0;
        for (size_t i = 0; i < n; i++) {
            if (i == var_index) {
                if (value) full_b |= (1ULL << i);
            } else {
                if ((b >> shift) & 1) full_b |= (1ULL << i);
                shift++;
            }
        }
        out_evals[b] = mex->evaluations[full_b];
    }

    out->evaluations = out_evals;
    out->num_vars = n - 1;
    out->prime = mex->prime;
    out->is_valid = 1;
    return 0;
}

/* Arithmetization of 3CNF (L4: IP=PSPACE)
 *
 * Given 3CNF phi, arithmetized clause:
 *   A_C(x) = prod_{l in C} (1 - lit_poly(l))
 *
 * Arithmetized formula: A_phi(x) = prod_{C in phi} A_C(x)
 * phi(x)=1  <=>  A_phi(x)=0
 */
uint64_t ip_arithmetize_3cnf_clause(const size_t *clause, size_t clause_len,
                                     const uint64_t *assignment, size_t n,
                                     uint64_t prime) {
    if (!clause || !assignment) return 0;
    uint64_t result = 1;
    for (size_t i = 0; i < clause_len; i++) {
        size_t encoded = clause[i];
        size_t var = encoded >> 1;
        int negated = (int)(encoded & 1);
        uint64_t x_var = (var < n) ? (assignment[var] & 1) : 0;
        uint64_t lit_eval;
        if (negated) {
            lit_eval = (x_var == 0) ? 1 : 0;
        } else {
            lit_eval = x_var;
        }
        uint64_t factor = (lit_eval == 0) ? 1 : 0;
        result = (result * factor) % prime;
    }
    return result;
}

int ip_arithmetize_3cnf(const size_t **clauses, const size_t *clause_lens,
                         size_t num_clauses, const uint64_t *assignment,
                         size_t n, uint64_t prime, uint64_t *out) {
    if (!clauses || !clause_lens || !assignment || !out) return -1;
    uint64_t product = 1;
    for (size_t c = 0; c < num_clauses; c++) {
        uint64_t a_c = ip_arithmetize_3cnf_clause(
            clauses[c], clause_lens[c], assignment, n, prime);
        product = (product * a_c) % prime;
    }
    *out = (product == 0) ? 1 : 0;
    return 0;
}