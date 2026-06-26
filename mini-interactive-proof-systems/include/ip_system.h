#ifndef MINI_IP_SYSTEM_H
#define MINI_IP_SYSTEM_H

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#define IP_MAX_ROUNDS           64
#define IP_MAX_MESSAGE_SIZE     1024
#define IP_DEFAULT_REPETITIONS  64
#define IP_TARGET_ERROR         1e-9
#define IP_MAX_INPUT_LENGTH     4096

typedef enum {
    IP_VERDICT_ACCEPT = 1,
    IP_VERDICT_REJECT = 0
} IPVerdict;

typedef enum {
    IP_MESSAGE_PROVER   = 0,
    IP_MESSAGE_VERIFIER = 1
} IPMessageType;

typedef enum {
    IP_PROTOCOL_GENERAL     = 0,
    IP_PROTOCOL_PUBLIC_COIN = 1,
    IP_PROTOCOL_PRIVATE_COIN = 2
} IPProtocolType;

typedef enum {
    IP_COMPLETENESS_PERFECT      = 0,
    IP_COMPLETENESS_NEAR_PERFECT = 1,
    IP_COMPLETENESS_STANDARD     = 2
} IPCompletenessClass;

typedef enum {
    IP_SOUNDNESS_PERFECT      = 0,
    IP_SOUNDNESS_STATISTICAL  = 1,
    IP_SOUNDNESS_STANDARD     = 2
} IPSoundnessClass;

typedef struct {
    uint8_t   data[IP_MAX_MESSAGE_SIZE];
    size_t    length;
    uint32_t  round;
    IPMessageType sender;
    uint64_t  timestamp;
} IPMessage;

typedef struct {
    IPMessage messages[IP_MAX_ROUNDS * 2];
    uint32_t  num_messages;
    uint32_t  total_rounds;
    IPVerdict final_verdict;
    int       verdict_is_set;
} IPTranscript;

typedef struct {
    uint64_t *coins;
    size_t    num_coins;
    size_t    coins_used;
    int       is_public;
} IPRandomTape;

typedef struct IPProver IPProver;

typedef int (*IPProverStrategy)(
    const char *input, size_t input_len,
    const char *witness, size_t witness_len,
    const IPTranscript *transcript,
    const IPMessage *challenge,
    IPMessage *response
);

struct IPProver {
    IPProverStrategy strategy;
    void            *state;
    size_t           state_size;
    int              is_initialized;
};

typedef struct IPVerifier IPVerifier;

typedef int (*IPVerifierStrategy)(
    const char *input, size_t input_len,
    const IPTranscript *transcript,
    IPRandomTape *tape,
    IPMessage *challenge
);

typedef int (*IPVerdictFunction)(
    const char *input, size_t input_len,
    const IPTranscript *transcript,
    IPVerdict *verdict
);

struct IPVerifier {
    IPVerifierStrategy   next_challenge;
    IPVerdictFunction    decide;
    IPRandomTape         tape;
    void                *state;
    size_t               state_size;
    int                  is_initialized;
    IPProtocolType       protocol_type;
};

typedef struct {
    char              language_name[128];
    IPProver          prover;
    IPVerifier        verifier;
    uint32_t          num_rounds;
    double            completeness_error;
    double            soundness_error;
    IPProtocolType    protocol_type;
    IPCompletenessClass completeness_class;
    IPSoundnessClass  soundness_class;
    int               is_valid;
} IPProofSystem;

typedef struct {
    IPVerdict    verdict;
    double       error_bound;
    IPTranscript transcript;
    uint32_t     rounds_executed;
    int          success;
} IPResult;

typedef struct {
    size_t   num_runs;
    size_t   num_accepts;
    double   accept_rate;
    double   min_error;
    double   max_error;
    double   avg_rounds;
} IPStatistics;

typedef struct {
    uint64_t prime;
    uint64_t *elements;
    size_t   num_elements;
} IPFiniteField;

typedef struct {
    uint64_t *coeffs;
    size_t    degree;
    uint64_t  prime;
    int       is_valid;
} IPPolynomial;

typedef struct {
    uint64_t *evaluations;
    size_t    num_vars;
    uint64_t  prime;
    int       is_valid;
} IPMultilinearExtension;

int ip_prover_init(IPProver *prover, IPProverStrategy strategy);
void ip_prover_free(IPProver *prover);
int ip_verifier_init(IPVerifier *verifier, IPVerifierStrategy next_challenge,
                     IPVerdictFunction decide, IPProtocolType prot_type, size_t num_coins);
void ip_verifier_free(IPVerifier *verifier);
int ip_proof_system_init(IPProofSystem *psys, const char *name, IPProver *prover,
                         IPVerifier *verifier, uint32_t rounds, IPProtocolType prot_type);
int ip_run(IPProofSystem *psys, const char *input, size_t input_len,
           const char *witness, size_t wit_len, IPResult *result);
int ip_run_with_error_reduction(IPProofSystem *psys, const char *input, size_t input_len,
                                const char *witness, size_t wit_len, size_t k, IPResult *result);
int ip_collect_statistics(IPProofSystem *psys, const char *input, size_t input_len,
                          const char *witness, size_t wit_len, size_t num_runs, IPStatistics *stats);
double ip_chernoff_bound(size_t k, double per_round_error);
void ip_transcript_init(IPTranscript *transcript);
int ip_transcript_add(IPTranscript *transcript, const IPMessage *msg);
int ip_transcript_to_string(const IPTranscript *transcript, char *buffer, size_t buf_size);
int ip_tape_init(IPRandomTape *tape, size_t num_coins, int is_public);
void ip_tape_free(IPRandomTape *tape);
uint64_t ip_tape_consume(IPRandomTape *tape, size_t k);
void ip_random_seed(uint64_t seed);
int ip_field_init(IPFiniteField *field, uint64_t prime);
void ip_field_free(IPFiniteField *field);
uint64_t ip_field_add(IPFiniteField *field, uint64_t a, uint64_t b);
uint64_t ip_field_sub(IPFiniteField *field, uint64_t a, uint64_t b);
uint64_t ip_field_mul(IPFiniteField *field, uint64_t a, uint64_t b);
uint64_t ip_field_pow(IPFiniteField *field, uint64_t a, uint64_t exp);
uint64_t ip_field_inv(IPFiniteField *field, uint64_t a);
int ip_polynomial_init(IPPolynomial *poly, const uint64_t *coeffs, size_t degree, uint64_t prime);
void ip_polynomial_free(IPPolynomial *poly);
uint64_t ip_polynomial_eval(IPPolynomial *poly, uint64_t x);
int ip_multilinear_init(IPMultilinearExtension *mex, const uint64_t *evals, size_t n, uint64_t prime);
void ip_multilinear_free(IPMultilinearExtension *mex);
uint64_t ip_multilinear_eval(IPMultilinearExtension *mex, const uint64_t *point);
uint64_t ip_multilinear_eval_dp(IPMultilinearExtension *mex, const uint64_t *point);
int ip_multilinear_restrict(IPMultilinearExtension *mex, size_t var_index, uint64_t value,
                            IPMultilinearExtension *out);
uint64_t ip_arithmetize_3cnf_clause(const size_t *clause, size_t clause_len,
                                     const uint64_t *assignment, size_t n,
                                     uint64_t prime);
int ip_arithmetize_3cnf(const size_t **clauses, const size_t *clause_lens,
                         size_t num_clauses, const uint64_t *assignment,
                         size_t n, uint64_t prime, uint64_t *out);
uint64_t ip_sumcheck_compute_sum(const IPMultilinearExtension *mex);
int ip_sumcheck_full(const IPMultilinearExtension *mex,
                     uint64_t claimed_sum, IPRandomTape *tape, int *accepted);
double ip_sumcheck_soundness_error(size_t n, uint64_t field_size, size_t repetitions);

#endif /* MINI_IP_SYSTEM_H */
