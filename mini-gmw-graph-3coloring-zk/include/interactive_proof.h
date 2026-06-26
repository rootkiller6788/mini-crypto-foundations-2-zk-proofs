/*
 * interactive_proof.h - Interactive Proof System Framework
 *
 * L1 Definitions:
 *   - Interactive Proof System (IP): pair of interactive Turing machines (P,V)
 *     P = prover (unbounded computational power)
 *     V = verifier (probabilistic polynomial-time)
 *   - (P,V) is an IP for language L if:
 *     Completeness: x in L => Pr[(P,V)(x) = 1] >= 2/3
 *     Soundness:    x not in L => forall P*, Pr[(P*,V)(x) = 1] <= 1/3
 *
 * L2 Core Concepts:
 *   - IP = PSPACE (Shamir 1992, Lund-Fortnow-Karloff-Nisan 1992)
 *   - Arthur-Merlin (AM) protocols: public coins, MA, AM, AM[k]
 *   - GMW protocol: computational ZK IP for all NP
 *
 * L3 Mathematical Structures:
 *   - IP protocol as k-round alternating message exchange
 *   - Verifier randomness: polynomial-length random string
 *   - Completeness / Soundness error bounds
 *
 * L4 Fundamental Theorems:
 *   - IP = PSPACE (Shamir 1992)
 *   - GMW Theorem: NP subset CZK (computational ZK)
 *   - IP[k] = AM[k+2] (Goldwasser-Sipser 1986)
 *
 * Reference:
 *   Goldwasser, Micali, Rackoff (1985) - The Knowledge Complexity of IP Systems
 *   Arora-Barak (2009) - Computational Complexity, Ch.8
 *   Goldreich (2004) - FOC I, Ch.4
 *
 * Courses: MIT 6.876, Stanford CS254, CMU 15-855
 */
#ifndef INTERACTIVE_PROOF_H
#define INTERACTIVE_PROOF_H

#include <stdlib.h>
#include <stdint.h>

/* -- IP Message Types -------------------------------------- */
typedef enum {
    IP_MSG_PROVER_TO_VERIFIER = 0,
    IP_MSG_VERIFIER_TO_PROVER = 1,
    IP_MSG_FINAL_ACCEPT = 2,
    IP_MSG_FINAL_REJECT = 3
} IPMessageType;

typedef struct {
    IPMessageType type;
    int           round;
    uint8_t*      data;
    size_t        data_len;
} IPMessage;

/* -- IP System Description -------------------------------- */
typedef struct {
    char*   language_name;
    int     total_rounds;
    int     soundness_error_per_round;  /* numerator, denominator stored separately */
    double  target_soundness;
    /* Protocol parameters */
    int     prover_unbounded;   /* 1 = computationally unbounded P */
    int     verifier_randomized; /* 1 = probabilistic V */
    int     public_coins;       /* 1 = Arthur-Merlin style */
    int     perfect_completeness; /* 1 = completeness = 1 (no error) */
} IPSystem;

/* -- Completeness & Soundness ----------------------------- */
/*
 * Completeness check: verify that honest prover convinces verifier
 * with probability >= completeness_threshold.
 */
int ip_test_completeness(IPSystem* sys, int trials, double threshold);

/*
 * Soundness check: verify that no cheating prover strategy
 * convinces verifier with probability > soundness_error.
 * (Simulated by trying random false statements.)
 */
int ip_test_soundness(IPSystem* sys, int trials, double error_bound);

/*
 * Estimate actual completeness/soundness from empirical trials.
 */
double ip_estimate_accept_probability(IPSystem* sys, int trials, int honest);

/* -- IP Complexity Classes --------------------------------- */
typedef enum {
    IP_CLASS_IP,        /* general interactive proofs */
    IP_CLASS_AM,        /* Arthur-Merlin (public coins) */
    IP_CLASS_MA,        /* Merlin-Arthur (1 round, M then A) */
    IP_CLASS_PCP,       /* Probabilistically Checkable Proofs */
    IP_CLASS_ZK,        /* Zero-Knowledge proofs */
    IP_CLASS_NIZK,      /* Non-Interactive ZK */
    IP_CLASS_SZK        /* Statistical ZK */
} IPClass;

typedef struct {
    IPClass class_type;
    int     round_complexity;   /* number of rounds */
    int     communication_bits; /* total bits exchanged */
    double  soundness;
    double  completeness;
    char*   description;
} IPComplexityInfo;

/* -- Round Structure -------------------------------------- */
typedef struct {
    int     round_number;
    int     prover_message_bits;
    int     verifier_random_bits;
    int     verifier_message_bits;
    int     is_last_round;
} IPRoundSpec;

/* -- IP Construction -------------------------------------- */
IPSystem*       ip_system_create(const char* name, int rounds);
void            ip_system_free(IPSystem* sys);
IPMessage*      ip_message_create(IPMessageType type, int round, size_t data_len);
void            ip_message_free(IPMessage* msg);
IPRoundSpec*    ip_round_spec_create(int number);
void            ip_round_spec_free(IPRoundSpec* spec);

/* -- Protocol Analysis ------------------------------------ */
/*
 * Compute required number of sequential repetitions to achieve
 * target soundness error from per-round error epsilon.
 * k = ceil(log(target_error) / log(epsilon))
 */
int ip_sequential_repetitions(double per_round_error, double target_error);

/*
 * Compute soundness error after k sequential repetitions.
 * error_k = epsilon^k
 */
double ip_repeated_soundness(double per_round_error, int k);

/*
 * Compute total communication complexity for a given round structure.
 * Returns total bits exchanged.
 */
int ip_communication_complexity(const IPRoundSpec* rounds, int n_rounds);

/* -- Proof System Verification ----------------------------- */
int ip_verify_completeness_proof(const IPSystem* sys);
int ip_verify_soundness_proof(const IPSystem* sys);

void ip_print_system_info(const IPSystem* sys);
void ip_print_complexity_info(const IPComplexityInfo* info);

#endif
