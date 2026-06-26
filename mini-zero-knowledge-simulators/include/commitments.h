#ifndef COMMITMENTS_H
#define COMMITMENTS_H

#include "zk_simulator.h"

/*
 * mini-zero-knowledge-simulators -- commitments.h
 * Commitment schemes: the digital envelope for ZK proofs.
 * Covers L2.7 (Commitments in ZK) and L3 (Mathematical Structures).
 *
 * A commitment scheme consists of two phases:
 *   1. Commit:  sender(C) -> receiver. C = Com(m; r) hides m.
 *   2. Reveal:  sender -> receiver. Opens C to reveal m.
 *
 * Security:
 *   Hiding:   from C alone, receiver learns nothing about m.
 *   Binding:  sender cannot open C to m' != m with non-negligible prob.
 *
 * Flavour combinations:
 *   Perfectly hiding + Computationally binding  (Pedersen)
 *   Computationally hiding + Perfectly binding  (ElGamal-based)
 *   Perfectly hiding + Perfectly binding        (IMPOSSIBLE)
 *
 * Reference: Goldreich (2004) Foundations of Cryptography, Vol. 1, Ch. 4
 *            Pedersen (1991) "Non-Interactive and Information-Theoretic
 *              Secure Verifiable Secret Sharing"
 * Courses: MIT 6.875, Stanford CS355, Berkeley CS276
 */

/* ================================================================
 * L2.7 -- Commitment Schemes in ZK
 * ================================================================ */

/*
 * Generic commitment structure.
 * value: the committed message (mod q for DLog-based schemes)
 * randomness: the random nonce used for hiding
 * commitment: Com(value; randomness)
 */
typedef struct {
    uint64_t value;        /* the committed message */
    uint64_t randomness;   /* random nonce (blinding factor) */
    uint64_t commitment;   /* Com(value; randomness) */
} commitment_t;

/*
 * L3.1 -- Pedersen Commitment
 *
 * Com(m; r) = g^m * h^r mod p
 *
 * where g, h are generators of a group of order q, and
 * log_g(h) is unknown (under DLog assumption).
 *
 * Perfectly hiding: For any m, there exists r' s.t. C = g^m * h^r'.
 *   Proof: r' = r + (m1 - m2)/log_g(h). Since log_g(h) is
 *   undefined for the committer, r' is a valid opening.
 *
 * Computationally binding: To open to m' != m, need to find
 *   (m', r') s.t. g^m * h^r = g^{m'} * h^{r'}, which implies
 *   g^{m-m'} = h^{r'-r} => log_g(h) = (m-m')/(r'-r), solving DLog.
 *
 * Homomorphic: Com(m1;r1) * Com(m2;r2) = Com(m1+m2; r1+r2)
 * This property is crucial for many ZK constructions.
 */
typedef struct {
    uint64_t m;     /* actual message (to be committed) */
    uint64_t r;     /* blinding factor */
    uint64_t C;     /* Com(m;r) = g^m * h^r mod p */
    const group_params_t *gp;
} pedersen_commitment_t;

void pedersen_commit(pedersen_commitment_t *pc,
                      uint64_t m, const random_tape_t *rng,
                      const group_params_t *gp);
int  pedersen_open(const pedersen_commitment_t *pc,
                    uint64_t *m_out, uint64_t *r_out);
int  pedersen_verify_opening(uint64_t C, uint64_t m, uint64_t r,
                              const group_params_t *gp);
/* Homomorphic addition: C1 * C2 = Com(m1+m2; r1+r2) */
void pedersen_homomorphic_add(const pedersen_commitment_t *pc1,
                               const pedersen_commitment_t *pc2,
                               pedersen_commitment_t *out,
                               const group_params_t *gp);

/*
 * L3.2 -- ElGamal-Based Commitment
 *
 * Com(m; r) = (g^r mod p,  m * h^r mod p)
 *            = (A, B)
 *
 * Computationally hiding: DLog assumption, A leaks nothing about r.
 * Perfectly binding: given A = g^r, r is uniquely determined,
 *   so B/m = h^r is fixed.
 *
 * This is essentially ElGamal encryption where the receiver
 * doesn't have the secret key. The commitment is opened by
 * revealing r (which also reveals m since m = B / h^r).
 */
typedef struct {
    uint64_t m;     /* message */
    uint64_t r;     /* randomness */
    uint64_t A;     /* g^r mod p */
    uint64_t B;     /* m * h^r mod p */
    const group_params_t *gp;
} elgamal_commitment_t;

void elgamal_commit(elgamal_commitment_t *ec,
                     uint64_t m, const random_tape_t *rng,
                     const group_params_t *gp);
int  elgamal_open(const elgamal_commitment_t *ec,
                   uint64_t *m_out, uint64_t *r_out);
int  elgamal_verify_opening(uint64_t A, uint64_t B,
                              uint64_t m, uint64_t r,
                              const group_params_t *gp);

/*
 * L3.3 -- Bit Commitment (for ZK protocols)
 *
 * A bit commitment commits to a single bit b in {0,1}.
 * Used in GMW-style ZK proofs for NP.
 *
 * Construction from Pedersen:
 *   Com(b; r) = g^b * h^r
 *
 * Key property for ZK: the simulator can open to either 0 or 1
 * (equivocation) if it controls h (trapdoor).
 */
typedef struct {
    int        bit;    /* 0 or 1 */
    uint64_t   r;      /* randomness */
    uint64_t   C;      /* g^bit * h^r mod p */
    const group_params_t *gp;
} bit_commitment_t;

void bit_commit(bit_commitment_t *bc, int bit,
                 const random_tape_t *rng,
                 const group_params_t *gp);
int  bit_verify_opening(const bit_commitment_t *bc);

/*
 * L3.4 -- String Commitment
 *
 * Commit to a byte string s of length len by committing to
 * each byte's representation as an integer mod q.
 *
 * For short strings (len <= 16), each byte is committed separately.
 * The commitment is a concatenation of individual commitments.
 * Opening reveals the string byte-by-byte.
 */
#define MAX_STRING_LEN 16

typedef struct {
    uint8_t    data[MAX_STRING_LEN];
    size_t     len;
    uint64_t   randomness[MAX_STRING_LEN];
    uint64_t   commitments[MAX_STRING_LEN];
    const group_params_t *gp;
} string_commitment_t;

void string_commit(string_commitment_t *sc,
                    const uint8_t *data, size_t len,
                    const random_tape_t *rng,
                    const group_params_t *gp);
int  string_open(const string_commitment_t *sc,
                  uint8_t *data_out, size_t *len_out);
int  string_verify_opening(const string_commitment_t *sc);

/*
 * L3.5 -- Trapdoor Commitments
 *
 * A trapdoor commitment has a trapdoor td s.t. anyone knowing td
 * can open the commitment to any value (equivocation).
 *
 * This is essential for ZK simulation: the simulator knows the
 * trapdoor and can equivocate commitments, making the simulation
 * indistinguishable from real protocol executions.
 *
 * Pedersen with known log_g(h): if you know t = log_g(h),
 * then Com(m;r) = g^{m + t*r} = g^{m' + t*r'} for chosen (m',r').
 * But in real Pedersen, log_g(h) is UNKNOWN (trusted setup).
 *
 * For simulation purposes, the simulator is often given a
 * trapdoor by the CRS model or uses rewinding to achieve
 * the same effect.
 */
typedef struct {
    uint64_t trapdoor;  /* log_g(h) -- usable for equivocation */
    const group_params_t *gp;
} trapdoor_t;

void trapdoor_equivocate(const trapdoor_t *td,
                          uint64_t C, uint64_t old_m, uint64_t old_r,
                          uint64_t new_m,
                          uint64_t *new_r_out);

#endif /* COMMITMENTS_H */

