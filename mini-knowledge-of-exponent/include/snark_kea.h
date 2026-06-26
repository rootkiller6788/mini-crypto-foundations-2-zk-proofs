/*
 * snark_kea.h — SNARK Construction from Knowledge of Exponent
 *
 * L1 Definitions:
 *   - SNARK: Succinct Non-interactive ARgument of Knowledge
 *     Succinct: proof size O(log |C|) and verification O(|x| + log |C|)
 *     Non-interactive: single message from prover to verifier
 *     Argument: computationally sound (vs. statistically sound proof)
 *     of Knowledge: extractor recovers witness from valid proof (KEA!)
 *
 *   - QAP: Quadratic Arithmetic Program — represents computation as
 *     polynomial equations. QAP = (A_i, B_i, C_i, Z) where:
 *     - A_i(x), B_i(x), C_i(x) are polynomials for each wire i
 *     - Z(x) is the target polynomial (vanishing polynomial)
 *     - Computation is satisfied iff exists witness w such that
 *       (Sum a_i*A_i(x)) * (Sum a_i*B_i(x)) - (Sum a_i*C_i(x))
 *       is divisible by Z(x)
 *
 *   - R1CS: Rank-1 Constraint System
 *     Each constraint: (a·w) * (b·w) = c·w
 *     a, b, c are vectors; w is the witness vector.
 *
 * L2 Core Concepts:
 *   - Information-theoretic proof -> CRS-based argument
 *   - Common Reference String (CRS): trusted setup
 *   - Proving key + verification key derivation
 *   - Knowledge extractor via KEA: if prover succeeds, extractor recovers witness
 *   - Succinctness via pairing-based polynomial commitments
 *
 * L3 Mathematical Structures:
 *   - R1CS matrices A, B, C (sparse representation)
 *   - QAP polynomial interpolation (Lagrange)
 *   - Target polynomial Z(x) = x^n - 1 (for roots of unity)
 *   - Polynomial commitment: g^{f(s)} in the CRS model
 *
 * L4 Theorems:
 *   - QAP reduction: any arithmetic circuit -> QAP (Gennaro et al. 2013)
 *   - GGPR13: NIZK from QAP + KEA + pairings
 *   - Groth16: optimal 3-element proof from QAP
 *
 * L5 Algorithms:
 *   - R1CS -> QAP conversion
 *   - Lagrange interpolation for QAP polynomials
 *   - CRS generation (setup)
 *   - Prover: compute proof pi from witness
 *   - Verifier: check pairing equations
 *
 * L7 Applications:
 *   - Zcash: shielded transactions using Groth16 SNARKs
 *   - Verifiable computation outsourcing
 *   - Blockchain scalability (zk-rollups)
 *
 * References:
 *   - Gennaro, Gentry, Parno, Raykova (2013) "Quadratic Span Programs and
 *     Succinct NIZKs without PCPs" — GGPR13
 *   - Groth (2016) "On the Size of Pairing-based Non-interactive Arguments"
 *     — Groth16 protocol
 *   - Bitansky, Canetti, Chiesa, Tromer (2012) "From Extractable Collision
 *     Resistance to Succinct Non-Interactive Arguments of Knowledge"
 *
 * Courses: Stanford CS255 (Cryptography), Berkeley CS276, MIT 6.875
 */

#ifndef KEA_SNARK_H
#define KEA_SNARK_H

#include "group.h"
#include "pairing.h"
#include "kea.h"
#include <stdlib.h>
#include <stdint.h>

/* ── R1CS ─────────────────────────────────────────────────── */

/*
 * Rank-1 Constraint System.
 * Each constraint: (a * w) * (b * w) = (c * w)
 * where w = (1, x, w_1, ..., w_m) is the witness vector.
 *
 * A, B, C are m x n matrices (m constraints, n witness variables).
 * Row i of A gives the linear combination for the A_i component.
 */
typedef struct {
    int      n_constraints;    /* m: number of constraints */
    int      n_vars;           /* n: total witness length */
    int      n_inputs;         /* number of public inputs */
    /* Sparse matrix representation (COO format) */
    int*     A_rows;           /* row indices */
    int*     A_cols;           /* column indices */
    int      A_nz;             /* number of non-zeros */
    int*     B_rows;
    int*     B_cols;
    int      B_nz;
    int*     C_rows;
    int*     C_cols;
    int      C_nz;
} R1CS;

/* ── QAP ──────────────────────────────────────────────────── */

/*
 * Quadratic Arithmetic Program.
 * Polynomials A_i(x), B_i(x), C_i(x) of degree < m,
 * and target polynomial Z(x) = x^m - 1 (or product of (x - r_i)).
 *
 * The QAP is satisfied iff:
 *   (Sum w_i * A_i(x)) * (Sum w_i * B_i(x)) - (Sum w_i * C_i(x))
 *   = H(x) * Z(x) for some H(x)
 */
typedef struct {
    int       m;               /* number of constraints = degree */
    int       n;               /* number of variables */
    uint64_t  p;               /* field modulus */
    /* Coefficients of A_i, B_i, C_i polynomials (degree < m, n variables) */
    uint64_t** A_coeffs;       /* A_coeffs[i][j] = coeff of x^j in A_i(x) */
    uint64_t** B_coeffs;
    uint64_t** C_coeffs;
    /* Target polynomial Z(x) = Prod_{i=0}^{m-1} (x - r^i) */
    uint64_t*  Z_coeffs;       /* degree m */
    uint64_t   root;           /* primitive m-th root of unity */
    int        initialized;
} QAP;

/* ── R1CS Construction ───────────────────────────────────── */

R1CS* r1cs_create(int n_constraints, int n_vars, int n_inputs);

/* Add a constraint: (a_vec * w) * (b_vec * w) = (c_vec * w) */
int r1cs_add_constraint_A(R1CS* r1cs, int constraint_idx, int var_idx);
int r1cs_add_constraint_B(R1CS* r1cs, int constraint_idx, int var_idx);
int r1cs_add_constraint_C(R1CS* r1cs, int constraint_idx, int var_idx);

/* Build R1CS for simple computations */
R1CS* r1cs_from_polynomial(int degree);          /* w_out = w_in^degree */
R1CS* r1cs_from_multiplication(void);             /* w_out = w_a * w_b */
R1CS* r1cs_from_cubic(void);                      /* w_out = w^3 */

void r1cs_free(R1CS* r1cs);
void r1cs_print(const R1CS* r1cs);

/* ── R1CS -> QAP Conversion ──────────────────────────────── */

/*
 * Convert R1CS to QAP via Lagrange interpolation.
 *
 * L5 Algorithm:
 *   1. Choose m distinct evaluation points r_1, ..., r_m (powers of primitive root)
 *   2. For each variable i, interpolate A_i(x) through the points:
 *        A_i(r_j) = A[j][i] (the A-matrix entry)
 *   3. Same for B_i, C_i
 *   4. Target polynomial: Z(x) = Prod_{j=1}^{m} (x - r_j)
 *
 * Complexity: O(m^3) naive, O(m log^2 m) with FFT.
 * Reference: Gennaro et al. (2013) — QSP paper, §2
 */
QAP* qap_from_r1cs(const R1CS* r1cs, uint64_t field_prime);

/* Create QAP directly from coefficients */
QAP* qap_create(int m, int n, uint64_t p, uint64_t primitive_root);

void qap_free(QAP* qap);
void qap_print(const QAP* qap);

/* Evaluate QAP polynomial at a point */
uint64_t qap_eval_A(const QAP* qap, int var_idx, uint64_t x);
uint64_t qap_eval_B(const QAP* qap, int var_idx, uint64_t x);
uint64_t qap_eval_C(const QAP* qap, int var_idx, uint64_t x);

/* Evaluate the target polynomial Z(x) at a point */
uint64_t qap_eval_Z(const QAP* qap, uint64_t x);

/* ── GGPR13 / Groth16 Setup (CRS Generation) ─────────────── */

/*
 * Common Reference String for Groth16.
 * Generated in a trusted setup phase.
 *
 * Proving key (pk):
 *   [alpha]_1, [beta]_1, [delta]_1
 *   [x]_1 = {[x^i * delta]_1}_{i=0}^{n-1}  (A polynomial powers)
 *   [A_i(tau)]_1, [B_i(tau)]_2, [B_i(tau)]_1  (for each variable)
 *   [K_i(tau)]_1 = (A_i(tau)*beta + B_i(tau)*alpha + C_i(tau))/delta
 *   [H(tau)^i]_1 (for quotient polynomial powers)
 *
 * Verification key (vk):
 *   [alpha]_1, [beta]_2, [gamma]_2, [delta]_2
 *   [A_i(tau)]_1 for i in public_inputs
 */

typedef struct {
    /* Toxic waste (must be destroyed after setup!) */
    uint64_t tau;        /* secret evaluation point */
    uint64_t alpha;      /* KEA secret for A-B consistency */
    uint64_t beta;       /* KEA secret for B-C consistency */
    uint64_t gamma;      /* for public input separation */
    uint64_t delta;      /* for C polynomial hiding */
    /* Derived values */
    int      n_vars;     /* total witness length */
    int      n_inputs;   /* public input count */
    uint64_t field_prime;
} Groth16ToxicWaste;

typedef struct {
    /* Proving key elements (G1 unless noted) */
    GroupElement** A_poly;     /* [A_i(tau)]_1 */
    GroupElement** B1_poly;    /* [B_i(tau)]_1 */
    GroupElement** B2_poly;    /* [B_i(tau)]_2 */
    GroupElement** K_poly;     /* [K_i(tau)]_1 = (beta*A_i + alpha*B_i + C_i)/delta */
    GroupElement*  alpha_g1;   /* [alpha]_1 */
    GroupElement*  beta_g1;    /* [beta]_1 */
    GroupElement*  delta_g1;   /* [delta]_1 */
    GroupElement*  delta_g2;   /* [delta]_2 */
    /* Powers of tau for H polynomial */
    GroupElement** tau_powers_g1;
    int            n_tau_powers;
} Groth16ProvingKey;

typedef struct {
    GroupElement*  alpha_g1;   /* [alpha]_1 */
    GroupElement*  beta_g2;    /* [beta]_2 */
    GroupElement*  gamma_g2;   /* [gamma]_2 */
    GroupElement*  delta_g2;   /* [delta]_2 */
    /* Public input encodings */
    GroupElement** ic;         /* [A_i(tau)]_1 for public inputs */
    int            n_ic;
} Groth16VerificationKey;

/* Groth16 setup (trusted setup phase) */
int groth16_setup(const QAP* qap, const BilinearPairing* bp,
                  Groth16ToxicWaste** waste_out,
                  Groth16ProvingKey** pk_out,
                  Groth16VerificationKey** vk_out);

void groth16_toxic_waste_free(Groth16ToxicWaste* w);
void groth16_pk_free(Groth16ProvingKey* pk);
void groth16_vk_free(Groth16VerificationKey* vk);

/* ── Groth16 Prover ──────────────────────────────────────── */

/*
 * Groth16 proof: 3 group elements (2 in G1, 1 in G2).
 * pi = ([A]_1, [B]_2, [C]_1)
 *
 * L5 Algorithm:
 *   A = alpha + Sum_{i=0}^{l} a_i*A_i(tau) + r*delta
 *   B = beta + Sum_{i=0}^{l} a_i*B_i(tau) + s*delta
 *   C = (Sum_{i=l+1}^{m} a_i*(beta*A_i + alpha*B_i + C_i)/delta
 *        + H(tau) + A*s + B*r - r*s*delta) / delta
 *   (with blinding factors r, s)
 */

typedef struct {
    GroupElement* A_g1;   /* proof element A in G1 */
    GroupElement* B_g2;   /* proof element B in G2 */
    GroupElement* C_g1;   /* proof element C in G1 */
} Groth16Proof;

Groth16Proof* groth16_prove(const Groth16ProvingKey* pk,
                            const QAP* qap,
                            const uint64_t* witness,
                            const BilinearPairing* bp);

void groth16_proof_free(Groth16Proof* pf);

/* ── Groth16 Verifier ────────────────────────────────────── */

/*
 * Verifier checks:
 *   e(A, B) = e(alpha, beta) * e(Sum_{i=0}^{l} a_i*[A_i(tau)]_1, gamma)
 *            * e(C, delta)
 *
 * L5: This is 1 pairing equation (3 pairings total, optimized to 1 using
 * the product pairing technique to combine alpha*beta check).
 *
 * Complexity: O(l) group operations in G1 + 3 pairings
 */
int groth16_verify(const Groth16VerificationKey* vk,
                   const Groth16Proof* pf,
                   const uint64_t* public_inputs,
                   const BilinearPairing* bp);

/* ── KEA in Groth16 ──────────────────────────────────────── */

/*
 * Demonstrate how KEA is used in Groth16:
 *
 * The setup includes [alpha]_1, [beta]_1, [beta]_2, [delta]_1, etc.
 * The prover computes:
 *   - A includes [Sum a_i*A_i(tau)]_1, which must be computed "honestly"
 *   - The verification pairing e(A, B) = ... ensures that A and B are
 *     consistent (both use the same witness).
 *   - KEA ensures the prover cannot create a valid A without knowing
 *     the witness coefficients a_i.
 *
 * Specifically:
 *   - The CRS contains [K_i(tau)]_1 = (beta*A_i + alpha*B_i + C_i)/delta
 *   - The prover computes C = Sum a_i*K_i + H + A*s + B*r - r*s*delta
 *   - KEA ensures that A was computed using A_i(tau) values from the CRS
 *   - Without KEA, a malicious prover could compute A' = g^{arbitrary}
 *     and find matching B, C to satisfy the verification equation
 */
void groth16_kea_demonstration(const BilinearPairing* bp);

/* ── Witness Extraction (KEA-based) ──────────────────────── */

/*
 * The knowledge extractor for Groth16:
 * Given a valid proof pi = (A, B, C) and the CRS:
 *   1. Since A = Sum a_i*[A_i(tau)]_1 + r*[delta]_1
 *   2. By KEA, the extractor can recover coefficients a_i
 *   3. These coefficients form a satisfying witness
 *
 * This function simulates extraction in the generic group model
 * by working backward from group element representations.
 */
int groth16_extract_witness(const Groth16Proof* pf,
                            const Groth16ProvingKey* pk,
                            const QAP* qap,
                            uint64_t* witness_out);

/* ── SNARK Security Properties ────────────────────────────── */

/*
 * Verify completeness: honest prover always convinces verifier.
 */
int snark_check_completeness(const QAP* qap, const BilinearPairing* bp,
                              const uint64_t* witness);

/*
 * Verify (computational) soundness: no polynomial-time adversary
 * can create a valid proof for a false statement.
 * (Tested via random search for invalid proofs.)
 */
int snark_check_soundness_heuristic(const QAP* qap, const BilinearPairing* bp,
                                     int trials);

/*
 * Verify zero-knowledge: the proof reveals nothing about the witness.
 * Uses simulation-based proof: creates a simulated proof WITHOUT witness
 * and shows it is valid and indistinguishable from real proofs.
 */
void snark_check_zero_knowledge(const QAP* qap, const BilinearPairing* bp,
                                 const uint64_t* witness);

/*
 * Groth16 Zero-Knowledge Simulator.
 *
 * L4 Theorem: Creates a valid Groth16 proof WITHOUT knowing a satisfying
 * witness, using only the trapdoor (alpha, beta, gamma, delta, tau) from
 * the trusted setup. The simulated proof is identically distributed to
 * a real proof → perfect zero-knowledge in the CRS model.
 *
 * Algorithm: pick random A_val, B_val ∈ Z_r; compute C_val such that
 * the pairing equation holds: C_val = (A_val·B_val - α·β)/δ
 *
 * Reference: Groth (2016), Theorem 3.2
 */
Groth16Proof* groth16_simulate_proof(const Groth16ToxicWaste* waste,
                                      const QAP* qap,
                                      const BilinearPairing* bp);

/* ── End-to-End SNARK Demo ───────────────────────────────── */

/*
 * Run a complete SNARK pipeline:
 *   1. Define computation (R1CS)
 *   2. Convert to QAP
 *   3. Setup (CRS generation)
 *   4. Prove (with witness)
 *   5. Verify
 *   6. Extract witness from proof
 *
 * Returns 1 if all steps succeed.
 */
int snark_end_to_end_demo(void);

/* ── Advanced / Batch ─────────────────────────────────────── */

/*
 * groth16_batch_verify — Batch-verify multiple Groth16 proofs.
 *
 * L8 Advanced Topic: Reduces n proofs verification from O(n) pairings
 * to O(1) using random linear combination. Essential for:
 *   - zk-Rollups: verifying hundreds of L2 transactions in one L1 check
 *   - Blockchain validators: batching SNARK verifications
 *
 * Algorithm: Combine verification equations using random challenges
 * c_i: ∏ e(A_i, B_i)^{c_i} = e(α,β)^{Σc_i} · e(∏C_i^{c_i}, δ)
 *
 * Soundness error: 1/r per batch (statistical, for prime order r)
 * Reference: Blazy, Fuchsbauer, Izabachene et al. (2013)
 */
int groth16_batch_verify(const Groth16VerificationKey* vk,
                         Groth16Proof** proofs,
                         const uint64_t** public_inputs,
                         int n_proofs,
                         const BilinearPairing* bp);

/* ── QAP Utilities ────────────────────────────────────────── */

/*
 * qap_verify_satisfiability — Verify that a witness satisfies a QAP.
 *
 * L6 Canonical Problem: Given QAP (A_i, B_i, C_i, Z) and witness w,
 * verify (Σ w_i·A_i(x))(Σ w_i·B_i(x)) ≡ (Σ w_i·C_i(x)) mod Z(x).
 *
 * Uses Schwartz-Zippel lemma: evaluates at random point x0;
 * if equation holds at x0, it holds everywhere with high probability.
 *
 * Error probability ≤ deg(P)/p (negligible for cryptographic-size p).
 * Reference: GGPR13, Section 2
 */
int qap_verify_satisfiability(const QAP* qap, const uint64_t* witness,
                               const BilinearPairing* bp);

/*
 * qap_polynomial_mul — Multiply two polynomials modulo prime p.
 *
 * L5 Algorithm: Naive convolution O(da·db). For production use,
 * FFT/NTT achieves O(n log n). Output array c must have size ≥ da+db+1.
 *
 * Reference: Knuth TAOCP, Vol. 2, §4.6.4
 */
void qap_polynomial_mul(const uint64_t* a, int da,
                         const uint64_t* b, int db,
                         uint64_t* c, uint64_t p);

/*
 * qap_check_witness_consistency — Verify that A and B encodings
 * use the same witness. This is the property enforced by KEA
 * in Groth16's CRS structure.
 *
 * L4: Without KEA, a malicious prover could use different linear
 * combinations for A_i(tau) and B_i(tau) and still satisfy the
 * pairing equation. KEA binds both to the same witness.
 */
int qap_check_witness_consistency(const uint64_t* witness_A,
                                   const uint64_t* witness_B,
                                   int n_vars);

#endif /* KEA_SNARK_H */