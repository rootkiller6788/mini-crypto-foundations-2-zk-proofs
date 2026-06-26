/* snark.h — zkSNARK prover and verifier
 *
 * Implements the Groth16 proving system, the most widely deployed zkSNARK.
 * The protocol works in three phases:
 *   1. Setup(λ, C) → (pk, vk)   — one-time trusted setup
 *   2. Prove(pk, x, w) → π       — prover with witness
 *   3. Verify(vk, x, π) → 0/1    — verifier with only statement
 *
 * Groth16 protocol (simplified):
 *   Setup: Choose τ, α, β, γ, δ ∈ F_p randomly
 *     pk = (G^α, G^β, G^δ, H^β, H^γ, H^δ,
 *           {G^{w_i(τ)}}_{i=0..ℓ}, {H^{w_i(τ)}}_{i=0..ℓ},
 *           {G^{(β·A_i(τ) + α·B_i(τ) + C_i(τ))/δ}}_{i=ℓ+1..m})
 *     vk = (G^α, G^β, G^γ, G^δ, H^γ, H^δ, {G^{w_i(τ)}}_{i=0..ℓ})
 *
 *   Prove:
 *     r, s ← F_p randomly (or r=s=0 for no ZK)
 *     A = G^α + ∑_{i=0..m} w_i · G^{A_i(τ)} + r·G^δ
 *     B = H^β + ∑_{i=0..m} w_i · H^{B_i(τ)} + s·H^δ
 *     C = ∑_{i=ℓ+1..m} w_i · G^{(β·A_i(τ)+α·B_i(τ)+C_i(τ))/δ}
 *         + G^{H(τ)·Z(τ)/δ} + s·A + r·B - r·s·G^δ
 *
 *   Verify:
 *     e(A, B) = e(G^α, H^β) · e(∑_{i=0..ℓ} w_i·G^{w_i(τ)}, H^γ) · e(C, H^δ)
 *
 * References:
 *   - Groth (2016) "On the Size of Pairing-based Non-interactive Arguments"
 *   - Bowe & Gabizon (2017) "Making Groth's zk-SNARK Simulation Extractable"
 *   - Ben-Sasson et al. (2013) "SNARKs for C" (Pinocchio)
 */
#ifndef SNARK_H
#define SNARK_H
#include "qap.h"
#include "dlog.h"
#include "r1cs.h"

/* ─── Proving key ─── */
typedef struct {
    G1Point alpha_g1;       /* G^α */
    G1Point beta_g1;        /* G^β */
    G1Point delta_g1;       /* G^δ */
    G2Point beta_g2;        /* H^β */
    G2Point gamma_g2;       /* H^γ */
    G2Point delta_g2;       /* H^δ */
    G1Point* abc_rest_g1;   /* {G^{(β·A_i(τ)+α·B_i(τ)+C_i(τ))/δ}}_{i=ℓ+1..m} */
    G1Point* A_query_g1;    /* {G^{A_i(τ)}}_{i=0..m} */
    G2Point* B_query_g2;    /* {H^{B_i(τ)}}_{i=0..m} */
    int n_vars;             /* total variables */
    int n_pub_inputs;       /* number of public inputs */
} ProvingKey;

/* ─── Verification key ─── */
typedef struct {
    G1Point alpha_g1;
    G1Point beta_g1;
    G1Point gamma_g1;
    G1Point delta_g1;
    G2Point gamma_g2;
    G2Point delta_g2;
    G1Point* IC;            /* {G^{w_i(τ)}}_{i=0..ℓ} — input correctness */
    int n_pub_inputs;
} VerifyingKey;

/* ─── Proof ─── */
typedef struct {
    G1Point A;    /* G^α + witness_A(τ) + r·G^δ */
    G2Point B;    /* H^β + witness_B(τ) + s·H^δ */
    G1Point C;    /* witness_C(τ) + correction_terms */
} Proof;

/* ─── Setup ─── */
/* Generates proving key and verification key from a QAP.
   In production, these toxic values (τ, α, β, γ, δ) are computed via
   multi-party computation and destroyed. Here we use known values for
   educational purposes. */
int  snark_setup(ProvingKey* pk, VerifyingKey* vk,
                 const QAP* qap, const GroupParams* gp,
                 const fe_t tau, const fe_t alpha, const fe_t beta,
                 const fe_t gamma, const fe_t delta);

void pk_free(ProvingKey* pk);
void vk_free(VerifyingKey* vk);

/* ─── Prove ─── */
/* Generates a proof that the prover knows a witness w satisfying the circuit.
   If zk is non-zero, adds random blinding for zero-knowledge. */
int  snark_prove(Proof* proof, const ProvingKey* pk, const QAP* qap,
                 const fe_t* witness, const GroupParams* gp,
                 int zk);

/* ─── Verify ─── */
/* Checks: e(A, B) = e(G^α, H^β) · e(Σ input, H^γ) · e(C, H^δ)
   Returns 1 if proof is valid, 0 otherwise. */
int  snark_verify(const Proof* proof, const VerifyingKey* vk,
                  const fe_t* public_inputs, const GroupParams* gp);

/* ─── Serialization (for interoperability) ─── */
int  proof_to_bytes(uint8_t* buf, int buf_len, const Proof* proof);
int  proof_from_bytes(Proof* proof, const uint8_t* buf, int buf_len);

/* ─── Full pipeline convenience ─── */
/* R1CS → QAP → Setup → Prove → Verify in one call chain */
typedef struct {
    R1CS*         r1cs;
    QAP*          qap;
    ProvingKey    pk;
    VerifyingKey  vk;
    GroupParams*  gp;
    int           initialized;
} SnarkPipeline;

SnarkPipeline* snark_pipeline_create(void);
int  snark_pipeline_setup(SnarkPipeline* sp, const R1CS* r1cs,
                          const fe_t tau, const fe_t alpha, const fe_t beta,
                          const fe_t gamma, const fe_t delta,
                          const FieldParams* fp);
int  snark_pipeline_prove(Proof* proof, const SnarkPipeline* sp,
                          const fe_t* witness, int zk);
int  snark_pipeline_verify(const Proof* proof, const SnarkPipeline* sp,
                           const fe_t* public_inputs);
void snark_pipeline_free(SnarkPipeline* sp);

/* ─── Socratic question generators ─── */
/* These functions create test instances that demonstrate specific
   SNARK properties (completeness, soundness, zero-knowledge). */
int  snark_demo_completeness(void);    /* honest proof → verify passes */
int  snark_demo_soundness(void);       /* false statement → verify fails */
int  snark_demo_zero_knowledge(void);  /* proof reveals nothing about witness */

#endif /* SNARK_H */
