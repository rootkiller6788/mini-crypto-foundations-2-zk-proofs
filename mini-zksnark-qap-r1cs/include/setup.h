/* setup.h — trusted setup and multi-party computation for SNARKs
 *
 * Implements the Powers-of-Tau ceremony and CRS generation for zkSNARKs.
 * The trusted setup creates a Common Reference String that all provers
 * and verifiers use. Security depends on the "toxic waste" (random secrets
 * τ, α, β, γ, δ) being destroyed after setup.
 *
 * Key concepts:
 *   - Trusted Setup: one-time generation of structured reference string
 *   - Toxic Waste: secret values that must be destroyed
 *   - MPC Ceremony: N parties sequentially contribute randomness,
 *     only 1 honest party needed for security
 *   - Powers of Tau: CRS containing g^{τ^i} for i=0..d
 *   - Updatable CRS: anyone can verify and extend existing CRS
 *   - Universal setup: CRS not tied to specific circuit
 *
 * References:
 *   - Bowe, Gabizon, Miers (2017) "Scalable Multi-party Computation for
 *     zk-SNARK Parameters in the Random Beacon Model"
 *   - Groth, Kohlweiss, Maller, Meiklejohn, Miers (2018) "Updatable and
 *     Universal Common Reference Strings with Applications to zk-SNARKs"
 *   - Ben-Sasson, Chiesa, Green, Tromer, Virza (2015) "Secure Sampling
 *     of Public Parameters for Succinct Zero Knowledge Proofs"
 */
#ifndef SETUP_H
#define SETUP_H
#include "dlog.h"
#include "qap.h"
#include "field.h"

/* ─── Phase 1: Powers of Tau ─── */
/* Phase 1 is circuit-independent — creates a universal CRS */
typedef struct {
    G1Point* tau_powers_g1;    /* {G^{τ^i}}_{i=0..d} */
    G2Point* tau_powers_g2;    /* {H^{τ^i}}_{i=0..d} */
    G2Point  tau_g2;           /* H^τ */
    G1Point  tau_g1;           /* G^τ */
    int      degree;           /* max degree d */
    int      num_participants; /* number of MPC participants */
} PowersOfTau;

/* ─── Phase 1 operations ─── */
/* Initialize Phase 1 CRS with a known τ (for testing).
   In production, use mpc_contribute(). */
PowersOfTau* pot_create(const fe_t tau, int degree, GroupParams* gp);
void         pot_free(PowersOfTau* pot);

/* Simulate one MPC contribution: given current CRS and new secret σ,
   produces updated CRS: (g^{τ·σ})^i = g^{(τ·σ)^i} */
int  mpc_contribute(PowersOfTau* pot, const fe_t sigma);

/* Verify a Phase 1 contribution: check consistency of G1/G2 powers */
int  pot_verify(const PowersOfTau* pot);

/* Extract Lagrange basis from Powers of Tau for a given domain */
int  pot_prepare_lagrange(G1Point* lagrange_basis, const PowersOfTau* pot,
                          const fe_t* domain, int domain_size);

/* ─── Phase 2: Circuit-specific setup ─── */
/* Phase 2 creates the proving key and verification key for a specific QAP */
typedef struct {
    G1Point* A_query;     /* {G^{A_i(τ)}} */
    G2Point* B_query;     /* {H^{B_i(τ)}} */
    G1Point* C_query;     /* {G^{C_i(τ)}} */
    G1Point* H_query;     /* {G^{τ^i·Z(τ)}} for H polynomial */
    G1Point  alpha_g1;
    G2Point  beta_g2;
    G1Point  delta_g1;
    G2Point  delta_g2;
    G2Point  gamma_g2;
    int      n_vars;
    int      n_pub_inputs;
} CircuitCRS;

/* Create circuit-specific CRS from Phase 1 CRS and QAP */
CircuitCRS* circuit_crs_create(const PowersOfTau* pot, const QAP* qap,
                               const fe_t alpha, const fe_t beta,
                               const fe_t gamma, const fe_t delta,
                               GroupParams* gp);
void        circuit_crs_free(CircuitCRS* ccrs);

/* ─── Full MPC ceremony simulation ─── */
typedef struct {
    fe_t* contributions;   /* list of secret contributions */
    int   n_contributions;
    int   capacity;
} MPCCeremony;

MPCCeremony* mpc_ceremony_create(int expected_participants);
void         mpc_ceremony_free(MPCCeremony* c);
int          mpc_ceremony_add_participant(MPCCeremony* c, const fe_t secret);
int          mpc_ceremony_is_secure(const MPCCeremony* c);
void         mpc_ceremony_print(const MPCCeremony* c);

#endif /* SETUP_H */
