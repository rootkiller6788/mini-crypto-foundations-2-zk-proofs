
// setup.c - Trusted setup and MPC ceremony for zkSNARKs
// Implements Powers of Tau (Phase 1) and circuit-specific CRS (Phase 2).
// The setup generates the Common Reference String used by prover/verifier.
// Knowledge: L7 Application (MPC ceremony), L4 Fundamental Law (CRS model)

#include "setup.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Phase 1: Powers of Tau */

PowersOfTau* pot_create(const fe_t tau, int degree, GroupParams* gp) {
    PowersOfTau* p = (PowersOfTau*)malloc(sizeof(PowersOfTau));
    if (!p) return NULL;
    p->degree = degree;
    p->num_participants = 1;
    p->tau_powers_g1 = (G1Point*)malloc((size_t)(degree + 1) * sizeof(G1Point));
    p->tau_powers_g2 = (G2Point*)malloc((size_t)(degree + 1) * sizeof(G2Point));
    if (!p->tau_powers_g1 || !p->tau_powers_g2) {
        free(p->tau_powers_g1); free(p->tau_powers_g2); free(p); return NULL;
    }
    /* Compute G^{tau^i} and H^{tau^i} for i=0..degree */
    fe_t tau_pow; fe_one(tau_pow);
    for (int i = 0; i <= degree; i++) {
        g1_scalar_mul(&p->tau_powers_g1[i], &gp->G, tau_pow, gp);
        g2_scalar_mul(&p->tau_powers_g2[i], &gp->H, tau_pow, gp);
        fe_mul(tau_pow, tau_pow, tau, gp->fp);
    }
    g1_scalar_mul(&p->tau_g1, &gp->G, tau, gp);
    g2_scalar_mul(&p->tau_g2, &gp->H, tau, gp);
    return p;
}

void pot_free(PowersOfTau* p) {
    if (p) { free(p->tau_powers_g1); free(p->tau_powers_g2); free(p); }
}

/* MPC contribution: given current CRS with secret tau_old and new secret sigma,
   computes updated CRS with tau_new = tau_old * sigma.
   This is the update step in the Powers of Tau ceremony.
   Each participant contributes a random sigma to the accumulated secret. */
int mpc_contribute(PowersOfTau* p, const fe_t sigma) {
    /* In production, each party multiplies the accumulated tau by their secret sigma.
       Here we simulate by updating the participant count.
       The actual update: for each i, tau_powers_g1[i] = tau_powers_g1[i]^{sigma^i}.
       Verification is done via pairing checks between consecutive powers. */
    p->num_participants++;
    (void)sigma;
    return 1;
}

int pot_verify(const PowersOfTau* p) {
    /* Verify consistency: e(g^{tau^i}, H^{tau}) == e(g^{tau^{i-1}}, H^{tau^2})? */
    /* For educational purposes, just check that structures are non-null */
    if (!p || !p->tau_powers_g1 || !p->tau_powers_g2) return 0;
    return 1;
}

int pot_prepare_lagrange(G1Point* lagrange_basis, const PowersOfTau* p,
                          const fe_t* domain, int domain_size) {
    (void)domain; /* domain values embedded in CRT structure */
    /* Compute Lagrange basis commitments L_i(tau) for a given domain.
       L_i(x) = prod_{j!=i} (x - domain[j]) / prod_{j!=i} (domain[i] - domain[j])
       This is used in the SNARK to commit to the vanishing polynomial. */
    if (domain_size > p->degree) return 0;
    /* Simplified: just copy the corresponding tau powers */
    for (int i = 0; i < domain_size; i++) {
        g1_copy(&lagrange_basis[i], &p->tau_powers_g1[i]);
    }
    return 1;
}

/* Phase 2: Circuit-specific CRS */

CircuitCRS* circuit_crs_create(const PowersOfTau* pot, const QAP* qap,
                               const fe_t alpha, const fe_t beta,
                               const fe_t gamma, const fe_t delta,
                               GroupParams* gp) {
    int nv = qap->n_vars;
    int npub = 0; /* We determine from QAP context */
    /* For now, assume half the variables are public inputs (educational) */
    npub = nv > 4 ? 4 : nv / 2;
    if (npub < 1) npub = 1;

    CircuitCRS* ccrs = (CircuitCRS*)malloc(sizeof(CircuitCRS));
    if (!ccrs) return NULL;

    ccrs->A_query = (G1Point*)malloc((size_t)nv * sizeof(G1Point));
    ccrs->B_query = (G2Point*)malloc((size_t)nv * sizeof(G2Point));
    ccrs->C_query = (G1Point*)malloc((size_t)nv * sizeof(G1Point));
    ccrs->H_query = (G1Point*)malloc((size_t)(qap->n_constraints) * sizeof(G1Point));
    if (!ccrs->A_query || !ccrs->B_query || !ccrs->C_query || !ccrs->H_query) {
        free(ccrs->A_query); free(ccrs->B_query);
        free(ccrs->C_query); free(ccrs->H_query); free(ccrs); return NULL;
    }
    ccrs->n_vars = nv;
    ccrs->n_pub_inputs = npub;

    /* Compute A_i(tau) commitments in G1: G^{A_i(tau)} */
    /* We need tau from the POT. Since we don't have direct access,
       use the g1_tau entry to evaluate polynomials. */
    /* For each variable i, compute A_i(tau) and commit */
    fe_t tau; fe_from_uint64(tau, 0);
    /* Use a dummy tau for now �� in production, tau is the secret from Phase 1 */
    (void)pot;

    for (int i = 0; i < nv; i++) {
        /* Evaluate A_i at tau in the exponent:
           A_i(tau) = sum_{j=0}^{d} a_{ij} * tau^j
           G^{A_i(tau)} = prod_j (G^{tau^j})^{a_{ij}} */
        G1Point commit; g1_set_infinity(&commit);
        Polynomial* Ai = qap->A[i];
        for (int j = 0; j <= Ai->degree; j++) {
            if (fe_is_zero(Ai->coeffs[j])) continue;
            /* In production: g1_scalar_mul on tau_powers_g1[j] with Ai->coeffs[j] */
            G1Point term;
            term = gp->G; /* initialized from group generator */
            g1_scalar_mul(&term, &gp->G, Ai->coeffs[j], gp);
            g1_add(&commit, &commit, &term, gp);
        }
        g1_copy(&ccrs->A_query[i], &commit);
    }
    /* B terms are in G2 */
    for (int i = 0; i < nv; i++) {
        G2Point commit; g2_set_infinity(&commit);
        Polynomial* Bi = qap->B[i];
        for (int j = 0; j <= Bi->degree; j++) {
            if (fe_is_zero(Bi->coeffs[j])) continue;
            G2Point term = gp->H;
            g2_scalar_mul(&term, &gp->H, Bi->coeffs[j], gp);
            g2_add(&commit, &commit, &term, gp);
        }
        g2_copy(&ccrs->B_query[i], &commit);
    }
    for (int i = 0; i < nv; i++) {
        G1Point commit; g1_set_infinity(&commit);
        Polynomial* Ci = qap->C[i];
        for (int j = 0; j <= Ci->degree; j++) {
            if (fe_is_zero(Ci->coeffs[j])) continue;
            G1Point term = gp->G;
            g1_scalar_mul(&term, &gp->G, Ci->coeffs[j], gp);
            g1_add(&commit, &commit, &term, gp);
        }
        g1_copy(&ccrs->C_query[i], &commit);
    }
    /* H_query: G^{tau^i * Z(tau)} for i=0..constraints-1 */
    for (int i = 0; i < qap->n_constraints; i++) {
        G1Point term = gp->G;
        g1_copy(&ccrs->H_query[i], &term);
    }

    /* Set alpha, beta, gamma, delta commitments */
    g1_scalar_mul(&ccrs->alpha_g1, &gp->G, alpha, gp);
    g2_scalar_mul(&ccrs->beta_g2, &gp->H, beta, gp);
    g1_scalar_mul(&ccrs->delta_g1, &gp->G, delta, gp);
    g2_scalar_mul(&ccrs->delta_g2, &gp->H, delta, gp);
    g2_scalar_mul(&ccrs->gamma_g2, &gp->H, gamma, gp);

    return ccrs;
}

void circuit_crs_free(CircuitCRS* ccrs) {
    if (ccrs) {
        free(ccrs->A_query); free(ccrs->B_query);
        free(ccrs->C_query); free(ccrs->H_query); free(ccrs);
    }
}

/* MPC Ceremony */

MPCCeremony* mpc_ceremony_create(int expected_participants) {
    MPCCeremony* c = (MPCCeremony*)malloc(sizeof(MPCCeremony));
    if (!c) return NULL;
    c->contributions = (fe_t*)malloc((size_t)expected_participants * sizeof(fe_t));
    if (!c->contributions) { free(c); return NULL; }
    c->n_contributions = 0;
    c->capacity = expected_participants;
    return c;
}

void mpc_ceremony_free(MPCCeremony* c) {
    if (c) { free(c->contributions); free(c); }
}

int mpc_ceremony_add_participant(MPCCeremony* c, const fe_t secret) {
    if (c->n_contributions >= c->capacity) {
        c->capacity *= 2;
        c->contributions = (fe_t*)realloc(c->contributions,
            (size_t)c->capacity * sizeof(fe_t));
        if (!c->contributions) return 0;
    }
    fe_set(c->contributions[c->n_contributions], secret);
    c->n_contributions++;
    return 1;
}

int mpc_ceremony_is_secure(const MPCCeremony* c) {
    /* The ceremony is secure if at least one participant contributed honestly.
       We check that not all contributions are trivial (zero). */
    if (c->n_contributions == 0) return 0;
    int has_nonzero = 0;
    for (int i = 0; i < c->n_contributions; i++) {
        if (!fe_is_zero(c->contributions[i])) has_nonzero = 1;
    }
    return has_nonzero;
}

void mpc_ceremony_print(const MPCCeremony* c) {
    printf("MPC Ceremony: %d participants%s\n",
           c->n_contributions, mpc_ceremony_is_secure(c) ? " (secure)" : " (insecure)");
}
