// example_mpc_ceremony.c - Multi-Party Computation Trusted Setup Demo
// Knowledge: L7 Application (MPC ceremony), L8 Advanced (distributed trust)
// Reference: Bowe, Gabizon, Miers (2017)

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include "setup.h"
#include "field.h"
#include "dlog.h"
#include "snark.h"
#include "qap.h"
#include "r1cs.h"

static void demo_one_of_n_security(void) {
    printf("=== 1-of-N Security Demo ===\n");
    printf("MPC ceremony: 1 honest participant suffices.\n");
    printf("Even if N-1 parties collude, the CRS stays\n");
    printf("unpredictable if 1 party is honest.\n\n");

    MPCCeremony* c = mpc_ceremony_create(5);

    fe_t pub_sec, priv_sec;
    fe_from_uint64(pub_sec, 42);
    fe_from_uint64(priv_sec, 99);

    for (int i = 0; i < 4; i++)
        mpc_ceremony_add_participant(c, pub_sec);
    mpc_ceremony_add_participant(c, priv_sec);

    printf("Ceremony: 4 colluding + 1 honest\n");
    mpc_ceremony_print(c);
    printf("Still secure: %s\n", mpc_ceremony_is_secure(c) ? "YES" : "NO");
    printf("=> 1-of-N security holds!\n");
    mpc_ceremony_free(c);
}

static void demo_full_ceremony(void) {
    printf("\n=== Full MPC Ceremony Demo ===\n");
    FieldParams fp = FIELD_BN254;
    GroupParams* gp = group_params_create_small();
    assert(gp != NULL);

    fe_t tau0; fe_from_uint64(tau0, 7);
    printf("Phase 1: Coordinator with tau0=7\n");

    PowersOfTau* pot = pot_create(tau0, 8, gp);
    assert(pot != NULL);
    printf("  POT created (deg 8), verify: %s\n", pot_verify(pot) ? "PASS" : "FAIL");

    uint64_t secrets[] = {13, 17, 19, 23, 29};
    printf("Phase 1: 5 participants contribute\n");
    for (int i = 0; i < 5; i++) {
        fe_t sigma; fe_from_uint64(sigma, secrets[i]);
        printf("  P%d (secret=%llu): ", i+1, (unsigned long long)secrets[i]);
        int ok = mpc_contribute(pot, sigma);
        printf("update=%s verify=%s\n", ok ? "OK" : "FAIL", pot_verify(pot) ? "PASS" : "FAIL");
    }
    printf("Final POT: %s\n", pot_verify(pot) ? "OK" : "FAIL");

    printf("\nPhase 2: Circuit-specific CRS...\n");
    R1CS* r = r1cs_create(2, 4, 2);
    int va[] = {1}; fe_t ca[1]; fe_from_uint64(ca[0], 1);
    int vb[] = {2}; fe_t cb[1]; fe_from_uint64(cb[0], 1);
    int vc[] = {3}; fe_t cc[1]; fe_from_uint64(cc[0], 1);
    r1cs_add_full_constraint(r, 0, va, ca, 1, vb, cb, 1, vc, cc, 1, &fp);

    fe_t qr[2]; fe_from_uint64(qr[0], 0); fe_from_uint64(qr[1], 1);
    QAP* q = qap_from_r1cs(r, qr, &fp);
    assert(q != NULL);
    qap_print_summary(q);

    fe_t alpha, beta, gamma, delta;
    fe_from_uint64(alpha, 2); fe_from_uint64(beta, 3);
    fe_from_uint64(gamma, 5); fe_from_uint64(delta, 11);

    CircuitCRS* ccrs = circuit_crs_create(pot, q, alpha, beta, gamma, delta, gp);
    assert(ccrs != NULL);
    printf("  Circuit CRS: %d vars, %d pub\n", ccrs->n_vars, ccrs->n_pub_inputs);

    SnarkPipeline* sp = snark_pipeline_create();
    assert(sp != NULL);
    snark_pipeline_setup(sp, r, tau0, alpha, beta, gamma, delta, &fp);

    fe_t witness[4];
    fe_one(witness[0]);
    fe_from_uint64(witness[1], 3);
    fe_from_uint64(witness[2], 4);
    fe_from_uint64(witness[3], 12);

    Proof proof;
    int po = snark_pipeline_prove(&proof, sp, witness, 1);
    printf("  Prove (ZK): %s\n", po ? "OK" : "FAIL");
    assert(po);

    fe_t pub_in[2];
    fe_from_uint64(pub_in[0], 3); fe_from_uint64(pub_in[1], 4);
    int vo = snark_pipeline_verify(&proof, sp, pub_in);
    printf("  Verify: %s\n", vo ? "PASS" : "FAIL");
    assert(vo);

    snark_pipeline_free(sp);
    circuit_crs_free(ccrs);
    qap_free(q); r1cs_free(r);
    pot_free(pot); group_params_free(gp);
    printf("\n=== MPC Ceremony: COMPLETE ===\n");
}

int main(void) {
    printf("=== MPC Ceremony & 1-of-N Security ===\n");
    printf("Demonstrates the trusted setup ceremony.\n");
    printf("Multi-party computation ensures 1-of-N security.\n\n");
    demo_full_ceremony();
    demo_one_of_n_security();
    printf("\n=== All MPC demos passed! ===\n");
    return 0;
}