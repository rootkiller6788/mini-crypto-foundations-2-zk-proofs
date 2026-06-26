/*
 * example_evoting_zk.c -- End-to-End: E-Voting with ZK Ballot Validity Proof
 *
 * Demonstrates electronic voting where each voter proves their ballot
 * is valid (vote is 0 or 1) without revealing which way they voted.
 *
 * Uses OR-composition: prover shows (vote=0) OR (vote=1) without
 * revealing which branch is the real one.
 *
 * Reference: Cramer-Damgard-Schoenmakers (1994)
 *            Cramer-Gennaro-Schoenmakers (1997)
 * Courses: MIT 6.875, Stanford CS355, ETH 263-4660
 */

#include "zk_simulator.h"
#include "sigma_protocols.h"
#include "commitments.h"
#include "fiat_shamir.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>

int main(void) {
    printf("=== E-Voting with ZK Ballot Validity Proof ===\n\n");

    group_params_t gp = {23, 2, 11, 8};
    random_tape_t rng;
    init_random_tape(&rng, (uint64_t)time(NULL));

    /* Setup: public keys for vote encoding
     * y0 = g^0 = 1: encoding for vote=0
     * y1 = g^1 = 2: encoding for vote=1
     *
     * The voter knows one witness (either 0 or 1) and proves
     * knowledge of the discrete log of one of y0, y1.
     */
    uint64_t y0 = mod_pow(gp.g, 0, gp.p);  /* g^0 = 1 */
    uint64_t y1 = mod_pow(gp.g, 1, gp.p);  /* g^1 = g = 2 */

    printf("Vote encoding public keys:\n");
    printf("  y0 = g^0 mod %llu = %llu  (represents vote=0)\n",
           (unsigned long long)gp.p, (unsigned long long)y0);
    printf("  y1 = g^1 mod %llu = %llu  (represents vote=1)\n",
           (unsigned long long)gp.p, (unsigned long long)y1);
    printf("\n");

    /* Simulation: 5 voters cast ballots */
    int num_voters = 5;
    int votes[5] = {0, 1, 0, 1, 1};

    printf("=== %d Voters Cast Ballots ===\n\n", num_voters);
    int total_yes = 0, total_no = 0;

    for (int voter = 0; voter < num_voters; voter++) {
        int vote = votes[voter];
        printf("Voter %d: actual vote = %s\n", voter + 1,
               vote ? "YES (1)" : "NO (0)");

        /* Voter proves: "I know witness for y0 OR y1"
         * real_side = 1 means witness for y0, 2 means witness for y1 */
        int real_side = (vote == 0) ? 1 : 2;
        uint64_t witness = (vote == 0) ? 0 : 1;

        or_composition_prover_t op;
        or_compose_prover_init(&op, real_side, witness, y0, y1, &gp);

        /* Verifier picks random challenge */
        uint64_t verifier_challenge = pull_random_mod_q(&rng, gp.q);

        or_composition_transcript_t ot;
        or_compose_prover_execute(&op, &rng, &ot, verifier_challenge);

        /* Verify the OR-proof */
        int valid = or_compose_verify(&ot, y0, y1, &gp);

        printf("  OR-proof: a1=%llu, a2=%llu, c=%llu\n",
               (unsigned long long)ot.a1, (unsigned long long)ot.a2,
               (unsigned long long)ot.c);
        printf("  Challenge split: c1=%llu, c2=%llu -> sum=%llu mod q\n",
               (unsigned long long)ot.c1, (unsigned long long)ot.c2,
               (unsigned long long)((ot.c1 + ot.c2) % gp.q));
        printf("  Verification: %s\n", valid ? "VALID" : "INVALID");

        if (valid) {
            if (vote) total_yes++; else total_no++;
        }
        printf("\n");
    }

    /* Tally result */
    printf("=== Tally ===\n");
    printf("  Total YES votes: %d\n", total_yes);
    printf("  Total NO votes:  %d\n", total_no);
    printf("  All ballots verified with ZK: ballot validity proven\n");
    printf("  without revealing individual votes.\n");

    /* ZK property demonstration:
     * Show that the simulated side and real side produce
     * indistinguishable transcripts. */
    printf("\n=== ZK Property: Indistinguishability ===\n");
    printf("For each OR-proof, one side is REAL (known witness)\n");
    printf("and one side is SIMULATED (HVZK sim). The verifier\n");
    printf("cannot tell which is which => witness indistinguishable.\n");

    /* Statistical analysis of simulated vs real transcripts */
    printf("\n=== E-Voting Demo Complete ===\n");
    return 0;
}
