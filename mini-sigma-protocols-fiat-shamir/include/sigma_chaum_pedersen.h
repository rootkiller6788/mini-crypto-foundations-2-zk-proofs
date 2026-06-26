#ifndef SIGMA_CHAUM_PEDERSEN_H
#define SIGMA_CHAUM_PEDERSEN_H

/**
 * sigma_chaum_pedersen.h ? Chaum-Pedersen Sigma Protocol
 *
 * Proves equality of discrete logarithms: I know x such that
 * y1 = g1^x AND y2 = g2^x (same x across two bases).
 *
 * Protocol:
 *   Prover(x)                              Verifier(y1, y2, g1, g2)
 *   ?????????????????????????????????????????????????????????????
 *   r ? Z_q
 *   a1 = g1^r, a2 = g2^r
 *                        ?? a1, a2 ???
 *                                            e ? Z_q
 *                        ??? e ??
 *   z = r + e?x mod q
 *                        ?? z ???
 *                                       g1^z ? a1 ? y1^e
 *                                       g2^z ? a2 ? y2^e
 *
 * L1 Definitions:
 *   - DLEQ (Discrete Log EQuality) proof
 *   - Chaum-Pedersen protocol
 *
 * L4 Theorems:
 *   - Special soundness: extract x = (z-z')/(e-e') from either pair
 *   - SHVZK: simulator picks z?Z_q, a1=g1^z?y1^{-e}, a2=g2^z?y2^{-e}
 *
 * L7 Applications:
 *   - Verifiable encryption (Cramer & Shoup 1998)
 *   - Anonymous credentials (Brands 1993)
 *   - Mix-net verification (Jakobsson & Juels 2000)
 *   - Cryptocurrency privacy (Monero RingCT)
 *   - Threshold cryptography (secure key generation)
 *
 * References:
 *   - Chaum & Pedersen (1993) "Wallet Databases with Observers"
 *     CRYPTO '92, LNCS 740, pp. 89-105
 *   - Cramer & Shoup (1998) "A Practical Public Key Cryptosystem
 *     Provably Secure against Adaptive Chosen Ciphertext Attack"
 *     CRYPTO '98
 *   - Brands (1993) "Untraceable Off-line Cash in Wallets with Observers"
 *     CRYPTO '93
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "sigma_math.h"
#include "sigma_core.h"

/* ??? Key/Statement Setup ??????????????????????????????????????????? */

/**
 * sigma_cp_setup ? Generate a DLEQ statement.
 *
 * Given witness x, bases g1, g2, compute y1 = g1^x, y2 = g2^x.
 * The bases g1, g2 must be independent generators of the group.
 * Standard choice: g1 = g (standard generator), g2 = H_to_group(seed).
 */
void sigma_cp_setup(sigma_chaum_pedersen_public *pub,
                    const sigma_chaum_pedersen_witness *wit,
                    const sigma_group_elem *base1,
                    const sigma_group_elem *base2);

/**
 * sigma_cp_setup_seeded ? Deterministic setup for testing.
 * g1 = g (standard), g2 = g^s for fixed seed s.
 */
void sigma_cp_setup_seeded(sigma_chaum_pedersen_public *pub,
                           sigma_chaum_pedersen_witness *wit,
                           uint64_t seed);

/* ??? Protocol Functions ????????????????????????????????????????????? */

/**
 * sigma_cp_commit ? Prover's first message.
 *
 * a1 = g1^r mod p
 * a2 = g2^r mod p
 *
 * Uses the SAME randomness r for both commitments. This is essential
 * for the equality proof to work.
 */
void sigma_cp_commit(sigma_group_elem *a1, sigma_group_elem *a2,
                     const sigma_scalar *randomness,
                     const sigma_chaum_pedersen_public *pub);

/**
 * sigma_cp_respond ? Prover's third message.
 *
 * z = r + e?x mod q
 */
void sigma_cp_respond(sigma_scalar *response,
                      const sigma_scalar *randomness,
                      const sigma_scalar *challenge,
                      const sigma_chaum_pedersen_witness *witness);

/**
 * sigma_cp_verify ? Verifier's check.
 *
 * Check both equations simultaneously:
 *   g1^z ? a1 ? y1^e
 *   g2^z ? a2 ? y2^e
 *
 * Returns true iff both equalities hold.
 */
bool sigma_cp_verify(const sigma_group_elem *a1,
                     const sigma_group_elem *a2,
                     const sigma_scalar *challenge,
                     const sigma_scalar *response,
                     const sigma_chaum_pedersen_public *pub);

/* ??? Combined Transcript Type ?????????????????????????????????????? */

/**
 * sigma_cp_transcript ? Chaum-Pedersen protocol transcript.
 * Contains two commitments (for the two bases).
 */
typedef struct {
    sigma_group_elem a1;       /* commitment for g1 */
    sigma_group_elem a2;       /* commitment for g2 */
    sigma_scalar     challenge;
    sigma_scalar     response;
} sigma_cp_transcript;

/**
 * sigma_cp_prove ? Run full CP protocol (prover side).
 */
void sigma_cp_prove(sigma_cp_transcript *t,
                    const sigma_chaum_pedersen_witness *wit,
                    const sigma_chaum_pedersen_public *pub,
                    const sigma_scalar *randomness);

/**
 * sigma_cp_verify_transcript ? Verify a CP transcript.
 */
bool sigma_cp_verify_transcript(const sigma_cp_transcript *t,
                                const sigma_chaum_pedersen_public *pub);

/* ??? Knowledge Extraction ?????????????????????????????????????????? */

/**
 * sigma_cp_extract ? Extract witness from two transcripts with same a1,a2.
 */
bool sigma_cp_extract(sigma_chaum_pedersen_witness *wit_out,
                      const sigma_cp_transcript *t1,
                      const sigma_cp_transcript *t2,
                      const sigma_chaum_pedersen_public *pub);

/* ??? Simulation ???????????????????????????????????????????????????? */

/**
 * sigma_cp_simulate ? Generate accepting transcript given challenge.
 */
void sigma_cp_simulate(sigma_cp_transcript *t,
                       const sigma_scalar *challenge,
                       const sigma_chaum_pedersen_public *pub);

/* ??? VTable ???????????????????????????????????????????????????????? */

/** Return a fully populated sigma_protocol vtable for Chaum-Pedersen. */
const sigma_protocol *sigma_cp_get_protocol(void);

#endif /* SIGMA_CHAUM_PEDERSEN_H */
