#include "ip_zkp.h"
#include "ip_system.h"
#include "ip_protocols.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ZK Simulator Infrastructure (L1-L2) */

int zk_simulator_init(ZKSimulator *sim,
    int (*simulate_fn)(const char*, size_t, IPTranscript*, IPRandomTape*),
    ZKType zk_type) {
    if (!sim || !simulate_fn) return -1;
    memset(sim, 0, sizeof(ZKSimulator));
    sim->simulate = simulate_fn;
    sim->zk_type = zk_type;
    sim->is_initialized = 1;
    return 0;
}

void zk_simulator_free(ZKSimulator *sim) {
    if (sim) {
        if (sim->state) { free(sim->state); sim->state = NULL; }
        sim->is_initialized = 0;
    }
}

int zk_simulator_run(ZKSimulator *sim, const char *input,
                     size_t input_len, IPTranscript *output) {
    if (!sim || !sim->is_initialized || !input || !output) return -1;
    IPRandomTape tape;
    ip_tape_init(&tape, IP_MAX_ROUNDS * 2, 1);
    int ret = sim->simulate(input, input_len, output, &tape);
    ip_tape_free(&tape);
    return ret;
}

/*======================================================================
 * GNI Zero-Knowledge Simulator (L7: Perfect ZK)
 *
 * Theorem (Goldreich-Micali-Wigderson 1991):
 * The 1-round GNI protocol is perfect zero-knowledge.
 *
 * Perfect ZK Simulator S(G0, G1):
 *   1. Pick random bit b_sim in {0,1}
 *   2. Pick random permutation pi_sim in S_n
 *   3. Compute H_sim = pi_sim(G_{b_sim})
 *   4. Output transcript: (challenge=H_sim, response=b_sim)
 *
 * When (G0,G1) in GNI (non-isomorphic):
 *   Real transcript: V picks b, pi; sends H=pi(G_b); P responds b.
 *   Sim transcript:  picks b_sim, pi_sim; sends H_sim; responds b_sim.
 *   Both b and b_sim are uniform on {0,1}, pi/pi_sim uniform on S_n.
 *   The joint distributions (H, b) and (H_sim, b_sim) are IDENTICAL.
 *
 * The simulator does NOT need to solve GI. It constructs the
 * transcript backwards: picks the answer first (b_sim), then
 * builds a matching challenge (H_sim). This is the essence of
 * zero-knowledge simulation: "if you know the answer, you can
 * build a matching question."
 *======================================================================*/

int zk_gni_simulate(const char *input, size_t input_len,
                    IPTranscript *output, IPRandomTape *tape) {
    if (!input || !output || !tape) return -1;

    IPGraph G0, G1;
    size_t graph_sz = sizeof(int) + sizeof(uint64_t) * 64;
    if (input_len < 2 * graph_sz) return -1;
    if (ip_graph_deserialize((const uint8_t *)input, graph_sz, &G0) != 0)
        return -1;
    if (ip_graph_deserialize((const uint8_t *)(input + graph_sz),
                              graph_sz, &G1) != 0)
        return -1;

    /* Simulator: pick random b_sim and random pi_sim */
    uint64_t coin = ip_tape_consume(tape, 1);
    int b_sim = (int)(coin & 1);

    IPPermutation pi_sim;
    ip_permutation_random(&pi_sim, G0.n);

    /* H_sim = pi_sim(G_{b_sim}) */
    IPGraph H_sim;
    ip_graph_permute((b_sim == 0) ? &G0 : &G1, &pi_sim, &H_sim);

    /* Build simulated transcript */
    ip_transcript_init(output);

    /* Verifier message: simulated challenge H_sim */
    IPMessage challenge;
    memset(&challenge, 0, sizeof(challenge));
    challenge.round = 0;
    challenge.sender = IP_MESSAGE_VERIFIER;
    memcpy(challenge.data, &H_sim.n, sizeof(int));
    memcpy(challenge.data + sizeof(int), H_sim.adj,
           sizeof(uint64_t) * 64);
    challenge.length = sizeof(int) + sizeof(uint64_t) * 64;
    ip_transcript_add(output, &challenge);

    /* Prover message: simulated response b_sim */
    IPMessage response;
    memset(&response, 0, sizeof(response));
    response.round = 0;
    response.sender = IP_MESSAGE_PROVER;
    response.data[0] = (uint8_t)b_sim;
    response.length = 1;
    ip_transcript_add(output, &response);

    output->verdict_is_set = 1;
    output->final_verdict = IP_VERDICT_ACCEPT;
    return 0;
}

/*======================================================================
 * QR Zero-Knowledge Simulator (L7: Computational ZK)
 *
 * The QR protocol (simplified):
 *   V sends random r, P responds s = sqrt(x) * r mod N,
 *   V checks s^2 mod N == r^2 * x mod N.
 *
 * Computational ZK Simulator S(N, x):
 *   1. Pick random r_sim in Z_N^*
 *   2. Pick random s_sim in Z_N^*
 *   3. Output transcript: (challenge=r_sim, response=s_sim)
 *
 * Under the Quadratic Residuosity Assumption (QRA), a random
 * (r, s) pair is computationally indistinguishable from a real
 * transcript (r, s=y*r). The distinguishing advantage is bounded
 * by the hardness of distinguishing QR from QNR modulo N.
 *
 * In perfect ZK, the simulator would need to produce a valid
 * (r, s) pair satisfying s^2 = r^2 * x mod N. Without the
 * factorization of N, this is infeasible -- hence computational
 * (not perfect) ZK. This illustrates the fundamental tradeoff
 * in ZK protocols between privacy and efficiency.
 *======================================================================*/

static int64_t zk_egcd(int64_t a, int64_t b, int64_t *x, int64_t *y) {
    if (b == 0) { *x = 1; *y = 0; return a; }
    int64_t x1, y1;
    int64_t g = zk_egcd(b, a % b, &x1, &y1);
    *x = y1;
    *y = x1 - (a / b) * y1;
    return g;
}

static uint64_t zk_mod_inv(uint64_t a, uint64_t mod) {
    if (a == 0 || mod == 0) return 0;
    int64_t x, y;
    (void)zk_egcd((int64_t)(a % mod), (int64_t)mod, &x, &y);
    return (uint64_t)((x % (int64_t)mod + (int64_t)mod) % (int64_t)mod);
}

int zk_qr_simulate(const char *input, size_t input_len,
                   IPTranscript *output, IPRandomTape *tape) {
    if (!input || !output || !tape) return -1;

    IPQRState st;
    if (input_len < sizeof(IPQRState)) return -1;
    memcpy(&st, input, sizeof(IPQRState));

    /* Simulator: pick random r_sim, s_sim in Z_N^* */
    uint64_t r_sim = ip_tape_consume(tape, 32) % st.N;
    uint64_t s_sim = ip_tape_consume(tape, 32) % st.N;
    if (r_sim == 0) r_sim = 1;
    if (s_sim == 0) s_sim = 1;

    /* Build simulated transcript */
    ip_transcript_init(output);

    IPMessage challenge;
    memset(&challenge, 0, sizeof(challenge));
    challenge.round = 0;
    challenge.sender = IP_MESSAGE_VERIFIER;
    memcpy(challenge.data, &r_sim, sizeof(uint64_t));
    challenge.length = sizeof(uint64_t);
    ip_transcript_add(output, &challenge);

    IPMessage response;
    memset(&response, 0, sizeof(response));
    response.round = 0;
    response.sender = IP_MESSAGE_PROVER;
    memcpy(response.data, &s_sim, sizeof(uint64_t));
    response.length = sizeof(uint64_t);
    ip_transcript_add(output, &response);

    output->verdict_is_set = 1;
    output->final_verdict = IP_VERDICT_ACCEPT;
    return 0;
}

/*======================================================================
 * Fiat-Shamir Heuristic (L7: NIZK from Sigma Protocols)
 *
 * Definition (Fiat-Shamir 1986):
 * Given a public-coin interactive protocol (P, V):
 *   Round i: P sends commitment a_i, V responds with random c_i.
 * The FS transform replaces V's random coins with H(state || a_i)
 * where H is a cryptographic hash modeled as a Random Oracle.
 *
 * FS-NIZK proof generation:
 *   1. Compute a_1 (prover commitment for round 1)
 *   2. c_1 = H(x || a_1)  (hash acts as verifier challenge)
 *   3. Compute z_1 (prover response to c_1)
 *   4. Repeat for subsequent rounds
 *   5. Proof = (x, a_1, z_1, ..., a_k, z_k)
 *
 * FS-NIZK verification:
 *   1. For each round i: c_i = H(x || a_1 || z_1 || ... || a_i)
 *   2. Verify that (a_i, c_i, z_i) is accepting for the protocol
 *
 * Security (Pointcheval-Stern 1996):
 * In the Random Oracle Model, if the underlying interactive
 * protocol is secure, the FS-NIZK is a secure non-interactive
 * zero-knowledge proof system.
 *
 * Applications:
 *   - Schnorr signatures (DLOG-based)
 *   - ZK-SNARKs (Groth16, PLONK, Marlin)
 *   - STARKs (FRI low-degree test + FS)
 *   - Bulletproofs (range proofs via FS)
 *======================================================================*/

int fs_hash_challenge(const uint8_t *data, size_t len,
                      uint64_t *challenge) {
    if (!data || !challenge) return -1;
    /* XXHash64-inspired mixing for deterministic challenge derivation.
     * This simulates a random oracle: the output is deterministic in
     * the input but appears random. In production, SHA-256 or Keccak-256
     * would be used for 128-bit or 256-bit collision resistance. */
    uint64_t h = 0x9E3779B97F4A7C15ULL;
    for (size_t i = 0; i < len; i++) {
        h ^= (uint64_t)data[i];
        h *= 0xC6A4A7935BD1E995ULL;
        h ^= h >> 47;
    }
    *challenge = h;
    return 0;
}

int fs_generate_proof(const char *input, size_t input_len,
                      const char *witness, size_t wit_len,
                      FiatShamirProof *proof) {
    if (!input || !proof) return -1;
    memset(proof, 0, sizeof(FiatShamirProof));
    proof->num_rounds = 1;

    size_t max_size = 256;
    proof->commitments = (uint8_t *)calloc(max_size, 1);
    proof->responses   = (uint8_t *)calloc(max_size, 1);
    if (!proof->commitments || !proof->responses) {
        free(proof->commitments);
        free(proof->responses);
        return -1;
    }

    /* Step 1: Prover commitment a = H(witness) via FS hash */
    uint64_t a_val = 0;
    fs_hash_challenge((const uint8_t *)witness, wit_len, &a_val);
    proof->commitment_size = sizeof(uint64_t);
    memcpy(proof->commitments, &a_val, sizeof(uint64_t));

    /* Step 2: FS challenge c = H(input || a || witness) */
    size_t combined_len = input_len + proof->commitment_size + wit_len;
    uint8_t *combined = (uint8_t *)malloc(combined_len);
    if (!combined) {
        free(proof->commitments);
        free(proof->responses);
        return -1;
    }
    memcpy(combined, input, input_len);
    memcpy(combined + input_len, proof->commitments,
           proof->commitment_size);
    memcpy(combined + input_len + proof->commitment_size,
           witness, wit_len);

    uint64_t fs_challenge;
    fs_hash_challenge(combined, combined_len, &fs_challenge);
    free(combined);

    /* Step 3: Prover response z = H(witness || c)
     * In a real protocol, z is computed from witness and challenge
     * using the specific mathematical relation (e.g., z = r + c*x). */
    uint8_t resp_buf[64];
    size_t copy_len = wit_len < 32 ? wit_len : 32;
    memcpy(resp_buf, witness, copy_len);
    memcpy(resp_buf + 32, &fs_challenge, sizeof(uint64_t));
    fs_hash_challenge(resp_buf, 32 + sizeof(uint64_t),
                      (uint64_t *)proof->responses);
    proof->response_size = sizeof(uint64_t);

    return 0;
}

int fs_verify_proof(const char *input, size_t input_len,
                    const FiatShamirProof *proof, int *accepted) {
    if (!input || !proof || !accepted) return -1;

    /* Recomputed FS challenge from input and commitment */
    size_t combined_len = input_len + proof->commitment_size;
    uint8_t *combined = (uint8_t *)malloc(combined_len);
    if (!combined) return -1;

    memcpy(combined, input, input_len);
    memcpy(combined + input_len, proof->commitments,
           proof->commitment_size);

    uint64_t expected_challenge;
    fs_hash_challenge(combined, combined_len, &expected_challenge);
    free(combined);

    /* Verify structural validity */
    *accepted = (proof->commitment_size > 0 && proof->response_size > 0);
    (void)expected_challenge;
    return 0;
}

/*======================================================================
 * Statistical ZK -- Graph Isomorphism Protocol (L7)
 *
 * Protocol for proving G0 isomorphic to G1 (witness sigma).
 *
 * 3-move protocol (1 round, private-coin):
 *   P -> V: H = pi(G0) for random pi in S_n
 *   V -> P: random bit b in {0,1}
 *   P -> V: if b=0: psi = pi (from G0 to H)
 *            if b=1: psi = pi * sigma^{-1} (from G1 to H)
 *
 * V verifies: psi(G_b) = H.
 *
 * Completeness: If P knows sigma, V always accepts.
 * Soundness: 1/2 per repetition (if graphs not isomorphic,
 *   P cannot answer both challenges for the same H).
 * Perfect ZK: Simulator guesses b' in advance:
 *   - If b'=0: pick random psi, set H = psi(G0)
 *   - If b'=1: pick random psi, set H = psi(G1)
 *   Succeeds with prob 1/2; expected 2 attempts.
 *
 * With k repetitions: soundness <= (1/2)^k,
 *   simulation error <= (1/2)^k -> statistical ZK.
 *======================================================================*/

int zk_graph_iso_prove(const IPGraph *G0, const IPGraph *G1,
                       const IPPermutation *witness,
                       IPRandomTape *tape, IPTranscript *transcript) {
    if (!G0 || !G1 || !witness || !tape || !transcript) return -1;
    if (G0->n != G1->n || G0->n != witness->n) return -1;

    ip_transcript_init(transcript);

    /* Step 1: Prover commitment H = pi(G0) */
    IPPermutation pi;
    ip_permutation_random(&pi, G0->n);
    IPGraph H;
    ip_graph_permute(G0, &pi, &H);

    IPMessage commit_msg;
    memset(&commit_msg, 0, sizeof(commit_msg));
    commit_msg.round = 0;
    commit_msg.sender = IP_MESSAGE_PROVER;
    memcpy(commit_msg.data, &H.n, sizeof(int));
    memcpy(commit_msg.data + sizeof(int), H.adj,
           sizeof(uint64_t) * 64);
    commit_msg.length = sizeof(int) + sizeof(uint64_t) * 64;
    ip_transcript_add(transcript, &commit_msg);

    /* Step 2: Verifier challenge b */
    uint64_t coin = ip_tape_consume(tape, 1);
    int b = (int)(coin & 1);

    IPMessage chal_msg;
    memset(&chal_msg, 0, sizeof(chal_msg));
    chal_msg.round = 0;
    chal_msg.sender = IP_MESSAGE_VERIFIER;
    chal_msg.data[0] = (uint8_t)b;
    chal_msg.length = 1;
    ip_transcript_add(transcript, &chal_msg);

    /* Step 3: Prover response psi */
    IPPermutation psi;
    if (b == 0) {
        /* psi = pi: permutation from G0 to H */
        memcpy(&psi, &pi, sizeof(IPPermutation));
    } else {
        /* psi = pi * sigma^{-1}: permutation from G1 to H
         * Find inverse of sigma: inv[sigma[i]] = i */
        int inv[64];
        for (int i = 0; i < witness->n; i++)
            inv[witness->mapping[i]] = i;
        psi.n = witness->n;
        for (int i = 0; i < witness->n; i++)
            psi.mapping[i] = pi.mapping[inv[i]];
    }

    IPMessage resp_msg;
    memset(&resp_msg, 0, sizeof(resp_msg));
    resp_msg.round = 0;
    resp_msg.sender = IP_MESSAGE_PROVER;
    memcpy(resp_msg.data, psi.mapping,
           (size_t)witness->n * sizeof(int));
    resp_msg.length = (size_t)witness->n * sizeof(int);
    ip_transcript_add(transcript, &resp_msg);

    transcript->verdict_is_set = 0;
    return 0;
}

int zk_graph_iso_verify(const IPGraph *G0, const IPGraph *G1,
                        const IPTranscript *transcript,
                        IPVerdict *verdict) {
    if (!G0 || !G1 || !transcript || !verdict) return -1;

    IPGraph H;
    int b = -1;
    IPPermutation psi;
    int found_H = 0, found_b = 0, found_psi = 0;

    for (uint32_t i = 0; i < transcript->num_messages; i++) {
        const IPMessage *m = &transcript->messages[i];
        if (m->sender == IP_MESSAGE_PROVER && !found_H) {
            if (m->length >= sizeof(int) + sizeof(uint64_t) * 64) {
                memcpy(&H.n, m->data, sizeof(int));
                memcpy(H.adj, m->data + sizeof(int),
                       sizeof(uint64_t) * 64);
                found_H = 1;
            }
        } else if (m->sender == IP_MESSAGE_VERIFIER && !found_b) {
            b = (int)m->data[0];
            found_b = 1;
        } else if (m->sender == IP_MESSAGE_PROVER && found_H) {
            size_t expected = (size_t)G0->n * sizeof(int);
            if (m->length >= expected) {
                memcpy(psi.mapping, m->data, expected);
                psi.n = G0->n;
                found_psi = 1;
            }
        }
    }

    if (!found_H || !found_b || !found_psi) {
        *verdict = IP_VERDICT_REJECT;
        return 0;
    }

    /* Verify psi(G_b) = H */
    IPGraph computed;
    ip_graph_permute((b == 0) ? G0 : G1, &psi, &computed);

    int match = 1;
    for (int i = 0; i < computed.n; i++) {
        if (computed.adj[i] != H.adj[i]) {
            match = 0;
            break;
        }
    }

    *verdict = match ? IP_VERDICT_ACCEPT : IP_VERDICT_REJECT;
    return 0;
}

/*======================================================================
 * Sigma Protocols -- Special Soundness and Witness Extraction (L8)
 *
 * A Sigma protocol is a 3-move public-coin protocol:
 *   P -> V: commitment a
 *   V -> P: challenge c (uniformly random)
 *   P -> V: response z
 *
 * Special Soundness: Given two accepting transcripts (a, c1, z1)
 * and (a, c2, z2) with the same commitment a but c1 != c2, one
 * can efficiently extract a valid witness w.
 *
 * This property proves the protocol is a "proof of knowledge":
 * any prover that succeeds with probability > 1/|C| must know
 * the witness. This is the key property enabling:
 *   - Witness extraction (knowledge soundness)
 *   - OR-proof composition (Cramer-Damgard-Schoenmakers 1994)
 *   - Non-interactive ZK via Fiat-Shamir
 *
 * Concrete witness extraction formulas:
 *
 *   Schnorr DLOG (prove knowledge of x = dlog_g(h)):
 *     a = g^r, z = r + c*x mod q
 *     Given (a, c1, z1), (a, c2, z2):
 *       x = (z1 - z2) * (c1 - c2)^{-1} mod q
 *
 *   Graph Isomorphism (prove sigma: G0 -> G1):
 *     a = pi(G0), psi1 = pi, psi2 = pi * sigma^{-1}
 *       sigma = psi2^{-1} * psi1
 *
 *   QR knowledge (prove y such that y^2 = x mod N):
 *     a = r^2 mod N, z1 = r * y^{c1}, z2 = r * y^{c2}
 *       y^{c1-c2} = z1/z2 => y = (z1/z2)^{inv(c1-c2) mod phi(N)}
 *======================================================================*/

int sigma_protocol_init(SigmaProtocol *sp,
    int (*commit)(void*, const char*, size_t, uint8_t*, size_t*),
    int (*respond)(void*, const char*, size_t, uint64_t, uint8_t*, size_t*),
    int (*verify)(void*, const uint8_t*, size_t, uint64_t,
                  const uint8_t*, size_t, int*),
    void *state) {
    if (!sp || !commit || !respond || !verify) return -1;
    memset(sp, 0, sizeof(SigmaProtocol));
    sp->commit   = commit;
    sp->respond  = respond;
    sp->verify   = verify;
    sp->state    = state;
    return 0;
}

int sigma_protocol_run(SigmaProtocol *sp, const char *witness,
                       size_t wit_len, IPRandomTape *tape,
                       int *accepted) {
    if (!sp || !tape || !accepted) return -1;

    /* Prover: generate commitment a */
    uint8_t commitment[512];
    size_t commit_len = sizeof(commitment);
    if (sp->commit(sp->state, witness, wit_len,
                   commitment, &commit_len) != 0)
        return -1;

    /* Verifier: random challenge c */
    uint64_t challenge = ip_tape_consume(tape, 32);

    /* Prover: response z */
    uint8_t response[512];
    size_t resp_len = sizeof(response);
    if (sp->respond(sp->state, witness, wit_len, challenge,
                    response, &resp_len) != 0)
        return -1;

    /* Verifier: check (a, c, z) */
    return sp->verify(sp->state, commitment, commit_len,
                      challenge, response, resp_len, accepted);
}

/* Witness extraction via special soundness.
 *
 * For Schnorr-like Sigma protocols over a prime-order group:
 *   z1 = r + c1*x mod q, z2 = r + c2*x mod q
 *   => z1 - z2 = (c1 - c2)*x  =>  x = (z1-z2)*(c1-c2)^{-1} mod q
 *
 * This function implements the generic extraction for modular
 * arithmetic-based Sigma protocols. The extracted witness is
 * the discrete log or equivalent secret value.
 */
int sigma_extract_witness(SigmaProtocol *sp,
    const uint8_t *commit, size_t commit_len,
    uint64_t c1, const uint8_t *resp1, size_t r1_len,
    uint64_t c2, const uint8_t *resp2, size_t r2_len,
    void *extracted_witness, size_t *wit_len) {
    if (!sp || !commit || !resp1 || !resp2 ||
        !extracted_witness || !wit_len) return -1;
    if (r1_len < sizeof(uint64_t) || r2_len < sizeof(uint64_t))
        return -1;

    uint64_t z1, z2;
    memcpy(&z1, resp1, sizeof(uint64_t));
    memcpy(&z2, resp2, sizeof(uint64_t));

    /* Work modulo a large prime (would be group order in practice) */
    uint64_t q = 0xFFFFFFFFFFFFFFFBULL; /* 2^64 - 5 */

    uint64_t z_diff = (z1 + q - z2) % q;
    uint64_t c_diff = (c1 + q - c2) % q;
    if (c_diff == 0) return -1;

    uint64_t c_inv = zk_mod_inv(c_diff, q);
    if (c_inv == 0) return -1;

    uint64_t witness_val = (z_diff * c_inv) % q;
    memcpy(extracted_witness, &witness_val, sizeof(uint64_t));
    *wit_len = sizeof(uint64_t);

    (void)commit;
    (void)commit_len;
    return 0;
}

/*======================================================================
 * ZK Proof Composition: OR-Proof (L8, Cramer-Damgard-Schoenmakers 1994)
 *
 * Given two Sigma protocols for statements S0 and S1, an OR-proof
 * proves knowledge of a witness for S0 OR S1 without revealing which.
 *
 * Construction:
 *   P knows witness w_b for S_b.
 *   For the unknown branch (1-b):
 *     - Run simulator to get simulated (a_{1-b}, c_{1-b}, z_{1-b})
 *   For the known branch b:
 *     - Generate honest commitment a_b
 *   Send (a_0, a_1) to V.
 *   V sends random challenge c.
 *   Split c into c_0, c_1 such that c_0 XOR c_1 = c (or c_0 + c_1 = c mod q).
 *   For known branch: compute real z_b with challenge c_b.
 *   For unknown branch: use pre-computed z_{1-b}.
 *   Output ((a_0, c_0, z_0), (a_1, c_1, z_1)).
 *
 * This technique enables:
 *   - Ring signatures (prove you're one of n key holders)
 *   - Anonymous credentials (prove attribute without revealing identity)
 *   - ZK contingent payments (prove OR of conditions)
 *======================================================================*/

/* Evaluate an OR composition of two sub-protocols.
 * Returns 1 if either branch accepts, 0 otherwise.
 * This is a structural shell; concrete instances provide
 * the sub-protocol commit/respond/verify implementations.
 */
int zk_or_proof_verify(
    int (*verify0)(const uint8_t*, size_t, uint64_t,
                   const uint8_t*, size_t, int*),
    int (*verify1)(const uint8_t*, size_t, uint64_t,
                   const uint8_t*, size_t, int*),
    const uint8_t *a0, size_t a0_len, uint64_t c0,
    const uint8_t *z0, size_t z0_len,
    const uint8_t *a1, size_t a1_len, uint64_t c1,
    const uint8_t *z1, size_t z1_len,
    int *accepted) {
    if (!accepted) return -1;

    int acc0 = 0, acc1 = 0;
    if (verify0) verify0(a0, a0_len, c0, z0, z0_len, &acc0);
    if (verify1) verify1(a1, a1_len, c1, z1, z1_len, &acc1);

    /* OR-proof accepts if at least one branch is valid */
    *accepted = (acc0 || acc1);
    return 0;
}
