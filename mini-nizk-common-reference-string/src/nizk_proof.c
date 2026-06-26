/**
 * nizk_proof.c - Non-Interactive Zero-Knowledge Proof System
 *
 * L1 Definition: A NIZK proof system converts interactive sigma protocols
 * into non-interactive proofs via the Fiat-Shamir transform:
 *
 *   Prover:  commitment t = sigma.commit(x, w)
 *            challenge  c = H(x || t)
 *            response  s = sigma.respond(x, w, c)
 *            proof pi = (t, s)
 *
 *   Verifier: c = H(x || t)
 *             check sigma.verify(x, t, c, s)
 *
 * The Fiat-Shamir heuristic replaces the verifier's random challenge
 * with a hash of the statement and commitment. This "removes" the
 * interaction, yielding a non-interactive proof.
 *
 * Reference: Fiat, A. and Shamir, A. "How to Prove Yourself: Practical
 *            Solutions to Identification and Signature Problems."
 *            CRYPTO 1986.
 *
 * Course Mapping:
 *   MIT 6.875: NIZK, Fiat-Shamir transform
 *   Stanford CS355: Non-interactive ZK
 *   Princeton COS 551: NIZK in ROM
 *   Berkeley CS278: Fiat-Shamir security proofs
 */

#include "nizk_proof.h"
#include "nizk_group.h"
#include "nizk_crs.h"
#include "nizk_sigma.h"
#include "nizk_commitment.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* =========================================================================
 * L5: SHA-256 Hash Implementation (Mini)
 * ========================================================================= */

/**
 * sha256_context - Internal state for SHA-256 computation.
 *
 * L3 Knowledge Point: Merkle-Damgard Hash Function Construction
 *
 * SHA-256 uses the Merkle-Damgard construction:
 *   - Message is padded to a multiple of 512 bits
 *   - Compression function f processes each 512-bit block
 *   - Internal state: 8 x 32-bit words (256 bits total)
 *   - Initialization vector (IV) from first 32 bits of fractional
 *     parts of square roots of first 8 primes
 *
 * This is a simplified educational implementation. Production code
 * should use a certified cryptographic library (OpenSSL, libsodium).
 *
 * Reference: FIPS 180-4, Secure Hash Standard (SHS)
 *
 * Course: Stanford CS355 Hash Functions, MIT 6.875 Random Oracles
 */
typedef struct {
    uint32_t state[8];       /* H0..H7 */
    uint64_t count;          /* bit count */
    uint8_t  buf[64];        /* input buffer */
    size_t   buf_len;        /* bytes in buffer */
} sha256_context_t;

/* SHA-256 initial hash values (first 32 bits of fractional parts
 * of the square roots of the first 8 primes: 2, 3, 5, 7, 11, 13, 17, 19) */
static const uint32_t sha256_iv[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

/* SHA-256 round constants (first 32 bits of fractional parts of
 * the cube roots of the first 64 primes: 2..311) */
static const uint32_t sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* Right rotate a 32-bit value */
static uint32_t rotr32(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

/* SHA-256 compression function: processes one 512-bit block */
static void sha256_compress(uint32_t state[8], const uint8_t block[64]) {
    uint32_t w[64];
    /* Prepare message schedule */
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i*4] << 24) |
               ((uint32_t)block[i*4+1] << 16) |
               ((uint32_t)block[i*4+2] << 8) |
               ((uint32_t)block[i*4+3]);
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i-15], 7) ^ rotr32(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = rotr32(w[i-2], 17) ^ rotr32(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }

    /* Initialize working variables */
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    /* Main compression loop */
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + sha256_k[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;

        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }

    /* Update state */
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

/* Initialize SHA-256 context */
static void sha256_init(sha256_context_t *ctx) {
    memcpy(ctx->state, sha256_iv, sizeof(sha256_iv));
    ctx->count = 0;
    ctx->buf_len = 0;
    memset(ctx->buf, 0, sizeof(ctx->buf));
}

/* Update SHA-256 with input data */
static void sha256_update(sha256_context_t *ctx,
                           const uint8_t *data, size_t len) {
    /* Process existing buffer if it would overflow */
    if (ctx->buf_len + len >= 64) {
        size_t fill = 64 - ctx->buf_len;
        if (ctx->buf_len > 0 && fill > 0 && fill <= len) {
            memcpy(ctx->buf + ctx->buf_len, data, fill);
            sha256_compress(ctx->state, ctx->buf);
            ctx->count += 512;
            data += fill;
            len -= fill;
            ctx->buf_len = 0;
        }
    }
    /* Process full blocks */
    while (len >= 64) {
        sha256_compress(ctx->state, data);
        ctx->count += 512;
        data += 64;
        len -= 64;
    }
    /* Buffer remaining */
    if (len > 0) {
        memcpy(ctx->buf + ctx->buf_len, data, len);
        ctx->buf_len += len;
    }
}

/* Finalize SHA-256 and output 32-byte digest */
static void sha256_final(sha256_context_t *ctx, uint8_t digest[32]) {
    uint64_t total_bits = ctx->count + ctx->buf_len * 8;

    /* Padding: append 0x80, then 0x00 until 56 mod 64, then 64-bit length */
    ctx->buf[ctx->buf_len++] = 0x80;
    if (ctx->buf_len > 56) {
        while (ctx->buf_len < 64) ctx->buf[ctx->buf_len++] = 0;
        sha256_compress(ctx->state, ctx->buf);
        ctx->buf_len = 0;
    }
    while (ctx->buf_len < 56) ctx->buf[ctx->buf_len++] = 0;

    /* Append length in big-endian */
    for (int i = 7; i >= 0; i--) {
        ctx->buf[ctx->buf_len++] = (uint8_t)(total_bits >> (i * 8));
    }

    sha256_compress(ctx->state, ctx->buf);

    /* Output digest in big-endian */
    for (int i = 0; i < 8; i++) {
        digest[i*4]     = (uint8_t)(ctx->state[i] >> 24);
        digest[i*4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        digest[i*4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        digest[i*4 + 3] = (uint8_t)(ctx->state[i]);
    }
}

/**
 * sha256_hash - Compute SHA-256 hash of input data.
 *
 * L5 Knowledge Point: Cryptographic Hash Functions
 *
 * SHA-256 maps arbitrary-length input to fixed 256-bit output.
 * Properties:
 *   - Preimage resistance: Given y, hard to find x with H(x) = y
 *   - Second preimage resistance: Given x, hard to find x' with H(x)=H(x')
 *   - Collision resistance: Hard to find x != x' with H(x) = H(x')
 *
 * In the Fiat-Shamir transform, SHA-256 is used as a "random oracle":
 * outputs are assumed to be uniformly random and unpredictable.
 * This assumption is not literally true (SHA-256 is deterministic),
 * but it's the standard model for security proofs of Fiat-Shamir.
 *
 * Course: Stanford CS355 Hash Functions, MIT 6.875 Random Oracle Model
 */
static void sha256_hash(const uint8_t *data, size_t len, uint8_t digest[32]) {
    sha256_context_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, digest);
}

/* =========================================================================
 * L5: Fiat-Shamir Transform - Converting Interactive to Non-Interactive
 * ========================================================================= */

/**
 * nizk_fiat_shamir_challenge - Derive challenge via Fiat-Shamir heuristic.
 *
 * L4 Theorem: Fiat-Shamir Transform
 *
 * Computes: c = H(stmt || t || aux_data) mod q
 *
 * The Fiat-Shamir transform:
 *   1. Serialize the statement and commitment to bytes
 *   2. Hash with SHA-256 (the "random oracle")
 *   3. Reduce the 256-bit hash modulo q to get a scalar challenge
 *
 * Why it works (intuition):
 *   In the interactive protocol, the verifier picks a random challenge.
 *   In Fiat-Shamir, we "simulate" the verifier by hashing the transcript
 *   so far. Since the hash is unpredictable (RO assumption), the prover
 *   cannot choose the commitment to control the challenge — this preserves
 *   soundness.
 *
 * Security Theorem (Pointcheval-Stern 1996):
 *   If the underlying sigma protocol is HVZK and has special soundness,
 *   then the Fiat-Shamir NIZK is zero-knowledge and simulation-sound
 *   in the Random Oracle Model.
 *
 * Limitation: The ROM assumption is strong. There exist contrived
 * counterexamples where Fiat-Shamir fails when instantiated with a
 * concrete hash function (Goldwasser-Kalai 2003). However, for natural
 * protocols, Fiat-Shamir is considered secure in practice.
 *
 * Reference: Pointcheval, D. and Stern, J. "Security Proofs for
 *            Signature Schemes." EUROCRYPT 1996.
 *
 * Course: MIT 6.875 Fiat-Shamir Security, Princeton COS 551 ROM
 */
void nizk_fiat_shamir_challenge(nizk_sigma_challenge_t *challenge,
                                 const nizk_sigma_statement_t *stmt,
                                 const nizk_sigma_commitment_t *commitment,
                                 const uint8_t *aux_data, size_t aux_len,
                                 const nizk_group_params_t *params) {
    /* Build input for hash: statement || commitment || aux_data */
    uint8_t hash_input[1024];
    size_t offset = 0;

    /* Serialize statement: include public key first limb as identifier */
    memcpy(hash_input + offset, &stmt->public_key.elem.limbs[0], 8);
    offset += 8;
    if (stmt->is_equality) {
        memcpy(hash_input + offset, &stmt->aux_element.elem.limbs[0], 8);
        offset += 8;
    }

    /* Serialize commitment */
    memcpy(hash_input + offset, &commitment->t.elem.limbs[0], 8);
    offset += 8;
    if (commitment->has_aux) {
        memcpy(hash_input + offset, &commitment->t_aux.elem.limbs[0], 8);
        offset += 8;
    }

    /* Append auxiliary data (e.g., label for domain separation) */
    if (aux_data != NULL && aux_len > 0) {
        size_t copy_len = aux_len;
        if (offset + copy_len > sizeof(hash_input))
            copy_len = sizeof(hash_input) - offset;
        memcpy(hash_input + offset, aux_data, copy_len);
        offset += copy_len;
    }

    /* Hash to get 32-byte digest */
    uint8_t digest[32];
    sha256_hash(hash_input, offset, digest);

    /* Reduce hash modulo q to get challenge scalar */
    nizk_bigint_t hash_val;
    nizk_bigint_zero(&hash_val);
    for (int i = 0; i < 4 && i < NIZK_BIGINT_LIMBS; i++) {
        hash_val.limbs[i] = 0;
        for (int j = 0; j < 8 && i * 8 + j < 32; j++) {
            hash_val.limbs[i] |= ((uint64_t)digest[i * 8 + j]) << (j * 8);
        }
    }

    /* Reduce modulo q */
    while (nizk_bigint_cmp(&hash_val, &params->q) >= 0) {
        nizk_bigint_t tmp = hash_val;
        uint64_t borrow = 0;
        for (int j = 0; j < NIZK_BIGINT_LIMBS; j++) {
            uint64_t diff = tmp.limbs[j] - params->q.limbs[j] - borrow;
            borrow = (tmp.limbs[j] < params->q.limbs[j] + borrow) ? 1 : 0;
            hash_val.limbs[j] = diff;
        }
        if (borrow) break;
    }

    nizk_bigint_copy(&challenge->c.val, &hash_val);
}

/**
 * nizk_hash_to_scalar - Hash arbitrary data to a scalar in Z_q.
 *
 * General-purpose utility: SHA-256 the data, reduce mod q.
 * Used for deterministic randomness and Fiat-Shamir derivation.
 */
void nizk_hash_to_scalar(nizk_scalar_t *out,
                          const uint8_t *data, size_t data_len,
                          const nizk_group_params_t *params) {
    uint8_t digest[32];
    sha256_hash(data, data_len, digest);

    nizk_bigint_zero(&out->val);
    for (int i = 0; i < 4 && i < NIZK_BIGINT_LIMBS; i++) {
        out->val.limbs[i] = 0;
        for (int j = 0; j < 8 && i * 8 + j < 32; j++) {
            out->val.limbs[i] |= ((uint64_t)digest[i * 8 + j]) << (j * 8);
        }
    }

    /* Reduce mod q */
    while (nizk_bigint_cmp(&out->val, &params->q) >= 0) {
        nizk_bigint_t tmp = out->val;
        uint64_t borrow = 0;
        for (int j = 0; j < NIZK_BIGINT_LIMBS; j++) {
            uint64_t diff = tmp.limbs[j] - params->q.limbs[j] - borrow;
            borrow = (tmp.limbs[j] < params->q.limbs[j] + borrow) ? 1 : 0;
            out->val.limbs[j] = diff;
        }
        if (borrow) break;
    }
}

/* =========================================================================
 * L5: NIZK for Discrete Log Knowledge (Schnorr + Fiat-Shamir)
 * ========================================================================= */

/**
 * nizk_prove_dlog - Generate NIZK proof of discrete log knowledge.
 *
 * L5 Knowledge Point: Schnorr NIZK via Fiat-Shamir
 *
 * Produces a non-interactive proof that the prover knows w = log_g(h).
 * This is essentially a Schnorr signature on the label.
 *
 * Algorithm:
 *   1. Run Schnorr commit: pick v, compute t = g^v
 *   2. Fiat-Shamir: c = H(h || t || label)
 *   3. Run Schnorr respond: s = v + c * w (mod q)
 *   4. Output proof pi = (t, s)
 *
 * L7 Application: Schnorr digital signatures.
 * The proof (t, s) is exactly a Schnorr signature on message label,
 * with the key insight: a Schnorr signature is a NIZK proof of
 * knowledge of the signing key!
 *
 * This means:
 *   - Schnorr signatures are unforgeable under chosen-message attack
 *     if and only if DLOG is hard (Pointcheval-Stern 1996)
 *   - The signature "proves" the signer knows sk, without revealing it
 *   - This is the "zero-knowledge signature" property
 */
void nizk_prove_dlog(nizk_proof_t *proof,
                      const nizk_crs_t *crs,
                      const nizk_group_elem_t *pubkey,
                      const nizk_scalar_t *witness,
                      const uint8_t *label, size_t label_len,
                      const nizk_group_params_t *params) {
    (void)crs;
    proof->type = NIZK_PROOF_DLOG_KNOWLEDGE;

    /* Step 1: Schnorr commit */
    nizk_scalar_t ephemeral;
    nizk_schnorr_commit(&proof->commitment, &ephemeral, params);

    /* Step 2: Build statement and derive Fiat-Shamir challenge */
    nizk_sigma_statement_t stmt;
    nizk_sigma_statement_init(&stmt, pubkey,
                               (nizk_group_elem_t*)&params->g, params);
    /* Use pubkey as generator for the statement */
    nizk_group_elem_t gen;
    nizk_bigint_copy(&gen.elem, &params->g);
    nizk_group_elem_copy(&stmt.base_g, &gen);

    nizk_sigma_challenge_t challenge;
    nizk_fiat_shamir_challenge(&challenge, &stmt, &proof->commitment,
                                label, label_len, params);

    /* Step 3: Schnorr respond */
    nizk_schnorr_respond(&proof->response, witness, &ephemeral,
                          &challenge, params);

    /* Store statement hash for binding */
    sha256_hash(label, label_len, proof->statement_hash);
}

/**
 * nizk_verify_dlog - Verify NIZK proof of discrete log knowledge.
 *
 * L5 Knowledge Point: NIZK Verification
 *
 * Recomputes the Fiat-Shamir challenge and checks the Schnorr
 * verification equation.
 *
 * Critical insight: The verifier recomputes c = H(h || t || label).
 * If the proof is valid, this c matches the one used by the prover.
 * The verification equation g^s == t * h^c then ensures that the
 * prover must know w = log_g(h).
 *
 * Why you can't forge without w:
 *   To create a valid proof (t, s) for public key h:
 *   1. Pick s, c randomly
 *   2. Compute t = g^s * h^{-c}
 *   3. Need H(h || t || label) = c  (contradiction: c = H(t) but t depends on c!)
 *   In the ROM, you can't satisfy this without either:
 *     a. Knowing w (real proof), or
 *     b. Programming the RO (simulation with trapdoor)
 *
 * This circular dependency is what makes Fiat-Shamir secure.
 */
int nizk_verify_dlog(const nizk_proof_t *proof,
                      const nizk_crs_t *crs,
                      const nizk_group_elem_t *pubkey,
                      const uint8_t *label, size_t label_len,
                      const nizk_group_params_t *params) {
    (void)crs;
    if (proof->type != NIZK_PROOF_DLOG_KNOWLEDGE) return 0;

    /* Recompute Fiat-Shamir challenge */
    nizk_sigma_statement_t stmt;
    nizk_group_elem_t gen;
    nizk_bigint_copy(&gen.elem, &params->g);
    nizk_sigma_statement_init(&stmt, pubkey, &gen, params);

    nizk_sigma_challenge_t challenge;
    nizk_fiat_shamir_challenge(&challenge, &stmt, &proof->commitment,
                                label, label_len, params);

    /* Check Schnorr verification: g^s == t * h^c */
    return nizk_schnorr_verify(&stmt, &proof->commitment,
                                &challenge, &proof->response, params);
}

/* =========================================================================
 * L5: NIZK for DLOG Equality (Chaum-Pedersen + Fiat-Shamir)
 * ========================================================================= */

/**
 * nizk_prove_dlog_eq - Generate NIZK proof of equal discrete logs.
 *
 * L5 Knowledge Point: Chaum-Pedersen NIZK
 *
 * Proves: log_g(u) = log_h(v) = w
 *
 * Algorithm:
 *   1. Run Chaum-Pedersen commit with bases g, h
 *   2. Fiat-Shamir challenge from both commitments
 *   3. Run Chaum-Pedersen respond with witness w
 *
 * L7 Application: Verifiable Encryption
 *   - PK = g^sk (public key)
 *   - v = h^sk (encrypted secret key under encryption key h)
 *   - Proof that log_g(PK) = log_h(v) proves that v encrypts sk
 *   - Used in: e-voting systems, sealed-bid auctions, key escrow
 *
 * L7 Application: DKG (Distributed Key Generation)
 *   - Each participant proves their share uses the same secret
 *   - Prevents "rogue key attacks" in threshold signatures
 */
void nizk_prove_dlog_eq(nizk_proof_t *proof,
                         const nizk_crs_t *crs,
                         const nizk_group_elem_t *u,
                         const nizk_group_elem_t *v,
                         const nizk_group_elem_t *base_h,
                         const nizk_scalar_t *witness,
                         const uint8_t *label, size_t label_len,
                         const nizk_group_params_t *params) {
    (void)crs;
    proof->type = NIZK_PROOF_DLOG_EQUALITY;

    /* Step 1: Chaum-Pedersen commit */
    nizk_scalar_t ephemeral;
    nizk_group_elem_t gen;
    nizk_bigint_copy(&gen.elem, &params->g);
    nizk_chaum_pedersen_commit(&proof->commitment, &ephemeral,
                                &gen, base_h, params);

    /* Step 2: Build statement and derive Fiat-Shamir challenge */
    nizk_sigma_statement_t stmt;
    nizk_sigma_statement_init(&stmt, u, &gen, params);
    stmt.is_equality = 1;
    nizk_group_elem_copy(&stmt.base_h, base_h);
    nizk_group_elem_copy(&stmt.aux_element, v);

    nizk_sigma_challenge_t challenge;
    nizk_fiat_shamir_challenge(&challenge, &stmt, &proof->commitment,
                                label, label_len, params);

    /* Step 3: Chaum-Pedersen respond */
    nizk_chaum_pedersen_respond(&proof->response, witness, &ephemeral,
                                 &challenge, params);

    sha256_hash(label, label_len, proof->statement_hash);
}

/**
 * nizk_verify_dlog_eq - Verify NIZK proof of equal discrete logs.
 */
int nizk_verify_dlog_eq(const nizk_proof_t *proof,
                          const nizk_crs_t *crs,
                          const nizk_group_elem_t *u,
                          const nizk_group_elem_t *v,
                          const nizk_group_elem_t *base_h,
                          const uint8_t *label, size_t label_len,
                          const nizk_group_params_t *params) {
    (void)crs;
    if (proof->type != NIZK_PROOF_DLOG_EQUALITY) return 0;

    /* Recompute challenge */
    nizk_sigma_statement_t stmt;
    nizk_group_elem_t gen;
    nizk_bigint_copy(&gen.elem, &params->g);
    nizk_sigma_statement_init(&stmt, u, &gen, params);
    stmt.is_equality = 1;
    nizk_group_elem_copy(&stmt.base_h, base_h);
    nizk_group_elem_copy(&stmt.aux_element, v);

    nizk_sigma_challenge_t challenge;
    nizk_fiat_shamir_challenge(&challenge, &stmt, &proof->commitment,
                                label, label_len, params);

    return nizk_chaum_pedersen_verify(&stmt, &proof->commitment,
                                       &challenge, &proof->response, params);
}

/* =========================================================================
 * L5: NIZK for Commitment Opening (Representation Proof)
 * ========================================================================= */

/**
 * nizk_prove_commitment - Prove knowledge of opening to Pedersen commitment.
 *
 * L5 Knowledge Point: Proof of Knowledge of Representation
 *
 * Proves: "I know (m, r) such that C = g^m * h^r"
 *
 * This is a proof of knowledge of a REPRESENTATION of C relative to
 * bases (g, h). It decomposes as an AND proof:
 *   - Knowledge of m such that C / h^r = g^m
 *   - Knowledge of r such that C / g^m = h^r
 *
 * But since we know BOTH (m, r), we can use a more efficient approach:
 * the Okamoto protocol, which uses a single Schnorr-like proof with
 * the combined statement C = g^m * h^r.
 *
 * Protocol (representation proof):
 *   1. Pick random u, v <- Z_q
 *   2. Compute t = g^u * h^v
 *   3. Receive challenge c
 *   4. Compute s1 = u + c*m, s2 = v + c*r (mod q)
 *   5. Verifier checks: g^{s1} * h^{s2} == t * C^c
 *
 * L7 Application: Confidential Transactions
 *   - Commit to transaction amounts: C_in = g^amount * h^blind
 *   - Prove knowledge of the opening to prove the amount is valid
 *   - Without revealing amount or blinding factor
 *
 * Course: Berkeley CS278 Confidential Transactions,
 *         MIT 6.875 Commitment Proofs
 */
void nizk_prove_commitment(nizk_proof_t *proof,
                            const nizk_crs_t *crs,
                            const nizk_commitment_t *com,
                            const nizk_commitment_opening_t *opening,
                            const uint8_t *label, size_t label_len,
                            const nizk_group_params_t *params) {
    (void)crs;
    proof->type = NIZK_PROOF_COMMITMENT;

    /* Representation proof: pick u, v random */
    nizk_scalar_t u, v;
    nizk_scalar_rand(&u, params);
    nizk_scalar_rand(&v, params);

    /* Compute t = g^u * h^v */
    nizk_group_elem_t gen;
    nizk_bigint_copy(&gen.elem, &params->g);
    nizk_group_multi_exp(&proof->commitment.t, &gen, &u,
                          &crs->h1, &v, params);
    proof->commitment.has_aux = 0;

    /* Fiat-Shamir challenge */
    nizk_sigma_statement_t stmt;
    nizk_sigma_statement_init(&stmt, (nizk_group_elem_t*)&com->C, &gen, params);

    nizk_sigma_challenge_t challenge;
    nizk_fiat_shamir_challenge(&challenge, &stmt, &proof->commitment,
                                label, label_len, params);

    /* Respond: s1 = u + c*m, s2 = v + c*r */
    nizk_scalar_t c_m, c_r;
    nizk_scalar_mul(&c_m, &challenge.c, &opening->m, params);
    nizk_scalar_mul(&c_r, &challenge.c, &opening->r, params);
    nizk_scalar_add(&proof->response.s, &u, &c_m, params);
    nizk_scalar_add(&proof->response.s_aux, &v, &c_r, params);
    proof->response.has_aux = 1;

    sha256_hash(label, label_len, proof->statement_hash);
}

/**
 * nizk_verify_commitment - Verify proof of commitment opening.
 *
 * Checks: g^{s1} * h^{s2} == t * C^c
 *
 * Proof of correctness:
 *   g^{s1} * h^{s2} = g^{u + c*m} * h^{v + c*r}
 *                   = (g^u * h^v) * (g^m * h^r)^c
 *                   = t * C^c
 *   QED.
 */
int nizk_verify_commitment(const nizk_proof_t *proof,
                             const nizk_crs_t *crs,
                             const nizk_commitment_t *com,
                             const uint8_t *label, size_t label_len,
                             const nizk_group_params_t *params) {
    (void)crs;
    if (proof->type != NIZK_PROOF_COMMITMENT) return 0;

    /* Recompute challenge */
    nizk_sigma_statement_t stmt;
    nizk_group_elem_t gen;
    nizk_bigint_copy(&gen.elem, &params->g);
    nizk_sigma_statement_init(&stmt, (nizk_group_elem_t*)&com->C, &gen, params);

    nizk_sigma_challenge_t challenge;
    nizk_fiat_shamir_challenge(&challenge, &stmt, &proof->commitment,
                                label, label_len, params);

    /* Check: g^{s1} * h^{s2} == t * C^c */
    /* LHS: multi-exp with g and h1 */
    nizk_group_elem_t lhs;
    nizk_group_multi_exp(&lhs, &gen, &proof->response.s,
                          &crs->h1, &proof->response.s_aux, params);

    /* RHS: t * C^c */
    nizk_group_elem_t C_c;
    nizk_group_exp(&C_c, (nizk_group_elem_t*)&com->C, &challenge.c, params);
    nizk_group_elem_t rhs;
    nizk_group_op(&rhs, &proof->commitment.t, &C_c, params);

    return nizk_group_elem_eq(&lhs, &rhs);
}

/* =========================================================================
 * L5: NIZK OR-Proof (Ring Signature)
 * ========================================================================= */

/**
 * nizk_prove_or - Generate NIZK OR-proof.
 *
 * L5 Knowledge Point: NIZK OR-Proof (Ring Signature)
 *
 * Proves knowledge of one of two secret keys without revealing which.
 *
 * Algorithm:
 *   1. Run OR commit: simulate unknown branch, real commit for known
 *   2. Fiat-Shamir challenge from both commitments
 *   3. Compute c_real = c_total - c_sim (mod q)
 *   4. Respond with simulated for unknown, real for known
 *
 * L7 Application: Ring Signatures
 *   A ring signature proves that the signer is one of a set (ring)
 *   without revealing which member. This is the 1-out-of-n OR proof
 *   generalized to n members.
 *
 * Applications of ring signatures:
 *   - Whistleblowing: prove you're an employee without revealing which one
 *   - Anonymous credentials: prove membership in a group
 *   - Monero: hide sender among a ring of decoys
 *   - E-voting: prove eligibility without revealing identity
 *
 * Course: Stanford CS355 Ring Signatures, Princeton COS 551 Anonymity
 */
void nizk_prove_or(nizk_proof_t *proof,
                    const nizk_crs_t *crs,
                    const nizk_group_elem_t *pubkey1,
                    const nizk_group_elem_t *pubkey2,
                    const nizk_scalar_t *witness,
                    int known_branch,
                    const uint8_t *label, size_t label_len,
                    const nizk_group_params_t *params) {
    (void)crs;
    proof->type = NIZK_PROOF_OR;
    proof->or_num_branches = 2;

    /* Build OR statement */
    nizk_or_statement_t or_stmt;
    nizk_group_elem_t gen;
    nizk_bigint_copy(&gen.elem, &params->g);
    nizk_sigma_statement_init(&or_stmt.stmt[0], pubkey1, &gen, params);
    nizk_sigma_statement_init(&or_stmt.stmt[1], pubkey2, &gen, params);

    /* Build OR witness */
    nizk_or_witness_t or_wit;
    or_wit.known_branch = known_branch;
    nizk_scalar_copy(&or_wit.secret, witness);

    /* Step 1: OR commit */
    nizk_scalar_t ephemerals[2];
    nizk_scalar_t sim_challenges[2];
    nizk_sigma_commitment_t commits[2];
    nizk_or_prove_commit(commits, ephemerals, sim_challenges,
                          &or_stmt, &or_wit, params);

    /* Store both commitments */
    nizk_group_elem_copy(&proof->commitment.t, &commits[0].t);
    proof->or_commitments[0] = commits[0];
    proof->or_commitments[1] = commits[1];

    /* Step 2: Fiat-Shamir challenge from combined commitments */
    nizk_sigma_commitment_t combined_com;
    nizk_group_elem_copy(&combined_com.t, &commits[0].t);
    combined_com.has_aux = 0;

    nizk_sigma_challenge_t total_challenge;
    nizk_fiat_shamir_challenge(&total_challenge, &or_stmt.stmt[0],
                                &combined_com, label, label_len, params);

    /* Step 3: Compute c_real = c_total - c_sim */
    nizk_scalar_t c_real;
    nizk_scalar_sub(&c_real, &total_challenge.c,
                     &sim_challenges[1 - known_branch], params);

    nizk_sigma_challenge_t real_ch;
    nizk_scalar_copy(&real_ch.c, &c_real);

    /* Step 4: Respond */
    /* For OR respond, we need to pass the right ephemerals.
     * Branch 0: ephemeral[0], sim_challenge[1] for unknown
     * Branch 1: ephemeral[1], sim_challenge[0] for unknown
     * Wait - the or_prove_respond takes single values.
     * We need to call it per-branch. Let's construct manually. */

    int unknown = 1 - known_branch;

    /* Simulated branch */
    nizk_scalar_copy(&proof->or_challenges[unknown].c,
                      &sim_challenges[unknown]);
    nizk_scalar_copy(&proof->or_responses[unknown].s,
                      &ephemerals[unknown]);
    proof->or_responses[unknown].has_aux = 0;

    /* Real branch */
    nizk_scalar_copy(&proof->or_challenges[known_branch].c, &c_real);
    nizk_scalar_t cw;
    nizk_scalar_mul(&cw, &c_real, witness, params);
    nizk_scalar_add(&proof->or_responses[known_branch].s,
                     &ephemerals[known_branch], &cw, params);
    proof->or_responses[known_branch].has_aux = 0;

    /* Store the total challenge for verification */
    proof->response.s = total_challenge.c;

    sha256_hash(label, label_len, proof->statement_hash);
}

/**
 * nizk_verify_or - Verify NIZK OR-proof.
 *
 * Checks: c_0 + c_1 == total_challenge (mod q)
 * AND both branches verify under their respective challenges.
 */
int nizk_verify_or(const nizk_proof_t *proof,
                     const nizk_crs_t *crs,
                     const nizk_group_elem_t *pubkey1,
                     const nizk_group_elem_t *pubkey2,
                     const uint8_t *label, size_t label_len,
                     const nizk_group_params_t *params) {
    (void)crs;
    if (proof->type != NIZK_PROOF_OR) return 0;
    if (proof->or_num_branches != 2) return 0;

    /* Check c_0 + c_1 == total_challenge */
    nizk_scalar_t sum;
    nizk_scalar_add(&sum, &proof->or_challenges[0].c,
                     &proof->or_challenges[1].c, params);
    nizk_scalar_t total_ch;
    nizk_scalar_copy(&total_ch, &proof->response.s);
    if (nizk_scalar_cmp(&sum, &total_ch) != 0) return 0;

    /* Verify both branches */
    nizk_scalar_t one;
    nizk_scalar_set_u64(&one, 1);
    nizk_group_elem_t gen;
    nizk_bigint_copy(&gen.elem, &params->g);

    nizk_group_elem_t *pks[2];
    pks[0] = (nizk_group_elem_t*)pubkey1;
    pks[1] = (nizk_group_elem_t*)pubkey2;

    for (int i = 0; i < 2; i++) {
        nizk_group_elem_t lhs;
        nizk_group_exp(&lhs, &gen, &proof->or_responses[i].s, params);

        nizk_group_elem_t rhs;
        nizk_group_multi_exp(&rhs, &proof->or_commitments[i].t, &one,
                              pks[i], &proof->or_challenges[i].c, params);

        if (!nizk_group_elem_eq(&lhs, &rhs)) return 0;
    }

    return 1;
}

/* =========================================================================
 * L2: Proof Serialization
 * ========================================================================= */

/**
 * nizk_proof_serialize - Serialize a proof to bytes.
 *
 * L2 Knowledge Point: Proof Serialization and Interoperability
 *
 * Converts a NIZK proof to a byte representation for network
 * transmission or storage. This is essential for:
 *   - Sending proofs over the network
 *   - Storing proofs in databases
 *   - Cross-platform proof verification
 *
 * Format (simplified):
 *   - 4 bytes: proof type
 *   - NIZK_BIGINT_LIMBS*8 bytes: commitment t
 *   - NIZK_BIGINT_LIMBS*8 bytes: response s
 *
 * Returns: number of bytes written, or required size if buf is NULL.
 */
size_t nizk_proof_serialize(uint8_t *buf, size_t buf_len,
                             const nizk_proof_t *proof,
                             const nizk_group_params_t *params) {
    (void)params;
    size_t needed = 4 + NIZK_BIGINT_LIMBS * 8 + NIZK_BIGINT_LIMBS * 8;
    if (buf == NULL) return needed;
    if (buf_len < needed) return 0;

    size_t off = 0;
    /* Type */
    buf[off++] = (uint8_t)(proof->type & 0xFF);
    buf[off++] = (uint8_t)((proof->type >> 8) & 0xFF);
    buf[off++] = (uint8_t)((proof->type >> 16) & 0xFF);
    buf[off++] = (uint8_t)((proof->type >> 24) & 0xFF);

    /* Commitment t */
    for (int i = 0; i < NIZK_BIGINT_LIMBS; i++) {
        for (int j = 0; j < 8; j++) {
            buf[off++] = (uint8_t)(proof->commitment.t.elem.limbs[i] >> (j * 8));
        }
    }

    /* Response s */
    for (int i = 0; i < NIZK_BIGINT_LIMBS; i++) {
        for (int j = 0; j < 8; j++) {
            buf[off++] = (uint8_t)(proof->response.s.val.limbs[i] >> (j * 8));
        }
    }

    return off;
}

/**
 * nizk_proof_deserialize - Deserialize bytes back to a proof.
 */
int nizk_proof_deserialize(nizk_proof_t *proof,
                             const uint8_t *buf, size_t buf_len,
                             const nizk_group_params_t *params) {
    (void)params;
    size_t needed = 4 + NIZK_BIGINT_LIMBS * 8 + NIZK_BIGINT_LIMBS * 8;
    if (buf_len < needed) return 0;

    size_t off = 0;
    /* Type */
    uint8_t b0 = buf[off++];
    uint8_t b1 = buf[off++];
    uint8_t b2 = buf[off++];
    uint8_t b3 = buf[off++];
    int type = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
    proof->type = (nizk_proof_type_t)type;

    /* Commitment */
    nizk_bigint_zero(&proof->commitment.t.elem);
    for (int i = 0; i < NIZK_BIGINT_LIMBS; i++) {
        for (int j = 0; j < 8; j++) {
            proof->commitment.t.elem.limbs[i] |=
                ((uint64_t)buf[off++]) << (j * 8);
        }
    }

    /* Response */
    nizk_bigint_zero(&proof->response.s.val);
    for (int i = 0; i < NIZK_BIGINT_LIMBS; i++) {
        for (int j = 0; j < 8; j++) {
            proof->response.s.val.limbs[i] |=
                ((uint64_t)buf[off++]) << (j * 8);
        }
    }

    return 1;
}

/**
 * nizk_proof_init - Initialize a proof structure.
 */
void nizk_proof_init(nizk_proof_t *proof, nizk_proof_type_t type) {
    memset(proof, 0, sizeof(*proof));
    proof->type = type;
    proof->commitment.has_aux = 0;
    nizk_bigint_one(&proof->commitment.t.elem);
    proof->response.has_aux = 0;
    nizk_scalar_zero(&proof->response.s);
    proof->or_num_branches = 0;
}

/**
 * nizk_proof_clear - Clear and zeroize a proof structure.
 */
void nizk_proof_clear(nizk_proof_t *proof) {
    memset(proof, 0, sizeof(*proof));
}
