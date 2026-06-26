/*
 * commitment.c -- Bit Commitment Schemes for GMW Protocol
 *
 * Implements two commitment schemes:
 *   A) Hash-based (SHA-256 style): computationally binding, statistically hiding
 *   B) Pedersen: perfectly hiding, computationally binding (safe-prime group)
 *
 * L1: Bit commitment = two-phase (Commit, Reveal) with Hiding + Binding
 * L2: Hash-based vs Pedersen: computational vs statistical properties
 * L3: Hash functions; discrete log in safe-prime groups Z_p*
 * L4: Binding = collision resistance; Hiding = one-wayness / DLOG
 * L7: Cryptographic commitment schemes as foundation for ZK proofs
 *
 * Reference:
 *   Goldreich (2004) FOC I, sec 4.4.1
 *   Pedersen (CRYPTO 1991) "Non-Interactive and Information-Theoretic
 *     Secure Verifiable Secret Sharing"
 *   Naor (1991) "Bit Commitment Using Pseudorandomness"
 *
 * Courses: MIT 6.876, Stanford CS255, Berkeley CS276
 */
#include "commitment.h"
#include "graph_3coloring.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

/* ================================================================
 * Simple Hash Function (Merkle-Damgard style, NOT cryptographic)
 *
 * This is a simplified hash for demonstration purposes.
 * In production, use SHA-256 or SHA-3.
 * The structure matches the interface expected by the GMW protocol.
 *
 * The core operation is a compression function f: {0,1}^256 x {0,1}^256 -> {0,1}^256
 * using XOR-rotate mixing (inspired by SHA-256's message schedule).
 * ================================================================ */

static uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

static void compress256(uint32_t state[8], const uint32_t block[8]) {
    /* Simple compression: XOR block into state, then 4 rounds of mixing */
    for (int i = 0; i < 8; i++) state[i] ^= block[i];
    for (int round = 0; round < 4; round++) {
        for (int i = 0; i < 8; i++) {
            state[i] = rotl32(state[i] ^ state[(i+1)&7], 7)
                     + rotl32(state[(i+2)&7] ^ state[(i+3)&7], 11)
                     + rotl32(state[(i+4)&7], 13);
        }
        state[0] ^= 0x9e3779b9u * (uint32_t)(round + 1);
    }
}

HashDigest hash256_compute(const uint8_t* data, size_t len) {
    HashDigest h;
    memset(&h, 0, sizeof(h));

    uint32_t state[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
    };

    /* Process full 32-byte blocks */
    size_t pos = 0;
    while (pos + 32 <= len) {
        uint32_t block[8];
        for (int i = 0; i < 8; i++) {
            block[i] = ((uint32_t)data[pos + 4*i] << 24)
                     | ((uint32_t)data[pos + 4*i + 1] << 16)
                     | ((uint32_t)data[pos + 4*i + 2] << 8)
                     | ((uint32_t)data[pos + 4*i + 3]);
        }
        compress256(state, block);
        pos += 32;
    }

    /* Padding: 0x80, then zeros, then 64-bit length in bits */
    uint8_t pad[64];
    size_t pad_len = 0;
    size_t rem = len - pos;
    memcpy(pad, data + pos, rem);
    pad_len += rem;
    pad[pad_len++] = 0x80;
    while (pad_len % 32 != 24) pad[pad_len++] = 0;
    /* Append bit length as big-endian 64-bit */
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 7; i >= 0; i--) {
        pad[pad_len++] = (uint8_t)(bits >> (8 * i));
    }

    /* Process padded blocks */
    for (size_t i = 0; i < pad_len; i += 32) {
        uint32_t block[8];
        for (int j = 0; j < 8; j++) {
            block[j] = ((uint32_t)pad[i + 4*j] << 24)
                     | ((uint32_t)pad[i + 4*j + 1] << 16)
                     | ((uint32_t)pad[i + 4*j + 2] << 8)
                     | ((uint32_t)pad[i + 4*j + 3]);
        }
        compress256(state, block);
    }

    /* Output: state as HashDigest */
    for (int i = 0; i < HASH_DIGEST_WORDS; i++) {
        h.w[i] = state[i];
    }
    return h;
}

/*
 * Compute hash over an int + nonce.
 * Packs: [b as uint8_t][nonce bytes] then hashes.
 */
static HashDigest hash_bit_and_nonce(uint8_t b, const CommitNonce* nonce) {
    uint8_t buf[1 + COMMIT_NONCE_BYTES];
    buf[0] = b;
    memcpy(buf + 1, nonce->nonce, COMMIT_NONCE_BYTES);
    return hash256_compute(buf, sizeof(buf));
}

/*
 * Hash an int + nonce. Encodes int as 4 bytes big-endian.
 */
static HashDigest hash_int_and_nonce(int value, const CommitNonce* nonce) {
    uint8_t buf[4 + COMMIT_NONCE_BYTES];
    buf[0] = (uint8_t)(value >> 24);
    buf[1] = (uint8_t)(value >> 16);
    buf[2] = (uint8_t)(value >> 8);
    buf[3] = (uint8_t)(value);
    memcpy(buf + 4, nonce->nonce, COMMIT_NONCE_BYTES);
    return hash256_compute(buf, sizeof(buf));
}

/* ================================================================
 * Hash-Based Commitment Operations
 * ================================================================ */

/*
 * Commit to a bit b = 0 or 1 using hash-based scheme.
 * c = H(b || nonce)
 *
 * Hiding: Given c, cannot determine b without knowing nonce
 * Binding: Cannot find nonce2 s.t. H(1-b || nonce2) = c (collision resistance)
 *
 * Complexity: O(1) hash
 */
HashDigest commit_bit(uint8_t b, const CommitNonce* nonce) {
    return hash_bit_and_nonce(b, nonce);
}

/*
 * Commit to an integer value.
 * c = H(value || nonce)
 */
HashDigest commit_int(int value, const CommitNonce* nonce) {
    return hash_int_and_nonce(value, nonce);
}

/*
 * Commit to a color (0,1,2).
 * c = H(color || nonce)
 */
HashDigest commit_color(int color, const CommitNonce* nonce) {
    return hash_int_and_nonce(color, nonce);
}

/*
 * Verify a bit commitment.
 * Recompute c' = H(b || nonce) and check c' == commitment.
 * Returns 1 if valid, 0 otherwise.
 */
int commit_verify_bit(uint8_t b, const CommitNonce* nonce,
                       const HashDigest* commitment) {
    HashDigest recomputed = hash_bit_and_nonce(b, nonce);
    return hashdigest_equals(&recomputed, commitment);
}

/*
 * Verify an integer commitment.
 */
int commit_verify_int(int value, const CommitNonce* nonce,
                       const HashDigest* commitment) {
    HashDigest recomputed = hash_int_and_nonce(value, nonce);
    return hashdigest_equals(&recomputed, commitment);
}

/*
 * Verify a color commitment.
 */
int commit_verify_color(int color, const CommitNonce* nonce,
                         const HashDigest* commitment) {
    HashDigest recomputed = hash_int_and_nonce(color, nonce);
    return hashdigest_equals(&recomputed, commitment);
}

/*
 * Generate commitments for an entire color array (one per vertex).
 * Returns malloc'd array of HashDigest (size n).
 * Caller must free with free().
 *
 * Complexity: O(n) hashes
 */
HashDigest* commit_color_array(const int* colors, int n,
                                const CommitNonce* nonces) {
    if (!colors || n <= 0 || !nonces) return NULL;
    HashDigest* commits = (HashDigest*)malloc((size_t)n * sizeof(HashDigest));
    if (!commits) return NULL;
    for (int i = 0; i < n; i++) {
        commits[i] = commit_color(colors[i], &nonces[i]);
    }
    return commits;
}

/*
 * Verify two revealed colors for an edge in the GMW protocol.
 * The verifier checks:
 *   1. commit_color(color_u, nonce_u) == all_commitments[u]
 *   2. commit_color(color_v, nonce_v) == all_commitments[v]
 *   3. color_u != color_v (different colors on edge endpoints)
 *   4. color_u, color_v in {0,1,2}
 */
int commit_verify_edge(const HashDigest* all_commitments, int u, int v,
                        int color_u, int color_v,
                        const CommitNonce* nonce_u,
                        const CommitNonce* nonce_v) {
    if (!all_commitments || !nonce_u || !nonce_v) return 0;
    if (color_u < 0 || color_u >= NUM_COLORS) return 0;
    if (color_v < 0 || color_v >= NUM_COLORS) return 0;
    if (color_u == color_v) return 0;

    if (!commit_verify_color(color_u, nonce_u, &all_commitments[u])) return 0;
    if (!commit_verify_color(color_v, nonce_v, &all_commitments[v])) return 0;

    return 1;
}

/* ================================================================
 * Nonce Generation
 * ================================================================ */

/*
 * Generate a random nonce for a commitment.
 * Uses rand() seeded by current time + counter.
 * In production: use /dev/urandom or a CSPRNG.
 *
 * Complexity: O(1)
 */
int commit_generate_nonce(CommitNonce* nonce) {
    if (!nonce) return 0;
    static int seeded = 0;
    if (!seeded) { srand((unsigned int)time(NULL)); seeded = 1; }
    for (int i = 0; i < COMMIT_NONCE_BYTES; i++) {
        nonce->nonce[i] = (uint8_t)(rand() & 0xFF);
    }
    return 1;
}

/*
 * Generate n random nonces.
 * Returns malloc'd array of CommitNonce.
 */
CommitNonce* commit_generate_nonces(int n) {
    if (n <= 0) return NULL;
    CommitNonce* nonces = (CommitNonce*)malloc((size_t)n * sizeof(CommitNonce));
    if (!nonces) return NULL;
    for (int i = 0; i < n; i++) {
        commit_generate_nonce(&nonces[i]);
    }
    return nonces;
}

/*
 * Derive a deterministic nonce from a seed and index.
 * Uses hash-based derivation: nonce = H(seed || index).
 * This ensures reproducibility for testing/simulation.
 */
void commit_nonce_from_seed(CommitNonce* nonce, uint64_t seed, int index) {
    if (!nonce) return;
    uint8_t buf[16];
    for (int i = 0; i < 8; i++) buf[i] = (uint8_t)(seed >> (8 * (7 - i)));
    buf[8]  = (uint8_t)(index >> 24);
    buf[9]  = (uint8_t)(index >> 16);
    buf[10] = (uint8_t)(index >> 8);
    buf[11] = (uint8_t)(index);
    buf[12] = 0; buf[13] = 0; buf[14] = 0; buf[15] = 0;

    HashDigest h = hash256_compute(buf, 16);
    memcpy(nonce->nonce, h.w, COMMIT_NONCE_BYTES);
}

/*
 * Free an array of nonces.
 */
void commit_free_nonces(CommitNonce* nonces) {
    free(nonces);
}

/* ================================================================
 * Pedersen Commitment Scheme
 *
 * Pedersen commitment in a safe-prime group Z_p* of order q:
 *   Let p = 2q + 1 for primes p, q (safe prime)
 *   Let g, h be generators of the q-order subgroup
 *   Commit(m, r) = g^m * h^r mod p
 *
 * Perfectly hiding: for any m, r -> g^m * h^r is uniform in the subgroup
 *   because h^r is a random group element
 * Computationally binding: breaking binding = computing discrete log of h base g
 *
 * Reference: Pedersen (CRYPTO 1991)
 * ================================================================ */

/*
 * Safe prime: p = 2q + 1 where p, q are prime.
 * Using a small safe prime for demonstration: p = 23, q = 11
 * (2*11+1 = 23, both 23 and 11 are prime)
 *
 * For the q-order subgroup of Z_23*:
 *   Z_23* has order 22 = 2*11
 *   The subgroup of order q=11: {g^0, g^1, ..., g^10} for generator g
 *   g = 2 has order 11 in Z_23* (since 2^11 = 2048 = 1 mod 23)
 *   h = 3 also has order 11
 *
 * For production: use 2048-bit or larger safe primes.
 */
#define PEDERSEN_P 23u
#define PEDERSEN_Q 11u
#define PEDERSEN_G 2u
#define PEDERSEN_H 3u

/*
 * Modular exponentiation: base^exp mod mod.
 * Uses square-and-multiply algorithm.
 * Complexity: O(log exp) multiplications.
 *
 * This is a general-purpose modular exponentiation for small moduli.
 * For large moduli, use Montgomery multiplication.
 */
static uint64_t mod_pow(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp & 1) result = (result * base) % mod;
        base = (base * base) % mod;
        exp >>= 1;
    }
    return result;
}

/*
 * Create Pedersen parameters (safe-prime group).
 * Returns malloc'd PedersenParams with p, q, g, h set.
 */
PedersenParams* pedersen_params_create(void) {
    PedersenParams* params = (PedersenParams*)malloc(sizeof(PedersenParams));
    if (!params) return NULL;
    bignum256_from_int(&params->p, PEDERSEN_P);
    bignum256_from_int(&params->q, PEDERSEN_Q);
    bignum256_from_int(&params->g, PEDERSEN_G);
    bignum256_from_int(&params->h, PEDERSEN_H);
    return params;
}

void pedersen_params_free(PedersenParams* params) {
    free(params);
}

/*
 * Pedersen commitment: C = g^m * h^r mod p.
 *
 * Perfectly hiding: For any m1, m2, there exists r' s.t. g^m1 h^r = g^m2 h^r'
 *   Proof: Set r' = r + (m1 - m2) * dlog_g(h)^{-1} mod q
 *   Since r is uniform, r' is uniform -> distributions identical
 *
 * Computationally binding: If adversary finds (m1,r1) != (m2,r2) with
 *   g^m1 h^r1 = g^m2 h^r2, then g^(m1-m2) = h^(r2-r1)
 *   => h = g^((m1-m2)*(r2-r1)^{-1} mod q), i.e., adversary computed dlog_g(h)
 */
PedersenCommitment pedersen_commit(const PedersenParams* params,
                                    const BigNum256* message,
                                    const BigNum256* randomness) {
    PedersenCommitment c;
    memset(&c, 0, sizeof(c));

    if (!params || !message || !randomness) return c;

    uint64_t m = message->value[0] % PEDERSEN_Q;
    uint64_t r = randomness->value[0] % PEDERSEN_Q;

    uint64_t gm = mod_pow(PEDERSEN_G, m, PEDERSEN_P);
    uint64_t hr = mod_pow(PEDERSEN_H, r, PEDERSEN_P);
    uint64_t result = (gm * hr) % PEDERSEN_P;

    bignum256_from_int(&c.value, result);
    return c;
}

/*
 * Verify a Pedersen commitment given the opening.
 * Checks: C == g^m * h^r mod p.
 */
int pedersen_verify(const PedersenParams* params,
                     const PedersenCommitment* commitment,
                     const PedersenOpening* opening) {
    if (!params || !commitment || !opening) return 0;

    PedersenCommitment recomputed = pedersen_commit(params,
        &opening->message, &opening->randomness);

    return bignum256_equals(&commitment->value, &recomputed.value);
}

/*
 * Convenience: commit to an integer value.
 */
PedersenCommitment pedersen_commit_int(const PedersenParams* params,
                                        int value, const BigNum256* randomness) {
    BigNum256 msg;
    bignum256_from_int(&msg, (uint64_t)(value >= 0 ? value : -value));
    return pedersen_commit(params, &msg, randomness);
}

/*
 * Convenience: verify integer commitment.
 */
int pedersen_verify_int(const PedersenParams* params,
                         const PedersenCommitment* commitment,
                         int value, const BigNum256* randomness) {
    PedersenOpening opening;
    bignum256_from_int(&opening.message, (uint64_t)(value >= 0 ? value : -value));
    memcpy(&opening.randomness, randomness, sizeof(BigNum256));
    return pedersen_verify(params, commitment, &opening);
}

/* ================================================================
 * Big Number (256-bit) Operations
 *
 * Simple 256-bit integer arithmetic for Pedersen scheme.
 * Represented as 8 uint32_t words (little-endian within words).
 * ================================================================ */

/*
 * Set big number from uint64_t.
 */
void bignum256_from_int(BigNum256* out, uint64_t value) {
    if (!out) return;
    memset(out, 0, sizeof(BigNum256));
    out->value[0] = (uint32_t)(value & 0xFFFFFFFFu);
    out->value[1] = (uint32_t)(value >> 32);
}

/*
 * Set big number from byte array (big-endian).
 */
void bignum256_from_bytes(BigNum256* out, const uint8_t* bytes) {
    if (!out || !bytes) return;
    memset(out, 0, sizeof(BigNum256));
    for (int i = 0; i < PEDERSEN_P_WORDS; i++) {
        int bi = PEDERSEN_P_WORDS - 1 - i;
        out->value[bi] = ((uint32_t)bytes[4*i] << 24)
                       | ((uint32_t)bytes[4*i+1] << 16)
                       | ((uint32_t)bytes[4*i+2] << 8)
                       | ((uint32_t)bytes[4*i+3]);
    }
}

/*
 * Convert big number to byte array (big-endian).
 */
void bignum256_to_bytes(uint8_t* out, const BigNum256* n) {
    if (!out || !n) return;
    for (int i = 0; i < PEDERSEN_P_WORDS; i++) {
        int bi = PEDERSEN_P_WORDS - 1 - i;
        out[4*i]   = (uint8_t)(n->value[bi] >> 24);
        out[4*i+1] = (uint8_t)(n->value[bi] >> 16);
        out[4*i+2] = (uint8_t)(n->value[bi] >> 8);
        out[4*i+3] = (uint8_t)(n->value[bi]);
    }
}

/*
 * Check if big number is zero.
 */
int bignum256_is_zero(const BigNum256* n) {
    if (!n) return 1;
    for (int i = 0; i < PEDERSEN_P_WORDS; i++)
        if (n->value[i] != 0) return 0;
    return 1;
}

/*
 * Compare two big numbers for equality.
 */
int bignum256_equals(const BigNum256* a, const BigNum256* b) {
    if (!a || !b) return 0;
    for (int i = 0; i < PEDERSEN_P_WORDS; i++)
        if (a->value[i] != b->value[i]) return 0;
    return 1;
}

/*
 * Print big number with label.
 */
void bignum256_print(const BigNum256* n, const char* label) {
    if (!n) return;
    printf("%s: ", label ? label : "BigNum256");
    for (int i = PEDERSEN_P_WORDS - 1; i >= 0; i--) {
        printf("%08x", n->value[i]);
    }
    printf("\n");
}

/* ================================================================
 * HashDigest Utility Functions
 * ================================================================ */

/*
 * Compare two hash digests for equality.
 * Constant-time comparison (not strictly necessary for ZK demo
 * but important in cryptographic implementations to prevent timing attacks).
 */
int hashdigest_equals(const HashDigest* a, const HashDigest* b) {
    if (!a || !b) return 0;
    int result = 0;
    for (int i = 0; i < HASH_DIGEST_WORDS; i++) {
        result |= (a->w[i] ^ b->w[i]);
    }
    return result == 0;
}

/*
 * Print a hash digest.
 */
void hashdigest_print(const HashDigest* h, const char* label) {
    if (!h) return;
    printf("%s: ", label ? label : "HashDigest");
    for (int i = 0; i < HASH_DIGEST_WORDS; i++) {
        printf("%08x", h->w[i]);
    }
    printf("\n");
}

/*
 * Create a HashDigest directly from bytes (for quick testing).
 */
void hashdigest_from_bytes(HashDigest* h, const uint8_t* data, int len) {
    if (!h || !data) return;
    memset(h, 0, sizeof(HashDigest));
    int bytes_to_copy = len < HASH_DIGEST_BYTES ? len : HASH_DIGEST_BYTES;
    memcpy(h->w, data, (size_t)bytes_to_copy);
}
