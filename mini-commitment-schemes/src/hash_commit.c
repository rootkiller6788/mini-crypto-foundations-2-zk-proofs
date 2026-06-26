/**
 * @file hash_commit.c
 * @brief Hash-based commitment scheme implementation
 *
 * Implements commitment schemes based on collision-resistant hash functions.
 *
 * Construction:
 *   Commit(m, r) = H(m || r)
 *
 * where H is a collision-resistant hash function (modeled as a random
 * oracle for security proofs).
 *
 * Security analysis (L2, L4):
 *
 *   Hiding: In the random oracle model, H(m || r) reveals nothing
 *     about m if r has sufficient entropy. Specifically, if r ¡Ê {0,1}^{2¦Ë}
 *     and H: {0,1}^* ¡ú {0,1}^¦Ë, then the advantage of any distinguisher
 *     is at most q_H ¡¤ 2^{-2¦Ë} (where q_H is the number of RO queries).
 *
 *   Binding: If H is collision-resistant, finding (m,r) ¡Ù (m',r')
 *     with H(m||r) = H(m'||r') breaks collision resistance.
 *     By reduction: an adversary breaking binding can be used to
 *     find a collision in H.
 *
 * Comparison with Pedersen:
 *   - Hash commitments are simpler (no trusted setup)
 *   - No algebraic homomorphic properties
 *   - Potentially post-quantum secure (if H is, e.g., SHA-3)
 *   - Hiding is only computational, not perfect
 *
 * Applications (L7, L9):
 *   - Post-quantum commitments (L9): With quantum-secure hash functions,
 *     hash-based commitments remain secure against quantum adversaries.
 *     Pedersen commitments (based on discrete log) are broken by Shor's
 *     algorithm.
 *   - Simple protocols: When homomorphic properties are not needed.
 *   - Blockchain: Commit-reveal schemes for sealed-bid auctions.
 *
 * References:
 *   - Damgard, I. "Commitment Schemes and Zero-Knowledge Protocols" (1999)
 *   - Halevi-Micali (CRYPTO 1996) ¡ª practical commitment from collision-free hash
 *   - Unruh, D. (EUROCRYPT 2016) ¡ª quantum-secure commitments
 *   - Goldreich, O. "Foundations of Cryptography Vol 1" (2001), ¡ì4.4
 *
 * Knowledge Mapping:
 *   L1: Hash commitment definition
 *   L2: Random oracle model, collision resistance
 *   L3: Merkle-Damgard construction, sponge construction
 *   L4: Collision resistance ¡ú binding proof
 *   L5: Hash-based commit/open/verify
 *   L7: Post-quantum commitment application
 *   L9: Quantum-secure commitments research direction
 */

#include "hash_commit.h"
#include <string.h>
#include <stdio.h>

/* =========================================================================
 * Simple Hash Implementation (L3, L5)
 *
 * We implement a simplified hash function based on the Davies-Meyer
 * construction with modular arithmetic. This demonstrates the structure
 * without depending on an external SHA-256 library.
 *
 * Davies-Meyer construction:
 *   H_{i+1} = E(m_i, H_i) XOR H_i
 *
 * where E is a block cipher. Our simplified version uses:
 *   state = (state * (block + CONST)) mod PRIME
 *
 * This is NOT cryptographically secure. It serves educational purposes
 * only. For real applications, use SHA-256, SHA-3, or BLAKE3.
 * ========================================================================= */

/* A 256-bit prime for hash operations */
static const uint64_t H_PRIME[4] = {
    0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFEULL,
    0xFFF00000000000FFULL
};

static void hash_get_prime(bigint *p) {
    bigint_init(p);
    for (int i = 0; i < 4; i++) {
        p->limbs[i] = H_PRIME[i];
    }
    p->nlimbs = 4;
}

/* Initialization vector ¡ª first 64 bits of SHA-256 IV */
#define HASH_IV 0x6A09E667F3BCC908ULL

void simple_hash_init(simple_hash_state *st) {
    bigint_init_u64(&st->state, HASH_IV);
    st->rounds = 0;
    st->absorbed_bytes = 0;
}

void simple_hash_absorb(simple_hash_state *st, const uint8_t *data, size_t len) {
    if (data == NULL || len == 0) return;

    bigint prime;
    hash_get_prime(&prime);

    for (size_t i = 0; i < len; i++) {
        /* Absorb one byte:
         * state = (state * (state + byte + CONST)) mod PRIME */
        bigint temp;
        bigint_init_u64(&temp, (uint64_t)data[i] + 0x9E3779B9ULL);

        bigint_add(&st->state, &temp);

        /* state = state * state mod PRIME (squaring) */
        bigint_mul(&st->state, &st->state, &st->state);
        bigint_mod(&st->state, &prime);

        st->rounds++;
        st->absorbed_bytes++;
    }
}

void simple_hash_absorb_bigint(simple_hash_state *st, const bigint *val) {
    if (val == NULL) return;

    /* Convert bigint to bytes and absorb */
    bigint prime;
    hash_get_prime(&prime);

    /* Absorb the bigint value directly: state += val, then square */
    bigint_add(&st->state, val);
    bigint_mul(&st->state, &st->state, &st->state);
    bigint_mod(&st->state, &prime);

    st->rounds++;
}

void simple_hash_squeeze(simple_hash_state *st, bigint *output) {
    bigint prime;
    hash_get_prime(&prime);

    /* Finalize: apply additional mixing rounds */
    bigint len_val;
    bigint_init_u64(&len_val, st->absorbed_bytes * 8); /* Length in bits */

    /* Davies-Meyer style finalization */
    bigint_add(&st->state, &len_val);
    bigint_mul(&st->state, &st->state, &st->state);
    bigint_mod(&st->state, &prime);

    /* Additional mixing to ensure avalanche */
    for (int i = 0; i < 4; i++) {
        bigint temp;
        bigint_init_u64(&temp, 0x510E527FADE682D1ULL * (uint64_t)(i + 1));
        bigint_add(&st->state, &temp);
        bigint_mul(&st->state, &st->state, &st->state);
        bigint_mod(&st->state, &prime);
    }

    bigint_copy(output, &st->state);
}

void simple_hash(const uint8_t *data, size_t len, bigint *output) {
    simple_hash_state st;
    simple_hash_init(&st);
    simple_hash_absorb(&st, data, len);
    simple_hash_squeeze(&st, output);
}

void simple_hash_bigint(const bigint *val, bigint *output) {
    simple_hash_state st;
    simple_hash_init(&st);
    simple_hash_absorb_bigint(&st, val);
    simple_hash_squeeze(&st, output);
}

/* =========================================================================
 * Hash Commitment (L1, L5)
 *
 * C = H(m || r)
 *
 * The message m and randomness r are concatenated and hashed.
 * For the domain-separated version, a domain tag is prepended.
 *
 * Implementation: We use the simple_hash with a serialization approach
 * for concatenating big integers.
 * ========================================================================= */

/**
 * Serialize a bigint to bytes for hashing.
 * Returns the number of bytes written.
 */
static size_t bigint_to_bytes(const bigint *a, uint8_t *buf, size_t buf_size) {
    if (bigint_is_zero(a)) {
        if (buf_size > 0) buf[0] = 0;
        return 1;
    }

    size_t nbytes = (bigint_bitlen(a) + 7) / 8;
    if (nbytes > buf_size) nbytes = buf_size;

    /* Store in big-endian byte order for consistency */
    for (size_t i = 0; i < nbytes; i++) {
        size_t bit_pos = (nbytes - 1 - i) * 8;
        size_t limb_idx = bit_pos / 64;
        size_t bit_idx = bit_pos % 64;
        uint8_t byte = 0;
        if (limb_idx < a->nlimbs) {
            byte = (uint8_t)((a->limbs[limb_idx] >> bit_idx) & 0xFF);
        }
        buf[i] = byte;
    }
    return nbytes;
}

void hash_commit(const bigint *m, const bigint *r, bigint *c) {
    uint8_t buf[256]; /* Enough for two 1024-bit numbers */
    size_t pos = 0;

    pos += bigint_to_bytes(m, buf + pos, sizeof(buf) - pos - 1);
    buf[pos++] = 0x7C; /* Separator byte '|' */
    pos += bigint_to_bytes(r, buf + pos, sizeof(buf) - pos);

    simple_hash(buf, pos, c);
}

bool hash_commit_verify(const bigint *c, const bigint *m, const bigint *r) {
    bigint computed;
    bigint_init(&computed);
    hash_commit(m, r, &computed);
    return bigint_cmp(c, &computed) == 0;
}

/* =========================================================================
 * Domain-separated hash commitment (L2)
 *
 * Domain separation prevents cross-protocol attacks:
 *   H("COMMIT" || m || r) ¡Ù H("SIGN" || m || r)
 *
 * This is standard practice in real cryptographic protocols
 * (see RFC 6979 for deterministic ECDSA, which uses domain
 * separation extensively).
 * ========================================================================= */

void hash_commit_domain(const uint8_t *domain, size_t domain_len,
                        const bigint *m, const bigint *r, bigint *c) {
    simple_hash_state st;
    simple_hash_init(&st);

    /* Absorb domain tag first */
    simple_hash_absorb(&st, domain, domain_len);

    /* Absorb separator */
    uint8_t sep = 0x7C;
    simple_hash_absorb(&st, &sep, 1);

    /* Absorb message */
    simple_hash_absorb_bigint(&st, m);

    /* Absorb second separator */
    simple_hash_absorb(&st, &sep, 1);

    /* Absorb randomness */
    simple_hash_absorb_bigint(&st, r);

    simple_hash_squeeze(&st, c);
}

bool hash_commit_domain_verify(const uint8_t *domain, size_t domain_len,
                               const bigint *c, const bigint *m,
                               const bigint *r) {
    bigint computed;
    bigint_init(&computed);
    hash_commit_domain(domain, domain_len, m, r, &computed);
    return bigint_cmp(c, &computed) == 0;
}

/* =========================================================================
 * Multi-round hash commitment (L7: strengthening)
 *
 * Two-round commitment:
 *   C = H( H(m || r1) || r2 )
 *
 * This provides a stronger security margin when the underlying
 * hash function is only one-way but not proven collision-resistant.
 *
 * The double hashing prevents length-extension attacks and provides
 * better composition properties (used in HMAC-based commitments).
 * ========================================================================= */

void hash_commit_double(const bigint *m, const bigint *r1,
                        const bigint *r2, bigint *c) {
    /* First round: h1 = H(m || r1) */
    bigint h1;
    bigint_init(&h1);
    hash_commit(m, r1, &h1);

    /* Second round: C = H(h1 || r2) */
    hash_commit(&h1, r2, c);
}

bool hash_commit_double_verify(const bigint *c,
                               const bigint *m, const bigint *r1,
                               const bigint *r2) {
    bigint computed;
    bigint_init(&computed);
    hash_commit_double(m, r1, r2, &computed);
    return bigint_cmp(c, &computed) == 0;
}

/* =========================================================================
 * Scheme comparison (L6)
 * ========================================================================= */

void hash_commit_compare_schemes(char *buf, size_t buf_size) {
    snprintf(buf, buf_size,
        "Commitment Scheme Comparison\n"
        "============================\n"
        "%-20s | %-12s | %-12s | %-10s | %-10s | %-8s\n"
        "%-20s-+-%-12s-+-%-12s-+-%-10s-+-%-10s-+-%-8s\n"
        "%-20s | %-12s | %-12s | %-10s | %-10s | %-8s\n"
        "%-20s | %-12s | %-12s | %-10s | %-10s | %-8s\n"
        "%-20s | %-12s | %-12s | %-10s | %-10s | %-8s\n"
        "%-20s | %-12s | %-12s | %-10s | %-10s | %-8s\n"
        "\n"
        "Perfect Hiding: information-theoretic, no computational assumption\n"
        "Statistical Hiding: negligible distinguishing advantage\n"
        "Computational Hiding: secure against poly-time adversaries only\n"
        "Post-Quantum: secure against quantum computers (Shor's algorithm)\n",
        "Scheme", "Hiding", "Binding", "Homomorphic", "Setup", "Post-Q",
        "", "", "", "", "", "",
        "Pedersen", "Perfect", "Computational", "Yes (add)", "Trusted", "No",
        "Hash-based", "Comp.", "Comp.", "No", "None", "Yes",
        "Fujisaki-Okamoto", "Statistical", "Comp.", "Yes (add)", "RSA mod", "No",
        "Merkle Vector", "Comp.", "Comp.", "No", "None", "Yes");
}
