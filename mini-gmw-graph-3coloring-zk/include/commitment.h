/*
 * commitment.h - Bit Commitment Schemes
 *
 * L1: Bit commitment = two-phase protocol between Sender and Receiver
 *   Phase 1 (Commit): c = Commit(b, r)
 *   Phase 2 (Reveal): reveal (b, r), verify Commit(b, r) == c
 *   Hiding: {Commit(0,r)} ~_c {Commit(1,r)}
 *   Binding: forall r1,r2: Commit(0,r1) != Commit(1,r2)
 *
 * L2: Two schemes:
 *   A) Hash-based (computationally binding, statistically hiding)
 *   B) Pedersen (perfectly hiding, computationally binding)
 *
 * L3: Hash-based: Commit(b,r) = H(b||r)
 *     Pedersen: Commit(m,r) = g^m * h^r mod p (safe-prime group)
 *
 * Reference: Goldreich (2004) FOC I sec4.4.1, Pedersen (CRYPTO 1991)
 * Courses: MIT 6.876, Stanford CS255, Berkeley CS276
 */
#ifndef COMMITMENT_H
#define COMMITMENT_H
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define HASH_DIGEST_BYTES 32
#define HASH_DIGEST_WORDS (HASH_DIGEST_BYTES / 4)
typedef struct { uint32_t w[HASH_DIGEST_WORDS]; } HashDigest;

#define COMMIT_NONCE_BYTES 32
typedef struct { uint8_t nonce[COMMIT_NONCE_BYTES]; } CommitNonce;

HashDigest   commit_bit(uint8_t b, const CommitNonce* nonce);
HashDigest   commit_int(int value, const CommitNonce* nonce);
HashDigest   commit_color(int color, const CommitNonce* nonce);
int          commit_verify_bit(uint8_t b, const CommitNonce* nonce, const HashDigest* commitment);
int          commit_verify_int(int value, const CommitNonce* nonce, const HashDigest* commitment);
int          commit_verify_color(int color, const CommitNonce* nonce, const HashDigest* commitment);
HashDigest*  commit_color_array(const int* colors, int n, const CommitNonce* nonces);
int          commit_verify_edge(const HashDigest* all_commitments, int u, int v,
                                 int color_u, int color_v,
                                 const CommitNonce* nonce_u, const CommitNonce* nonce_v);
int          commit_generate_nonce(CommitNonce* nonce);
CommitNonce* commit_generate_nonces(int n);
void         commit_nonce_from_seed(CommitNonce* nonce, uint64_t seed, int index);
void         commit_free_nonces(CommitNonce* nonces);

/* Pedersen commitment (safe prime group) */
#define PEDERSEN_P_WORDS 8
typedef struct { uint32_t value[PEDERSEN_P_WORDS]; } BigNum256;
typedef struct { BigNum256 p, q, g, h; } PedersenParams;
typedef struct { BigNum256 value; } PedersenCommitment;
typedef struct { BigNum256 message, randomness; } PedersenOpening;

PedersenParams*  pedersen_params_create(void);
void             pedersen_params_free(PedersenParams* params);
PedersenCommitment pedersen_commit(const PedersenParams* params, const BigNum256* message, const BigNum256* randomness);
int              pedersen_verify(const PedersenParams* params, const PedersenCommitment* commitment, const PedersenOpening* opening);
PedersenCommitment pedersen_commit_int(const PedersenParams* params, int value, const BigNum256* randomness);
int              pedersen_verify_int(const PedersenParams* params, const PedersenCommitment* commitment, int value, const BigNum256* randomness);

void bignum256_from_int(BigNum256* out, uint64_t value);
void bignum256_from_bytes(BigNum256* out, const uint8_t* bytes);
void bignum256_to_bytes(uint8_t* out, const BigNum256* n);
int  bignum256_is_zero(const BigNum256* n);
int  bignum256_equals(const BigNum256* a, const BigNum256* b);
void bignum256_print(const BigNum256* n, const char* label);

int  hashdigest_equals(const HashDigest* a, const HashDigest* b);
void hashdigest_print(const HashDigest* h, const char* label);
void hashdigest_from_bytes(HashDigest* h, const uint8_t* data, int len);
HashDigest hash256_compute(const uint8_t* data, size_t len);

#endif
