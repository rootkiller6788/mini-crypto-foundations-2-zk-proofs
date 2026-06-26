/*
 * group.h — Cryptographic Group Theory Foundations
 *
 * L1 Definitions:
 *   - Group: (G, ·) with closure, associativity, identity, inverses
 *   - Cyclic group: G = ⟨g⟩ for some generator g ∈ G
 *   - Group order: |G| = n, smallest n such that g^n = 1
 *   - Subgroup: H ⊆ G that is itself a group under G's operation
 *   - Z_p*: multiplicative group of integers modulo prime p
 *   - Generator: Element g such that {g^0, g^1, ..., g^(n-1)} = G
 *
 * L3 Mathematical Structures:
 *   - Group element: element of Z_p* represented as uint64_t mod p
 *   - Group metadata: prime order, generator, and precomputed values
 *   - Modular arithmetic: add, mul, pow, inv in Z_p
 *
 * This module provides the group-theoretic foundation needed for
 * the Knowledge of Exponent assumption (KEA). KEA is stated over
 * a cyclic group G = <g> of prime order p.
 *
 * References:
 *   - Damgard (1991) "Towards Practical Public Key Systems Secure Against
 *     Chosen Ciphertext Attacks" — first Knowledge of Exponent paper
 *   - Bellare & Palacio (2004) "The Knowledge-of-Exponent Assumptions and
 *     3-Round Zero-Knowledge Protocols"
 *   - Groth (2010) "Short Pairing-Based Non-interactive Zero-Knowledge Arguments"
 *
 * Courses: Stanford CS255 (Cryptography), Berkeley CS276 (Graduate Cryptography),
 *          MIT 6.875 (Cryptography & Cryptanalysis), ETH 263-4600 (Cryptographic Protocols)
 */

#ifndef KEA_GROUP_H
#define KEA_GROUP_H

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/* ── Modular Arithmetic on Prime Fields ───────────────────── */

typedef uint64_t mpz_prime_t;
typedef uint64_t mpz_elem_t;

int mpz_is_prime_naive(uint64_t n);
int mpz_is_safe_prime(uint64_t p);
uint64_t mpz_next_prime(uint64_t n);

uint64_t mpz_mod_add(uint64_t a, uint64_t b, uint64_t p);
uint64_t mpz_mod_sub(uint64_t a, uint64_t b, uint64_t p);
uint64_t mpz_mod_mul(uint64_t a, uint64_t b, uint64_t p);
uint64_t mpz_mod_inv(uint64_t a, uint64_t p);
uint64_t mpz_mod_pow(uint64_t base, uint64_t exp, uint64_t p);
uint64_t mpz_mod_sqrt(uint64_t a, uint64_t p);
int      mpz_is_quadratic_residue(uint64_t a, uint64_t p);

uint64_t mpz_extended_gcd(uint64_t a, uint64_t p, int64_t *x, int64_t *y);
int mpz_verify_order(uint64_t g, uint64_t order, uint64_t p);
int mpz_miller_rabin(uint64_t n, int k);

/* ── Cyclic Group ─────────────────────────────────────────── */

typedef struct {
    uint64_t    modulus;
    uint64_t    order;
    uint64_t    generator;
    char*       description;
    uint64_t    cofactor;
    int         is_initialized;
} CyclicGroup;

/* ── Group Element ────────────────────────────────────────── */

typedef struct {
    uint64_t    value;
    CyclicGroup *group;
} GroupElement;

/* ── Subgroup Structure ──────────────────────────────────── */

typedef struct {
    CyclicGroup *parent;
    uint64_t    subgroup_order;
    uint64_t    subgroup_gen;
    int         is_prime_order;
} Subgroup;

/* ── Group Construction & Destruction ──────────────────────── */

CyclicGroup* group_create_from_safe_prime(uint64_t p);
CyclicGroup* group_create_custom(uint64_t modulus, uint64_t order, uint64_t generator);
uint64_t group_find_quadratic_residue_generator(uint64_t p);
void group_free(CyclicGroup* g);

/* ── Group Element Operations ─────────────────────────────── */

GroupElement* ge_create(uint64_t value, CyclicGroup* g);
GroupElement* ge_clone(const GroupElement* a);
void ge_free(GroupElement* a);
GroupElement* ge_identity(CyclicGroup* g);
GroupElement* ge_generator(CyclicGroup* g);

/* ── Group Operations ──────────────────────────────────────── */

GroupElement* ge_mul(const GroupElement* a, const GroupElement* b);
GroupElement* ge_inv(const GroupElement* a);
GroupElement* ge_pow(const GroupElement* a, uint64_t k);
GroupElement* ge_random(CyclicGroup* g, uint64_t seed);
GroupElement* ge_div(const GroupElement* a, const GroupElement* b);

/* ── Group Element Inspection ──────────────────────────────── */

int ge_equal(const GroupElement* a, const GroupElement* b);
int ge_is_identity(const GroupElement* a);
int ge_is_generator(const GroupElement* a);
int ge_in_subgroup(const GroupElement* a, const Subgroup* H);
void ge_print(const GroupElement* a, const char* label);

/* ── Subgroup Operations ──────────────────────────────────── */

Subgroup* subgroup_create(CyclicGroup* parent, uint64_t order, uint64_t gen);
int subgroup_contains(const Subgroup* H, const GroupElement* a);
GroupElement* subgroup_cofactor_clear(const Subgroup* H, const GroupElement* a);
void subgroup_free(Subgroup* H);

/* ── Group Encoding / Serialization ───────────────────────── */

int ge_serialize(const GroupElement* a, uint8_t* buf, size_t buf_len);
GroupElement* ge_deserialize(const uint8_t* buf, size_t buf_len, CyclicGroup* g);

/* ── Batch Operations ──────────────────────────────────────── */

GroupElement* ge_multi_exp(const GroupElement** bases, const uint64_t* exps,
                            int count, CyclicGroup* g);

/* ── Group Properties ─────────────────────────────────────── */

int group_is_cyclic(const CyclicGroup* g);
uint64_t group_order(const CyclicGroup* g);
int group_verify_lagrange(const CyclicGroup* g);

/* ── Pre-built Standard Groups ────────────────────────────── */

CyclicGroup* group_create_oakley14(void);
CyclicGroup* group_create_test_group(void);
CyclicGroup* group_create_medium_group(void);

/* ── Legendre Symbol ──────────────────────────────────────── */

int legendre_symbol(uint64_t a, uint64_t p);

/* ── Tonelli-Shanks Square Root ────────────────────────────── */

uint64_t mpz_mod_sqrt_3mod4(uint64_t a, uint64_t p);

#endif /* KEA_GROUP_H */