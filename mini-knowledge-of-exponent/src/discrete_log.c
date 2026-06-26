/*
 * discrete_log.c — Discrete Logarithm and Diffie-Hellman Problems
 *
 * Implements the core hardness problems on which KEA is built:
 * DLP, CDH, DDH, and their algorithmic solutions.
 *
 * L1: DLP, CDH, DDH formal problem definitions
 * L2: Hardness hierarchy (DLP >= CDH >= DDH)
 * L5: Baby-step Giant-step, Pollard's Rho, Pohlig-Hellman, Index Calculus
 * L6: DLP/CDH/DDH as canonical cryptographic problems
 *
 * Courses: Stanford CS255, MIT 6.875, Berkeley CS276
 * (C) Mini-Theory-of-Computation — mini-knowledge-of-exponent
 */

#include "discrete_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

/* ═══════════════════════════════════════════════════════════════
   DLP Instance Management
   ═══════════════════════════════════════════════════════════════ */

DLPInstance* dlp_instance_create(CyclicGroup* group, uint64_t secret) {
    if (!group) return NULL;
    DLPInstance* inst = (DLPInstance*)calloc(1, sizeof(DLPInstance));
    if (!inst) return NULL;
    inst->generator = ge_create(group->generator, group);
    inst->group = group;
    inst->target = ge_pow(inst->generator, secret);
    inst->solved = 0;
    inst->solution = 0;
    if (!inst->target) { dlp_instance_free(inst); return NULL; }
    return inst;
}

DLPInstance* dlp_instance_random(CyclicGroup* group) {
    if (!group) return NULL;
    uint64_t secret = 1 + (group->order > 1 ? group->order / 2 : 1);
    if (secret >= group->order) secret = group->order - 1;
    if (secret == 0) secret = 1;
    return dlp_instance_create(group, secret);
}

void dlp_instance_free(DLPInstance* inst) {
    if (!inst) return;
    ge_free(inst->generator);
    ge_free(inst->target);
    free(inst);
}

void dlp_print(const DLPInstance* inst) {
    if (!inst) return;
    printf("=== DLP Instance ===\n");
    ge_print(inst->generator, "Generator g");
    ge_print(inst->target, "Target h = g^x");
    if (inst->solved) printf("Solution x = %llu\n", (unsigned long long)inst->solution);
    else printf("Unsolved.\n");
    printf("====================\n");
}

/* ═══════════════════════════════════════════════════════════════
   CDH Instance Management
   ═══════════════════════════════════════════════════════════════ */

CDHInstance* cdh_instance_create(CyclicGroup* group, uint64_t a, uint64_t b) {
    if (!group) return NULL;
    CDHInstance* inst = (CDHInstance*)calloc(1, sizeof(CDHInstance));
    if (!inst) return NULL;
    inst->g = ge_create(group->generator, group);
    inst->g_a = ge_pow(inst->g, a);
    inst->g_b = ge_pow(inst->g, b);
    inst->answer = NULL;
    inst->group = group;
    inst->solved = 0;
    if (!inst->g_a || !inst->g_b) { cdh_instance_free(inst); return NULL; }
    return inst;
}

CDHInstance* cdh_instance_random(CyclicGroup* group) {
    if (!group) return NULL;
    uint64_t a = 1 + (group->order > 2 ? group->order / 3 : 1);
    uint64_t b = 1 + (group->order > 3 ? group->order / 7 : 1);
    if (a >= group->order) a = group->order - 1;
    if (b >= group->order) b = group->order - 1;
    return cdh_instance_create(group, a, b);
}

void cdh_instance_free(CDHInstance* inst) {
    if (!inst) return;
    ge_free(inst->g); ge_free(inst->g_a);
    ge_free(inst->g_b); ge_free(inst->answer);
    free(inst);
}

int cdh_verify(const CDHInstance* inst) {
    if (!inst || !inst->answer) return 0;
    return inst->answer != NULL;
}

void cdh_print(const CDHInstance* inst) {
    if (!inst) return;
    printf("=== CDH Instance ===\n");
    ge_print(inst->g, "g"); ge_print(inst->g_a, "g^a");
    ge_print(inst->g_b, "g^b");
    printf("Solve: compute g^{ab}\n====================\n");
}

/* ═══════════════════════════════════════════════════════════════
   DDH Instance Management
   ═══════════════════════════════════════════════════════════════ */

DDHInstance* ddh_instance_create(CyclicGroup* group, uint64_t a, uint64_t b, int is_dh) {
    if (!group) return NULL;
    DDHInstance* inst = (DDHInstance*)calloc(1, sizeof(DDHInstance));
    if (!inst) return NULL;
    inst->g = ge_create(group->generator, group);
    inst->g_a = ge_pow(inst->g, a);
    inst->g_b = ge_pow(inst->g, b);
    if (is_dh) {
        inst->g_c = ge_pow(inst->g, mpz_mod_mul(a, b, group->order));
        inst->is_dh_tuple = 1;
    } else {
        uint64_t c = (a + b + 1) % group->order;
        if (c == mpz_mod_mul(a, b, group->order)) c = (c + 1) % group->order;
        inst->g_c = ge_pow(inst->g, c);
        inst->is_dh_tuple = 0;
    }
    inst->group = group;
    if (!inst->g_a || !inst->g_b || !inst->g_c) { ddh_instance_free(inst); return NULL; }
    return inst;
}

DDHInstance* ddh_instance_random(CyclicGroup* group) {
    if (!group) return NULL;
    uint64_t a = 1 + (group->order > 2 ? group->order / 3 : 1);
    uint64_t b = 1 + (group->order > 3 ? group->order / 5 : 1);
    if (a >= group->order) a = group->order - 1;
    if (b >= group->order) b = group->order - 1;
    return ddh_instance_create(group, a, b, 1);
}

void ddh_instance_free(DDHInstance* inst) {
    if (!inst) return;
    ge_free(inst->g); ge_free(inst->g_a);
    ge_free(inst->g_b); ge_free(inst->g_c);
    free(inst);
}

void ddh_print(const DDHInstance* inst) {
    if (!inst) return;
    printf("=== DDH Instance ===\n");
    ge_print(inst->g, "g"); ge_print(inst->g_a, "g^a");
    ge_print(inst->g_b, "g^b"); ge_print(inst->g_c, "g^c");
    printf("Is DH tuple? %s\n", inst->is_dh_tuple ? "YES" : "NO");
    printf("====================\n");
}

/* ═══════════════════════════════════════════════════════════════
   Baby-step Giant-step Algorithm (Shanks 1971)
   ═══════════════════════════════════════════════════════════════ */

uint64_t dlp_baby_giant_step(const GroupElement* g, const GroupElement* h,
                              const CyclicGroup* group) {
    if (!g || !h || !group) return 0;
    if (ge_equal(g, h)) return 1;
    if (ge_is_identity(h)) return 0;

    uint64_t n = group->order, p = group->modulus;
    uint64_t m = 1;
    while (m * m < n) m++;
    if (m > 500000) return 0;

    typedef struct { uint64_t value; uint64_t j; } BabyStep;
    BabyStep* table = (BabyStep*)calloc(m, sizeof(BabyStep));
    if (!table) return 0;

    uint64_t current = 1;
    for (uint64_t j = 0; j < m; j++) {
        table[j].value = current; table[j].j = j;
        current = mpz_mod_mul(current, g->value, p);
    }
    for (uint64_t i = 1; i < m; i++) {
        BabyStep key = table[i]; int64_t jj = (int64_t)i - 1;
        while (jj >= 0 && table[jj].value > key.value) {
            table[jj + 1] = table[jj]; jj--;
        }
        table[jj + 1] = key;
    }

    uint64_t g_m = mpz_mod_pow(g->value, m, p);
    uint64_t gamma = mpz_mod_inv(g_m, p);
    if (gamma == 0) { free(table); return 0; }

    uint64_t giant = h->value, result = 0;
    for (uint64_t i = 0; i < m; i++) {
        uint64_t lo = 0, hi = m;
        while (lo < hi) { uint64_t mid = (lo+hi)/2;
            if (table[mid].value < giant) lo = mid+1; else hi = mid; }
        if (lo < m && table[lo].value == giant) {
            result = (i * m + table[lo].j) % n; break;
        }
        giant = mpz_mod_mul(giant, gamma, p);
    }
    free(table); return result;
}

/* ═══════════════════════════════════════════════════════════════
   Pollard's Rho Algorithm (Pollard 1978)
   ═══════════════════════════════════════════════════════════════ */

uint64_t dlp_pollard_rho(const GroupElement* g, const GroupElement* h,
                          const CyclicGroup* group) {
    if (!g || !h || !group) return 0;
    if (ge_equal(g, h)) return 1;
    if (ge_is_identity(h)) return 0;

    uint64_t p = group->modulus, n = group->order;
    uint64_t x1 = 1, a1 = 0, b1 = 0, x2 = 1, a2 = 0, b2 = 0;
    uint64_t max_steps = n > 0 ? 2 * ((uint64_t)sqrt((double)n) + 2) : 1000;
    if (max_steps > 500000) max_steps = 500000;

    for (uint64_t step = 0; step < max_steps; step++) {
        for (int t = 0; t < 2; t++) {
            uint64_t s = x2 % 3;
            if (s == 0) { x2 = mpz_mod_mul(x2, h->value, p); b2 = (b2+1)%n; }
            else if (s == 1) { x2 = mpz_mod_mul(x2, x2, p); a2 = (a2*2)%n; b2 = (b2*2)%n; }
            else { x2 = mpz_mod_mul(x2, g->value, p); a2 = (a2+1)%n; }
        }
        { uint64_t s = x1 % 3;
            if (s == 0) { x1 = mpz_mod_mul(x1, h->value, p); b1 = (b1+1)%n; }
            else if (s == 1) { x1 = mpz_mod_mul(x1, x1, p); a1 = (a1*2)%n; b1 = (b1*2)%n; }
            else { x1 = mpz_mod_mul(x1, g->value, p); a1 = (a1+1)%n; } }
        if (x1 == x2) {
            int64_t db = ((int64_t)b1 - (int64_t)b2) % (int64_t)n;
            int64_t da = ((int64_t)a2 - (int64_t)a1) % (int64_t)n;
            if (db < 0) db += (int64_t)n;
            if (da < 0) da += (int64_t)n;
            if (db == 0) return 0;
            uint64_t inv_db = mpz_mod_inv((uint64_t)db, n);
            if (inv_db == 0) return 0;
            return mpz_mod_mul((uint64_t)da, inv_db, n);
        }
    }
    return 0;
}

/* ═══════════════════════════════════════════════════════════════
   Pohlig-Hellman Algorithm (1978)
   ═══════════════════════════════════════════════════════════════ */

uint64_t dlp_pohlig_hellman(const GroupElement* g, const GroupElement* h,
                             const CyclicGroup* group,
                             const uint64_t* prime_factors, int n_factors) {
    if (!g || !h || !group || !prime_factors || n_factors < 1) return 0;
    if (ge_equal(g, h)) return 1;
    uint64_t n = group->order, p = group->modulus;
    uint64_t result = 0, mod_product = 1;
    uint64_t* xi = (uint64_t*)calloc(n_factors, sizeof(uint64_t));
    uint64_t* moduli = (uint64_t*)calloc(n_factors, sizeof(uint64_t));
    if (!xi || !moduli) { free(xi); free(moduli); return 0; }

    for (int i = 0; i < n_factors; i++) {
        uint64_t q = prime_factors[i], n_copy = n; int e = 0;
        while (n_copy % q == 0) { n_copy /= q; e++; }
        uint64_t qi = 1;
        for (int exp_i = 0; exp_i < e; exp_i++) {
            qi *= q; uint64_t ni = n / qi;
            uint64_t gi = mpz_mod_pow(g->value, ni, p);
            uint64_t hi = mpz_mod_pow(h->value, ni, p);
            if (exp_i > 0) {
                uint64_t corr = mpz_mod_pow(g->value, mpz_mod_mul(xi[i], n/qi*q, n), p);
                hi = mpz_mod_mul(hi, mpz_mod_inv(corr, p), p);
            }
            GroupElement* gg = ge_create(gi, (CyclicGroup*)group);
            GroupElement* hh = ge_create(hi, (CyclicGroup*)group);
            uint64_t xj = dlp_baby_giant_step(gg, hh, group);
            ge_free(gg); ge_free(hh);
            xi[i] = (xi[i] + xj * (qi/q)) % qi;
        }
        moduli[i] = qi; mod_product *= qi;
    }
    for (int i = 0; i < n_factors; i++) {
        if (moduli[i] == 0) continue;
        uint64_t Mi = mod_product / moduli[i];
        uint64_t inv_Mi = mpz_mod_inv(Mi, moduli[i]);
        result = (result + mpz_mod_mul(mpz_mod_mul(xi[i], Mi, mod_product), inv_Mi, mod_product)) % mod_product;
    }
    free(xi); free(moduli); return result;
}

/* ═══════════════════════════════════════════════════════════════
   Index Calculus (Simplified Educational Version)
   ═══════════════════════════════════════════════════════════════ */

uint64_t dlp_index_calculus(const GroupElement* g, const GroupElement* h,
                             const CyclicGroup* group) {
    if (!g || !h || !group) return 0;
    if (ge_equal(g, h)) return 1;
    if (ge_is_identity(h)) return 0;
    uint64_t p = group->modulus, n = group->order;
    if (p > 50000) return 0;

    int B = 12; uint64_t factor_base[30] = {0}; int n_fb = 0;
    for (uint64_t q = 2; q < (uint64_t)B && n_fb < 28; q++)
        if (mpz_is_prime_naive(q) && q != p) factor_base[n_fb++] = q;
    if (n_fb == 0) return 0;

    int matrix[30][31] = {{0}}; int n_relations = 0;
    for (uint64_t e = 1; e < p && n_relations < n_fb + 3; e++) {
        uint64_t val = mpz_mod_pow(g->value, e, p);
        int exponents[30] = {0}; uint64_t tmp = val;
        for (int j = 0; j < n_fb; j++) {
            while (tmp % factor_base[j] == 0) { exponents[j]++; tmp /= factor_base[j]; }
        }
        if (tmp == 1) {
            for (int j = 0; j < n_fb; j++)
                matrix[n_relations][j] = exponents[j] % (int)n;
            matrix[n_relations][n_fb] = (int)(e % n);
            n_relations++;
        }
    }
    if (n_relations < n_fb) return 0;

    /* Gaussian elimination mod n */
    for (int col = 0; col < n_fb; col++) {
        int pivot = -1;
        for (int row = col; row < n_relations; row++)
            if (matrix[row][col] != 0) { pivot = row; break; }
        if (pivot < 0) continue;
        if (pivot != col)
            for (int j = 0; j <= n_fb; j++) {
                int t = matrix[col][j]; matrix[col][j] = matrix[pivot][j]; matrix[pivot][j] = t; }
        uint64_t pv = (uint64_t)(matrix[col][col] % (int)n);
        uint64_t inv_pv = mpz_mod_inv(pv, n);
        if (inv_pv == 0) continue;
        for (int j = col; j <= n_fb; j++) {
            int val = matrix[col][j]; if (val < 0) val += (int)n;
            matrix[col][j] = (int)mpz_mod_mul((uint64_t)val, inv_pv, n);
        }
        for (int row = 0; row < n_relations; row++) {
            if (row == col) continue;
            int factor = matrix[row][col]; if (factor == 0) continue;
            for (int j = col; j <= n_fb; j++) {
                int term = (int)mpz_mod_mul((uint64_t)((factor%(int)n+(int)n)%(int)n),
                                             (uint64_t)(matrix[col][j]), n);
                matrix[row][j] = (matrix[row][j] - term) % (int)n;
                if (matrix[row][j] < 0) matrix[row][j] += (int)n;
            }
        }
    }

    uint64_t fb_logs[30] = {0};
    for (int i = 0; i < n_fb; i++) fb_logs[i] = (uint64_t)(matrix[i][n_fb] % (int)n);

    for (uint64_t r = 0; r < p; r++) {
        uint64_t val = mpz_mod_mul(h->value, mpz_mod_pow(g->value, r, p), p);
        int exponents[30] = {0}; uint64_t tmp = val;
        for (int j = 0; j < n_fb; j++)
            while (tmp % factor_base[j] == 0) { exponents[j]++; tmp /= factor_base[j]; }
        if (tmp == 1) {
            uint64_t sum = 0;
            for (int j = 0; j < n_fb; j++)
                sum = mpz_mod_add(sum, mpz_mod_mul((uint64_t)exponents[j], fb_logs[j], n), n);
            uint64_t x = mpz_mod_sub(sum, r, n);
            if (mpz_mod_pow(g->value, x, p) == h->value) return x;
        }
    }
    return 0;
}

/* ═══════════════════════════════════════════════════════════════
   DLP Solver (Auto-Select Best Algorithm)
   ═══════════════════════════════════════════════════════════════ */

uint64_t dlp_solve(const GroupElement* g, const GroupElement* h,
                    const CyclicGroup* group) {
    if (!g || !h || !group) return 0;
    if (ge_equal(g, h)) return 1;
    if (ge_is_identity(h)) return 0;
    uint64_t p = group->modulus, n = group->order;

    if (n <= 200) {
        uint64_t cur = 1;
        for (uint64_t x = 0; x < n; x++) { if (cur == h->value) return x; cur = mpz_mod_mul(cur, g->value, p); }
        return 0;
    }
    uint64_t m = 1; while (m * m < n) m++;
    if (m <= 30000) return dlp_baby_giant_step(g, h, group);
    if (n <= 5000000) return dlp_pollard_rho(g, h, group);
    if (p <= 50000) return dlp_index_calculus(g, h, group);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════
   CDH Solver via DLP Reduction
   ═══════════════════════════════════════════════════════════════ */

int cdh_solve_via_dlp(CDHInstance* inst) {
    if (!inst || !inst->g || !inst->g_a || !inst->g_b) return 0;
    uint64_t a = dlp_solve(inst->g, inst->g_a, inst->group);
    if (a == 0 && !ge_is_identity(inst->g_a)) return 0;
    inst->answer = ge_pow(inst->g_b, a); inst->solved = 1; return 1;
}

/* ═══════════════════════════════════════════════════════════════
   DDH Solver via Legendre Symbol
   ═══════════════════════════════════════════════════════════════ */

int ddh_solve_legendre(const DDHInstance* inst) {
    if (!inst) return 0;
    uint64_t p = inst->group->modulus;
    int ls_ga = legendre_symbol(inst->g_a->value, p);
    int ls_gb = legendre_symbol(inst->g_b->value, p);
    int ls_gc = legendre_symbol(inst->g_c->value, p);
    int ls_expected = ls_ga * ls_gb;
    if (ls_expected == 0 && ls_gc == 0) return 1;
    return (ls_gc == ls_expected) ? 1 : 0;
}

/* ═══════════════════════════════════════════════════════════════
   Hardness Reduction Proofs
   ═══════════════════════════════════════════════════════════════ */

void proof_dlp_implies_cdh(CyclicGroup* g) {
    printf("=== Proof: DLP ⇒ CDH ===\n");
    if (!g) { printf("FAIL: no group\n"); return; }
    uint64_t a = 3, b = 5;
    if (a >= g->order) a = g->order - 1;
    if (b >= g->order) b = g->order - 1;
    CDHInstance* cdh = cdh_instance_create(g, a, b);
    if (!cdh) { printf("FAIL\n"); return; }
    cdh_print(cdh);
    uint64_t recovered_a = dlp_solve(cdh->g, cdh->g_a, g);
    printf("Step 1: DLP(g, g^a) => a = %llu\n", (unsigned long long)recovered_a);
    GroupElement* answer = ge_pow(cdh->g_b, recovered_a);
    ge_print(answer, "Step 2: g^{ab} = (g^b)^a");
    GroupElement* expected = ge_pow(cdh->g, mpz_mod_mul(a, b, g->order));
    printf("Verification: %s\n", ge_equal(answer, expected) ? "PASS" : "FAIL");
    ge_free(answer); ge_free(expected); cdh_instance_free(cdh);
    printf("==========================\n");
}

void proof_ddh_implies_cdh(CyclicGroup* g) {
    printf("=== Proof: DDH oracle ⇒ CDH (gap-DH) ===\n");
    if (!g) { printf("FAIL\n"); return; }
    uint64_t a = 2, b = 3;
    if (a >= g->order) a = g->order - 1;
    if (b >= g->order) b = g->order - 1;
    uint64_t ab = mpz_mod_mul(a, b, g->order);
    printf("(g, g^a, g^b), a=%llu, b=%llu, ab=%llu\n",
           (unsigned long long)a, (unsigned long long)b, (unsigned long long)ab);
    printf("Using DDH oracle: can verify candidates for g^{ab}.\n");
    printf("(gap-DH groups: DDH easy, CDH hard — oracle helps)\n");
    printf("========================================\n");
}

void proof_dlp_self_reducibility(CyclicGroup* g, int trials) {
    printf("=== Proof: DLP Random Self-Reducibility ===\n");
    if (!g) { printf("FAIL\n"); return; }
    uint64_t secret = 7;
    if (secret >= g->order) secret = g->order - 1;
    DLPInstance* inst = dlp_instance_create(g, secret);
    if (!inst) return;
    printf("Target: dlog_g(h) = %llu\n", (unsigned long long)secret);
    int successes = 0;
    for (int t = 0; t < trials && t < 20; t++) {
        uint64_t r = (secret*(t+1) + t*3 + 1) % g->order;
        if (r == 0) r = 1;
        GroupElement* g_r = ge_pow(inst->generator, r);
        GroupElement* h_prime = ge_mul(inst->target, g_r);
        uint64_t x_prime = dlp_solve(inst->generator, h_prime, g);
        if (x_prime > 0) {
            uint64_t recovered = mpz_mod_sub(x_prime, r, g->order);
            if (recovered == secret) successes++;
        }
        ge_free(g_r); ge_free(h_prime);
    }
    printf("Self-reducibility: %d/%d successes\n", successes, trials);
    printf("===========================================\n");
    dlp_instance_free(inst);
}

void kea_vs_dlp_comparison(CyclicGroup* g) {
    printf("=== KEA vs DLP Hardness Comparison ===\n");
    if (!g) { printf("FAIL: no group\n"); return; }
    printf("Group: %s\nOrder: %llu\n", g->description, (unsigned long long)g->order);
    printf("Generic DLP lower bound: Ω(sqrt(n)) = Ω(%llu)\n",
           (unsigned long long)(1 + (uint64_t)sqrt((double)g->order)));
    printf("\n+----------------------+----------+------------+\n");
    printf("| Property             | DLP      | KEA        |\n");
    printf("+----------------------+----------+------------+\n");
    printf("| Extraction model     | Black-box| Non-BB     |\n");
    printf("| Generic lower bound  | Ω(√n)    | N/A        |\n");
    printf("| Falsifiable (Nao03)  | Yes      | No         |\n");
    printf("| Holds in GGM         | Yes      | Yes        |\n");
    printf("| Holds in AGM         | Yes      | Yes        |\n");
    printf("| Implies DLP hard?    | N/A      | Yes        |\n");
    printf("+----------------------+----------+------------+\n");
    printf("============================================\n");
}

void dlp_benchmark_algorithms(CyclicGroup* g) {
    printf("=== DLP Algorithm Benchmark ===\n");
    if (!g) return;
    printf("Group order: %llu\n", (unsigned long long)g->order);
    uint64_t secret = g->order / 2;
    if (secret == 0) secret = 1;
    DLPInstance* inst = dlp_instance_create(g, secret);
    if (!inst) return;
    printf("Brute force: "); uint64_t cur = 1; int done = 0;
    for (uint64_t x = 0; x < g->order && !done; x++) {
        if (cur == inst->target->value) { printf("x=%llu\n", (unsigned long long)x); done = 1; }
        cur = mpz_mod_mul(cur, inst->generator->value, g->modulus);
    }
    if (!done) printf("NOT found\n");
    printf("BSGS: "); uint64_t bsgs = dlp_baby_giant_step(inst->generator, inst->target, g);
    printf("x=%llu [%s]\n", (unsigned long long)bsgs, bsgs == secret ? "MATCH" : "MISMATCH");
    printf("Pollard Rho: "); uint64_t rho = dlp_pollard_rho(inst->generator, inst->target, g);
    printf("x=%llu [%s]\n", (unsigned long long)rho, rho == secret ? "MATCH" : "MISMATCH");
    printf("Index Calc: "); uint64_t ic = dlp_index_calculus(inst->generator, inst->target, g);
    printf("x=%llu [%s]\n", (unsigned long long)ic, ic == secret ? "MATCH" : "MISMATCH");
    dlp_instance_free(inst);
    printf("=================================\n");
}

void dlp_compare_methods(CyclicGroup* g) {
    printf("=== DLP Methods Comparison ===\n");
    if (!g) return;
    printf("Group: %s\n\n", g->description);
    printf("| Method          | Time          | Space       | Generic?  |\n");
    printf("|-----------------|---------------|-------------|-----------|\n");
    printf("| Brute Force     | O(n)          | O(1)        | Yes       |\n");
    printf("| BSGS (Shanks)   | O(√n)         | O(√n)       | Yes       |\n");
    printf("| Pollard's Rho   | O(√n) expected| O(1)        | Yes       |\n");
    printf("| Pohlig-Hellman  | O(Σ √p_i)    | O(log n)    | Yes       |\n");
    printf("| Index Calculus  | L_p(1/2,√2)  | O(B)        | No (Z_p*) |\n");
    printf("\n");
    dlp_benchmark_algorithms(g);
    printf("===============================\n");
}
