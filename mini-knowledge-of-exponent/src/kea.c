/*
 * kea.c — Knowledge of Exponent Assumption (KEA)
 * L1: KEA1, KEA2, KEA3 definitions; extractor; non-black-box
 * L2: Falsifiability (Nao03), generic group model, algebraic group model
 * L3: KEAInstance, KEAResponse, KEAExtractor, KEAAdversaryState
 * L5: Extraction algorithm, security game simulation
 * L7: Cryptographic applications (SNARK frontend)
 * Courses: Stanford CS255, Berkeley CS276, MIT 6.875
 * (C) Mini-Theory-of-Computation — mini-knowledge-of-exponent
 */
#include "kea.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ═══════════════════════════════════════════════════════════════
   KEA Instance Management
   ═══════════════════════════════════════════════════════════════ */

KEAInstance* kea_instance_create(CyclicGroup* g) {
    if (!g) return NULL;
    KEAInstance* inst = (KEAInstance*)calloc(1, sizeof(KEAInstance));
    if (!inst) return NULL;
    inst->group = g;
    inst->secret_exp = 1 + (g->order > 2 ? g->order / 3 : 1);
    if (inst->secret_exp >= g->order) inst->secret_exp = g->order - 1;
    inst->base = ge_create(g->generator, g);
    inst->challenge = ge_pow(inst->base, inst->secret_exp);
    inst->variant = 1;
    if (!inst->base || !inst->challenge) { kea_instance_free(inst); return NULL; }
    return inst;
}

KEA2Instance* kea2_instance_create(CyclicGroup* g) {
    if (!g) return NULL;
    KEA2Instance* inst = (KEA2Instance*)calloc(1, sizeof(KEA2Instance));
    if (!inst) return NULL;
    inst->group = g;
    inst->secret_a = 1 + (g->order > 2 ? g->order / 3 : 1);
    inst->secret_b = 1 + (g->order > 3 ? g->order / 5 : 1);
    if (inst->secret_a >= g->order) inst->secret_a = g->order - 1;
    if (inst->secret_b >= g->order) inst->secret_b = g->order - 1;
    inst->base = ge_create(g->generator, g);
    inst->challenge_a = ge_pow(inst->base, inst->secret_a);
    inst->challenge_b = ge_pow(inst->base, inst->secret_b);
    inst->challenge_ab = ge_pow(inst->base, mpz_mod_mul(inst->secret_a, inst->secret_b, g->order));
    if (!inst->base || !inst->challenge_a || !inst->challenge_b || !inst->challenge_ab) {
        kea2_instance_free(inst); return NULL;
    }
    return inst;
}

void kea_instance_free(KEAInstance* inst) {
    if (!inst) return;
    ge_free(inst->base); ge_free(inst->challenge);
    free(inst);
}

void kea2_instance_free(KEA2Instance* inst) {
    if (!inst) return;
    ge_free(inst->base); ge_free(inst->challenge_a);
    ge_free(inst->challenge_b); ge_free(inst->challenge_ab);
    free(inst);
}

void kea_instance_print(const KEAInstance* inst) {
    if (!inst) return;
    printf("=== KEA Instance (variant %d) ===\n", inst->variant);
    ge_print(inst->base, "Base g");
    ge_print(inst->challenge, "Challenge g^a");
    printf("Secret exponent: (hidden)\n");
    printf("==================================\n");
}

/* ═══════════════════════════════════════════════════════════════
   KEA Response Operations
   ═══════════════════════════════════════════════════════════════ */

KEAResponse* kea_response_create(const KEAInstance* inst, uint64_t r) {
    if (!inst) return NULL;
    KEAResponse* resp = (KEAResponse*)calloc(1, sizeof(KEAResponse));
    if (!resp) return NULL;
    resp->c = ge_pow(inst->base, r);
    resp->c_prime = ge_pow(inst->challenge, r);
    resp->witness = r;
    GroupElement* check = ge_pow(resp->c, inst->secret_exp);
    resp->is_valid = ge_equal(resp->c_prime, check);
    ge_free(check);
    if (!resp->c || !resp->c_prime) { kea_response_free(resp); return NULL; }
    return resp;
}

KEA2Response* kea2_response_create(const KEA2Instance* inst, uint64_t r) {
    if (!inst) return NULL;
    KEA2Response* resp = (KEA2Response*)calloc(1, sizeof(KEA2Response));
    if (!resp) return NULL;
    resp->c = ge_pow(inst->base, r);
    resp->c_a = ge_pow(inst->challenge_a, r);
    resp->c_b = ge_pow(inst->challenge_b, r);
    resp->c_ab = ge_pow(inst->challenge_ab, r);
    resp->witness = r;
    int valid_a = ge_equal(resp->c_a, ge_pow(resp->c, inst->secret_a));
    int valid_b = ge_equal(resp->c_b, ge_pow(resp->c, inst->secret_b));
    GroupElement* ca_b = ge_pow(resp->c_a, inst->secret_b);
    int valid_ab = ge_equal(resp->c_ab, ca_b);
    ge_free(ca_b);
    resp->is_valid = valid_a && valid_b && valid_ab;
    if (!resp->c || !resp->c_a || !resp->c_b || !resp->c_ab) {
        kea2_response_free(resp); return NULL;
    }
    return resp;
}

int kea_response_verify(const KEAInstance* inst, const KEAResponse* resp) {
    if (!inst || !resp || !resp->c || !resp->c_prime) return 0;
    GroupElement* check = ge_pow(resp->c, inst->secret_exp);
    int ok = ge_equal(resp->c_prime, check);
    ge_free(check);
    return ok;
}

int kea2_response_verify(const KEA2Instance* inst, const KEA2Response* resp) {
    if (!inst || !resp) return 0;
    int ok_a = ge_equal(resp->c_a, ge_pow(resp->c, inst->secret_a));
    int ok_b = ge_equal(resp->c_b, ge_pow(resp->c, inst->secret_b));
    GroupElement* ca_b = ge_pow(resp->c_a, inst->secret_b);
    int ok_ab = ge_equal(resp->c_ab, ca_b);
    ge_free(ca_b);
    return ok_a && ok_b && ok_ab;
}

void kea_response_free(KEAResponse* resp) {
    if (!resp) return;
    ge_free(resp->c); ge_free(resp->c_prime);
    free(resp);
}

void kea2_response_free(KEA2Response* resp) {
    if (!resp) return;
    ge_free(resp->c); ge_free(resp->c_a);
    ge_free(resp->c_b); ge_free(resp->c_ab);
    free(resp);
}

void kea_response_print(const KEAResponse* resp) {
    if (!resp) return;
    printf("=== KEA Response ===\n");
    ge_print(resp->c, "C = g^r");
    ge_print(resp->c_prime, "C' = g^{ar}");
    printf("Witness r: %llu\n", (unsigned long long)resp->witness);
    printf("Valid: %s\n", resp->is_valid ? "YES" : "NO");
    printf("====================\n");
}

/* ═══════════════════════════════════════════════════════════════
   Extractor Operations
   ═══════════════════════════════════════════════════════════════ */

KEAExtractor* kea_extractor_create(void) {
    KEAExtractor* ext = (KEAExtractor*)calloc(1, sizeof(KEAExtractor));
    return ext;
}

int kea_extractor_extract(KEAExtractor* ext, const KEAAdversaryState* adv,
                           const KEAInstance* inst, uint64_t* witness_out) {
    if (!ext || !adv || !inst || !witness_out) return 0;
    ext->num_queries++;
    /* In GGM: extractor reads witness from adversary's random tape */
    if (adv->last_witness > 0) {
        *witness_out = adv->last_witness;
        ext->success_count++;
        ext->success_rate = (double)ext->success_count / ext->num_queries;
        ext->extracted_values = (uint64_t*)realloc(ext->extracted_values,
            ext->success_count * sizeof(uint64_t));
        if (ext->extracted_values) {
            ext->extracted_values[ext->success_count - 1] = *witness_out;
        }
        return 1;
    }
    ext->success_rate = (double)ext->success_count / ext->num_queries;
    return 0;
}

void kea_extractor_free(KEAExtractor* ext) {
    if (!ext) return;
    free(ext->extracted_values);
    free(ext);
}

/* ═══════════════════════════════════════════════════════════════
   Adversary Simulation
   ═══════════════════════════════════════════════════════════════ */

KEAAdversaryState* kea_adversary_create(CyclicGroup* g, uint64_t seed) {
    KEAAdversaryState* adv = (KEAAdversaryState*)calloc(1, sizeof(KEAAdversaryState));
    if (!adv) return NULL;
    adv->group = g;
    adv->tape_index = 0;
    adv->op_count = 0;
    uint64_t state = seed;
    for (int i = 0; i < 32; i++) {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        adv->random_tape[i] = state % (g ? g->order : 1000);
        if (adv->random_tape[i] == 0) adv->random_tape[i] = 1;
    }
    return adv;
}

KEAResponse* kea_adversary_compute(KEAAdversaryState* adv,
                                    const KEAInstance* inst) {
    if (!adv || !inst) return NULL;
    uint64_t r = adv->random_tape[adv->tape_index];
    adv->last_witness = r;
    adv->tape_index = (adv->tape_index + 1) % 32;
    adv->op_count += 2;
    return kea_response_create(inst, r);
}

KEAResponse* kea_malicious_adversary(KEAAdversaryState* adv,
                                      const KEAInstance* inst) {
    if (!adv || !inst) return NULL;
    KEAResponse* resp = (KEAResponse*)calloc(1, sizeof(KEAResponse));
    if (!resp) return NULL;
    uint64_t r = adv->random_tape[adv->tape_index];
    adv->last_witness = r;
    adv->tape_index = (adv->tape_index + 1) % 32;
    resp->c = ge_pow(inst->base, r);
    /* Malicious: use wrong exponent */
    uint64_t fake_r = (r + 1) % inst->group->order;
    if (fake_r == 0) fake_r = 1;
    resp->c_prime = ge_pow(inst->challenge, fake_r);
    resp->witness = r;
    resp->is_valid = kea_response_verify(inst, resp);
    adv->op_count += 2;
    return resp;
}

KEA2Response* kea2_adversary_compute(KEAAdversaryState* adv,
                                      const KEA2Instance* inst) {
    if (!adv || !inst) return NULL;
    uint64_t r = adv->random_tape[adv->tape_index];
    adv->last_witness = r;
    adv->tape_index = (adv->tape_index + 1) % 32;
    adv->op_count += 4;
    return kea2_response_create(inst, r);
}

void kea_adversary_free(KEAAdversaryState* adv) {
    free(adv);
}

/* ═══════════════════════════════════════════════════════════════
   KEA Security Games
   ═══════════════════════════════════════════════════════════════ */

int kea_security_game(CyclicGroup* g, int verbose) {
    if (!g) return 0;
    if (verbose) printf("========== KEA1 Security Game ==========\n");
    KEAInstance* inst = kea_instance_create(g);
    if (!inst) return 0;
    if (verbose) kea_instance_print(inst);
    KEAAdversaryState* adv = kea_adversary_create(g, 42);
    if (!adv) { kea_instance_free(inst); return 0; }
    KEAResponse* resp = kea_adversary_compute(adv, inst);
    if (!resp) { kea_adversary_free(adv); kea_instance_free(inst); return 0; }
    if (verbose) kea_response_print(resp);
    int valid = kea_response_verify(inst, resp);
    if (verbose) printf("Verification: %s\n", valid ? "PASS" : "FAIL");
    uint64_t extracted = 0;
    KEAExtractor* ext = kea_extractor_create();
    int extr_ok = kea_extractor_extract(ext, adv, inst, &extracted);
    int extr_correct = 0;
    if (extr_ok) {
        GroupElement* check = ge_pow(inst->base, extracted);
        extr_correct = ge_equal(check, resp->c);
        ge_free(check);
    }
    if (verbose) {
        printf("Extracted r=%llu, correct r=%llu, ok=%s\n",
               (unsigned long long)extracted, (unsigned long long)resp->witness,
               extr_correct ? "YES" : "NO");
        printf("Adversary %s\n", (valid && !extr_correct) ? "WINS" : "LOSES");
        printf("=========================================\n");
    }
    kea_extractor_free(ext);
    kea_response_free(resp);
    kea_adversary_free(adv);
    kea_instance_free(inst);
    return valid && !extr_correct;
}

int kea2_security_game(CyclicGroup* g, int verbose) {
    if (!g) return 0;
    if (verbose) printf("========== KEA2 Security Game ==========\n");
    KEA2Instance* inst = kea2_instance_create(g);
    if (!inst) return 0;
    KEAAdversaryState* adv = kea_adversary_create(g, 123);
    if (!adv) { kea2_instance_free(inst); return 0; }
    KEA2Response* resp = kea2_adversary_compute(adv, inst);
    if (!resp) { kea_adversary_free(adv); kea2_instance_free(inst); return 0; }
    int valid = kea2_response_verify(inst, resp);
    if (verbose) {
        printf("KEA2 verification: %s\n", valid ? "PASS" : "FAIL");
        printf("Witness r=%llu\n", (unsigned long long)resp->witness);
        printf("=========================================\n");
    }
    kea2_response_free(resp);
    kea_adversary_free(adv);
    kea2_instance_free(inst);
    return !valid;
}

/* ═══════════════════════════════════════════════════════════════
   KEA Variant: Auxiliary Input
   ═══════════════════════════════════════════════════════════════ */

KEAInstance* kea_auxiliary_input_create(CyclicGroup* g, uint64_t* aux, int aux_len) {
    if (!g) return NULL;
    KEAInstance* inst = kea_instance_create(g);
    if (!inst) return NULL;
    if (aux_len > 0) {
        printf("KEA with auxiliary input: ");
        for (int i = 0; i < aux_len && i < 4; i++)
            printf("%llu ", (unsigned long long)aux[i]);
        printf("\n");
    }
    return inst;
}

/* ═══════════════════════════════════════════════════════════════
   KEA Variant: q-KEA (Multiple Powers)
   ═══════════════════════════════════════════════════════════════ */

QKEAInstance* qkea_instance_create(CyclicGroup* g, int q) {
    if (!g || q < 1 || q > 16) return NULL;
    QKEAInstance* inst = (QKEAInstance*)calloc(1, sizeof(QKEAInstance));
    if (!inst) return NULL;
    inst->q = q;
    inst->base = kea_instance_create(g);
    if (!inst->base) { free(inst); return NULL; }
    inst->powers = (GroupElement**)calloc(q, sizeof(GroupElement*));
    if (!inst->powers) { kea_instance_free(inst->base); free(inst); return NULL; }
    uint64_t a = inst->base->secret_exp;
    for (int i = 0; i < q; i++) {
        uint64_t exp = a;
        for (int j = 0; j < i; j++) exp = mpz_mod_mul(exp, a, g->order);
        inst->powers[i] = ge_pow(inst->base->base, exp);
        if (!inst->powers[i]) { qkea_instance_free(inst); return NULL; }
    }
    return inst;
}

void qkea_instance_free(QKEAInstance* inst) {
    if (!inst) return;
    if (inst->powers) {
        for (int i = 0; i < inst->q; i++) ge_free(inst->powers[i]);
        free(inst->powers);
    }
    kea_instance_free(inst->base);
    free(inst);
}

/* ═══════════════════════════════════════════════════════════════
   Statistical Analysis
   ═══════════════════════════════════════════════════════════════ */

double kea_extraction_rate(CyclicGroup* g, int trials) {
    if (!g || trials <= 0) return 0.0;
    int successes = 0;
    for (int t = 0; t < trials; t++) {
        KEAInstance* inst = kea_instance_create(g);
        if (!inst) continue;
        KEAAdversaryState* adv = kea_adversary_create(g, 42 + t * 7);
        if (!adv) { kea_instance_free(inst); continue; }
        KEAResponse* resp = kea_adversary_compute(adv, inst);
        if (!resp || !resp->is_valid) {
            kea_response_free(resp); kea_adversary_free(adv);
            kea_instance_free(inst); continue;
        }
        uint64_t extracted = 0;
        KEAExtractor* ext = kea_extractor_create();
        int ok = kea_extractor_extract(ext, adv, inst, &extracted);
        if (ok && extracted == resp->witness) successes++;
        kea_extractor_free(ext);
        kea_response_free(resp);
        kea_adversary_free(adv);
        kea_instance_free(inst);
    }
    return trials > 0 ? (double)successes / trials : 0.0;
}

void kea_compare_adversaries(CyclicGroup* g, int trials) {
    printf("=== KEA Adversary Comparison ===\n");
    if (!g) { printf("FAIL: no group\n"); return; }
    printf("Group order: %llu, Trials: %d\n\n",
           (unsigned long long)g->order, trials);
    int honest_valid = 0, honest_extr = 0;
    int malicious_valid = 0;
    for (int t = 0; t < trials; t++) {
        KEAInstance* inst = kea_instance_create(g);
        if (!inst) continue;
        KEAAdversaryState* adv_h = kea_adversary_create(g, 42 + t);
        KEAResponse* resp_h = kea_adversary_compute(adv_h, inst);
        if (resp_h && resp_h->is_valid) {
            honest_valid++;
            KEAExtractor* ext = kea_extractor_create();
            uint64_t r;
            if (kea_extractor_extract(ext, adv_h, inst, &r) && r == resp_h->witness) honest_extr++;
            kea_extractor_free(ext);
        }
        kea_response_free(resp_h); kea_adversary_free(adv_h);
        KEAAdversaryState* adv_m = kea_adversary_create(g, 999 - t);
        KEAResponse* resp_m = kea_malicious_adversary(adv_m, inst);
        if (resp_m && resp_m->is_valid) malicious_valid++;
        kea_response_free(resp_m); kea_adversary_free(adv_m);
        kea_instance_free(inst);
    }
    printf("Honest:   %d/%d valid, %d/%d extracted\n",
           honest_valid, trials, honest_extr, honest_valid);
    printf("Malicious: %d/%d valid (KEA not required to extract)\n",
           malicious_valid, trials);
    printf("================================\n");
}
