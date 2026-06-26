#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <assert.h>
#include "graph_3coloring.h"
#include "commitment.h"
#include "gmw_protocol.h"
#include "simulator.h"
#include "interactive_proof.h"
#include "zk_applications.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { tests_run++; printf("  TEST: %s... ", name); } while(0)
#define PASS() do { printf("PASS\n"); tests_passed++; } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); } while(0)
#define CHECK(cond) do { if (!(cond)) { FAIL(#cond); return; } } while(0)

static void test_graph_create(void) {
    TEST("graph_create");
    Graph3Col* g = graph3_create(5, 10);
    CHECK(g != NULL);
    CHECK(g->n_vertices == 5);
    CHECK(g->n_edges == 0);
    graph3_free(g);
    PASS();
}

static void test_add_edge(void) {
    TEST("add_edge");
    Graph3Col* g = graph3_create(5, 10);
    CHECK(graph3_add_edge(g, 0, 1) == 1);
    CHECK(graph3_add_edge(g, 0, 2) == 1);
    CHECK(graph3_has_edge(g, 0, 1) == 1);
    CHECK(graph3_has_edge(g, 0, 3) == 0);
    CHECK(graph3_add_edge(g, 0, 1) == 0);
    CHECK(graph3_add_edge(g, 0, 0) == 0);
    graph3_free(g);
    PASS();
}

static void test_named_graphs(void) {
    TEST("named_graphs");
    Graph3Col* t = graph3_create_named("triangle");
    CHECK(t != NULL);
    CHECK(t->n_edges == 3);
    graph3_free(t);
    Graph3Col* k4 = graph3_create_named("k4");
    CHECK(k4 != NULL);
    CHECK(k4->n_edges == 6);
    graph3_free(k4);
    Graph3Col* p = graph3_create_named("petersen");
    CHECK(p != NULL);
    CHECK(p->n_vertices == 10);
    graph3_free(p);
    PASS();
}

static void test_connected(void) {
    TEST("connected");
    Graph3Col* g = graph3_create_named("triangle");
    CHECK(graph3_is_connected(g) == 1);
    CHECK(graph3_count_components(g) == 1);
    CHECK(graph3_count_triangles(g) == 1);
    graph3_free(g);
    PASS();
}

static void test_verify_coloring(void) {
    TEST("verify_coloring");
    Graph3Col* g = graph3_create_named("triangle");
    Coloring3* c = coloring3_create(3);
    c->colors[0] = COLOR_RED;
    c->colors[1] = COLOR_GREEN;
    c->colors[2] = COLOR_BLUE;
    CHECK(coloring3_verify(g, c) == 1);
    CHECK(coloring3_count_conflicts(g, c) == 0);
    coloring3_free(c);
    graph3_free(g);
    PASS();
}

static void test_conflict(void) {
    TEST("conflict");
    Graph3Col* g = graph3_create_named("triangle");
    Coloring3* c = coloring3_create(3);
    c->colors[0] = COLOR_RED;
    c->colors[1] = COLOR_RED;
    c->colors[2] = COLOR_BLUE;
    CHECK(coloring3_verify(g, c) == 0);
    CHECK(coloring3_count_conflicts(g, c) == 1);
    int u, v;
    CHECK(coloring3_find_conflict_edge(g, c, &u, &v) == 1);
    CHECK(u == 0);
    CHECK(v == 1);
    coloring3_free(c);
    graph3_free(g);
    PASS();
}

static void test_backtrack(void) {
    TEST("backtrack");
    Graph3Col* g = graph3_create_named("triangle");
    Coloring3* c = NULL;
    CHECK(graph3_find_coloring_backtrack(g, &c) == 1);
    CHECK(c != NULL);
    CHECK(coloring3_verify(g, c) == 1);
    coloring3_free(c);
    graph3_free(g);
    PASS();
}

static void test_k4_not_3col(void) {
    TEST("k4_not_3col");
    Graph3Col* g = graph3_create_named("k4");
    Coloring3* c = NULL;
    CHECK(graph3_find_coloring_backtrack(g, &c) == 0);
    CHECK(c == NULL);
    graph3_free(g);
    PASS();
}

static void test_bipartite(void) {
    TEST("bipartite");
    Graph3Col* g = graph3_create_named("square");
    Coloring3* c = coloring3_create(4);
    CHECK(graph3_is_bipartite(g, c) == 1);
    CHECK(c->colors[0] != c->colors[1]);
    coloring3_free(c);
    Graph3Col* tg = graph3_create_named("triangle");
    Coloring3* c2 = coloring3_create(3);
    CHECK(graph3_is_bipartite(tg, c2) == 0);
    coloring3_free(c2);
    graph3_free(g);
    graph3_free(tg);
    PASS();
}

static void test_hash_commit(void) {
    TEST("hash_commit");
    CommitNonce n;
    commit_generate_nonce(&n);
    HashDigest c0 = commit_bit(0, &n);
    HashDigest c1 = commit_bit(1, &n);
    CHECK(!hashdigest_equals(&c0, &c1));
    CHECK(commit_verify_bit(0, &n, &c0) == 1);
    CHECK(commit_verify_bit(1, &n, &c0) == 0);
    PASS();
}

static void test_color_commit(void) {
    TEST("color_commit");
    CommitNonce n0, n1, n2;
    commit_generate_nonce(&n0);
    commit_generate_nonce(&n1);
    commit_generate_nonce(&n2);
    HashDigest c0 = commit_color(COLOR_RED, &n0);
    HashDigest c1 = commit_color(COLOR_GREEN, &n1);
    HashDigest c2 = commit_color(COLOR_BLUE, &n2);
    CHECK(commit_verify_color(COLOR_RED, &n0, &c0) == 1);
    HashDigest all[3] = {c0, c1, c2};
    CHECK(commit_verify_edge(all, 0, 1, COLOR_RED, COLOR_GREEN, &n0, &n1) == 1);
    CHECK(commit_verify_edge(all, 0, 1, COLOR_RED, COLOR_RED, &n0, &n1) == 0);
    PASS();
}

static void test_color_array(void) {
    TEST("color_array");
    int cols[4] = {COLOR_RED, COLOR_GREEN, COLOR_BLUE, COLOR_RED};
    CommitNonce* ns = commit_generate_nonces(4);
    CHECK(ns != NULL);
    HashDigest* cs = commit_color_array(cols, 4, ns);
    CHECK(cs != NULL);
    for (int i = 0; i < 4; i++)
        CHECK(commit_verify_color(cols[i], &ns[i], &cs[i]) == 1);
    free(cs);
    commit_free_nonces(ns);
    PASS();
}

static void test_pedersen(void) {
    TEST("pedersen");
    PedersenParams* pp = pedersen_params_create();
    CHECK(pp != NULL);
    BigNum256 m, r;
    bignum256_from_int(&m, 5);
    bignum256_from_int(&r, 3);
    PedersenCommitment pc = pedersen_commit(pp, &m, &r);
    CHECK(!bignum256_is_zero(&pc.value));
    PedersenOpening op;
    op.message = m;
    op.randomness = r;
    CHECK(pedersen_verify(pp, &pc, &op) == 1);
    pedersen_params_free(pp);
    PASS();
}

static void test_soundness(void) {
    TEST("soundness");
    Graph3Col* g = graph3_create_named("triangle");
    GMWSession* s = gmw_session_create(g, NULL, 0, 10);
    CHECK(s != NULL);
    double e1 = gmw_soundness_error(s, 1);
    CHECK(fabs(e1 - 2.0/3.0) < 0.01);
    double e10 = gmw_soundness_error(s, 10);
    CHECK(e10 < 0.02);
    gmw_session_free(s);
    graph3_free(g);
    PASS();
}

static void test_simulator(void) {
    TEST("simulator");
    Graph3Col* g = graph3_create_named("triangle");
    SimulatedTranscript* t = simulator_generate_transcript(g, 42);
    CHECK(t != NULL);
    CHECK(simulator_verify_consistency(t, g) == 1);
    simulator_free_transcript(t);
    graph3_free(g);
    PASS();
}

static void test_real_transcript(void) {
    TEST("real_transcript");
    Graph3Col* g = graph3_create_named("triangle");
    Coloring3* c = coloring3_create(3);
    c->colors[0] = COLOR_RED;
    c->colors[1] = COLOR_GREEN;
    c->colors[2] = COLOR_BLUE;
    c->valid = 1;
    GMWTranscript* t = simulator_generate_real_transcript(g, c, 3, 123);
    CHECK(t != NULL);
    CHECK(t->verifier_accept == 1);
    if (t->rounds) {
        for (int i = 0; i < t->n_rounds; i++)
            gmw_round_free(t->rounds[i], 3);
        free(t->rounds);
    }
    free(t);
    coloring3_free(c);
    graph3_free(g);
    PASS();
}

static void test_zk_distinguisher(void) {
    TEST("zk_distinguisher");
    Graph3Col* g = graph3_create_named("triangle");
    Coloring3* c = coloring3_create(3);
    c->colors[0] = COLOR_RED;
    c->colors[1] = COLOR_GREEN;
    c->colors[2] = COLOR_BLUE;
    c->valid = 1;
    ZKDistinguisherReport* r = zk_distinguisher_run(g, c, 10, 999);
    CHECK(r != NULL);
    CHECK(r->samples_compared == 10);
    zk_distinguisher_report_free(r);
    coloring3_free(c);
    graph3_free(g);
    PASS();
}

static void test_ip_system(void) {
    TEST("ip_system");
    IPSystem* s = ip_system_create("TEST", 5);
    CHECK(s != NULL);
    CHECK(s->total_rounds == 5);
    ip_system_free(s);
    PASS();
}

static void test_ip_repetition(void) {
    TEST("ip_repetition");
    int k = ip_sequential_repetitions(0.5, 1e-6);
    CHECK(k > 0);
    double e = ip_repeated_soundness(0.5, k);
    CHECK(e <= 1e-6);
    PASS();
}

static void test_zk_auth(void) {
    TEST("zk_auth");
    ZKAuthCredential* cred = zk_auth_setup("alice", "secret", 5);
    CHECK(cred != NULL);
    CHECK(zk_auth_prove(cred, 42) == 1);
    zk_auth_free(cred);
    PASS();
}

static void test_nizk(void) {
    TEST("nizk");
    Graph3Col* g = graph3_create_named("triangle");
    Coloring3* c = coloring3_create(3);
    c->colors[0] = COLOR_RED;
    c->colors[1] = COLOR_GREEN;
    c->colors[2] = COLOR_BLUE;
    c->valid = 1;
    NIZKProof* p = nizk_gmw_prove(g, c, 42);
    CHECK(p != NULL);
    CHECK(nizk_gmw_verify(g, p) == 1);
    free(p->commitments);
    free(p);
    coloring3_free(c);
    graph3_free(g);
    PASS();
}

int main(void) {
    printf("=== GMW Graph 3-Coloring ZK Tests ===\n\n");
    test_graph_create();
    test_add_edge();
    test_named_graphs();
    test_connected();
    test_verify_coloring();
    test_conflict();
    test_backtrack();
    test_k4_not_3col();
    test_bipartite();
    test_hash_commit();
    test_color_commit();
    test_color_array();
    test_pedersen();
    test_soundness();
    test_simulator();
    test_real_transcript();
    test_zk_distinguisher();
    test_ip_system();
    test_ip_repetition();
    test_zk_auth();
    test_nizk();
    printf("\n=== Results: %d/%d tests passed ===\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
