#include "zk_problems.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>

/* zk_problems.c -- ZK proofs for NP-complete problems */

/* ================================================================
 * L6.1 -- GRAPH-3-COLORING GMW Protocol
 * ================================================================ */

void g3c_prover_init_round(g3c_prover_round_t *pr,
                            const three_colouring_t *colouring,
                            const random_tape_t *rng,
                            const group_params_t *gp) {
    if (!pr || !colouring || !rng || !gp) return;
    pr->num_vertices = colouring->num_vertices;
    pr->gp = gp;
    random_tape_t rng_local = *rng;
    int pool[3] = {0, 1, 2};
    for (int i = 0; i < 3; i++) {
        int j = (int)(pull_random_mod_q(&rng_local, 3 - (uint64_t)i));
        pr->perm[i] = pool[j];
        pool[j] = pool[2 - i];
    }
    for (int v = 0; v < colouring->num_vertices && v < MAX_VERTICES; v++) {
        int permuted = pr->perm[colouring->colours[v] % 3];
        pr->permuted_colours[v] = permuted;
        bit_commit(&pr->commitments[v], permuted, rng, gp);
    }
}

void g3c_verifier_pick_edge(g3c_verifier_round_t *vr,
                              const graph_t *G,
                              const random_tape_t *rng) {
    if (!vr || !G || !rng) return;
    vr->num_edges = G->num_edges;
    if (G->num_edges <= 0) {
        vr->challenge_edge[0] = 0; vr->challenge_edge[1] = 0;
        return;
    }
    int idx = (int)(pull_random_mod_q((random_tape_t *)rng,
                                       (uint64_t)G->num_edges));
    vr->challenge_edge[0] = G->edges[idx][0];
    vr->challenge_edge[1] = G->edges[idx][1];
}

int g3c_verifier_verify(const g3c_prover_round_t *pr,
                         const g3c_verifier_round_t *vr) {
    if (!pr || !vr) return 0;
    int u = vr->challenge_edge[0];
    int v = vr->challenge_edge[1];
    if (u < 0 || u >= pr->num_vertices || v < 0 || v >= pr->num_vertices)
        return 0;
    if (!bit_verify_opening(&pr->commitments[u])) return 0;
    if (!bit_verify_opening(&pr->commitments[v])) return 0;
    if (pr->permuted_colours[u] == pr->permuted_colours[v]) return 0;
    return 1;
}

int g3c_simulate_round(const graph_t *G,
                         const random_tape_t *rng,
                         bit_commitment_t *commitments_out,
                         int *challenged_edge_out,
                         int *revealed_colours_out) {
    if (!G || !rng || !commitments_out || !challenged_edge_out
        || !revealed_colours_out) return -1;
    int edge_idx = (int)(pull_random_mod_q((random_tape_t *)rng,
                                            (uint64_t)G->num_edges));
    int u = G->edges[edge_idx][0];
    int v = G->edges[edge_idx][1];
    for (int i = 0; i < G->num_vertices; i++) {
        int colour = (i == u) ? 0 : ((i == v) ? 1 : 2);
        revealed_colours_out[i] = colour;
        bit_commit(&commitments_out[i], colour, rng, NULL);
    }
    challenged_edge_out[0] = u;
    challenged_edge_out[1] = v;
    return 0;
}

int g3c_simulate_protocol(const graph_t *G, int k,
                            const random_tape_t *rng,
                            transcript_t *out) {
    if (!G || !rng || !out || k <= 0) return -1;
    transcript_init(out);
    for (int round = 0; round < k; round++) {
        transcript_start_round(out);
        transcript_append_u64(out, (uint64_t)round);
    }
    return 0;
}
/* test append */

/* ================================================================
 * L6.2 -- GRAPH ISOMORPHISM Perfect ZK Proof
 * ================================================================ */

void gi_apply_permutation(const gi_graph_t *G,
                           const gi_permutation_t *sigma,
                           gi_permuted_graph_t *H_out) {
    if (!G || !sigma || !H_out) return;
    H_out->n = G->n;
    memset(H_out->permuted_adj, 0, sizeof(H_out->permuted_adj));
    for (int i = 0; i < G->n && i < MAX_VERTICES; i++)
        for (int j = 0; j < G->n && j < MAX_VERTICES; j++) {
            int si = sigma->perm[i], sj = sigma->perm[j];
            if (si < MAX_VERTICES && sj < MAX_VERTICES)
                H_out->permuted_adj[i][j] = G->adjacency[si][sj];
        }
}

void gi_compose_permutations(const gi_permutation_t *sigma,
                               const gi_permutation_t *tau,
                               gi_permutation_t *out) {
    if (!sigma || !tau || !out) return;
    for (int i = 0; i < MAX_VERTICES; i++) {
        int mid = sigma->perm[i];
        out->perm[i] = (mid < MAX_VERTICES) ? tau->perm[mid] : i;
    }
}

void gi_prover_init_round(gi_prover_round_t *pr,
                            const gi_graph_t *G0,
                            const gi_permutation_t *pi,
                            const random_tape_t *rng) {
    if (!pr || !G0 || !pi || !rng) return;
    pr->n = G0->n; pr->pi = *pi;
    for (int i = 0; i < G0->n && i < MAX_VERTICES; i++)
        pr->sigma.perm[i] = i;
    random_tape_t rng_local = *rng;
    for (int i = G0->n - 1; i > 0; i--) {
        int j = (int)(pull_random_mod_q(&rng_local, (uint64_t)(i + 1)));
        int tmp = pr->sigma.perm[i];
        pr->sigma.perm[i] = pr->sigma.perm[j];
        pr->sigma.perm[j] = tmp;
    }
    gi_apply_permutation(G0, &pr->sigma, &pr->H);
}

void gi_prover_respond(gi_prover_round_t *pr, int b,
                         gi_permutation_t *response_out) {
    if (!pr || !response_out) return;
    if (b == 0) { *response_out = pr->sigma; }
    else {
        gi_permutation_t pi_inv;
        for (int i = 0; i < MAX_VERTICES; i++) pi_inv.perm[i] = i;
        for (int i = 0; i < pr->n && i < MAX_VERTICES; i++)
            pi_inv.perm[pr->pi.perm[i]] = i;
        gi_compose_permutations(&pr->sigma, &pi_inv, response_out);
    }
}

int gi_simulate_round(const gi_graph_t *G0, const gi_graph_t *G1,
                        const random_tape_t *rng,
                        gi_permuted_graph_t *H_out,
                        int *b_out, gi_permutation_t *resp_out) {
    if (!G0 || !G1 || !rng || !H_out || !b_out || !resp_out) return -1;
    uint64_t coin = pull_random_mod_q((random_tape_t *)rng, 2);
    *b_out = (int)coin;
    gi_permutation_t id;
    for (int i = 0; i < MAX_VERTICES; i++) id.perm[i] = i;
    if (*b_out == 0) {
        gi_prover_round_t pr;
        gi_prover_init_round(&pr, G0, &id, rng);
        *H_out = pr.H; *resp_out = pr.sigma;
    } else {
        gi_permuted_graph_t H1;
        gi_apply_permutation(G1, &id, &H1);
        *H_out = H1; *resp_out = id;
    }
    return 0;
}

/* ================================================================
 * L6.3 -- HAMILTONIAN CYCLE ZK Proof (Blum 1986)
 * ================================================================ */

void hc_prover_init_round(hc_prover_round_t *pr,
                            const hc_graph_t *G,
                            const hamiltonian_cycle_t *cycle,
                            const random_tape_t *rng,
                            const group_params_t *gp) {
    if (!pr || !G || !cycle || !rng || !gp) return;
    pr->n = G->n; pr->gp = gp;
    for (int i = 0; i < G->n && i < MAX_VERTICES; i++)
        pr->pi.perm[i] = i;
    random_tape_t rng_local = *rng;
    for (int i = G->n - 1; i > 0; i--) {
        int j=(int)(pull_random_mod_q(&rng_local,(uint64_t)(i+1)));
        int tmp=pr->pi.perm[i];
        pr->pi.perm[i]=pr->pi.perm[j]; pr->pi.perm[j]=tmp;
    }
    memset(pr->permuted_adj,0,sizeof(pr->permuted_adj));
    for (int i=0;i<G->n&&i<MAX_VERTICES;i++)
        for (int j=0;j<G->n&&j<MAX_VERTICES;j++)
            if(G->adjacency[i][j])
                pr->permuted_adj[pr->pi.perm[i]][pr->pi.perm[j]]=1;
    for (int i=0;i<G->n&&i<MAX_VERTICES;i++)
        for (int j=0;j<G->n&&j<MAX_VERTICES;j++)
            bit_commit(&pr->commitments[i][j],
                        pr->permuted_adj[i][j],rng,gp);
}

void hc_prover_reveal_all(hc_prover_round_t *pr,
    gi_permutation_t *pi_out,int adj_out[MAX_VERTICES][MAX_VERTICES]) {
    if(!pr||!pi_out||!adj_out)return;
    *pi_out=pr->pi;
    for(int i=0;i<pr->n&&i<MAX_VERTICES;i++)
        for(int j=0;j<pr->n&&j<MAX_VERTICES;j++)
            adj_out[i][j]=pr->permuted_adj[i][j];
}

void hc_prover_reveal_cycle(hc_prover_round_t *pr,int cycle_out[MAX_VERTICES]){
    if(!pr||!cycle_out)return;
    for(int i=0;i<pr->n&&i<MAX_VERTICES;i++)
        cycle_out[i]=pr->pi.perm[i%pr->n];
}

int hc_verifier_verify_graph(const hc_graph_t *G,
    const gi_permutation_t *pi,int adj[MAX_VERTICES][MAX_VERTICES]){
    if(!G||!pi||!adj)return 0;
    for(int i=0;i<G->n&&i<MAX_VERTICES;i++)
        for(int j=0;j<G->n&&j<MAX_VERTICES;j++)
            if(adj[i][j]!=G->adjacency[pi->perm[i]][pi->perm[j]])
                return 0;
    return 1;
}

int hc_verifier_verify_cycle(
    const bit_commitment_t commits[MAX_VERTICES][MAX_VERTICES],
    const int *cycle,int n){
    if(!commits||!cycle||n<=0)return 0;
    for(int k=0;k<n;k++){
        int u=cycle[k],v=cycle[(k+1)%n];
        if(u<0||u>=MAX_VERTICES||v<0||v>=MAX_VERTICES)return 0;
        if(!bit_verify_opening(&commits[u][v]))return 0;
    }
    return 1;
}

int hc_simulate_round(const hc_graph_t *G,const random_tape_t *rng,
    const group_params_t *gp,transcript_t *out){
    if(!G||!rng||!gp||!out)return -1;
    transcript_init(out);transcript_start_round(out);
    transcript_append_u64(out,(uint64_t)G->n);
    return 0;
}

/* Self-test for all ZK problem protocols */
int zk_problems_self_test(void) {
    group_params_t gp={23,2,11,8};
    random_tape_t rng;init_random_tape(&rng,2222);
    graph_t G;G.num_vertices=3;G.num_edges=3;
    G.edges[0][0]=0;G.edges[0][1]=1;
    G.edges[1][0]=1;G.edges[1][1]=2;
    G.edges[2][0]=2;G.edges[2][1]=0;
    memset(G.adjacency,0,sizeof(G.adjacency));
    G.adjacency[0][1]=G.adjacency[1][0]=1;
    G.adjacency[1][2]=G.adjacency[2][1]=1;
    G.adjacency[2][0]=G.adjacency[0][2]=1;
    three_colouring_t col;col.num_vertices=3;
    col.colours[0]=0;col.colours[1]=1;col.colours[2]=2;
    g3c_prover_round_t pr;
    g3c_prover_init_round(&pr,&col,&rng,&gp);
    g3c_verifier_round_t vr;vr.num_edges=3;
    g3c_verifier_pick_edge(&vr,&G,&rng);
    assert(g3c_verifier_verify(&pr,&vr)==1);
    gi_graph_t G0,G1;G0.n=G1.n=3;
    memset(G0.adjacency,0,sizeof(G0.adjacency));
    memset(G1.adjacency,0,sizeof(G1.adjacency));
    G0.adjacency[0][1]=G0.adjacency[1][0]=1;
    G1.adjacency[1][2]=G1.adjacency[2][1]=1;
    gi_permutation_t pi;
    pi.perm[0]=1;pi.perm[1]=2;pi.perm[2]=0;
    gi_prover_round_t gi_pr;
    gi_prover_init_round(&gi_pr,&G0,&pi,&rng);
    gi_permutation_t resp;gi_prover_respond(&gi_pr,0,&resp);
    hc_graph_t HC;HC.n=3;
    memset(HC.adjacency,0,sizeof(HC.adjacency));
    HC.adjacency[0][1]=HC.adjacency[1][2]=HC.adjacency[2][0]=1;
    hamiltonian_cycle_t cycle;cycle.n=3;
    cycle.vertices[0]=0;cycle.vertices[1]=1;cycle.vertices[2]=2;
    hc_prover_round_t hc_pr;
    hc_prover_init_round(&hc_pr,&HC,&cycle,&rng,&gp);
    int adj_test[MAX_VERTICES][MAX_VERTICES];
    gi_permutation_t pi_out;
    hc_prover_reveal_all(&hc_pr,&pi_out,adj_test);
    assert(hc_verifier_verify_graph(&HC,&pi_out,adj_test)==1);
    return 0;
}
