/*
 * graph_3coloring.h - Graph 3-Coloring Data Structures & Verification
 *
 * L1 Definitions:
 *   - Graph G = (V, E): vertices V = {0,...,n-1}, edges E subset V x V
 *   - k-coloring: function c: V -> {0,...,k-1} s.t. forall (u,v) in E: c(u) != c(v)
 *   - 3-COLORING = {<G> | G is 3-colorable} (NP-complete, Karp 1972)
 *
 * L2 Core Concepts:
 *   - Proper coloring, chromatic number chi(G)
 *   - NP-completeness: 3SAT <=p 3-COLORING
 *   - Coloring as NP witness
 *
 * L3 Mathematical Structures:
 *   - Adjacency matrix + adjacency list (dual representation)
 *   - Color assignment: int array of length |V|
 *   - Permutation group S3 acting on colors {0,1,2}
 *
 * Reference:
 *   Karp (1972), Garey & Johnson (1979), Goldreich (2004)
 *   Goldreich, Micali, Wigderson (STOC 1986)
 * Courses: MIT 6.876, Stanford CS255, Berkeley CS276
 */

#ifndef GRAPH_3COLORING_H
#define GRAPH_3COLORING_H

#include <stdlib.h>
#include <stdint.h>

#define COLOR_RED    0
#define COLOR_GREEN  1
#define COLOR_BLUE   2
#define NUM_COLORS   3
#define COLOR_STRING(c) ((c)==0?"RED":((c)==1?"GREEN":"BLUE"))

typedef struct {
    int     n_vertices;
    int     n_edges;
    int*    adj_matrix;
    int**   adj_list;
    int*    adj_list_sizes;
    int*    adj_list_caps;
    int     directed;
    int     max_degree;
    int     min_degree;
    double  density;
} Graph3Col;

typedef struct {
    int  n_vertices;
    int* colors;
    int  valid;
} Coloring3;

typedef struct {
    int vertex;
    int color;
    int n_conflicts;
} ColoringStep;

Graph3Col*  graph3_create(int n_vertices, int max_edges);
void        graph3_free(Graph3Col* g);
int         graph3_add_edge(Graph3Col* g, int u, int v);
int         graph3_has_edge(const Graph3Col* g, int u, int v);
void        graph3_calculate_stats(Graph3Col* g);

void        graph3_print(const Graph3Col* g);
void        graph3_print_compact(const Graph3Col* g);
int         graph3_write_dimacs(const Graph3Col* g, const char* filename);
Graph3Col*  graph3_read_dimacs(const char* filename);
void        graph3_print_adjlist(const Graph3Col* g);

Coloring3*  coloring3_create(int n_vertices);
Coloring3*  coloring3_clone(const Coloring3* c);
void        coloring3_free(Coloring3* c);
void        coloring3_print(const Coloring3* c);
int         coloring3_copy_colors(Coloring3* dest, const Coloring3* src);

int         coloring3_verify(const Graph3Col* g, const Coloring3* c);
int         coloring3_count_conflicts(const Graph3Col* g, const Coloring3* c);
int         coloring3_find_conflict_edge(const Graph3Col* g,
                                          const Coloring3* c,
                                          int* u_out, int* v_out);
int         coloring3_count_colors_used(const Coloring3* c);
int         coloring3_same_color(const Coloring3* c, int u, int v);

Graph3Col*  graph3_generate_random(int n_vertices, double edge_prob, unsigned int seed);
Graph3Col*  graph3_generate_3colorable(int n_vertices, double edge_prob, unsigned int seed);
Graph3Col*  graph3_create_named(const char* name);
Graph3Col*  graph3_clone(const Graph3Col* g);

int         graph3_find_coloring_bruteforce(const Graph3Col* g, Coloring3** out);
int         graph3_find_coloring_backtrack(const Graph3Col* g, Coloring3** out);
int         graph3_greedy_coloring(const Graph3Col* g, const int* order,
                                    Coloring3* out);
void        graph3_random_order(int n_vertices, int* order, unsigned int seed);
int         graph3_welsh_powell(const Graph3Col* g, Coloring3* out);
int         graph3_is_bipartite(const Graph3Col* g, Coloring3* out);

void        graph3_print_stats(const Graph3Col* g);
int         graph3_vertex_degree(const Graph3Col* g, int v);
int         graph3_is_connected(const Graph3Col* g);
int         graph3_count_triangles(const Graph3Col* g);
int         graph3_count_components(const Graph3Col* g);

#endif
