/*
 * graph_3coloring.c -- Graph 3-Coloring Data Structures & Algorithms
 *
 * Full implementation of graph data structure with adjacency matrix/list
 * dual representation and coloring algorithms for the GMW protocol.
 *
 * L1: Graph, proper coloring, 3-COLORING as NP-complete language
 * L2: NP-completeness of 3-COLORING (Karp 1972), witness as coloring
 * L3: S3 permutation group on colors, adjacency matrix/list duality
 * L5: Backtracking search, Welsh-Powell greedy, bipartiteness detection
 * L6: 3-COLORING as canonical NP-complete problem
 *
 * Reference: Karp (1972), Garey & Johnson (1979), Goldreich-Micali-Wigderson (1986)
 * Courses: MIT 6.876, Stanford CS255, Berkeley CS276, Princeton COS 522
 */
#include "graph_3coloring.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

Graph3Col* graph3_create(int n_vertices, int max_edges) {
    if (n_vertices <= 0 || max_edges < 0) return NULL;
    Graph3Col* g = (Graph3Col*)malloc(sizeof(Graph3Col));
    if (!g) return NULL;
    g->n_vertices = n_vertices; g->n_edges = 0;
    g->directed = 0; g->max_degree = 0; g->min_degree = 0; g->density = 0.0;
    int mat_size = n_vertices * n_vertices;
    g->adj_matrix = (int*)calloc((size_t)mat_size, sizeof(int));
    if (!g->adj_matrix) { free(g); return NULL; }
    g->adj_list = (int**)malloc((size_t)n_vertices * sizeof(int*));
    g->adj_list_sizes = (int*)calloc((size_t)n_vertices, sizeof(int));
    g->adj_list_caps = (int*)malloc((size_t)n_vertices * sizeof(int));
    if (!g->adj_list || !g->adj_list_sizes || !g->adj_list_caps) {
        free(g->adj_matrix); free(g->adj_list);
        free(g->adj_list_sizes); free(g->adj_list_caps);
        free(g); return NULL;
    }
    int dcap = max_edges > 0 ? max_edges / n_vertices + 1 : 4;
    for (int i = 0; i < n_vertices; i++) {
        g->adj_list_caps[i] = dcap;
        g->adj_list[i] = (int*)malloc((size_t)dcap * sizeof(int));
        if (!g->adj_list[i]) {
            for (int j = 0; j < i; j++) free(g->adj_list[j]);
            free(g->adj_matrix); free(g->adj_list);
            free(g->adj_list_sizes); free(g->adj_list_caps);
            free(g); return NULL;
        }
        g->adj_list_sizes[i] = 0;
    }
    return g;
}

void graph3_free(Graph3Col* g) {
    if (!g) return;
    free(g->adj_matrix);
    if (g->adj_list) {
        for (int i = 0; i < g->n_vertices; i++) free(g->adj_list[i]);
        free(g->adj_list);
    }
    free(g->adj_list_sizes); free(g->adj_list_caps);
    free(g);
}

int graph3_add_edge(Graph3Col* g, int u, int v) {
    if (!g || u < 0 || u >= g->n_vertices || v < 0 || v >= g->n_vertices)
        return 0;
    if (u == v) return 0;
    int idx = u * g->n_vertices + v;
    if (g->adj_matrix[idx]) return 0;
    g->adj_matrix[idx] = 1;
    g->adj_matrix[v * g->n_vertices + u] = 1;
    g->n_edges++;
    for (int pass = 0; pass < 2; pass++) {
        int a = (pass == 0) ? u : v;
        int b = (pass == 0) ? v : u;
        if (g->adj_list_sizes[a] >= g->adj_list_caps[a]) {
            g->adj_list_caps[a] *= 2;
            g->adj_list[a] = (int*)realloc(g->adj_list[a],
                (size_t)g->adj_list_caps[a] * sizeof(int));
        }
        g->adj_list[a][g->adj_list_sizes[a]++] = b;
    }
    return 1;
}

int graph3_has_edge(const Graph3Col* g, int u, int v) {
    if (!g || u < 0 || u >= g->n_vertices || v < 0 || v >= g->n_vertices)
        return 0;
    return g->adj_matrix[u * g->n_vertices + v];
}

void graph3_calculate_stats(Graph3Col* g) {
    if (!g || g->n_vertices == 0) return;
    g->max_degree = 0; g->min_degree = g->n_vertices;
    for (int i = 0; i < g->n_vertices; i++) {
        int deg = 0;
        for (int j = 0; j < g->n_vertices; j++)
            if (g->adj_matrix[i * g->n_vertices + j]) deg++;
        if (deg > g->max_degree) g->max_degree = deg;
        if (deg < g->min_degree) g->min_degree = deg;
    }
    if (g->min_degree > g->max_degree) g->min_degree = 0;
    int mp = g->n_vertices * (g->n_vertices - 1) / 2;
    g->density = mp > 0 ? (double)g->n_edges / mp : 0.0;
}

int graph3_vertex_degree(const Graph3Col* g, int v) {
    if (!g || v < 0 || v >= g->n_vertices) return -1;
    int deg = 0;
    for (int i = 0; i < g->n_vertices; i++)
        if (g->adj_matrix[v * g->n_vertices + i]) deg++;
    return deg;
}

void graph3_print(const Graph3Col* g) {
    if (!g) { printf("Graph3Col: NULL\n"); return; }
    printf("Graph3Col: |V|=%d, |E|=%d, density=%.4f, max_deg=%d, min_deg=%d\n",
           g->n_vertices, g->n_edges, g->density, g->max_degree, g->min_degree);
}

void graph3_print_compact(const Graph3Col* g) {
    if (!g) { printf("G(NULL)"); return; }
    printf("G(V%d_E%d)", g->n_vertices, g->n_edges);
}

int graph3_write_dimacs(const Graph3Col* g, const char* filename) {
    if (!g || !filename) return 0;
    FILE* f = fopen(filename, "w");
    if (!f) return 0;
    fprintf(f, "p edge %d %d\n", g->n_vertices, g->n_edges);
    for (int i = 0; i < g->n_vertices; i++)
        for (int j = i + 1; j < g->n_vertices; j++)
            if (g->adj_matrix[i * g->n_vertices + j])
                fprintf(f, "e %d %d\n", i + 1, j + 1);
    fclose(f); return 1;
}

Graph3Col* graph3_read_dimacs(const char* filename) {
    if (!filename) return NULL;
    FILE* f = fopen(filename, "r");
    if (!f) return NULL;
    Graph3Col* g = NULL; char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == 'c') continue;
        if (line[0] == 'p') {
            int n, m;
            if (sscanf(line, "p edge %d %d", &n, &m) == 2) {
                g = graph3_create(n, m);
                if (!g) { fclose(f); return NULL; }
            }
        } else if (line[0] == 'e' && g) {
            int u, v;
            if (sscanf(line, "e %d %d", &u, &v) == 2)
                graph3_add_edge(g, u - 1, v - 1);
        }
    }
    fclose(f);
    if (g) graph3_calculate_stats(g);
    return g;
}

void graph3_print_adjlist(const Graph3Col* g) {
    if (!g) return;
    for (int i = 0; i < g->n_vertices; i++) {
        printf("  v%d:", i);
        for (int j = 0; j < g->adj_list_sizes[i]; j++)
            printf(" %d", g->adj_list[i][j]);
        printf("\n");
    }
}

void graph3_print_stats(const Graph3Col* g) {
    if (!g) return;
    graph3_print(g);
    printf("  Max edges: %d\n", g->n_vertices*(g->n_vertices-1)/2);
    printf("  Connected: %s\n", graph3_is_connected(g)?"yes":"no");
    printf("  Components: %d\n", graph3_count_components(g));
    printf("  Triangles: %d\n", graph3_count_triangles(g));
}

Graph3Col* graph3_generate_random(int n_vertices, double edge_prob,
                                   unsigned int seed) {
    if (n_vertices <= 1 || edge_prob < 0.0 || edge_prob > 1.0) return NULL;
    int me = (int)(n_vertices*(n_vertices-1)/2*edge_prob*1.5);
    if (me < 2) me = 2;
    Graph3Col* g = graph3_create(n_vertices, me);
    if (!g) return NULL;
    srand(seed);
    for (int i = 0; i < n_vertices; i++)
        for (int j = i+1; j < n_vertices; j++)
            if ((double)rand()/RAND_MAX < edge_prob)
                graph3_add_edge(g, i, j);
    graph3_calculate_stats(g);
    return g;
}

Graph3Col* graph3_generate_3colorable(int n_vertices, double edge_prob,
                                       unsigned int seed) {
    if (n_vertices <= 1 || edge_prob < 0.0 || edge_prob > 1.0) return NULL;
    srand(seed);
    int* sc = (int*)malloc((size_t)n_vertices*sizeof(int));
    if (!sc) return NULL;
    for (int i = 0; i < n_vertices; i++) sc[i] = rand() % NUM_COLORS;
    int me = (int)(n_vertices*(n_vertices-1)/2*edge_prob*1.5);
    if (me < 2) me = 2;
    Graph3Col* g = graph3_create(n_vertices, me);
    if (!g) { free(sc); return NULL; }
    for (int i = 0; i < n_vertices; i++)
        for (int j = i+1; j < n_vertices; j++)
            if ((double)rand()/RAND_MAX < edge_prob && sc[i] != sc[j])
                graph3_add_edge(g, i, j);
    graph3_calculate_stats(g);
    free(sc);
    return g;
}

Graph3Col* graph3_create_named(const char* name) {
    if (!name) return NULL;
    Graph3Col* g = NULL;
    if (strcmp(name,"triangle")==0) {
        g=graph3_create(3,3);
        graph3_add_edge(g,0,1);graph3_add_edge(g,1,2);graph3_add_edge(g,0,2);
    } else if (strcmp(name,"square")==0) {
        g=graph3_create(4,4);
        graph3_add_edge(g,0,1);graph3_add_edge(g,1,2);
        graph3_add_edge(g,2,3);graph3_add_edge(g,3,0);
    } else if (strcmp(name,"k4")==0) {
        g=graph3_create(4,6);
        for(int i=0;i<4;i++)for(int j=i+1;j<4;j++)graph3_add_edge(g,i,j);
    } else if (strcmp(name,"odd5")==0) {
        g=graph3_create(5,5);
        for(int i=0;i<5;i++)graph3_add_edge(g,i,(i+1)%5);
    } else if (strcmp(name,"house")==0) {
        g=graph3_create(5,6);
        graph3_add_edge(g,0,1);graph3_add_edge(g,1,2);graph3_add_edge(g,2,3);
        graph3_add_edge(g,3,0);graph3_add_edge(g,0,2);graph3_add_edge(g,3,4);
    } else if (strcmp(name,"petersen")==0) {
        int eds[15][2]={{0,1},{1,2},{2,3},{3,4},{4,0},
                        {5,7},{7,9},{9,6},{6,8},{8,5},
                        {0,5},{1,6},{2,7},{3,8},{4,9}};
        g=graph3_create(10,15);
        for(int i=0;i<15;i++)graph3_add_edge(g,eds[i][0],eds[i][1]);
    }
    if(g)graph3_calculate_stats(g);
    return g;
}

Graph3Col* graph3_clone(const Graph3Col* g) {
    if (!g) return NULL;
    Graph3Col* c = graph3_create(g->n_vertices, g->n_edges);
    if (!c) return NULL;
    for (int i=0;i<g->n_vertices;i++)
        for(int j=i+1;j<g->n_vertices;j++)
            if(g->adj_matrix[i*g->n_vertices+j])
                graph3_add_edge(c,i,j);
    graph3_calculate_stats(c);
    return c;
}

int graph3_is_connected(const Graph3Col* g) {
    if (!g||g->n_vertices==0)return 0;
    if(g->n_vertices==1)return 1;
    int*vis=(int*)calloc((size_t)g->n_vertices,sizeof(int));
    if(!vis)return 0;
    int*q=(int*)malloc((size_t)g->n_vertices*sizeof(int));
    if(!q){free(vis);return 0;}
    int h=0,t=0;q[t++]=0;vis[0]=1;
    while(h<t){int v=q[h++];
        for(int i=0;i<g->n_vertices;i++)
            if(g->adj_matrix[v*g->n_vertices+i]&&!vis[i])
                {vis[i]=1;q[t++]=i;}
    }
    int conn=1;
    for(int i=0;i<g->n_vertices;i++)if(!vis[i]){conn=0;break;}
    free(q);free(vis);return conn;
}

int graph3_count_components(const Graph3Col* g) {
    if (!g||g->n_vertices==0)return 0;
    int*vis=(int*)calloc((size_t)g->n_vertices,sizeof(int));
    if(!vis)return-1;
    int*q=(int*)malloc((size_t)g->n_vertices*sizeof(int));
    if(!q){free(vis);return-1;}
    int comp=0;
    for(int s=0;s<g->n_vertices;s++){
        if(vis[s]) continue;
        comp++;
        int h=0,t=0;q[t++]=s;vis[s]=1;
        while(h<t){int v=q[h++];
            for(int i=0;i<g->n_vertices;i++)
                if(g->adj_matrix[v*g->n_vertices+i]&&!vis[i])
                    {vis[i]=1;q[t++]=i;}
        }
    }
    free(q);free(vis);return comp;
}

int graph3_count_triangles(const Graph3Col* g) {
    if(!g)return 0;
    int cnt=0;
    for(int u=0;u<g->n_vertices;u++){
        int*nu=g->adj_list[u];int sz=g->adj_list_sizes[u];
        for(int i=0;i<sz;i++){int v=nu[i];if(v<u)continue;
            for(int j=i+1;j<sz;j++){int w=nu[j];if(w<u)continue;
                if(g->adj_matrix[v*g->n_vertices+w])cnt++;}
        }
    }
    return cnt;
}

Coloring3* coloring3_create(int n_vertices) {
    if(n_vertices<=0)return NULL;
    Coloring3*c=(Coloring3*)malloc(sizeof(Coloring3));
    if(!c)return NULL;
    c->n_vertices=n_vertices;
    c->colors=(int*)malloc((size_t)n_vertices*sizeof(int));
    if(!c->colors){free(c);return NULL;}
    for(int i=0;i<n_vertices;i++)c->colors[i]=-1;
    c->valid=0;return c;
}

Coloring3* coloring3_clone(const Coloring3* c) {
    if(!c)return NULL;
    Coloring3*cl=coloring3_create(c->n_vertices);
    if(!cl)return NULL;
    memcpy(cl->colors,c->colors,(size_t)c->n_vertices*sizeof(int));
    cl->valid=c->valid;return cl;
}

void coloring3_free(Coloring3* c) {
    if(!c) return;
    free(c->colors);
    free(c);
}

void coloring3_print(const Coloring3* c) {
    if(!c){printf("Coloring3: NULL\n");return;}
    printf("Coloring3: %d verts, valid=%s\n",
           c->n_vertices,c->valid?"yes":"no");
    for(int i=0;i<c->n_vertices;i++)
        printf("  v%d: %s\n",i,COLOR_STRING(c->colors[i]));
}

int coloring3_copy_colors(Coloring3* d, const Coloring3* s) {
    if(!d||!s||d->n_vertices<s->n_vertices)return 0;
    memcpy(d->colors,s->colors,(size_t)s->n_vertices*sizeof(int));
    d->n_vertices=s->n_vertices;d->valid=s->valid;return 1;
}

int coloring3_verify(const Graph3Col* g, const Coloring3* c) {
    if(!g||!c||g->n_vertices!=c->n_vertices)return 0;
    for(int i=0;i<g->n_vertices;i++)
        if(c->colors[i]<0||c->colors[i]>=NUM_COLORS)return 0;
    for(int i=0;i<g->n_vertices;i++)
        for(int j=i+1;j<g->n_vertices;j++)
            if(g->adj_matrix[i*g->n_vertices+j])
                if(c->colors[i]==c->colors[j])return 0;
    return 1;
}

int coloring3_count_conflicts(const Graph3Col* g, const Coloring3* c) {
    if(!g||!c||g->n_vertices!=c->n_vertices)return -1;
    int cf=0;
    for(int i=0;i<g->n_vertices;i++)
        for(int j=i+1;j<g->n_vertices;j++)
            if(g->adj_matrix[i*g->n_vertices+j])
                if(c->colors[i]==c->colors[j])cf++;
    return cf;
}

int coloring3_find_conflict_edge(const Graph3Col* g, const Coloring3* c,
                                  int* uo, int* vo) {
    if(!g||!c||g->n_vertices!=c->n_vertices||!uo||!vo)return 0;
    for(int i=0;i<g->n_vertices;i++)
        for(int j=i+1;j<g->n_vertices;j++)
            if(g->adj_matrix[i*g->n_vertices+j])
                if(c->colors[i]==c->colors[j]){*uo=i;*vo=j;return 1;}
    return 0;
}

int coloring3_count_colors_used(const Coloring3* c) {
    if(!c)return 0;
    int u[NUM_COLORS]={0,0,0};
    for(int i=0;i<c->n_vertices;i++){
        int co=c->colors[i];
        if(co>=0&&co<NUM_COLORS)u[co]=1;
    }
    return u[0]+u[1]+u[2];
}

int coloring3_same_color(const Coloring3* c, int u, int v) {
    if(!c||u<0||u>=c->n_vertices||v<0||v>=c->n_vertices)return -1;
    return c->colors[u]==c->colors[v]?1:0;
}

int graph3_find_coloring_bruteforce(const Graph3Col* g, Coloring3** out) {
    if(!g||!out)return 0;
    int n=g->n_vertices;
    if(n>15)return 0;
    Coloring3*tr=coloring3_create(n);
    if(!tr)return 0;
    long long total=1;
    for(int i=0;i<n;i++)total*=3;
    for(long long t=0;t<total;t++){
        long long x=t;
        for(int i=0;i<n;i++){tr->colors[i]=(int)(x%3);x/=3;}
        if(coloring3_verify(g,tr)){tr->valid=1;*out=tr;return 1;}
    }
    coloring3_free(tr);*out=NULL;return 0;
}

static int bt_recurse(const Graph3Col* g, Coloring3* c, int depth) {
    if(depth==g->n_vertices){c->valid=1;return 1;}
    int bv=-1,bd=-1;
    for(int v=0;v<g->n_vertices;v++){
        if(c->colors[v]>=0)continue;
        int d=graph3_vertex_degree(g,v);
        if(d>bd){bd=d;bv=v;}
    }
    if(bv<0){c->valid=1;return 1;}
    for(int col=0;col<NUM_COLORS;col++){
        int ok=1;
        for(int j=0;j<g->n_vertices;j++)
            if(g->adj_matrix[bv*g->n_vertices+j])
                if(c->colors[j]==col){ok=0;break;}
        if(!ok)continue;
        c->colors[bv]=col;
        if(bt_recurse(g,c,depth+1))return 1;
        c->colors[bv]=-1;
    }
    return 0;
}

int graph3_find_coloring_backtrack(const Graph3Col* g, Coloring3** out) {
    if(!g||!out)return 0;
    Coloring3*c=coloring3_create(g->n_vertices);
    if(!c)return 0;
    if(bt_recurse(g,c,0)){*out=c;return 1;}
    coloring3_free(c);*out=NULL;return 0;
}

int graph3_greedy_coloring(const Graph3Col* g, const int* ord, Coloring3* out) {
    if(!g||!ord||!out||g->n_vertices!=out->n_vertices)return 0;
    for(int i=0;i<g->n_vertices;i++)out->colors[i]=-1;
    for(int p=0;p<g->n_vertices;p++){
        int v=ord[p];
        int forbid[NUM_COLORS]={0,0,0};
        for(int j=0;j<g->n_vertices;j++)
            if(g->adj_matrix[v*g->n_vertices+j]&&out->colors[j]>=0)
                forbid[out->colors[j]]=1;
        int asgn=0;
        for(int col=0;col<NUM_COLORS;col++)
            if(!forbid[col]){out->colors[v]=col;asgn=1;break;}
        if(!asgn)return 0;
    }
    out->valid=coloring3_verify(g,out);
    return out->valid;
}

void graph3_random_order(int n, int* ord, unsigned int seed) {
    if(!ord||n<=0)return;
    for(int i=0;i<n;i++)ord[i]=i;
    srand(seed);
    for(int i=n-1;i>0;i--){
        int j=rand()%(i+1);
        int t=ord[i];ord[i]=ord[j];ord[j]=t;
    }
}

int graph3_welsh_powell(const Graph3Col* g, Coloring3* out) {
    if(!g||!out||g->n_vertices!=out->n_vertices)return 0;
    int*deg=(int*)malloc((size_t)g->n_vertices*sizeof(int));
    int*ord=(int*)malloc((size_t)g->n_vertices*sizeof(int));
    if(!deg||!ord){free(deg);free(ord);return 0;}
    for(int i=0;i<g->n_vertices;i++){deg[i]=graph3_vertex_degree(g,i);ord[i]=i;}
    for(int i=0;i<g->n_vertices-1;i++)
        for(int j=i+1;j<g->n_vertices;j++)
            if(deg[ord[j]]>deg[ord[i]]){int t=ord[i];ord[i]=ord[j];ord[j]=t;}
    int r=graph3_greedy_coloring(g,ord,out);
    free(deg);free(ord);return r;
}

int graph3_is_bipartite(const Graph3Col* g, Coloring3* out) {
    if(!g||!out||g->n_vertices!=out->n_vertices)return 0;
    for(int i=0;i<g->n_vertices;i++)out->colors[i]=-1;
    int*q=(int*)malloc((size_t)g->n_vertices*sizeof(int));
    if(!q)return 0;
    int bip=1;
    for(int s=0;s<g->n_vertices&&bip;s++){
        if(out->colors[s]>=0)continue;
        out->colors[s]=0;int h=0,t=0;q[t++]=s;
        while(h<t&&bip){int v=q[h++];
            for(int u=0;u<g->n_vertices;u++){
                if(!g->adj_matrix[v*g->n_vertices+u])continue;
                if(out->colors[u]<0){out->colors[u]=1-out->colors[v];q[t++]=u;}
                else if(out->colors[u]==out->colors[v]){bip=0;break;}
            }
        }
    }
    free(q);return bip;
}
