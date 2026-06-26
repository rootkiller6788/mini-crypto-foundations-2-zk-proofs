# Knowledge Graph — GMW Graph 3-Coloring ZK Proofs

## L1: Definitions

| # | Term | Definition | Code |
|---|------|-----------|------|
| 1 | Graph G=(V,E) | Set of vertices V and edges E (undirected) | `graph_3coloring.h:Graph3Col` |
| 2 | Proper k-coloring | f: V->{0..k-1} s.t. forall (u,v) in E: f(u)!=f(v) | `graph_3coloring.h:Coloring3` |
| 3 | 3-COLORING | {<G> | G is 3-colorable} (NP-complete, Karp 1972) | `graph_3coloring.c:coloring3_verify` |
| 4 | Interactive Proof (IP) | (P,V): P (unbounded) interacts with V (PPT) | `interactive_proof.h:IPSystem` |
| 5 | Zero-Knowledge | Forall V* exists S s.t. View_V* ~_c S(x) | `simulator.h:SimulatedTranscript` |
| 6 | Bit Commitment | (Commit, Reveal): Hiding + Binding | `commitment.h:commit_bit` |
| 7 | GMW Protocol | ZK IP for 3-COLORING (Goldreich-Micali-Wigderson 1986) | `gmw_protocol.h:GMWSession` |
| 8 | Soundness Error | Pr[V accepts false statement] <= epsilon | `gmw_protocol.c:gmw_soundness_error` |
| 9 | NIZK | Non-Interactive ZK via Fiat-Shamir transform | `zk_applications.h:NIZKProof` |
| 10 | Pedersen Commitment | Perfectly hiding, computationally binding | `commitment.h:PedersenCommitment` |

## L2: Core Concepts

| # | Concept | Description | Code |
|---|---------|-------------|------|
| 1 | Completeness | If x in L, honest P convinces V w.p. >= 2/3 | `interactive_proof.c:ip_test_completeness` |
| 2 | Soundness | If x not in L, any P* convinces V w.p. <= 1/3 | `interactive_proof.c:ip_test_soundness` |
| 3 | Computational ZK | View distributions computationally indistinguishable | `simulator.c:simulator_generate_transcript` |
| 4 | HVZK | Honest-Verifier Zero-Knowledge | `simulator.c` (HVZK simulator) |
| 5 | Soundness Amplification | Repeat k times: error -> epsilon^k | `gmw_protocol.c:gmw_rounds_for_soundness` |
| 6 | NP-completeness of 3-COLORING | 3SAT <=p 3-COLORING (Karp 1972) | `graph_3coloring.c` (coloring as NP witness) |
| 7 | IP = PSPACE | Every PSPACE language has an IP (Shamir 1992) | `interactive_proof.h:IPClass` |
| 8 | Fiat-Shamir Heuristic | Replace verifier challenge with hash | `zk_applications.c:nizk_gmw_prove` |

## L3: Mathematical Structures

| # | Structure | Formal Definition | Code |
|---|-----------|-------------------|------|
| 1 | Adjacency Matrix | A[i][j] = 1 iff (i,j) in E | `graph_3coloring.c:graph3_create` |
| 2 | Adjacency List | Neighbor[v] = {u: (v,u) in E} | `graph_3coloring.c:graph3_create` |
| 3 | S3 Permutation Group | 6 bijections on {0,1,2} | `gmw_protocol.h:ColorPermutation` |
| 4 | Protocol Transcript | (commitments, challenge, decommitments) | `gmw_protocol.h:GMWTranscript` |
| 5 | Round State Machine | 5 phases: Init->Commit->Challenge->Reveal->Verify | `gmw_protocol.h:GMWPhase` |
| 6 | Merkle-Damgard Hash | Compression function f: {0,1}^256 x {0,1}^256 -> {0,1}^256 | `commitment.c:hash256_compute` |
| 7 | Safe-Prime Group | Z_p* where p=2q+1, subgroup of order q | `commitment.c:pedersen_commit` |
| 8 | Big Number (256-bit) | 8-word uint32 array for modular arithmetic | `commitment.h:BigNum256` |

## L4: Fundamental Theorems

| # | Theorem | Statement | Code Verification |
|---|---------|-----------|-------------------|
| 1 | GMW Theorem | Every L in NP has computational ZK proof | `simulator.c:simulator_np_language` |
| 2 | GMW Soundness Bound | epsilon = 1 - 1/|E| per round | `gmw_protocol.c:gmw_soundness_error` |
| 3 | Sequential Repetition | epsilon_k = (1 - 1/|E|)^k | `interactive_proof.c:ip_repeated_soundness` |
| 4 | Pedersen Perfect Hiding | forall m1,m2 exists r' s.t. g^m1 h^r = g^m2 h^r' | `commitment.c:pedersen_commit` |
| 5 | Pedersen Binding | Breaking = computing dlog_g(h) | `commitment.c:pedersen_verify` |
| 6 | Konig's Theorem | G bipartite iff no odd cycle | `graph_3coloring.c:graph3_is_bipartite` |
| 7 | K4 is not 3-colorable | chi(K4) = 4 > 3 | `graph_3coloring.c:graph3_find_coloring_backtrack` |
| 8 | NP <=p 3-COLORING | Every NP language reduces to 3-COLORING | `zk_applications.c:simulator_np_language` |

## L5: Algorithms/Methods

| # | Algorithm | Description | Complexity | Code |
|---|-----------|-------------|------------|------|
| 1 | GMW Prover Commit | Random permute + commit all vertices | O(|V|) hashes | `gmw_protocol.c:gmw_prover_commit` |
| 2 | GMW Verifier Challenge | Random edge selection | O(|E|) | `gmw_protocol.c:gmw_verifier_challenge` |
| 3 | GMW Verifier Verify | Check 2 colors differ + match commitments | O(1) | `gmw_protocol.c:gmw_verifier_verify` |
| 4 | Backtracking 3-Coloring | MRV heuristic + forward checking | O(3^|V|) worst | `graph_3coloring.c:graph3_find_coloring_backtrack` |
| 5 | Brute-force 3-Coloring | Enumerate all 3^|V| colorings | O(3^|V|) | `graph_3coloring.c:graph3_find_coloring_bruteforce` |
| 6 | Welsh-Powell Coloring | Degree-ordering greedy | O(|V|^2) | `graph_3coloring.c:graph3_welsh_powell` |
| 7 | BFS Bipartiteness Test | 2-color via BFS | O(|V|+|E|) | `graph_3coloring.c:graph3_is_bipartite` |
| 8 | ZK Simulator | HVZK simulator for GMW | O(|V|) hashes | `simulator.c:simulator_generate_transcript` |
| 9 | Fiat-Shamir Transform | Hash commitments -> challenge | O(|V|) | `zk_applications.c:nizk_gmw_prove` |
| 10 | Triangle Counting | Adjacency list enumeration | O(|V|*d_max^2) | `graph_3coloring.c:graph3_count_triangles` |

## L6: Canonical Problems

| # | Problem | Status | Code |
|---|---------|--------|------|
| 1 | 3-COLORING | NP-complete (Karp 1972) | `graph_3coloring.c` |
| 2 | Graph Isomorphism (ZK proof) | in NP, not known NP-complete | `zk_applications.c:zk_graph_iso_prove` |
| 3 | Hamiltonian Cycle (ZK proof) | NP-complete | `zk_applications.c:zk_hamcycle_prove` |
| 4 | Bipartiteness | in P (BFS) | `graph_3coloring.c:graph3_is_bipartite` |

## L7: Applications

| # | Application | Description | Code |
|---|-------------|-------------|------|
| 1 | ZK Password Authentication | Prove password knowledge without revealing it | `zk_applications.c:zk_auth_setup/prove` |
| 2 | Anonymous Credentials | Prove attribute threshold without identity | `zk_applications.c:zk_credential_prove_attribute` |
| 3 | NIZK via Fiat-Shamir | Non-interactive ZK for 3-COLORING | `zk_applications.c:nizk_gmw_prove/verify` |
| 4 | Cryptographic Commitments | Hash-based + Pedersen for ZK protocols | `commitment.c` |

## L8: Advanced Topics

| # | Topic | Description | Code |
|---|-------|-------------|------|
| 1 | Sigma Protocols | 3-move structure with special soundness | `zk_applications.h:SigmaRound` |
| 2 | Fiat-Shamir Heuristic | ROM-based NIZK transform | `zk_applications.c:nizk_gmw_prove` |
| 3 | GMW -> zkSNARK | GMW as historical precursor | Documented in `zk_applications.h` |

## L9: Research Frontiers

| # | Topic | Status |
|---|-------|--------|
| 1 | Post-quantum ZK proofs | Documented only |
| 2 | Recursive proof composition | Documented only |
| 3 | Succinct ZK (zkSNARK/STARK) | Documented only |
