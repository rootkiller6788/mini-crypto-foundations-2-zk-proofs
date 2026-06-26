# Course Alignment — GMW Graph 3-Coloring ZK Proofs

| School | Course | Topic | This Module |
|--------|--------|-------|-------------|
| **MIT** | 6.876/18.426 Adv Cryptography | GMW protocol, ZK definitions | `gmw_protocol.c`, `simulator.c` |
| **Stanford** | CS255 Intro to Cryptography | Commitment schemes, ZK proofs | `commitment.c`, `simulator.c` |
| **Berkeley** | CS276 Cryptography | Interactive proofs, ZK | `interactive_proof.c` |
| **Princeton** | COS 551 Advanced Complexity | NP-completeness + cryptography | `graph_3coloring.c`, `gmw_protocol.c` |
| **CMU** | 15-855 Graduate Complexity | IP = PSPACE, complexity classes | `interactive_proof.h:IPClass` |
| **Caltech** | CS 154 Limits of Computation | NP-completeness of 3-COLORING | `graph_3coloring.c` |
| **Cambridge** | Part III Adv Cryptography | Sigma protocols, NIZK | `zk_applications.c` |
| **Oxford** | Advanced Complexity Theory | Zero-Knowledge, proof systems | `simulator.c`, `zk_applications.c` |
| **ETH** | 263-4650 Advanced Complexity | Interactive proofs, PCP | `interactive_proof.c` |

## Key Course Topics Covered

### MIT 6.876 (Goldwasser)
1. Interactive Proofs: definition, completeness, soundness
2. Zero-Knowledge: simulation paradigm, computational vs statistical ZK
3. GMW protocol for 3-COLORING
4. Commitment schemes (hash-based, Pedersen)

### Stanford CS255 (Boneh)
1. Bit commitment: hiding + binding
2. ZK proofs for all NP via GMW
3. Fiat-Shamir transform for NIZK

### Princeton COS 551 (Barak)
1. NP-completeness: 3SAT -> 3-COLORING
2. ZK proofs: definition via simulation
3. Sequential repetition for soundness amplification
