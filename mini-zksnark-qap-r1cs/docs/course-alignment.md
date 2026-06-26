# Course Alignment ¡ª mini-zksnark-qap-r1cs

## 9-School Curriculum Mapping

| School | Course | Topics Aligned |
|--------|--------|---------------|
| MIT | 6.841 Advanced Complexity | Interactive proofs, PCP, SNARKs, zero-knowledge |
| MIT | 6.845 Quantum Complexity | Post-quantum cryptography implications |
| Stanford | CS254 Computational Complexity | Circuit complexity, lower bounds, PCP theorem |
| Stanford | CS358 Circuit Complexity | Arithmetic circuits, Boolean function complexity |
| Berkeley | CS278 Computational Complexity | SNARK constructions, PCP theorem applications |
| CMU | 15-855 Graduate Complexity | Circuit lower bounds, proof complexity |
| Princeton | COS 522 Computational Complexity | Cryptographic applications of complexity |
| Cambridge | Part II Complexity Theory | NP-completeness, polynomial hierarchy |
| Cambridge | Part III Advanced Complexity | Interactive proofs, zero-knowledge |
| Oxford | Computational Complexity | PCP and hardness of approximation |
| ETH | 263-4650 Advanced Complexity | Proof systems, cryptographic primitives |

## Topic Coverage Map

| Topic | Coverage | Implementation |
|-------|----------|---------------|
| NP-Completeness | Full | R1CS reduction from SAT |
| Interactive Proofs | Full | Groth16 prover/verifier |
| PCP Theorem | Partial | QAP as polynomial PCP encoding |
| Zero-Knowledge | Full | Blinding factors in snark_prove |
| Circuit Complexity | Full | Arithmetic circuit DAG, gate types |
| Pairing-Based Crypto | Full | G1/G2/GT, simplified pairing |
| MPC/Secure Computation | Partial | Powers of Tau ceremony |
| Polynomial Commitments | Full | KZG-style commitments |
