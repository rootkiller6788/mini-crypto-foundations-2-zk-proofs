# Knowledge Graph — mini-knowledge-of-exponent

## L1: Definitions (Complete)
- CyclicGroup: finite cyclic group (G, ·) of prime order p
- GroupElement: element of Z_p* under multiplication
- DLP: given (g, h = g^x), find x
- CDH: given (g, g^a, g^b), compute g^{ab}
- DDH: distinguish DH tuples from random
- KEA1: from (g, g^a), valid (C, C') ⇒ extract r s.t. C = g^r
- KEA2: extended with two exponents
- KEA3: bilinear variant
- q-KEA: powers variant (used in GGPR13)
- R1CS: Rank-1 Constraint System
- QAP: Quadratic Arithmetic Program
- SNARK: Succinct Non-interactive ARgument of Knowledge

## L2: Core Concepts (Complete)
- Hardness reduction: DLP ≥ CDH ≥ DDH
- Generic Group Model (GGM): Shoup 1997
- Algebraic Group Model (AGM): Fuchsbauer et al. 2018
- Non-falsifiability: Naor 2003 classification of KEA
- Common Reference String (CRS) model
- Trusted setup: toxic waste (tau, alpha, beta)
- Proving key vs verification key
- Knowledge extraction via KEA
- Blind signature / delegation extension

## L3: Mathematical Structures (Complete)
- Modular arithmetic: add, sub, mul, pow, inv in Z_p
- CyclicGroup struct with order/generator/modulus/cofactor
- GroupElement struct with value + group pointer
- Subgroup: parent group, order, generator
- R1CS sparse matrix representation (COO format)
- QAP polynomial arrays: A_i(x), B_i(x), C_i(x), Z(x)
- BilinearPairing: G1, G2, GT groups with generators
- Groth16ToxicWaste: tau, alpha, beta, gamma, delta fields
- Groth16ProvingKey / Groth16VerificationKey: group element arrays

## L4: Fundamental Theorems (Complete)
- Lagrange: a^{|G|} = 1 for all a ∈ G
- DLP ⇒ CDH (constructive reduction)
- DDH ⇒ CDH (gap-DH reduction)
- DLP random self-reducibility
- QAP reduction theorem (GGPR13): circuit → QAP
- Groth16 completeness: honest prover → accept
- Groth16 soundness: via q-KEA + q-PDH
- Groth16 perfect ZK: simulation-based proof (Groth 2016 §3.2)
- Schwartz-Zippel: polynomial identity testing via random evaluation
- KEA consistency: A and B CRS elements bind to same witness

## L5: Algorithms/Methods (Complete)
- Extended GCD / modular inverse
- Miller-Rabin primality test
- Tonelli-Shanks sqrt mod p
- Multi-exponentiation (Pippenger/Straus)
- Baby-step Giant-step DLP
- Pollard's Rho DLP
- Pohlig-Hellman DLP reduction
- Index Calculus for Z_p*
- Auto-select DLP solver
- R1CS → QAP via Lagrange interpolation
- Groth16 CRS generation (setup)
- Groth16 prover algorithm
- Groth16 verifier (pairing check)
- **Groth16 ZK simulator** (trapdoor-based, no witness required)
- **Polynomial multiplication mod p** (convolution)
- **QAP satisfiability verification** (Schwartz-Zippel evaluation)

## L6: Canonical Problems (Complete)
- DLP: discrete log in Z_p* (various methods)
- CDH: computational Diffie-Hellman
- DDH: decisional Diffie-Hellman
- KEA1 security game
- KEA2 security game
- SNARK proof for multiplication gate
- **QAP satisfiability**: verify witness satisfies QAP constraints
- **Batch verification**: verify multiple SNARK proofs at once

## L7: Applications (Complete — 3 apps)
- **Zcash**: shielded transactions using Groth16 SNARKs
- **zk-Rollups**: Ethereum L2 scaling via proof aggregation
- **Verifiable computation**: outsourcing with proof verification
- **SNARK end-to-end demo**: full pipeline demo

## L8: Advanced Topics (Partial — 4/5)
- Bilinear pairing: simulated pairing implementation
- KEA3 (bilinear KEA): challenge-response in G1 × G2
- Miller's algorithm: simplified for educational pairing
- **Batch verification**: randomized linear combination, O(1) pairings
- **Simulation-based ZK**: perfect zero-knowledge in CRS model
- Pairing-based SNARK optimization (product pairing) — documented
- Pairing-friendly curve families (BN, BLS12) — documented

## L9: Research Frontiers (Partial)
- Non-falsifiability of KEA (Naor 2003): formal statement
- Algebraic Group Model (Fuchsbauer et al. 2018): formal structure
- Post-quantum SNARKs: identified as future direction
