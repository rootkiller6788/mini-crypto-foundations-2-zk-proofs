# Knowledge Graph — Interactive Proof Systems

## L1: Definitions (Complete)
- Interactive Proof System (IP): Prover P, Verifier V
- Completeness: Pr[⟨P,V⟩(x)=accept | x∈L] ≥ 2/3
- Soundness: Pr[⟨P*,V⟩(x)=accept | x∉L] ≤ 1/3
- IP[k]: k-round interactive proofs
- Arthur-Merlin (AM): public-coin IP
- Private-coin vs Public-coin protocols
- Zero-Knowledge Interactive Proof
- Polynomial Commitment Scheme

## L2: Core Concepts (Complete)
- Error reduction via sequential repetition
- Completeness-soundness gap amplification
- Public-coin / private-coin equivalence (Goldwasser-Sipser)
- Chernoff bound for probabilistic analysis
- Protocol simulation and transcript
- Polynomial-time verifier constraint
- Sequential vs parallel repetition

## L3: Mathematical Structures (Complete)
- Finite field GF(p) arithmetic (add, sub, mul, pow, inv)
- Polynomials over finite fields (Horner evaluation)
- Multilinear extensions over GF(p)
- Lagrange interpolation basis χ_b(x)
- Boolean hypercube {0,1}^n
- Graph structures (adjacency, isomorphism, permutation)
- Quadratic residues, Legendre/Jacobi symbols
- Multilinear polynomial degree analysis

## L4: Fundamental Laws (Complete)
- Goldwasser-Sipser Theorem: IP[k] = AM[k+2]
- Shamir's Theorem: IP = PSPACE
- Sumcheck soundness: error ≤ n·d / |F|
- Chernoff bound: Pr[ΣX ≥ (1+δ)μ] ≤ exp(-δ²μ/3)
- Goldreich-Micali-Wigderson GNI protocol completeness
- Quadratic residuosity assumption
- KZG commitment binding from d-SDH

## L5: Algorithms/Methods (Complete)
- Sumcheck protocol (prover + verifier algorithms)
- Arithmetization of Boolean formulas
- Gate arithmetization: AND/OR/NOT/NAND/XOR
- GKR layer reduction via sumcheck
- Polynomial commitment: commit, open, verify
- Batch opening for polynomial commitments
- Sequential repetition algorithm
- Multilinear evaluation DP algorithm

## L6: Canonical Problems (Complete)
- Graph Non-Isomorphism (GNI): in IP, not known in NP
- Quadratic Residuosity (QR): in NP ∩ co-NP
- #SAT: counting satisfying assignments via sumcheck
- TQBF: True Quantified Boolean Formulas (PSPACE-complete)
- 3SAT arithmetization for IP=PSPACE
- Matrix multiplication delegation via GKR

## L7: Applications (Complete)
- Perfect ZK simulator for Graph Non-Isomorphism (GMW 1991)
- Computational ZK simulator for Quadratic Residuosity (QRA-based)
- Non-interactive ZK via Fiat-Shamir heuristic (ROM)
- Goldwasser-Micali public-key encryption (QR-based)
- Delegation of computation (GKR protocol)
- ZK-rollup blockchain scaling concepts
- Sigma protocol proof of knowledge

## L8: Advanced Topics (Complete)
- GKR doubly-efficient IP (implemented)
- Batch polynomial commitment opening (implemented)
- Sigma protocol special soundness + witness extraction (implemented)
- OR-proof composition (Cramer-Damgard-Schoenmakers 1994, implemented)
- PCP Theorem + verifier structure (formally defined)
- Interactive Oracle Proofs (IOPs, documented + formal definition)

## L9: Research Frontiers (Partial)
- Quantum interactive proofs (QIP)
- Doubly-efficient IP for all of P
- Succinct non-interactive arguments (SNARKs)
- Post-quantum polynomial commitments
