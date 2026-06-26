# Knowledge Graph — mini-zero-knowledge-simulators

## L1: Definitions

| ID | Concept | Location | Status |
|----|---------|----------|--------|
| L1.1 | ZK Proof System (P,V) with completeness/soundness/ZK | `include/zk_simulator.h` | Complete |
| L1.2 | Simulator S: PPT algorithm producing indistinguishable transcripts | `include/zk_simulator.h` | Complete |
| L1.3 | Verifier View = (r, m1, ..., mk) | `include/zk_simulator.h` | Complete |
| L1.4 | Transcript: all messages in one execution | `include/zk_simulator.h` | Complete |
| L1.5 | Perfect / Statistical / Computational ZK flavours | `include/zk_simulator.h` | Complete |
| L1.6 | Commitment Scheme: (Commit, Open) with hiding+binding | `include/commitments.h` | Complete |
| L1.7 | Sigma Protocol: 3-move public-coin interactive proof | `include/sigma_protocols.h` | Complete |
| L1.8 | Proof of Knowledge (PoK): extractor exists | `include/zk_simulator.h` | Complete |

## L2: Core Concepts

| ID | Concept | Location | Status |
|----|---------|----------|--------|
| L2.1 | Honest-Verifier Zero-Knowledge (HVZK) | `include/zk_simulator.h` | Complete |
| L2.2 | Witness Indistinguishability (WI) | `include/zk_simulator.h` | Complete |
| L2.3 | Black-Box vs Non-Black-Box Simulation | `include/simulator_core.h` | Complete |
| L2.4 | Rewinding: the fundamental ZK technique | `include/simulator_core.h` | Complete |
| L2.5 | Statistical Distance & Negligible Functions | `include/zk_simulator.h` | Complete |
| L2.6 | Simulation Modes (BB, NBB, Straight-line) | `include/zk_simulator.h` | Complete |
| L2.7 | Commitment Binding + Hiding | `include/commitments.h` | Complete |
| L2.8 | Equivocation / Trapdoor | `include/commitments.h` | Complete |
| L2.9 | Expected Polynomial-Time Simulation | `include/simulator_core.h` | Complete |
| L2.10 | GMW Paradigm: Commit-then-Challenge | `include/zk_problems.h` | Complete |

## L3: Mathematical Structures

| ID | Concept | Location | Status |
|----|---------|----------|--------|
| L3.1 | Group Parameters for DLog-based ZK | `include/zk_simulator.h` | Complete |
| L3.2 | Modular Arithmetic (Z_m) | `src/zk_simulator.c` | Complete |
| L3.3 | Pedersen Commitment: g^m·h^r | `include/commitments.h` | Complete |
| L3.4 | ElGamal-Based Commitment | `include/commitments.h` | Complete |
| L3.5 | Bit Commitment via Pedersen | `include/commitments.h` | Complete |
| L3.6 | String Commitment | `include/commitments.h` | Complete |
| L3.7 | Schnorr Group (p,q,g) structure | `include/sigma_protocols.h` | Complete |
| L3.8 | RSA Group for Guillou-Quisquater | `include/sigma_protocols.h` | Complete |
| L3.9 | Random Oracle (didactic hash function) | `include/fiat_shamir.h` | Complete |
| L3.10 | Graph adjacency matrix representation | `include/zk_problems.h` | Complete |

## L4: Fundamental Laws / Theorems

| ID | Theorem | Location | Status |
|----|---------|----------|--------|
| L4.1 | Schnorr Completeness (1991) | `src/zk_simulator.c` | Complete |
| L4.2 | HVZK Simulation Theorem (Perfect) | `src/zk_simulator.c` | Complete |
| L4.3 | Special Soundness / Witness Extraction | `src/zk_simulator.c` | Complete |
| L4.4 | OR-Composition (CDS 1994) | `src/sigma_protocols.c` | Complete |
| L4.5 | Fiat-Shamir Transform (1986) | `src/fiat_shamir.c` | Complete |
| L4.6 | Forking Lemma (PS 1996) | `src/fiat_shamir.c` | Complete |
| L4.7 | GMW Theorem: ZK for all NP (1991) | `src/zk_problems.c` | Complete |
| L4.8 | Homomorphic property of Pedersen | `src/commitments.c` | Complete |
| L4.9 | Chaum-Pedersen equality of DLog verification | `src/sigma_protocols.c` | Complete |
| L4.10 | Goldreich-Krawczyk-Luby BB simulation time bound | `include/simulator_core.h` | Complete |

## L5: Algorithms / Methods

| ID | Algorithm | Location | Status |
|----|-----------|----------|--------|
| L5.1 | Black-Box Rewinding Simulator | `src/simulator_core.c` | Complete |
| L5.2 | HVZK Simulator for Schnorr | `src/zk_simulator.c` | Complete |
| L5.3 | Schnorr Prover (commit + respond) | `src/sigma_protocols.c` | Complete |
| L5.4 | Chaum-Pedersen Prover | `src/sigma_protocols.c` | Complete |
| L5.5 | Guillou-Quisquater Protocol | `src/sigma_protocols.c` | Complete |
| L5.6 | AND-Composition | `src/sigma_protocols.c` | Complete |
| L5.7 | OR-Composition (CDS 1994) | `src/sigma_protocols.c` | Complete |
| L5.8 | Parallel Repetition | `src/sigma_protocols.c` | Complete |
| L5.9 | Fiat-Shamir NIZK Prover | `src/fiat_shamir.c` | Complete |
| L5.10 | Fiat-Shamir OR-NIZK | `src/fiat_shamir.c` | Complete |
| L5.11 | G3C GMW Protocol | `src/zk_problems.c` | Complete |
| L5.12 | GI Perfect ZK Simulator | `src/zk_problems.c` | Complete |
| L5.13 | HC Blum Protocol | `src/zk_problems.c` | Complete |
| L5.14 | Modular Exponentiation (square-and-multiply) | `src/zk_simulator.c` | Complete |
| L5.15 | Extended Euclidean Algorithm | `src/zk_simulator.c` | Complete |
| L5.16 | Rejection Sampling for Uniform mod q | `src/zk_simulator.c` | Complete |
| L5.17 | Pedersen Homomorphic Addition | `src/commitments.c` | Complete |
| L5.18 | Trapdoor Equivocation | `src/commitments.c` | Complete |
| L5.19 | Generic Sigma Simulator | `src/sigma_protocols.c` | Complete |
| L5.20 | Concurrent Session Scheduler | `src/concurrent_zk.c` | Complete |

## L6: Canonical Problems

| ID | Problem | Location | Status |
|----|---------|----------|--------|
| L6.1 | Graph 3-Coloring (G3C) NP-Complete | `src/zk_problems.c` | Complete |
| L6.2 | Graph Isomorphism (GI) with Perfect ZK | `src/zk_problems.c` | Complete |
| L6.3 | Hamiltonian Cycle (HC) NP-Complete | `src/zk_problems.c` | Complete |
| L6.4 | Discrete Logarithm (Schnorr) | `examples/example_schnorr_zk.c` | Complete |
| L6.5 | RSA-Based Identity (Guillou-Quisquater) | `src/sigma_protocols.c` | Complete |

## L7: Applications

| ID | Application | Location | Status |
|----|-------------|----------|--------|
| L7.1 | Password Authentication without Revealing Password | `src/zk_applications.c` | Complete |
| L7.2 | Zcash-style Coin Minting & Verification | `src/zk_applications.c` | Complete |
| L7.3 | Electronic Voting with OR-Proofs | `src/zk_applications.c` | Complete |
| L7.4 | Anonymous Credentials (Camenisch-Lysyanskaya) | `src/zk_applications.c` | Complete |
| L7.5 | Schnorr-based Digital Signatures via FS | `src/fiat_shamir.c` | Complete |

## L8: Advanced Topics

| ID | Topic | Location | Status |
|----|-------|----------|--------|
| L8.1 | Concurrent Zero Knowledge | `src/concurrent_zk.c` | Complete |
| L8.2 | Resettable Zero Knowledge | `src/concurrent_zk.c` | Complete |
| L8.3 | Non-Black-Box Simulation | `src/concurrent_zk.c` | Complete |
| L8.4 | Straight-Line Simulation | `src/concurrent_zk.c` | Complete |
| L8.5 | Bounded Concurrent Composition | `src/concurrent_zk.c` | Complete |
| L8.6 | Constant-Round ZK (HC-based) | `src/zk_problems.c` | Complete |
| L8.7 | CRS Model NIZK | `src/fiat_shamir.c` | Complete |
| L8.8 | Strong vs Weak Fiat-Shamir | `include/fiat_shamir.h` | Complete |

## L9: Research Frontiers

| ID | Topic | Location | Status |
|----|-------|----------|--------|
| L9.1 | Post-Quantum ZK Proofs | `docs/course-alignment.md` | Partial (documented) |
| L9.2 | zk-STARKs | `docs/course-alignment.md` | Partial (documented) |
| L9.3 | Recursive Proof Composition | `docs/course-alignment.md` | Partial (documented) |
| L9.4 | Bulletproofs and IPA | `docs/course-alignment.md` | Partial (documented) |
| L9.5 | Lattice-Based ZK | `docs/course-alignment.md` | Partial (documented) |

---

**Summary**: L1-L6 Complete, L7 Complete, L8 Complete, L9 Partial
**Total Score**: 2+2+2+2+2+2+2+2+1 = **17/18**
