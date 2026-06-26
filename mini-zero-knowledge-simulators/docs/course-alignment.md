# Course Alignment — mini-zero-knowledge-simulators

Nine-school course mapping for ZK proof simulators.

## MIT — 6.875 / 18.425 Cryptography & Cryptanalysis

| Topic | This Module | Status |
|-------|-------------|--------|
| Interactive Proofs and Zero Knowledge | `zk_simulator.h` L1 definitions | ✅ |
| Sigma Protocols | `sigma_protocols.h` Schnorr, CP, GQ | ✅ |
| Fiat-Shamir Heuristic | `fiat_shamir.h` | ✅ |
| GMW Theorem: ZK for NP | `zk_problems.h` G3C protocol | ✅ |
| Concurrent ZK | `concurrent_zk.c` | ✅ |

## Stanford — CS355 Cryptography

| Topic | This Module | Status |
|-------|-------------|--------|
| ZK Proof Definitions | `zk_simulator.h` | ✅ |
| HVZK, WI, PoK | `zk_simulator.h` L2 | ✅ |
| Commitment Schemes | `commitments.h` | ✅ |
| OR-Proofs (CDS 1994) | `sigma_protocols.h` | ✅ |
| NIZK and ROM | `fiat_shamir.h` | ✅ |

## Berkeley — CS276 Cryptography

| Topic | This Module | Status |
|-------|-------------|--------|
| GMW 3-Coloring Proof | `zk_problems.h` L6.1 | ✅ |
| Black-Box Simulation | `simulator_core.h` | ✅ |
| Sigma Protocol Theory | `sigma_protocols.h` | ✅ |
| Statistical vs Computational ZK | `zk_simulator.h` | ✅ |
| Proofs of Knowledge | Extractors in `zk_simulator.h` | ✅ |

## CMU — 15-859 Cryptography

| Topic | This Module | Status |
|-------|-------------|--------|
| BB Simulator Construction | `simulator_core.c` | ✅ |
| Rewinding Technique | `simulator_core.h` L5.1 | ✅ |
| Expected Polynomial Time | `simulator_core.h` L5.5 | ✅ |
| Witness Extraction | `zk_simulator.c` L4.3 | ✅ |
| Parallel Repetition | `sigma_protocols.c` L5.8 | ✅ |

## Princeton — COS 561 Advanced Cryptography

| Topic | This Module | Status |
|-------|-------------|--------|
| Fiat-Shamir Transform | `fiat_shamir.h` | ✅ |
| Forking Lemma | `fiat_shamir.h` L4.5.4 | ✅ |
| Random Oracle Model | `fiat_shamir.h` hash function | ✅ |
| NIZK in CRS Model | `fiat_shamir.h` L4.5.6 | ✅ |
| Strong vs Weak FS | `fiat_shamir.h` L4.5.5 | ✅ |

## Caltech — CS 151 Complexity Theory

| Topic | This Module | Status |
|-------|-------------|--------|
| Interactive Proof Systems | `zk_simulator.h` IP framework | ✅ |
| IP = PSPACE connection | Documented in headers | ✅ |
| Arthur-Merlin Games | Public-coin = AM (Sigma Protocols) | ✅ |

## Cambridge — Part II Cryptography

| Topic | This Module | Status |
|-------|-------------|--------|
| Commitment Schemes | `commitments.h` (Pedersen, ElGamal) | ✅ |
| Sigma Protocol Composition | `sigma_protocols.c` AND/OR | ✅ |
| Schnorr Identification | `sigma_protocols.c` | ✅ |
| Guillou-Quisquater | `sigma_protocols.c` | ✅ |

## Oxford — Advanced Cryptography

| Topic | This Module | Status |
|-------|-------------|--------|
| Concurrent ZK | `concurrent_zk.c` | ✅ |
| Resettable ZK | `concurrent_zk.c` | ✅ |
| Non-Black-Box Simulation | `concurrent_zk.c` | ✅ |
| Bounded Concurrency | `concurrent_zk.c` | ✅ |

## ETH Zurich — 263-4660 Advanced Cryptography

| Topic | This Module | Status |
|-------|-------------|--------|
| Sigma Protocol Theory | `sigma_protocols.h` comprehensive | ✅ |
| OR-Composition Theorem | `sigma_protocols.c` CDS 1994 | ✅ |
| Chaum-Pedersen Protocol | `sigma_protocols.c` | ✅ |
| Modular Proof Design | CDS methodology in AND/OR | ✅ |

## Research Frontiers (L9 — Documented Only)

| Topic | School | Description |
|-------|--------|-------------|
| Post-Quantum ZK | MIT, ETH | Lattice-based ZK from SIS/LWE assumptions |
| zk-STARKs | Stanford | Scalable Transparent ARguments of Knowledge (Ben-Sasson et al.) |
| Recursive Composition | Berkeley | Halo2 (Zcash), Nova (Kothapalli et al.) |
| Bulletproofs | Stanford | Short NIZK for range proofs via inner-product arguments |
| PLONK/Custom Gates | ETH, Berkeley | Universal trusted setup with custom constraint systems |

**Overall coverage**: 9/9 schools, all required topics covered at Complete level.
