# mini-zero-knowledge-simulators

Zero-Knowledge Proof Simulator Framework — the central paradigm of ZK cryptography.

## Module Status: COMPLETE ✅

| Level | Status | Description |
|-------|--------|-------------|
| L1 Definitions | **Complete** | 8 definitions: ZK proof system, simulator, verifier view, transcript, flavours, PoK |
| L2 Core Concepts | **Complete** | 10 concepts: HVZK, WI, PoK, rewinding, commitments, simulation modes |
| L3 Math Structures | **Complete** | 10 structures: modular arithmetic, Pedersen, ElGamal, Schnorr group, hash |
| L4 Fundamental Laws | **Complete** | 10 theorems: Schnorr, OR-composition, Fiat-Shamir, Forking Lemma, GMW |
| L5 Algorithms/Methods | **Complete** | 20 algorithms: BB simulator, sigma protocols, composition, NIZK |
| L6 Canonical Problems | **Complete** | 5 problems: G3C, GI, HC, Schnorr DLog, Guillou-Quisquater |
| L7 Applications | **Complete** | 5 applications: password auth, Zcash coins, e-voting, credentials, signatures |
| L8 Advanced Topics | **Complete** | 8 topics: concurrent ZK, resettable ZK, NBB sim, straight-line, UC ZK |
| L9 Research Frontiers | **Partial** | 5 topics documented (post-quantum ZK, STARKs, recursive composition) |

**Score**: L1(2)+L2(2)+L3(2)+L4(2)+L5(2)+L6(2)+L7(2)+L8(2)+L9(1) = **17/18 → COMPLETE**

## Line Count
- **include/** : 1,592 lines (7 headers: zk_simulator, sigma_protocols, commitments, simulator_core, zk_problems, fiat_shamir, concurrent_zk)
- **src/**    : 2,199 lines (8 source files + 1 Lean 4 formalization)
- **Total include/ + src/**   : **3,791 lines** ✅
- **Lean 4**  : `src/ZKSimulator.lean` (formal definitions + theorems)
- **Examples**: 3 (Schnorr ZK, G3C, E-Voting)
- **Benchmarks**: 1 (simulator operations)
- **Demos**: 1 (interactive ZK lifecycle)
- **Docs**: 5/5 knowledge documents

## Core Definitions (L1)

| Concept | Definition |
|---------|-----------|
| ZK Proof System | (P,V) interactive protocol satisfying completeness, soundness, zero-knowledge |
| Simulator | PPT S producing View_V*(x) indistinguishable from real execution |
| Verifier View | (r, m1, ..., mk) — all information V* observes |
| Transcript | All messages exchanged in one protocol execution |
| Perfect/Statistical/Computational ZK | Three flavours of indistinguishability |

## Core Theorems (L4)

| Theorem | Statement |
|---------|-----------|
| **Schnorr (1991)** | DLog sigma protocol: g^s = a·y^c mod p |
| **HVZK Simulation** | Pick c,s←Z_q; a=g^s·y^{-c}. Perfect simulation. |
| **Special Soundness** | (a,c1,s1),(a,c2,s2) → w=(s1-s2)(c1-c2)^{-1} mod q |
| **OR-Composition** (CDS 1994) | Σ1, Σ2 → Σ_L1∨L2 via c=c1+c2 mod q |
| **Fiat-Shamir (1986)** | Interactive→NIZK: c=H(a∥x) in ROM |
| **Forking Lemma** (PS 1996) | From FS adversary, extract witness via rewinding |
| **GMW (1991)** | All NP has computational ZK (via G3C reduction) |

## Core Algorithms (L5)

| Algorithm | Complexity | Description |
|-----------|-----------|-------------|
| BB Rewind Simulator | O(q·poly(n)) | Expected rewinds = 1/p_favourable |
| Schnorr Prover | O(log q) | 3-move DLog proof |
| Chaum-Pedersen | O(log q) | Equality of DLogs |
| OR-Composition Prover | O(log q) | Uses HVZK simulator as building block |
| Fiat-Shamir Transform | O(log q) | Hash-based NIZK |
| G3C Simulator | O(\|E\|·k) | Rewind-based for edge challenge |

## Canonical Problems (L6)

| Problem | ZK Flavour | Soundness Error |
|---------|-----------|-----------------|
| Graph 3-Coloring (G3C) | Computational | (1-1/\|E\|)^k |
| Graph Isomorphism (GI) | Perfect | (1/2)^k |
| Hamiltonian Cycle (HC) | Perfect | (1/2)^k |
| Schnorr Identification | Perfect HVZK | 1/q |

## Nine-School Course Mapping

| School | Course | Topic Covered |
|--------|--------|---------------|
| MIT | 6.875 Cryptography | Sigma protocols, ZK definition |
| Stanford | CS355 Cryptography | HVZK, WI, OR-proofs |
| Berkeley | CS276 Cryptography | GMW theorem, G3C |
| CMU | 15-859 Cryptography | BB simulation, rewinding |
| Princeton | COS 561 Crypto | Fiat-Shamir, NIZK |
| Caltech | CS 151 Complexity | Interactive proofs |
| Cambridge | Part II Cryptography | Commitment schemes |
| Oxford | Adv Crypto | Concurrent ZK |
| ETH | 263-4660 Crypto | Sigma protocol theory |

## Build & Test

```bash
make          # Build library + tests
make test     # Run all 12 test suites
make clean    # Clean build artifacts
```

## Reference

- Goldreich (2004) *Foundations of Cryptography, Vol. 1*
- Goldwasser, Micali & Rackoff (1989) *The Knowledge Complexity of Interactive Proof Systems*
- Arora & Barak (2009) *Computational Complexity: A Modern Approach*, Ch. 18
- Schnorr (1991) *Efficient Signature Generation by Smart Cards*
- Cramer, Damgard & Schoenmakers (1994) *Proofs of Partial Knowledge*
- Fiat & Shamir (1986) *How to Prove Yourself*
- Pointcheval & Stern (1996) *Security Proofs for Signature Schemes*
- Goldreich, Micali & Wigderson (1991) *Proofs that Yield Nothing But Their Validity*
