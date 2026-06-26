# mini-interactive-proof-systems

Interactive Proof Systems and their applications: IP = PSPACE, sumcheck protocol, GKR protocol, polynomial commitments, and zero-knowledge proofs.

## Module Status: COMPLETE ✅

- L1-L6: Complete (all core definitions, concepts, structures, theorems, algorithms, problems)
- L7: Complete (4 applications: ZK simulator, GM encryption, delegation, ZK-rollup)
- L8: Complete (GKR protocol, batch opening, Sigma special soundness, OR-proof composition, PCP statement)
- L9: Partial (QIP, SNARGs, IOPs documented; research-level implementations omitted)

Score: 17/18 ≥ 16 → **COMPLETE**

---

## Nine-Layer Knowledge Coverage

| Level | Name | Status | Key Components |
|-------|------|--------|----------------|
| **L1** | Definitions | ✅ Complete | IPProver, IPVerifier, IPProofSystem, completeness/soundness, IP/AM classes |
| **L2** | Core Concepts | ✅ Complete | Error reduction, sequential repetition, public/private coin, Chernoff bound |
| **L3** | Math Structures | ✅ Complete | GF(p) arithmetic, polynomials, multilinear extension, graphs, layered circuits |
| **L4** | Fundamental Laws | ✅ Complete | IP = PSPACE, sumcheck soundness, Chernoff bound, KZG security, Goldwasser-Sipser |
| **L5** | Algorithms | ✅ Complete | Sumcheck protocol, arithmetization, GKR layer reduction, polynomial commit + open + batch, ZK simulator, Fiat-Shamir transform, Sigma protocol special soundness |
| **L6** | Canonical Problems | ✅ Complete | GNI, QR, #SAT via sumcheck, TQBF arithmetization, Graph Iso ZK, 4 examples |
| **L7** | Applications | ✅ Complete | GM encryption, delegation of computation, ZK-rollup concepts, perfect ZK for GNI, computational ZK for QR, NIZK via Fiat-Shamir, Sigma protocol extraction |
| **L8** | Advanced Topics | ✅ Complete | GKR protocol, batch polynomial opening, Sigma special soundness + witness extraction, OR-proof composition, PCP verifier structure |
| **L9** | Research Frontiers | ⚠️ Partial | QIP, SNARGs, IOPs formally defined; research-level implementations documented |

---

## Core Definitions (L1)

- **Interactive Proof System**: A pair (P,V) where V is polynomial-time probabilistic and P is computationally unbounded
- **Completeness**: ∀x∈L, Pr[⟨P,V⟩(x)=accept] ≥ 2/3
- **Soundness**: ∀x∉L, ∀P*, Pr[⟨P*,V⟩(x)=accept] ≤ 1/3
- **IP[k]**: Interactive proofs with k rounds of interaction
- **AM[k]**: Arthur-Merlin (public-coin) interactive proofs
- **Zero-Knowledge**: ∃ simulator S such that ∀x∈L, S(x) ≈ transcript of ⟨P,V⟩(x)

## Core Theorems (L4)

1. **IP = PSPACE** (Shamir 1992): Every language decidable in polynomial space has an interactive proof
2. **Sumcheck Soundness** (LFKN 1990): Error ≤ n·d / |F| per repetition
3. **Goldwasser-Sipser** (1989): IP[k] ⊆ AM[k+2] (private coins = public coins + O(1) rounds)
4. **Chernoff Bound**: Pr[ΣX ≥ (1+δ)μ] ≤ exp(-δ²μ/3) for independent Bernoulli trials
5. **KZG Binding**: Polynomial commitment is binding under d-Strong Diffie-Hellman assumption

## Core Algorithms (L5)

- **Sumcheck Protocol**: Verifies Σ_{x∈{0,1}ⁿ} g(x) = H in n rounds with O(n) verifier time
- **Arithmetization**: Boolean → polynomial conversion (AND→×, OR→+, NOT→1-x)
- **GKR Protocol**: Delegates layered circuit computation with O(d log|C|) verifier time
- **KZG Commitment**: Commits to polynomial P(X), opens at any point z with O(1) proof size
- **Batch Opening**: Opens polynomial at k points with a single combined proof

## Canonical Problems (L6)

| Problem | Complexity | IP Protocol |
|---------|-----------|-------------|
| Graph Non-Isomorphism (GNI) | In IP, not known in NP | 1-round private-coin |
| Quadratic Residuosity (QR) | In NP ∩ co-NP | 1-round private-coin |
| #SAT | #P-complete | Sumcheck + arithmetization |
| TQBF | PSPACE-complete | Arithmetization + sumcheck |

## Nine-School Curriculum Mapping

| School | Alignment |
|--------|-----------|
| **MIT** 6.841 | IP = PSPACE, GKR, sumcheck |
| **Stanford** CS254 | IP characterization, AM hierarchy |
| **Berkeley** CS278 | PCP, IOPs, sumcheck |
| **CMU** 15-855 | Interactive proofs, delegation |
| **Princeton** COS 522 | Zero-knowledge, QR-based crypto |
| **Caltech** CS 151 | Interactive proof classes |
| **Cambridge** Part III | IP = PSPACE proof, arithmetization |
| **Oxford** Adv Complexity | Quantum IP, multi-prover IP |
| **ETH** 263-4650 | Sumcheck, PCP, algebraic methods |

## Building

```
make all      # Build library + tests + examples
make test     # Run test suite
make examples # Run examples
make clean    # Clean build
```

## File Structure

```
mini-interactive-proof-systems/
├── Makefile
├── README.md
├── include/
│   ├── ip_system.h           (core types and API)
│   ├── ip_protocols.h        (GNI, QR protocols)
│   ├── ip_sumcheck.h         (sumcheck protocol)
│   ├── ip_arithmetization.h  (Boolean-to-algebraic)
│   ├── ip_gkr.h              (GKR protocol)
│   └── ip_zkp.h              (zero-knowledge proofs)
├── src/
│   ├── ip_system.c           (core runtime, fields, polynomials)
│   ├── ip_protocols.c        (GNI + QR implementations)
│   ├── ip_sumcheck.c         (sumcheck protocol)
│   ├── ip_arithmetization.c  (circuit arithmetization)
│   ├── ip_gkr.c              (GKR layered circuit protocol)
│   ├── ip_polynomial_commitment.c (KZG-style commitment)
│   ├── ip_zkp.c              (zero-knowledge proofs + simulators)
│   └── ip.lean               (formal definitions in Lean 4)
├── tests/
│   └── test_ip_systems.c     (comprehensive test suite, 28 tests)
├── examples/
│   ├── example_gni.c         (Graph Non-Isomorphism)
│   ├── example_sumcheck.c    (Sumcheck protocol)
│   ├── example_qr.c          (Quadratic Residuosity)
│   └── example_zk_gni.c      (ZK Simulator for GNI)
├── docs/
│   ├── knowledge-graph.md    (L1-L9 knowledge mapping)
│   ├── coverage-report.md    (completeness assessment)
│   ├── gap-report.md         (missing items + priority)
│   ├── course-alignment.md   (9-school curriculum mapping)
│   └── course-tree.md        (prerequisite dependency tree)
├── demos/
├── benches/
└── PROMPT.md
```

## Reference

- Goldwasser, Micali, Rackoff. "The knowledge complexity of interactive proof-systems." SIAM J. Comput. 18(1), 1989.
- Lund, Fortnow, Karloff, Nisan. "Algebraic methods for interactive proof systems." J. ACM 39(4), 1992.
- Shamir. "IP = PSPACE." J. ACM 39(4), 1992.
- Goldwasser, Kalai, Rothblum. "Delegating computation: interactive proofs for muggles." J. ACM 62(4), 2015.
- Kate, Zaverucha, Goldberg. "Constant-size commitments to polynomials and their applications." ASIACRYPT 2010.
- Arora & Barak. Computational Complexity: A Modern Approach. Cambridge, 2009.
