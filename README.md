# Mini Crypto Foundations 2 — Zero-Knowledge Proofs

A collection of **from-scratch, zero-dependency C implementations** of zero-knowledge proof systems and their cryptographic building blocks. This module covers the foundational theory and constructions—interactive proofs, sigma protocols, commitment schemes, the GMW protocol, non-interactive ZK (NIZK), the Knowledge of Exponent assumption, and zkSNARKs—each translated from graduate-level cryptography into runnable C code.

## Sub-Modules

| Sub-Module | Topics | Key Courses |
|-----------|--------|-------------|
| [mini-commitment-schemes](mini-commitment-schemes/) | Bit commitments, Pedersen commitments (perfectly hiding), hash-based commitments (statistically hiding), Merkle-tree vector commitments, modular arithmetic over prime fields, hiding vs binding tradeoffs | MIT 6.875, Stanford CS355 |
| [mini-gmw-graph-3coloring-zk](mini-gmw-graph-3coloring-zk/) | GMW protocol (Goldreich-Micali-Wigderson 1986), graph 3-coloring NP-completeness, interactive ZK for all NP, bit commitments, ZK simulators, completeness/soundness/zero-knowledge trilemma | MIT 6.875, Stanford CS355 |
| [mini-interactive-proof-systems](mini-interactive-proof-systems/) | Interactive proof systems, IP=PSPACE (Shamir 1992), sumcheck protocol (LFKN 1990), GKR doubly-efficient protocol, arithmetization of Boolean formulas, Graph Non-Isomorphism ZK | MIT 6.845, Stanford CS254, Princeton COS 522 |
| [mini-knowledge-of-exponent](mini-knowledge-of-exponent/) | Knowledge of Exponent Assumption (KEA1/KEA2/KEA3), discrete logarithm and Diffie-Hellman problems, cryptographic group theory, bilinear pairings, SNARK construction from extractability assumption | MIT 6.876, Stanford CS355 |
| [mini-nizk-common-reference-string](mini-nizk-common-reference-string/) | Non-interactive zero-knowledge (NIZK) in the CRS model, Fiat-Shamir transform from sigma protocols, Pedersen commitments over safe-prime groups, NIZK simulators with trapdoor, NIZK proofs for NP | MIT 6.876, Stanford CS355 |
| [mini-sigma-protocols-fiat-shamir](mini-sigma-protocols-fiat-shamir/) | Sigma protocols (Schnorr, Chaum-Pedersen, Guillou-Quisquater), 3-move honest-verifier ZK, protocol composition (AND/OR/EQ), Fiat-Shamir heuristic, non-interactive digital signatures from sigma protocols | MIT 6.875, Stanford CS355 |
| [mini-zero-knowledge-simulators](mini-zero-knowledge-simulators/) | ZK simulation framework (perfect/statistical/computational), canonical NP-complete problems for ZK, concurrent zero-knowledge, simulator scheduling, sigma protocols, Fiat-Shamir transform | MIT 6.875, Stanford CS355 |
| [mini-zksnark-qap-r1cs](mini-zksnark-qap-r1cs/) | zkSNARK construction (Groth16), R1CS arithmetic constraints, quadratic arithmetic programs (QAP), circuit-to-R1CS compilation, polynomial commitments via pairings, trusted setup (powers-of-tau), FFT/NTT over finite fields | MIT 6.876, Stanford CS251 |

## Design Philosophy

- **Zero external dependencies** — pure C (C99/C11), only `libc` and `libm`
- **Self-contained modules** — each directory has its own `Makefile`, `include/`, `src/`, `docs/`, `demos/`, `tests/`
- **Theory-to-code mapping** — every module maps .h file constructs directly to textbook definitions, theorems, and protocol steps
- **Educational fidelity** — implementations expose complete protocol flows (commit → challenge → response → verify), not opaque cryptographic APIs

## Building

Each module is standalone. Navigate to a module directory and run:

```bash
cd mini-commitment-schemes
make all    # build everything
make test   # run tests
```

Requires **GCC** and **GNU Make**.

## Project Structure

```
mini-crypto-foundations-2-zk-proofs/
├── mini-commitment-schemes/           # Bit commitments, Pedersen, Merkle-tree vector commitments
├── mini-gmw-graph-3coloring-zk/       # GMW protocol for graph 3-colorability ZK
├── mini-interactive-proof-systems/    # IP systems, sumcheck, GKR, arithmetization
├── mini-knowledge-of-exponent/        # KEA assumptions, discrete log, SNARK from extractability
├── mini-nizk-common-reference-string/  # NIZK proofs via common reference string model
├── mini-sigma-protocols-fiat-shamir/  # Sigma protocols, Fiat-Shamir transform
├── mini-zero-knowledge-simulators/    # ZK simulator framework, concurrent ZK
└── mini-zksnark-qap-r1cs/             # zkSNARK Groth16, QAP, R1CS, trusted setup
```

## License

MIT
