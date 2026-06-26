# Course Tree — mini-zero-knowledge-simulators

Prerequisite dependency tree for this module.

## Direct Prerequisites

```
mini-zero-knowledge-simulators
├── mini-cook-levin-theorem            (NP-completeness → GMW reduction)
├── mini-p-np-np-completeness          (NP class definition)
├── mini-boolean-circuits-model        (circuit representation of NP witnesses)
├── mini-circuit-sat-complexity        (NP-completeness via Circuit-SAT)
└── mini-interactive-proofs            (IP model, Arthur-Merlin games)
```

## Knowledge Prerequisites

### Computational Complexity
- Definition of NP and NP-completeness (Cook-Levin)
- Polynomial-time reductions between NP problems
- Circuit families and uniform computation

### Cryptography
- One-way functions and hard problems
- Discrete logarithm assumption
- Random oracle model
- Cryptographic hash functions

### Algebra
- Finite groups Z_p^*
- Modular arithmetic
- Fermat's Little Theorem, Euler's Theorem
- Extended Euclidean algorithm

### Probability Theory
- Statistical distance (total variation distance)
- Negligible functions
- Expectation and variance of geometric distribution
- Rejection sampling

## Dependency Graph (Within This Module)

```
zk_simulator.h ─────────────────────────────────────────────┐
├── L1: Definitions (ZK, Simulator, Transcript)             │
├── L2: Core Concepts (HVZK, WI, PoK, Statistical Distance) │
├── L3: Math Structures (Group params, Modular arithmetic)  │
└── L4: Theorems (Schnorr, HVZK sim, Special soundness)     │
                                                            │
sigma_protocols.h ← depends on zk_simulator.h               │
├── Schnorr, Chaum-Pedersen, Guillou-Quisquater protocols   │
└── AND/OR composition, parallel repetition                  │
                                                            │
commitments.h ← depends on zk_simulator.h                   │
├── Pedersen, ElGamal, bit, string commitments              │
└── Trapdoor equivocation                                    │
                                                            │
simulator_core.h ← depends on zk_simulator.h, sigma_protocols.h│
├── Rewind session framework                                 │
├── View generation, expected time analysis                  │
└── Simulation quality metrics                               │
                                                            │
zk_problems.h ← depends on zk_simulator.h, commitments.h    │
├── G3C (GMW), GI, HC ZK protocols                          │
└── Protocol simulators                                      │
                                                            │
fiat_shamir.h ← depends on zk_simulator.h, sigma_protocols.h│
├── Fiat-Shamir NIZK transform                               │
├── Forking lemma demonstration                              │
└── CRS model                                                │
```

## Downstream Dependencies

Modules that depend on this one:

```
mini-zero-knowledge-simulators
├── mini-pcp-theorem                    (PCP as a form of ZK)
├── mini-ip-pspace                      (IP=PSPACE via ZK techniques)
├── mini-secure-multiparty-computation  (ZK is core MPC building block)
├── mini-zk-snarks                      (Advanced NIZK constructions)
└── mini-post-quantum-zk                (Lattice-based ZK)
```

## Learning Path

1. **Start**: `zk_simulator.h` — understand ZK definitions
2. **Build**: `sigma_protocols.h` — master Schnorr and composition
3. **Extend**: `commitments.h` — learn commitment schemes
4. **Apply**: `simulator_core.h` — construct BB simulators
5. **Advance**: `zk_problems.h` — GMW theorem for NP
6. **Transform**: `fiat_shamir.h` — NIZK in ROM
7. **Deepen**: `concurrent_zk.c` — composition issues
8. **Deploy**: `zk_applications.c` — real-world use cases
