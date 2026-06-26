# Course Tree — Interactive Proof Systems

## Prerequisites

```
mini-complexity-foundations/
├── mini-cook-levin-theorem/        (NP-completeness, 3SAT)
├── mini-p-np-np-completeness/     (complexity classes)
├── mini-pspace-npspace/           (PSPACE, TQBF)
└── mini-reductions-completeness/  (reduction techniques)

mini-circuit-complexity/
└── mini-boolean-circuits-model/   (circuit model)
```

## Dependency Graph

```
3SAT/Boolean Functions
    ↓
Arithmetization (ip_arithmetization.c)
    ↓
Multilinear Extension + GF(p) Arithmetic
    ↓
Sumcheck Protocol (ip_sumcheck.c)
    ↓                    ↓
IP = PSPACE          GKR Protocol (ip_gkr.c)
    ↓                    ↓
GNI/QR Protocols    Polynomial Commitments (ip_polynomial_commitment.c)
    ↓                    ↓
ZKP Applications    ZK-Rollup/Delegation (L7)
```

## Core Theorems Chain

1. Cook-Levin: 3SAT is NP-complete → Boolean formula representation
2. Arithmetization: Boolean → polynomial over GF(p)
3. Sumcheck (LFKN): Verifying sums over hypercube
4. IP = PSPACE (Shamir): TQBF arithmetization + sumcheck
5. GKR: Delegating layered circuit computation
6. KZG: Polynomial commitments for succinct proofs

## L9 Research Frontiers Dependencies

- Quantum IP: Requires quantum computing foundations
- SNARKs: KZG + bilinear pairings + QAP (Quadratic Arithmetic Programs)
- Post-quantum: Lattice-based commitments
