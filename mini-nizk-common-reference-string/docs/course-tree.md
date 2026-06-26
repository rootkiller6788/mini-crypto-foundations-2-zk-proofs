# Course Dependency Tree - NIZK Common Reference String

## Prerequisites
```
Group Theory (Z_p^*, cyclic groups, generators)
  └── Discrete Logarithm Problem (DLOG assumption)
       └── Pedersen Commitments
            └── Sigma Protocols (Schnorr, Chaum-Pedersen)
                 └── Fiat-Shamir Transform (ROM)
                      └── NIZK Proofs in CRS Model
                           └── Simulation & Zero-Knowledge
                                └── OR/AND Composition
                                     └── Applications (Signatures, Ring Sigs)
```

## Internal Dependencies
- nizk_group.h → nizk_crs.h → nizk_commitment.h → nizk_sigma.h → nizk_proof.h → nizk_simulator.h
