# Course Tree — mini-knowledge-of-exponent

## Prerequisite Dependency Graph

```
                    ┌─────────────────┐
                    │  Modular Arith  │ (L3: add, mul, pow, inv)
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │  Cyclic Group   │ (L1: G = ⟨g⟩, order, generator)
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
     ┌────────▼────────┐    │    ┌─────────▼────────┐
     │       DLP       │    │    │  Bilinear        │
     │ (L1: g^x = h)   │    │    │  Pairing         │
     └────────┬────────┘    │    │ (L1: e:G1×G2→GT) │
              │              │    └─────────┬────────┘
     ┌────────▼────────┐    │              │
     │  DLP Algorithms │    │              │
     │ BSGS,Rho,P-H    │    │              │
     │ (L5)            │    │              │
     └────────┬────────┘    │              │
              │              │              │
     ┌────────▼────────┐    │              │
     │  CDH / DDH      │    │              │
     │ (L1: hardness)  │    │              │
     └────────┬────────┘    │              │
              │              │              │
     ┌────────▼────────────────────────────▼────────┐
     │                  KEA                         │
     │  (L1: from (g,g^a), valid (C,C')⇒know r)    │
     │  (L5: extraction in GGM)                     │
     └───────────────────┬──────────────────────────┘
                         │
              ┌──────────┼──────────┐
              │          │          │
     ┌────────▼──┐  ┌───▼────┐  ┌──▼──────────┐
     │  KEA1/2   │  │  KEA3  │  │   q-KEA     │
     │ (basic)   │  │(bilin) │  │  (powers)    │
     └───────────┘  └───┬────┘  └──┬──────────┘
                        │          │
              ┌─────────▼──────────▼───────────┐
              │    R1CS → QAP (GGPR13)          │
              │    (L4: circuit → polynomial)   │
              │    (L5: Lagrange interpolation) │
              └────────────────┬────────────────┘
                               │
              ┌────────────────▼────────────────┐
              │       Groth16 SNARK             │
              │  (L1: definition)               │
              │  (L4: completeness/soundness/ZK)│
              │  (L5: setup/prove/verify)       │
              │  (L7: Zcash, zk-rollups)        │
              └─────────────────────────────────┘
```

## Dependency Summary

| Module | Prerequisites | Provides To |
|--------|--------------|-------------|
| Modular Arithmetic | — (standalone) | Cyclic Group |
| Cyclic Group | Modular Arithmetic | DLP, CDH, DDH, KEA |
| DLP | Cyclic Group | CDH, DDH, DLP Algorithms |
| DLP Algorithms | DLP | KEA extraction |
| Bilinear Pairing | Cyclic Group | KEA3, Groth16 |
| KEA | DLP, Cyclic Group | KEA variants, Groth16 |
| KEA3 | KEA, Pairing | Groth16 |
| q-KEA | KEA | Groth16 |
| R1CS → QAP | — (standalone) | Groth16 |
| Groth16 | QAP, Pairing, q-KEA, KEA3 | Applications |
| Applications | Groth16 | — (terminal) |

## Research Frontiers (L9)

Non-falsifiability (Naor 2003) and Algebraic Group Model (Fuchsbauer et al. 2018) are meta-theoretical topics that contextualize KEA in the broader landscape of cryptographic assumptions. They are not prerequisites but conceptual companions.
