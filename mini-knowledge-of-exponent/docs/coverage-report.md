# Coverage Report — mini-knowledge-of-exponent

| Level | Status | Assessment |
|-------|--------|------------|
| **L1** Definitions | **Complete** | 13 definitions (Group, DLP, CDH, DDH, KEA1/2/3, q-KEA, R1CS, QAP, SNARK) — all have C typedef/struct and Lean definitions |
| **L2** Core Concepts | **Complete** | 9 concepts (hardness hierarchy, GGM, AGM, non-falsifiability, CRS, setup, pk/vk, extraction, blinding) — all with implementation |
| **L3** Math Structures | **Complete** | 8 structures (modular arithmetic, Group, Subgroup, R1CS, QAP, BilinearPairing, ToxicWaste, PK/VK) — fully typed |
| **L4** Fundamental Laws | **Complete** | 10 theorems (Lagrange, DLP→CDH, gap-DH, self-reducibility, QAP reduction, completeness, soundness, perfect ZK via simulation, Schwartz-Zippel, KEA consistency) — C verification + Lean statements |
| **L5** Algorithms | **Complete** | 15 algorithms (GCD, Miller-Rabin, Tonelli-Shanks, multi-exp, BSGS, Rho, Pohlig-Hellman, Index Calc, auto-solve, Lagrange, poly-mul, QAP-sat, setup, prove, verify, ZK-sim, batch-verify) — full implementations |
| **L6** Canonical Problems | **Complete** | 7 problems (DLP solve, CDH solve, DDH decide, KEA1 game, KEA2 game, SNARK demo, QAP satisfiability) — all in examples/ |
| **L7** Applications | **Complete** | 3 applications (Zcash, zk-rollups, SNARK demo) — documented + in examples |
| **L8** Advanced Topics | **Partial** | 4/5 (pairing, KEA3, Miller's, batch verification, simulation-based ZK) — implemented; curve families documented |
| **L9** Research Frontiers | **Partial** | 2 topics (non-falsifiability, AGM) — formal Lean statements |

## Scoring

| Level | Score |
|-------|-------|
| L1 | 2 (Complete) |
| L2 | 2 (Complete) |
| L3 | 2 (Complete) |
| L4 | 2 (Complete) |
| L5 | 2 (Complete) |
| L6 | 2 (Complete) |
| L7 | 2 (Complete) |
| L8 | 1 (Partial) |
| L9 | 1 (Partial) |
| **Total** | **16/18** |

**Rating: COMPLETE** (≥16/18, L1-L6 all Complete)
