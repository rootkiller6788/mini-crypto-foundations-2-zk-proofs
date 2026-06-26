# mini-knowledge-of-exponent

**Knowledge of Exponent Assumption (KEA) and Groth16 SNARK**

Knowledge of Exponent is a foundational cryptographic assumption that enables the "Knowledge" property in SNARKs (Succinct Non-interactive Arguments of Knowledge). KEA states: any adversary that produces a valid response (C, C') such that C' = C^a from (g, g^a) must "know" the discrete logarithm r such that C = g^r.

---

## Module Status: COMPLETE ✅

- **L1-L6**: Complete
- **L7**: Complete (3 applications: Zcash, zk-rollups, SNARK demo)
- **L8**: Partial (KEA3 bilinear variant, Miller's algorithm, batch verification)
- **L9**: Partial (Non-falsifiability, AGM formalized in Lean)

---

## Line Count

| Directory | Lines |
|-----------|-------|
| include/ (5 headers) | 1351 |
| src/ (5 C files + 1 Lean) | 3372 |
| **Total** | **4723** |

---

## Knowledge Coverage

### L1 — Definitions
- CyclicGroup: (G, ·) with generator, order, modulus
- GroupElement: value in Z_p*
- DLP: given (g, h=g^x), find x
- CDH: given (g, g^a, g^b), compute g^{ab}
- DDH: distinguish (g^a, g^b, g^{ab}) from (g^a, g^b, g^c)
- KEA1: from (g, g^a), valid (C, C') ⇒ knowledge of r
- KEA2: extended with two exponents
- KEA3: bilinear variant
- q-KEA: powers variant
- R1CS: Rank-1 Constraint System
- QAP: Quadratic Arithmetic Program
- SNARK: Succinct Non-interactive ARgument of Knowledge

### L2 — Core Concepts
- Hardness hierarchy: DLP ≥ CDH ≥ DDH
- Generic Group Model (GGM)
- Algebraic Group Model (AGM)
- Non-falsifiability of KEA (Naor 2003)
- CRS model / trusted setup
- Proving key vs verification key
- Knowledge extraction

### L3 — Mathematical Structures
- Modular arithmetic in Z_p (add, sub, mul, pow, inv, sqrt)
- CyclicGroup struct: modulus, order, generator, cofactor
- GroupElement struct: value + group reference
- Subgroup: parent group, order, generator
- R1CS sparse matrices (COO format)
- QAP polynomial arrays (A, B, C, Z coefficients)
- BilinearPairing: G1, G2, GT groups
- Groth16ToxicWaste: tau, alpha, beta, gamma, delta

### L4 — Fundamental Theorems
- Lagrange's theorem (a^{|G|} = 1)
- DLP ⇒ CDH reduction
- DDH oracle ⇒ CDH (gap-DH)
- DLP random self-reducibility
- QAP reduction theorem (GGPR13)
- Groth16 completeness
- Groth16 soundness (via q-KEA + q-PDH)
- Groth16 perfect zero-knowledge (simulation-based, Groth 2016 §3.2)
- KEA extraction in GGM/AGM
- Schwartz-Zippel lemma (polynomial identity testing for QAP)
- KEA witness consistency (A and B bind to same witness)

### L5 — Algorithms
- Extended GCD algorithm
- Miller-Rabin primality test
- Tonelli-Shanks square root mod p
- Multi-exponentiation (Pippenger)
- Baby-step Giant-step DLP (Shanks 1971)
- Pollard's Rho DLP (Pollard 1978)
- Pohlig-Hellman DLP (1978)
- Index Calculus for Z_p*
- Auto-select DLP solver
- Lagrange interpolation for QAP
- Groth16 setup (CRS generation)
- Groth16 prover
- Groth16 verifier
- **Groth16 ZK simulator** (trapdoor-based, no witness needed)
- **Polynomial multiplication** mod p (convolution-based)
- **QAP satisfiability verification** (Schwartz-Zippel evaluation)

### L6 — Canonical Problems
- DLP: discrete logarithm in Z_p*
- CDH: computational Diffie-Hellman
- DDH: decisional Diffie-Hellman
- KEA1/KEA2 security games
- SNARK: proving y = x^2
- **QAP satisfiability**: verify witness satisfies QAP constraints
- **Batch verification**: verify multiple SNARK proofs efficiently

### L7 — Applications
- **Zcash shielded transactions**: Groth16 SNARKs for private payments
- **zk-Rollups**: Ethereum L2 scaling via SNARK aggregation
- **Verifiable computation**: outsourcing with proof verification

### L8 — Advanced Topics
- Bilinear pairing cryptography
- KEA3 (bilinear KEA)
- Pairing-based SNARK optimization
- **Batch verification** (randomized linear combination, O(1) pairings)
- **Simulation-based ZK** (perfect zero-knowledge in CRS model)
- FFT-based QAP interpolation (documented as future work)

### L9 — Research Frontiers
- Non-falsifiability of cryptographic assumptions (Naor 2003)
- Algebraic Group Model (Fuchsbauer, Kiltz, Loss 2018)
- Post-quantum SNARKs (future direction)

---

## Core Theorems

| Theorem | Statement | Reference |
|---------|-----------|-----------|
| **DLP → CDH** | DLP solvable ⇒ CDH solvable | Diffie-Hellman 1976 |
| **DLP Self-Reducibility** | DLP is randomly self-reducible | Blum-Micali 1984 |
| **KEA Extraction** | Valid KEA response ⇒ knowledge of dlog | Damgard 1991 |
| **QAP Reduction** | Arithmetic circuit → QAP | GGPR13 |
| **Groth16 Completeness** | Honest prover → verifier accepts | Groth 2016 |
| **Groth16 Soundness** | No false proof (under q-KEA + q-PDH) | Groth 2016 |
| **Groth16 Perfect ZK** | Simulator produces indistinguishable proofs without witness | Groth 2016 §3.2 |
| **Schwartz-Zippel** | Polynomial identity test via random evaluation | Schwartz 1980, Zippel 1979 |
| **KEA Consistency** | A and B encodings must use same witness (KEA-enforced) | Groth 2016 |

---

## Core Algorithms

| Algorithm | Complexity | Reference |
|-----------|-----------|-----------|
| Miller-Rabin | O(k log³ n) | Miller 1976, Rabin 1980 |
| Extended GCD | O(log n) | Euclid, Knuth TAOCP |
| Tonelli-Shanks | O(S + log p) | Tonelli 1891, Shanks 1972 |
| Baby-step Giant-step | O(√n) time, O(√n) space | Shanks 1971 |
| Pollard's Rho | O(√n) time, O(1) space | Pollard 1978 |
| Pohlig-Hellman | O(Σ e_i·(log n + √p_i)) | Pohlig-Hellman 1978 |
| Index Calculus | L_p(1/2, √2) | Kraitchik, Adleman 1979 |
| Lagrange Interpolation | O(m²) naive | Lagrange 1795 |
| Polynomial Multiplication | O(da·db) convolution | Knuth TAOCP |
| QAP Satisfiability | O(n·m) Horner eval | Schwartz-Zippel |
| Groth16 Setup | O(m + n) group ops | Groth 2016 |
| Groth16 Prove | O(m + n) group ops | Groth 2016 |
| Groth16 Verify | O(1) pairings | Groth 2016 |
| **Groth16 ZK Simulate** | O(1) exponentiations | Groth 2016 §3.2 |
| **Groth16 Batch Verify** | O(1) pairings (randomized) | Blazy et al. 2013 |

---

## Nine-School Curriculum Mapping

| School | Course | Topics Covered |
|--------|--------|---------------|
| **MIT** | 6.875 Cryptography & Cryptanalysis | DLP, CDH, DDH, KEA |
| **Stanford** | CS255 Cryptography | KEA, pairing-based crypto |
| **Berkeley** | CS276 Graduate Cryptography | SNARKs, R1CS, QAP |
| **CMU** | 15-855 Graduate Complexity | Computational assumptions |
| **Princeton** | COS 522 Complexity | Non-black-box extraction |
| **Caltech** | CS 151 Complexity Theory | Generic group model |
| **Cambridge** | Part II Cryptography | Bilinear pairings |
| **Oxford** | Advanced Cryptography | SNARK constructions |
| **ETH** | 263-4600 Cryptographic Protocols | KEA-based protocols |

---

## Build & Run

```bash
make        # build everything
make test   # run test suite (65+ tests, 72+ assertions)
make examples  # build examples
./examples/example_kea     # KEA demo
./examples/example_dlp     # DLP algorithms demo
./examples/example_snark   # Groth16 SNARK demo (incl. ZK simulation)
make clean  # clean build artifacts
```

## References

1. Damgard (1991) — Towards Practical Public Key Systems Secure Against CCA
2. Bellare & Palacio (2004) — The KEA Assumptions and 3-Round ZK Protocols
3. Groth (2016) — On the Size of Pairing-based Non-interactive Arguments
4. Gennaro, Gentry, Parno, Raykova (2013) — Quadratic Span Programs (GGPR13)
5. Naor (2003) — On Cryptographic Assumptions and Challenges
6. Fuchsbauer, Kiltz, Loss (2018) — The Algebraic Group Model
7. Shoup (1997) — Lower Bounds for DLP in the Generic Group Model

---

> (C) Mini-Theory-of-Computation
