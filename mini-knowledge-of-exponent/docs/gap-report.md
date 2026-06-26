# Gap Report — mini-knowledge-of-exponent

## Current Gaps

### L8: Advanced Topics
| Gap | Priority | Notes |
|-----|----------|-------|
| FFT-based QAP interpolation | Medium | Current uses naive O(m³) Lagrange; FFT would give O(m log² m) |
| Full Miller's algorithm | Low | Simplified simulation; real implementation needs elliptic curves |
| Pairing-friendly curve generation | Low | BN254, BLS12-381 curve construction not implemented |
| Recursive SNARK composition | Medium | Proving verification of one SNARK inside another |

### L9: Research Frontiers
| Gap | Priority | Notes |
|-----|----------|-------|
| Post-quantum SNARKs | Low | STARK-based or lattice-based alternatives |
| Incrementally Verifiable Computation (IVC) | Medium | Folding schemes, Nova |
| Universal/Updateable CRS | Medium | Powers-of-tau ceremony, Sonic/Marlin |
| Subversion-resistant SNARKs | Low | CRS subversion attacks and mitigations |

## Resolved Gaps (from previous audit)
- [x] Discrete logarithm algorithms (BSGS, Rho, Pohlig-Hellman, Index Calculus)
- [x] KEA extraction mechanism (GGM simulation)
- [x] Groth16 prover/verifier (pairing equation check)
- [x] SNARK completeness verification
- [x] ZK property demonstration → now **real simulation-based ZK** (Groth16Simulator)
- [x] ZK simulator implementation (`groth16_simulate_proof` — trapdoor-based, no witness)
- [x] Batch verification (`groth16_batch_verify` — randomized linear combination)
- [x] QAP satisfiability verification (Schwartz-Zippel evaluation)
- [x] Polynomial multiplication mod p (convolution-based)
- [x] KEA witness consistency check (A and B bind to same witness)

## No Critical Blockers
All L1-L7 required items are implemented with enhanced ZK, batch, and SAT verification.
L8-L9 gaps are advanced topics. Module meets COMPLETE standard.
