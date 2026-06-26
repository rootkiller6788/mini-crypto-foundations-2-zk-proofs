# Course Alignment — mini-knowledge-of-exponent

## Nine-School Curriculum Mapping

### MIT — 6.875 Cryptography & Cryptanalysis
- **Week 5**: Discrete logarithm, Diffie-Hellman problems
- **Week 8**: Knowledge assumptions, non-black-box extraction
- **Mapping**: DLP/CDH/DDH algorithms, KEA security games

### Stanford — CS255 Cryptography
- **Lecture 8**: Number theory, cyclic groups, DLP
- **Lecture 12**: Pairing-based cryptography
- **Lecture 18**: SNARKs and verifiable computation
- **Mapping**: Group theory, bilinear pairings, Groth16 prover/verifier

### Berkeley — CS276 Graduate Cryptography
- **Module 3**: Computational assumptions (DLP, CDH, DDH)
- **Module 6**: SNARKs, R1CS, QAP, Groth16
- **Mapping**: R1CS → QAP conversion, Groth16 full pipeline

### CMU — 15-855 Graduate Complexity Theory
- **Unit 4**: Interactive proofs and arguments
- **Unit 5**: PCP theorem and consequences
- **Mapping**: SNARK as computational argument, witness extraction

### Princeton — COS 522 Computational Complexity
- **Chapter 8**: Cryptography in complexity theory
- **Chapter 9**: Non-black-box techniques
- **Mapping**: KEA non-falsifiability, extraction model

### Caltech — CS 151 Complexity Theory
- **Topic 5**: Generic group model, lower bounds
- **Mapping**: GGM analysis of DLP, Pollard Rho lower bound

### Cambridge — Part II Complexity Theory
- **Section 7**: Interactive proofs
- **Section 8**: Zero-knowledge arguments
- **Mapping**: SNARK as succinct argument system

### Oxford — Advanced Cryptography
- **Term 2**: SNARK constructions, pairing-based crypto
- **Mapping**: Groth16 setup, proving key, verification key

### ETH — 263-4600 Cryptographic Protocols
- **Week 10**: SNARKs and applications
- **Week 11**: zk-SNARKs for blockchain
- **Mapping**: Zcash application, zk-rollup use case

## Coverage Matrix

| Topic | MIT | Stanford | Berkeley | CMU | Princeton | Caltech | Cambridge | Oxford | ETH |
|-------|-----|----------|----------|-----|-----------|---------|-----------|--------|-----|
| Groups | ✓ | ✓ | ✓ | - | - | ✓ | - | - | - |
| DLP | ✓ | ✓ | ✓ | - | - | ✓ | - | - | - |
| CDH/DDH | ✓ | ✓ | ✓ | - | - | - | - | - | - |
| KEA | ✓ | ✓ | ✓ | - | ✓ | - | - | - | - |
| Pairings | - | ✓ | - | - | - | - | - | ✓ | - |
| R1CS/QAP | - | ✓ | ✓ | - | - | - | - | - | - |
| Groth16 | - | ✓ | ✓ | - | ✓ | - | ✓ | ✓ | ✓ |
| Zcash | - | ✓ | - | - | - | - | - | - | ✓ |
