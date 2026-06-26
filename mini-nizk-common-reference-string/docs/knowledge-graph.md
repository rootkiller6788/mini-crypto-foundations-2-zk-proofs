# Knowledge Graph - NIZK Common Reference String

## L1: Definitions (Complete)
- **NIZK Proof System**: Setup, Prove, Verify algorithms
- **Common Reference String (CRS)**: Public string enabling NIZK
- **Zero-Knowledge**: Simulator produces indistinguishable proofs
- **Soundness**: Cannot prove false statements
- **Completeness**: Honest prover always convinces verifier
- **Sigma Protocol**: 3-move interactive proof (commit, challenge, respond)
- **Pedersen Commitment**: C = g^m * h^r, perfectly hiding, computationally binding
- **Fiat-Shamir Transform**: c = H(stmt || commitment)
- **Simulation Trapdoor**: tau where h = g^tau
- **Special Soundness**: Extract witness from two transcripts

## L2: Core Concepts (Complete)
- CRS Model vs Random Oracle Model
- Soundness CRS vs ZK CRS tradeoff
- CRS setup: soundness mode (unknown DL)
- CRS setup: ZK mode (known trapdoor)
- Simulation in CRS model
- HVZK property and simulator construction
- CRS validation and subversion resistance
- Domain separation in hashing
- Secure deletion / zeroization
- Proof serialization

## L3: Mathematical Structures (Complete)
- Cyclic group G of prime order q (subgroup of Z_p^*)
- Big integer arithmetic (2048-bit, multi-limb)
- Modular arithmetic: add, sub, mul, exp, inv, neg
- Group element operations: multiply, exponentiate, multi-exp
- Scalar operations in Z_q
- Hash-to-group (exponentiation method)
- SHA-256 Merkle-Damgard construction
- Domain separation via Feistel-like expansion

## L4: Fundamental Theorems (Complete)
- **Special Soundness of Schnorr**: w = (s1-s2)/(c1-c2) mod q
- **Fiat-Shamir Security**: HVZK + special soundness => NIZK secure in ROM
- **Perfect Hiding of Pedersen**: C uniform in G regardless of m
- **Computational Binding of Pedersen**: Requires solving DLOG
- **OR-Proof Soundness**: Prover must know at least one witness
- **CRS Trapdoor Verification**: h = g^tau iff tau = log_g(h)
- **Perfect ZK in ROM**: Real proofs ≡ Simulated proofs with uniform trapdoor

## L5: Algorithms/Methods (Complete)
- Pedersen commitment: commit and verify
- Homomorphic operations: add, sub, scalar_mul
- Vector Pedersen commitment
- Schnorr sigma protocol: commit, respond, verify
- Special soundness witness extractor
- Chaum-Pedersen DLOG equality protocol
- OR-proof composition (Cramer-Damgard-Schoenmakers)
- AND-proof composition
- HVZK transcript simulator
- Fiat-Shamir transform (SHA-256 based)
- NIZK for DLOG knowledge (Schnorr + FS)
- NIZK for DLOG equality (Chaum-Pedersen + FS)
- NIZK for commitment opening (representation proof)
- NIZK OR-proof
- Proof serialization/deserialization

## L6: Canonical Problems (Complete)
- Schnorr Identification / Digital Signature
- Pedersen Commitment with Opening
- Ring Signature (via OR-proof)
- Confidential Transaction (via homomorphic commitments)
- Verifiable Encryption (via DLOG equality proof)

## L7: Applications (Complete)
- **Schnorr digital signatures** (L7: Cryptography - OWF)
- **Confidential transactions** (L7: amounts hidden, validity proven)
- **Ring signatures / anonymous authentication** (L7: privacy)
- **Verifiable secret sharing** (L7: distributed trust)
- **Distributed key generation** (L7: threshold crypto)

## L8: Advanced Topics (Partial)
- Vector commitments (zk-SNARK witness commitments)
- CRS subversion resistance (Bellare et al. 2016)
- Statistical vs computational zero-knowledge
- Distinguisher test methodology
- Multi-CRS model (Groth-Ostrovsky-Sahai)

## L9: Research Frontiers (Partial - documented)
- zk-SNARK constructions (Groth16, PLONK)
- Bulletproofs (range proofs)
- MPC ceremonies for CRS generation
- Post-quantum NIZK (lattice-based)
