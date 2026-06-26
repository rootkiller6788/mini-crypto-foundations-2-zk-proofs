# Course Tree ¡ª Commitment Schemes

## Prerequisite Knowledge Dependencies

```
Commitment Schemes
©À©¤©¤ Number Theory (Z_p, groups, generators)
©¦   ©À©¤©¤ Modular arithmetic (mini-complexity-foundations)
©¦   ©À©¤©¤ Prime numbers and finite fields
©¦   ©¸©¤©¤ Discrete logarithm problem
©À©¤©¤ Cryptography Foundations
©¦   ©À©¤©¤ One-way functions
©¦   ©À©¤©¤ Hash functions (collision resistance)
©¦   ©¸©¤©¤ Random oracle model
©À©¤©¤ Data Structures
©¦   ©À©¤©¤ Binary trees
©¦   ©¸©¤©¤ Hash chains
©À©¤©¤ Complexity Theory
©¦   ©À©¤©¤ Computational vs information-theoretic security
©¦   ©¸©¤©¤ Security reductions
©¸©¤©¤ Zero-Knowledge Proofs
    ©À©¤©¤ ¦²-protocols (3-move proofs)
    ©À©¤©¤ Proof of knowledge
    ©¸©¤©¤ Simulation paradigm
```

## Internal Dependencies (within this module)

```
bigint.h/c     ¡ú  modarith.h/c   ¡ú  commitment.h/c
                                  ¡ú  pedersen.h/c
                                  ¡ú  hash_commit.h/c
                 vector_commit.h/c (independent)
```

## Downstream Dependencies (modules that need this)

```
mini-crypto-foundations-2-zk-proofs/
©À©¤©¤ mini-commitment-schemes  ¡û THIS MODULE
©À©¤©¤ mini-zero-knowledge-proofs  ¡û depends on commitments
©À©¤©¤ mini-sigma-protocols        ¡û depends on commitments
©¸©¤©¤ mini-non-interactive-zk     ¡û depends on commitments
```

## Learning Path

1. Start with bigint.h/c ¡ª multi-precision integer arithmetic
2. Then modarith.h/c ¡ª modular arithmetic over Z_p
3. Core: commitment.h/c ¡ª generic commitment framework
4. Pedersen: pedersen.h/c ¡ª group-based commitments
5. Hash: hash_commit.h/c ¡ª hash-based commitments
6. Vector: vector_commit.h/c ¡ª Merkle tree commitments
7. Examples: demonstrate real protocols
8. Lean: formal verification of properties
