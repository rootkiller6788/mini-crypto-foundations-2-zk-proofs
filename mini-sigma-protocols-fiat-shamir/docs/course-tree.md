# Course Tree — Prerequisite Dependencies

## Module: mini-sigma-protocols-fiat-shamir

```
Group Theory (finite cyclic groups, Z_p^*)
  ├── Modular Arithmetic (add, mul, exp, inv in Z_p)
  ├── Hash Functions (SHA-256, random oracle model)
  └── Discrete Logarithm Assumption
        │
        ├── Schnorr Sigma Protocol
        │     ├── Special Soundness
        │     ├── SHVZK
        │     └── Knowledge Error kappa = 1/q
        │
        ├── Fiat-Shamir Transform
        │     ├── FS Non-Interactive Proofs
        │     ├── FS Digital Signatures (Schnorr/EdDSA)
        │     ├── Strong vs Weak FS
        │     ├── Batch Verification
        │     └── Forking Lemma
        │
        ├── Chaum-Pedersen (DLEQ)
        │     ├── Equality of Discrete Logs
        │     ├── Verifiable Encryption
        │     └── Mix-net Verification
        │
        ├── Guillou-Quisquater (RSA-based)
        │     ├── RSA Modulus Generation
        │     ├── RSA Assumption
        │     └── GQ Identification/Signatures
        │
        └── Sigma Protocol Composition
              ├── AND (Conjunction)
              ├── OR (Disjunction, WI)
              ├── Ring (1-out-of-N)
              └── EQ (Same Witness)
```

## Dependencies on Other Modules

| Depends On | Reason |
|-----------|--------|
| mini-cook-levin-theorem | NP relation R(x,w) concept |
| mini-p-np-np-completeness | Proof systems as NP verification |
| mini-boolean-circuits-model | Circuit representation of relations (future) |

## Modules That Depend On This

| Dependency | Reason |
|-----------|--------|
| mini-zk-snarks | Sigma protocols as building block |
| mini-bulletproofs | Inner product argument uses sigma protocol structure |
| mini-threshold-crypto | DLEQ for verifiable secret sharing |
