# Course Tree — GMW Graph 3-Coloring ZK Proofs

## Prerequisites (What You Need Before This Module)

```
mini-cook-levin-theorem/
  └── NP-completeness (3SAT <=p 3-COLORING)
  
mini-p-np-np-completeness/
  └── NP class, NP-complete problems, polynomial-time reductions

mini-boolean-circuits-model/ (optional)
  └── Circuit model for NP reductions
```

## Dependency Graph (This Module)

```
graph_3coloring.h/.c          ← Foundation: graph data structures
    ↓
commitment.h/.c               ← Cryptographic commitments (hash + Pedersen)
    ↓
gmw_protocol.h/.c             ← GMW protocol core (prover/verifier)
    ↓
simulator.h/.c                ← ZK simulator + distinguisher
    ↓
interactive_proof.h/.c        ← IP framework + soundness analysis
    ↓
zk_applications.h/.c          ← Applications (ZK auth, NIZK, credentials)
```

## What This Module Enables

```
This Module
    ↓
┌─────────────────────────────────────┐
│ Future modules:                      │
│  - mini-sigma-protocols/            │
│  - mini-nizk-fiat-shamir/           │
│  - mini-ZK-for-NP/                  │
│  - mini-zksnark-groth16/            │
│  - mini-ip-pspace/                  │
│  - mini-pcp-theorem/                │
└─────────────────────────────────────┘
```
