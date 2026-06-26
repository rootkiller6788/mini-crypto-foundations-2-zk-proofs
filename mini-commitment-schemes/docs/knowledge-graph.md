# Knowledge Graph �� Commitment Schemes

## L1: Definitions (Complete)
- Commitment scheme: (Commit, Verify) protocol pair
- Hiding property: commitment reveals no info about message
- Binding property: cannot change committed message
- Pedersen commitment: C = g^m * h^r mod p
- Hash-based commitment: C = H(m || r)
- Vector commitment: C = MerkleRoot(v_1, ..., v_n)
- Fujisaki-Okamoto commitment: C = g^m * r^n mod N
- Opening: reveal (m, r)
- Verification: recompute Commit(m, r) == C
- Trapdoor: secret enabling equivocation
- Homomorphic commitment: C(m1+m2) = C(m1) * C(m2)

## L2: Core Concepts (Complete)
- Perfect hiding: information-theoretic, unconditional
- Statistical hiding: negligible distinguishing advantage
- Computational hiding: secure against PPT adversaries
- Perfect binding: no collision possible even with unbounded power
- Computational binding: collision implies solving hard problem
- Damgard impossibility: cannot have both perfect hiding and binding
- Random oracle model: hash modeled as random function
- Commit-reveal paradigm: two-phase protocol
- Domain separation: prevent cross-protocol attacks
- Security reduction: binding �� discrete log

## L3: Mathematical Structures (Complete)
- Z_p: finite prime field (bigint + modctx)
- Z_p^*: multiplicative group of units
- Group generators g, h (Pedersen parameters)
- Binary Merkle tree (complete binary tree)
- Hash chain: sequential hash composition
- Ring operations: +, ��, mod on big integers
- Group exponentiation: g^e mod p
- Discrete log group: cyclic group of prime order
- Euclidean domain Z: division algorithm
- Bezout's identity: gcd(a,b) = ua + vb

## L4: Fundamental Laws (Complete)
- Fermat's Little Theorem: a^{p-1} �� 1 (mod p)
- Lagrange's Theorem: subgroup order divides group order
- Discrete Log Assumption: DL in Z_p^* is hard
- Bezout's Identity: ?u,v: ua+vb=gcd(a,b)
- Damgard Impossibility Theorem (1999)
- Collision resistance �� binding reduction
- Perfect hiding of Pedersen: information-theoretic proof
- Binding of Pedersen �� DLP: equivalence proof
- Soundness of ��-protocols: special soundness

## L5: Algorithms/Methods (Complete)
- Pedersen commit: g^m * h^r mod p
- Pedersen verify: recompute and compare
- Square-and-multiply exponentiation
- Extended Euclidean algorithm (modular inverse)
- Montgomery multiplication (bigint)
- Merkle tree construction: O(n) build, O(log n) proof
- Merkle proof generation: sibling path
- Merkle proof verification: recompute root
- Hash-based commit: H(m || r)
- Double-round hashing: H(H(m||r1)||r2)
- Domain-separated hashing: H(domain||m||r)
- Schnorr identification protocol
- Cramer-Damgard-Schoenmakers ��-protocol
- Sigma protocol proof generation
- Sigma protocol verification

## L6: Canonical Problems (Complete)
- Bit commitment: commit to 0 or 1
- Coin flipping: fair over telephone (Blum 1981)
- Membership proof: prove element in vector
- Non-membership proof: prove element not in vector
- Scheme selection: which commitment to use
- Hiding game: adversary guesses committed message
- Binding game: adversary finds collision

## L7: Applications (Complete, 4 applications)
- Coin flipping by telephone (Blum 1981)
- Zero-knowledge proof building block (��-protocols)
- Blockchain light clients (Bitcoin SPV with Merkle proofs)
- Verifiable databases (Certificate Transparency)
- zk-rollup state trees
- Post-quantum commitments (hash-based)

## L8: Advanced Topics (Complete, 3 topics)
- Homomorphic commitments: additive property
- Trapdoor equivocation: ZK simulation
- Updatable commitments: Merkle tree updates
- Proof aggregation: multiple Merkle proofs
- ��-protocol composition: AND/OR proofs
- Vector commitments with algebraic properties

## L9: Research Frontiers (Partial)
- Post-quantum commitment schemes (hash-based, lattice-based)
- Hash-based PQ implemented: double-round, domain-separated
- Quantum-secure commitments (Unruh 2016, Damgard 2014)
- Grover's algorithm speedup simulation (16-bit search demo)
- NIST PQC standardization mapping (SPHINCS+, SHA-3 status)
- BHT quantum collision algorithm bound analysis
- Verkle trees: more efficient vector commitments
- Polynomial commitments (KZG)
- Non-malleable commitments
