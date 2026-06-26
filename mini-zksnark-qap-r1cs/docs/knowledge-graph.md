# Knowledge Graph ！ mini-zksnark-qap-r1cs

## L1 ！ Definitions (Complete)
- R1CS: Rank-1 Constraint System, (A.w) o (B.w) = C.w
- QAP: Quadratic Arithmetic Program, A(x).B(x) - C(x) = H(x).Z(x)
- zkSNARK: Succinct Non-interactive Argument of Knowledge
- Groth16: Pairing-based zkSNARK with 3 group elements
- Arithmetic Circuit: DAG of add/mul gates over F_p
- Finite Field F_p: Z/pZ for prime p, implemented as uint64_t[4]
- Bilinear Pairing: e: G1 x G2 -> GT, bilinear map
- Trusted Setup: One-time generation of CRS from secret tau,alpha,beta,gamma,delta
- Witness: Satisfying assignment to circuit variables w = (1, x, w_aux)
- Public Input: Statement variables visible to verifier

## L2 ！ Core Concepts (Complete)
- NP-completeness: SAT reduces to R1CS
- Succinctness: Proof size O(1) independent of circuit size
- Zero-Knowledge: Proof reveals nothing about witness beyond statement
- Soundness: False statement cannot produce valid proof (under d-DDH)
- Completeness: True statement + valid witness always proves correctly
- Polynomial Identity Testing: Schwartz-Zippel lemma
- Lagrange Interpolation: Reconstruct polynomial from evaluations
- Montgomery Form: aR mod p for efficient modular multiplication
- Knowledge of Exponent: Extractability assumption for group elements
- d-Power DDH: Hardness of distinguishing g^{P(tau)} from random

## L3 ！ Mathematical Structures (Complete)
- F_p: 256-bit prime field, 4-limb representation
- G1: Elliptic curve group over F_p (y^2 = x^3 + b)
- G2: Quadratic extension group F_{p^2}
- GT: Pairing target group F_{p^12}
- Polynomial: Coeff vector + degree, coefficient and evaluation forms
- Sparse Matrix: COO format (row, col, val) triples
- NTT Domain: Powers of primitive n-th root of unity
- Arithmetic Circuit DAG: Gates (INPUT/CONSTANT/ADD/MUL/OUTPUT)
- QAP Triple: (A_i, B_i, C_i) polynomial vectors for i=0..n_vars-1
- Vanishing Polynomial: Z(x) = prod_{k=0}^{m-1} (x - r_k)

## L4 ！ Fundamental Laws (Complete)
- QAP Theorem: R1CS(w)=0 <=> exists H: A_w.B_w - C_w = H.Z
- Schwartz-Zippel: For nonzero P of degree d: Pr[P(r)=0] <= d/|F|
- Groth16 Completeness: e(A,B) = e(G^a,H^b).e(sum,G^g).e(C,H^d)
- Groth16 Soundness: Under q-type DDH, false -> invalid with overwhelming prob
- Groth16 Zero-Knowledge: Blinding factors r,s hide witness in A,B,C
- Lagrange Interpolation Theorem: Unique deg-n poly through n+1 points
- Convolution Theorem: FFT(P*Q) = FFT(P) . FFT(Q)
- Euler Criterion: a^{(p-1)/2} = Legendre(a/p) mod p

## L5 ！ Algorithms/Methods (Complete)
- Cooley-Tukey radix-2 NTT: O(n log n) with bit-reversal
- Montgomery COMB reduction: a.b.R^{-1} mod p without division
- Extended Euclidean GCD: Modular inverse in O(log p)
- Square-and-Multiply: Exponentiation in O(log e)
- Montgomery Batch Inversion: n inverses with 1 inversion + O(n) mul
- Lagrange Interpolation: O(n^2) via barycentric formula
- Polynomial Long Division: Euclidean algorithm for polynomials
- KZG Commitment: com = g^{P(tau)} with hiding via r.Z(tau)
- Groth16 Proving: Compute A,B,C from witness + CRS
- Groth16 Verification: Single pairing equation check
- Double-and-Add: Scalar multiplication on elliptic curves
- MPC Powers of Tau: Sequential participant contributions
- Circuit Flattening: Nested expression -> flat gate list

## L6 ！ Canonical Problems (Complete)
- SAT -> R1CS: Boolean formula to constraint system
- x^3+x+5 Circuit: Classic SNARK demo benchmark
- SHA256 Round: Simplified hash function in arithmetic circuit
- Merkle Inclusion: Binary tree membership proof circuit
- Matrix Multiplication: C = A x B as arithmetic circuit
- Groth16 Proof: 3-group-element non-interactive argument

## L7 ！ Applications (Partial+)
- ZK Proofs for NP: Prover/verifier for arbitrary NP statements
- MPC Ceremony: Multi-party trusted setup with 1-of-N security
- KZG Commitments: Polynomial commitment with constant-size opening
- Merkle ZK: Zero-knowledge Merkle tree verification

## L8 ！ Advanced Topics (Partial)
- ZK Blinding: r,s random factors in Groth16 prove
- Batch Inversion: O(n) with single inverse
- Montgomery Arithmetic: Optimized modular multiplication
- Split-Radix NTT: Reduced operation count vs radix-2
- Good-Thomas NTT: Prime factor decomposition for composite sizes

## L9 ！ Research Frontiers (Partial)
- Blockchain Scalability: zkRollups and recursive SNARKs
- Universal CRS: Updatable structured reference strings
- Post-Quantum: Lattice-based and hash-based alternatives
