# Knowledge Graph 〞 Mini Sigma Protocols & Fiat-Shamir

## L1: Definitions

| # | Definition | C Implementation | Lean Representation |
|---|-----------|-----------------|---------------------|
| 1 | Sigma Protocol: 3-move public-coin interactive proof (commit, challenge, respond) | `sigma_protocol` vtable in sigma_core.h | 〞 |
| 2 | Transcript (a, e, z): commitment a, challenge e, response z | `sigma_transcript` struct | 〞 |
| 3 | Special Soundness: extract witness from two accepting transcripts with same a | `extract` function pointer | 〞 |
| 4 | SHVZK: existence of simulator producing identically distributed transcripts | `simulate` function pointer | 〞 |
| 5 | Proof of Knowledge: prover demonstrates knowledge of witness w | `prove_commit` / `prove_response` | 〞 |
| 6 | Knowledge Error 百: probability dishonest prover succeeds without witness | `sigma_estimate_knowledge_error` | 〞 |
| 7 | Fiat-Shamir Transform: interactive ↙ non-interactive via hash as random oracle | `sigma_fs_prove` / `sigma_fs_verify` | 〞 |
| 8 | Schnorr Protocol: prove knowledge of x s.t. y = g^x | `sigma_schnorr_*` functions | 〞 |
| 9 | Chaum-Pedersen Protocol: prove equality of discrete logs y1=g1^x, y2=g2^x | `sigma_cp_*` functions | 〞 |
| 10 | Guillou-Quisquater Protocol: RSA-based identification (prove e-th root) | `sigma_gq_*` functions | 〞 |
| 11 | AND Composition: prove conjunction R1(x1,w1) ＿ R2(x2,w2) | `sigma_and_*` functions | 〞 |
| 12 | OR Composition: prove disjunction R1(x1,w1) ˍ R2(x2,w2) with WI | `sigma_or_*` functions | 〞 |
| 13 | Ring Signature: 1-out-of-N OR proof for anonymous signing | `sigma_ring_*` functions | 〞 |
| 14 | Strong Fiat-Shamir: include public key in hash (resists key substitution) | `sigma_fs_is_strong` | 〞 |
| 15 | Weak Fiat-Shamir: omit public key from hash (vulnerable) | `sigma_fs_weak_prove` | 〞 |
| 16 | Non-Interactive ZK (NIZK): zero-knowledge without interaction in ROM | `sigma_fs_prove` | 〞 |

## L2: Core Concepts

| # | Concept | Source File |
|---|---------|-------------|
| 1 | Honest-Verifier Model: verifier follows protocol honestly | sigma_core.c (sigma_run_protocol) |
| 2 | Random Oracle Model (ROM): hash modeled as truly random function | sigma_fiat_shamir.c |
| 3 | Discrete Logarithm Assumption: computing x from g^x is hard | sigma_schnorr.c |
| 4 | RSA Assumption: computing e-th roots modulo N is hard | sigma_gq.c |
| 5 | Witness Indistinguishability (WI): verifier cannot tell which witness was used | sigma_composition.c (OR) |
| 6 | Witness Hiding (WH): verifier learns nothing beyond validity of statement | sigma_composition.c (Ring) |
| 7 | Public-Coin Protocol: verifier's messages are truly random | sigma_core.c |
| 8 | Forking Lemma: rewinding argument for extractor in security proofs | sigma_fiat_shamir.c (documented) |
| 9 | Completeness: honest prover always convinces honest verifier | All test files |
| 10 | Zero-Knowledge: verifier learns nothing beyond truth of statement | sigma_schnorr.c (simulate) |

## L3: Mathematical Structures

| # | Structure | Implementation |
|---|-----------|---------------|
| 1 | Finite Cyclic Group G ? Z_p^* of prime order q (2048-bit p, 256-bit q) | sigma_math.h: sigma_biguint, sigma_group_elem |
| 2 | Scalar field Z_q (256-bit prime) | sigma_math.h: sigma_scalar |
| 3 | Big integer arithmetic (add, sub, mul, div, exp, inv) | sigma_math.c: full implementation |
| 4 | Modular exponentiation (square-and-multiply) | sigma_math.c: sigma_mod_exp |
| 5 | Extended Euclidean algorithm for modular inverse | sigma_math.c: sigma_mod_inv |
| 6 | SHA-256 hash function (Merkle-Damgard + Davies-Meyer) | sigma_math.c: sigma_hash_*  |
| 7 | xoshiro256** PRNG for test-grade randomness | sigma_math.c: sigma_random_* |
| 8 | RSA modulus N = p﹞q structure | sigma_gq.h: sigma_gq_modulus |
| 9 | Protocol vtable (abstract interface with function pointers) | sigma_core.h: sigma_protocol |
| 10 | Barrett modular reduction for 2048-bit operands | sigma_math.c: sigma_mod_mul (via division) |

## L4: Fundamental Theorems/Laws

| # | Theorem | Verification |
|---|---------|-------------|
| 1 | Special Soundness of Schnorr: x = (z-z')/(e-e') from (a,e,z), (a,e',z') | test_schnorr.c: extraction test |
| 2 | SHVZK of Schnorr: (a,e,z) ~ (g^z﹞y^{-e}, e, z) | test_schnorr.c: simulation test |
| 3 | Knowledge Error 百 = 1/q for Schnorr (negligible for 256-bit q) | test_schnorr.c: kerr test |
| 4 | Fiat-Shamir Theorem: HVZK + special soundness ↙ NIZK in ROM | test_fiat_shamir.c |
| 5 | Forking Lemma: security reduction for FS signatures | sigma_fiat_shamir.c (documented) |
| 6 | CDS Theorem: AND/OR composition preserves sigma protocol properties | test_composition.c |
| 7 | OR composition preserves Witness Indistinguishability | test_composition.c |
| 8 | Knowledge Error of OR: 百 ≒ max(百1, 百2) | sigma_composition.c (documented) |
| 9 | Special Soundness of GQ: extract e-th root via gcd(e, |c-c'|) | sigma_gq.c: sigma_gq_extract |
| 10 | SHVZK of GQ: Y = z^e ﹞ X^{-c} simulates without witness | sigma_gq.c: sigma_gq_simulate |
| 11 | Chaum-Pedersen DLEQ: same x across bases g1, g2 extractable | test_chaum_pedersen.c |
| 12 | Strong FS resists key-substitution attacks | sigma_fiat_shamir.c |

## L5: Algorithms/Methods

| # | Algorithm | Source |
|---|-----------|--------|
| 1 | Schoolbook Multiplication (O(n^2) big integer) | sigma_math.c: schoolbook_mul |
| 2 | Binary Long Division (shift-subtract) | sigma_math.c: long_divrem |
| 3 | Square-and-Multiply Exponentiation (left-to-right binary) | sigma_math.c: sigma_mod_exp |
| 4 | Binary Extended GCD for Modular Inverse | sigma_math.c: sigma_mod_inv |
| 5 | SHA-256 Compression Function (64 rounds) | sigma_math.c: sha256_compress |
| 6 | xoshiro256** with SplitMix64 seeding | sigma_math.c: xoshiro_next |
| 7 | Rejection Sampling for Uniform Z_q | sigma_math.c: sigma_random_scalar |
| 8 | Schnorr Key Generation: x↘Z_q^*, y=g^x | sigma_schnorr.c |
| 9 | Schnorr Extraction: x = (z-z')﹞(e-e')^{-1} | sigma_schnorr.c: sigma_schnorr_extract |
| 10 | Schnorr Simulation: z↘Z_q, a=g^z﹞y^{-e} | sigma_schnorr.c: sigma_schnorr_simulate |
| 11 | Fiat-Shamir Non-Interactive Proof Generation | sigma_fiat_shamir.c: sigma_fs_prove |
| 12 | Schnorr Signature (FS-based): e=H(R||pk||msg), s=r+ex | sigma_fiat_shamir.c: sigma_fs_sign |
| 13 | Batch Verification (small exponents test) | sigma_fiat_shamir.c: sigma_fs_batch_verify |
| 14 | CDS OR Composition with challenge splitting | sigma_composition.c: sigma_or_prove |
| 15 | Ring Signature via n-way OR | sigma_composition.c: sigma_ring_prove |
| 16 | Miller-Rabin Primality Test for GQ key generation | sigma_gq.c: is_probable_prime |
| 17 | GQ Extraction with Extended Euclid for gcd(e,d)=1 | sigma_gq.c: sigma_gq_extract |
| 18 | Chaum-Pedersen Dual-Commitment (same r, two bases) | sigma_chaum_pedersen.c |

## L6: Canonical Problems

| # | Problem | Example/Test |
|---|---------|-------------|
| 1 | Schnorr Identification: Prove knowledge of discrete log | example_schnorr_id.c |
| 2 | Fiat-Shamir Signature: Sign and verify messages non-interactively | example_fs_signature.c |
| 3 | Ring Signature: Anonymous 1-out-of-N signing | example_ring_signature.c |
| 4 | DLEQ Proof: Prove equality of two discrete logs | test_chaum_pedersen.c |
| 5 | RSA Root Knowledge: Prove knowledge of e-th root (GQ) | sigma_gq.c |
| 6 | AND Composition: Prove knowledge of two secret keys | test_composition.c |
| 7 | OR Composition: Prove knowledge of one-of-two without revealing which | test_composition.c |

## L7: Applications

| # | Application | Implementation |
|---|-------------|---------------|
| 1 | Schnorr Signatures for Bitcoin (BIP-340/Taproot) | sigma_fiat_shamir.c: sigma_fs_sign |
| 2 | Ring Signatures for Monero/Privacy Coins | sigma_composition.c: sigma_ring_prove |
| 3 | DLEQ for Verifiable Encryption | sigma_chaum_pedersen.c |
| 4 | Batch Verification for Block Validation | sigma_fiat_shamir.c: sigma_fs_batch_verify |
| 5 | GQ Signatures for Smart Cards (ISO/IEC 9796-2) | sigma_gq.c: sigma_gq_sign |
| 6 | Anonymous Credentials (Identity Mixer) | sigma_composition.c (OR framework) |

## L8: Advanced Topics

| # | Topic | Status |
|---|-------|--------|
| 1 | Strong vs Weak Fiat-Shamir (Bernhard et al. 2012) | Implemented: sigma_fs_is_strong, sigma_fs_weak_prove |
| 2 | Batch Verification with Small Exponents (Bellare-Garay-Rabin 1998) | Implemented: sigma_fs_batch_verify |
| 3 | Forking Lemma Security Reduction (Pointcheval-Stern 2000) | Documented in sigma_fiat_shamir.c |
| 4 | Fiat-Shamir without ROM (Correlation-Intractable Hash) | Documented only |
| 5 | Quantum Security / Unruh Transform | Documented only |

## L9: Research Frontiers

| # | Topic | Status |
|---|-------|--------|
| 1 | Post-Quantum Sigma Protocols (lattice-based) | Documented only |
| 2 | Recursive Proof Composition (Halo, Nova) | Documented only |
| 3 | Sigma Protocols for General NP Relations | Documented only |
