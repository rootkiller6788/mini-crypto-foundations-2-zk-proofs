# Course Alignment

## Nine-School Curriculum Mapping for Sigma Protocols & Fiat-Shamir

| School | Course | Relevant Topics | Our Coverage |
|--------|--------|----------------|-------------|
| **MIT** | 6.875 Cryptography | Sigma protocols, ZK proofs, FS transform | sigma_core, sigma_schnorr, sigma_fiat_shamir |
| **Stanford** | CS355 Cryptography | Schnorr, DLEQ, OR proofs, ring signatures | sigma_schnorr, sigma_chaum_pedersen, sigma_composition |
| **Berkeley** | CS276 Cryptography | NIZK, ROM, FS signatures | sigma_fiat_shamir |
| **CMU** | 15-859M Crypto | Modular protocol design, composition | sigma_composition |
| **Princeton** | COS 433 Cryptography | Identification, signatures, anonymity | sigma_schnorr, sigma_fiat_shamir, sigma_composition |
| **Caltech** | CS/IDS 142 Crypto | RSA-based identification (GQ) | sigma_gq |
| **Cambridge** | Part II Cryptography | Sigma protocols theory, security proofs | All modules |
| **Oxford** | Advanced Security | Privacy-preserving protocols | sigma_composition (ring signatures) |
| **ETH** | 263-4660 Crypto | Formal verification of protocols | sigma_core (vtable abstraction) |

## Textbook Alignment

| Textbook | Chapters | Our Implementation |
|----------|----------|-------------------|
| Goldreich (2004) Foundations of Cryptography I | §4.7 Zero-Knowledge Proofs | sigma_core, sigma_schnorr |
| Katz & Lindell (2014) Intro to Modern Crypto | Ch 13 Digital Signatures | sigma_fiat_shamir |
| Hazay & Lindell (2010) Efficient Secure 2PC | Ch 6 Sigma Protocols | sigma_core protocol runtime |
| Boneh & Shoup (2020) Graduate Crypto | Ch 19 Identification & Signatures | All modules |
| Menezes et al. (1996) Handbook of Applied Crypto | Ch 11 Digital Signatures | sigma_math (big ints), sigma_fiat_shamir |
| Schnorr (1991) J. Cryptology | Efficient Signature Generation | sigma_schnorr |
| Fiat & Shamir (1986) CRYPTO 86 | How to Prove Yourself | sigma_fiat_shamir |
| Chaum & Pedersen (1993) CRYPTO 92 | Wallet Databases | sigma_chaum_pedersen |
| Guillou & Quisquater (1988) EUROCRYPT 88 | Zero-Knowledge Protocol | sigma_gq |
| Cramer et al. (1994) CRYPTO 94 | Proofs of Partial Knowledge | sigma_composition |
