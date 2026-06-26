# Gap Report
## Mini Sigma Protocols & Fiat-Shamir

### Complete Areas
- L1-L6: All core knowledge covered with implementations and tests
- L7: 6 applications implemented
- L8: Strong/Weak FS, Batch Verify, Forking Lemma implemented

### Missing Items (Priority Order)

1. **HIGH**: None — all critical knowledge implemented
2. **MEDIUM**: L8 Fiat-Shamir without ROM — CI hash functions (documented)
3. **MEDIUM**: L8 Quantum security — Unruh transform (documented)
4. **LOW**: L9 Post-quantum sigma protocols (documented)
5. **LOW**: L9 Recursive proof composition (documented)
6. **LOW**: L9 General NP sigma protocols (documented)

### Known Limitations
- RSA modulus generation uses small test primes (not production-grade)
- SHA-256 not hardened against length-extension (standard SHA-256 behavior)
- PRNG is xoshiro256** (statistical, not cryptographic — suitable for tests only)
- No constant-time implementation (vulnerable to timing side-channels)
- GQ vtable adapters are simplified (full abstraction would need dual-commitment support)
