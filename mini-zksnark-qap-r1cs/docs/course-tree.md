# Course Dependency Tree ¡ª mini-zksnark-qap-r1cs

## Prerequisites (before this module)

1. **Finite Fields** (field.h, field.c)
   - Modular arithmetic, Fermat's little theorem
   - Extended Euclidean algorithm
   
2. **Polynomial Algebra** (polynomial.h, polynomial.c)
   - Polynomial rings over F_p
   - Lagrange interpolation
   - Polynomial division

3. **Discrete Mathematics**
   - Graph theory (circuit DAG)
   - Boolean algebra

## Dependencies Within Module



## Post-Dependencies (modules that depend on this)

1. **mini-pcp-theorem**: PCP construction builds on R1CS/QAP
2. **mini-ip-pspace**: Interactive proofs generalize SNARK protocol
3. **mini-approximation-algorithms**: Hardness of approximation uses PCP
4. **Advanced Cryptography**: Real-world deployment (libsnark, Circom, ZoKrates)
