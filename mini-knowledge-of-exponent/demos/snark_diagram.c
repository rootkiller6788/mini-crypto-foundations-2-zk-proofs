/*
 * snark_diagram.c — Groth16 SNARK Architecture Diagram
 *
 * Renders the full SNARK pipeline as an ASCII flowchart showing
 * data flow between R1CS, QAP, CRS, Prover, and Verifier.
 */
#include <stdio.h>

int main(void) {
    printf("\n╔══════════════════════════════════════════════════════╗\n");
    printf("║   Groth16 SNARK — Architecture Diagram              ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n\n");

    printf("  ┌─────────────── TRUSTED SETUP ──────────────────┐\n");
    printf("  │                                                  │\n");
    printf("  │   Random: τ, α, β, γ, δ   (TOXIC WASTE!)       │\n");
    printf("  │   │                                              │\n");
    printf("  │   ├──► Proving Key (pk)                         │\n");
    printf("  │   │    [A_i(τ)]₁, [B_i(τ)]₁,₂, [K_i(τ)]₁       │\n");
    printf("  │   │    [α]₁, [β]₁, [δ]₁                         │\n");
    printf("  │   │                                              │\n");
    printf("  │   └──► Verification Key (vk)                    │\n");
    printf("  │        [α]₁, [β]₂, [γ]₂, [δ]₂                  │\n");
    printf("  │                                                  │\n");
    printf("  │   (τ,α,β,γ,δ) MUST BE DESTROYED!                │\n");
    printf("  └──────────────────────────────────────────────────┘\n\n");

    printf("  ┌──────────── PROVER ────────────────────────────┐\n");
    printf("  │                                                 │\n");
    printf("  │  Input: witness w₀..wₙ, pk, public inputs       │\n");
    printf("  │  Pick blinding: r, s (for ZK)                   │\n");
    printf("  │                                                 │\n");
    printf("  │  A = [α]₁ + Σ wᵢ[Aᵢ(τ)]₁ + r[δ]₁   ∈ G₁        │\n");
    printf("  │  B = [β]₂ + Σ wᵢ[Bᵢ(τ)]₂ + s[δ]₂   ∈ G₂        │\n");
    printf("  │  C = Σ wᵢ[Kᵢ(τ)]₁ + A·s + B·r - rs[δ]₁  ∈ G₁   │\n");
    printf("  │                                                 │\n");
    printf("  │  Output: π = (A, B, C)   (3 group elements!)    │\n");
    printf("  │                                                 │\n");
    printf("  │  ★ KEA ensures A and B use same witness! ★      │\n");
    printf("  └─────────────────────────────────────────────────┘\n\n");

    printf("  ┌──────────── VERIFIER ──────────────────────────┐\n");
    printf("  │                                                 │\n");
    printf("  │  Input: proof π = (A,B,C), vk, public inputs x  │\n");
    printf("  │                                                 │\n");
    printf("  │  Check: e(A, B) ≟ e(α,β) · e(C,δ)             │\n");
    printf("  │           · e(Σ xᵢ·ICᵢ, γ)    (full equation)  │\n");
    printf("  │                                                 │\n");
    printf("  │  Complexity: 3 pairings (or 1 optimized)        │\n");
    printf("  │  = CONSTANT independent of computation size!    │\n");
    printf("  │                                                 │\n");
    printf("  └─────────────────────────────────────────────────┘\n\n");

    printf("  ┌─────────── EXTRACTOR (KEA-based) ──────────────┐\n");
    printf("  │                                                 │\n");
    printf("  │  Given: valid proof π = (A, B, C)               │\n");
    printf("  │  In GGM: reads representation of A              │\n");
    printf("  │  A = Σ aᵢ·[Aᵢ(τ)]₁ + r·[δ]₁                    │\n");
    printf("  │  ⇒ Recovers coefficients aᵢ                     │\n");
    printf("  │  ⇒ These form a valid witness!                  │\n");
    printf("  │                                                 │\n");
    printf("  │  This is the 'Argument of KNOWLEDGE' property.  │\n");
    printf("  └─────────────────────────────────────────────────┘\n\n");

    printf("  ═══════ FLOW SUMMARY ═══════\n\n");
    printf("  Computation        R1CS (matrices A, B, C)\n");
    printf("       │\n");
    printf("       ▼\n");
    printf("  Polynomials       QAP: A(x), B(x), C(x), Z(x)\n");
    printf("       │\n");
    printf("       ▼\n");
    printf("  Setup             CRS: pk (for prover), vk (for verifier)\n");
    printf("       │\n");
    printf("       ├─────► Prover(witness, pk) → π = (A, B, C)\n");
    printf("       │\n");
    printf("       └─────► Verifier(π, vk, input) → accept/reject\n");
    printf("                           │\n");
    printf("                           ▼\n");
    printf("       Extractor(π, pk) → witness\n\n");

    printf("  Application: Zcash uses this to prove transactions\n");
    printf("  valid WITHOUT revealing sender, receiver, or amount!\n\n");

    printf("═══ Groth16 Architecture Diagram Complete ═══\n\n");
    return 0;
}
