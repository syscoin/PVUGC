# PVUGC Protocol: Proof-Agnostic Verifiable Unique Group Commitments

## Overview

PVUGC is a cryptographic protocol that enables Key Encapsulation Mechanism (KEM) extraction from Groth-Sahai attestations in a **proof-agnostic** manner. The system allows a DECAPPER to extract a shared secret `K = target^ρ` from any valid proof, without learning the secret masking scalar `ρ`.

**Key Properties:**
- **Proof-Agnostic**: Different proofs for the same statement yield the same key
- **Offline ARMER**: Setup party computes `ρ`-powered bases once, then goes offline
- **Online DECAPPER**: Extracts keys without knowing `ρ` (GT-XPDH security)
- **Randomized Commitments**: Full witness-indistinguishability via GS proof system

## Three-Role Architecture

### 1. ARMER (Offline, One-Time)
- Generates secret scalar `ρ`
- Publishes "armed bases" = `bases^ρ` (ρ-powered CRS bases)
- Goes offline permanently
- **Critical**: `ρ` never leaves the ARMER

### 2. PROVER (Runtime, Repeatable)
- Generates proof `π` (Groth16, R1CS, or other)
- Creates Groth-Sahai attestation with commitments + auxiliary elements
- Does NOT know `ρ`
- Can generate multiple proofs for same or different statements

### 3. DECAPPER (Runtime, Repeatable)  
- Receives attestation from PROVER
- Extracts shared secret `K = target^ρ` using armed bases
- Does NOT know `ρ` (security via GT-XPDH assumption)
- Proof-agnostic: same `K` from all proofs of same statement

## Protocol Phases

The PVUGC construction consists of **6 phases** for general PPE verification, with an optional **Phase 7** for Groth16 integration.

---

## Phase 1: Per-Slot CRS with Binding Structure

**Goal**: Generate a CRS where each commitment slot has independent randomization, with a linear binding structure enabling randomness cancellation.

### CRS Structure

Each slot `i` (for X-commitments) and `j` (for Y-commitments) has **two rows**:
- **Rand row**: `(p, q)` where `q = a·p` (global binding)
- **Var row**: `(u_{i,0}, u_{i,1})` where `u_{i,1} = a·u_{i,0}` (per-slot binding)

```rust
// CRS Generation (per-slot)
pub struct CRS<E: Pairing> {
    pub u: Vec<Com1<E>>,      // 2m rows: rand₀, var₀, rand₁, var₁, ...
    pub v: Vec<Com2<E>>,      // 2n rows: rand₀, var₀, rand₁, var₁, ...
    pub a1: E::ScalarField,   // Public binding tag for G1
    pub a2: E::ScalarField,   // Public binding tag for G2
}

// Binding structure enforced:
// u_{i,1} = a1 * u_{i,0}  for all i
// v_{j,1} = a2 * v_{j,0}  for all j
```

**Implementation**: `groth-sahai/src/generator.rs::generate_crs_per_slot()`

---

## Phase 2: Rank Decomposition for Γ Matrix

**Goal**: Decompose the coefficient matrix `Γ` into a sum of rank-1 matrices to construct statement-only verifier bases.

### Rank Decomposition

Given `Γ` (m×n matrix), decompose as:
```
Γ = Σ_{a=1}^r u^(a) · (v^(a))^T
```

Where `r = rank(Γ)` and `u^(a) ∈ ℝ^m`, `v^(a) ∈ ℝ^n`.

### Statement-Only Bases

For PPE: `Σ_{i,j} Γ_{i,j} · e(X_i, Y_j) = target`

Construct bases that depend only on public values (not witness):
- `U` bases: For pairing with X-commitments `C¹`
- `V` bases: For pairing with Y-commitments `C²`
- `W` bases: For pairing with θ proof elements (rank block)
- `Z` bases: For pairing with π proof elements (linear block)

```rust
pub struct RankDecompPpeBases<E: Pairing> {
    pub U: Vec<E::G2Affine>,  // m bases for C¹
    pub V: Vec<E::G1Affine>,  // n bases for C²  
    pub W: Vec<E::G2Affine>,  // r bases for θ (rank block)
    pub Z: Vec<E::G1Affine>,  // n bases for π (linear block)
}
```

**Implementation**: `groth-sahai/src/rank_decomp.rs`, `groth-sahai/src/base_construction.rs::RankDecompPpeBases`

---

## Phase 3: Four-Bucket Verifier

**Goal**: Implement a verifier that extracts `M = Σ Γ_{i,j} · e(X_i, Y_j)` using four pairing buckets, with all randomness terms cancelling.

### Four-Bucket Formula

```
M = B1 + B2 + B3 + B4
```

Where:
- **B1**: `Σ e(C¹[i], U[i])` - X-commitments × U bases
- **B2**: `Σ e(V[i], C²[i])` - V bases × Y-commitments
- **B3**: `Σ e(θ[a], W[a])` - Rank block for Γ structure
- **B4**: `Σ e(Z[j], π[j])` - Linear block for constant terms

**Key Property**: Randomness from commitments `C¹, C²` cancels via complementarity of bases, leaving only `M = Σ Γ_{i,j} · e(X_i, Y_j)`.

**Implementation**: `groth-sahai/src/verifier.rs::verify_rank_decomp()`

---

## Phase 4: PVUGC Arming

**Goal**: Enable ARMER to publish ρ-powered bases that allow DECAPPER to extract `target^ρ` without knowing `ρ`.

### Arming Function

```rust
pub fn pvugc_arm<E: Pairing>(
    bases: &RankDecompPpeBases<E>,
    rho: &E::ScalarField,
) -> ArmedBases<E> {
    ArmedBases {
        D1: bases.U.iter().map(|u| (u^ρ)).collect(),  // U^ρ
        D2: bases.V.iter().map(|v| (v^ρ)).collect(),  // V^ρ
        DP: bases.W.iter().map(|w| (w^ρ)).collect(),  // W^ρ
        DQ: bases.Z.iter().map(|z| (z^ρ)).collect(),  // Z^ρ
    }
}
```

**One-Time Setup**: ARMER publishes armed bases, then goes offline with `ρ` secret.


**Code**: `groth-sahai/src/pvugc.rs::pvugc_arm()`

---

## Phase 5: PVUGC Decapping

**Goal**: Extract `K = target^ρ` from a proof using armed bases, without knowing `ρ`.

### Decapping Function

```rust
pub fn pvugc_decap<E: Pairing>(
    attestation: &CProof<E>,
    armed_bases: &ArmedBases<E>,
) -> PairingOutput<E> {
    // Four-bucket extraction with ρ-powered bases
    let M_rho = 
        Σ e(C¹[i], U^ρ[i]) +     // B1 with armed bases
        Σ e(V^ρ[i], C²[i]) +     // B2 with armed bases  
        Σ e(θ[a], W^ρ[a]) +      // B3 with armed bases
        Σ e(Z^ρ[j], π[j])        // B4 with armed bases
    
    M_rho  // = M^ρ = target^ρ = K
}
```

**Proof-Agnostic Property**: Any valid proof for the same PPE yields the same `K`.


**Code**: `groth-sahai/src/pvugc.rs::pvugc_decap()`

---

## Phase 6: Soundness Validation

**Goal**: Verify that the construction is algebraically sound and matches theoretical expectations.

### Test Coverage

1. **ρ-Lift Identity**: Confirms armed bases satisfy `e(C¹, U^ρ) = e(C¹, U)^ρ`
2. **Proof-Agnostic Extraction**: Multiple proofs yield same key
3. **Target Matching**: Extracted key equals `target^ρ`
4. **Full-Rank Γ**: Works for arbitrary coefficient matrices
5. **Diagonal Γ**: Optimized path for identity-like structures


**Code**: `groth-sahai/src/pvugc.rs::tests`

---

## Phase 7: Groth16 Integration (Optional)

**Goal**: Compile Groth16 verification equation into the PVUGC PPE framework using a 4-term auxiliary recomposition technique.

### Groth16 as PPE

Groth16 verification:
```
e(A,B) · e(C,δ⁻¹) · e(L(x),γ⁻¹) = e(α,β)
```

Compiled to 3×3 PPE:
- **X slots**: `[A, C, L(x)]` (G1)
- **Y slots**: `[B, δ⁻¹, γ⁻¹]` (G2)
- **Γ**: Identity matrix
- **Target**: `e(α,β)`

### 4-Term Auxiliary Recomposition

Instead of rank-decomposition bases, use **aux legs** supplied by prover:
- `aux_x[i] = r_i · u_{i,0}` (randomizer on G1)
- `aux_y[j] = s_j · v_{j,0}` (randomizer on G2)

**Extraction Formula** (per Γ-pair):
```
e(X_i, Y_j) = 
    e(c1.1, c2.1) ·                    // Main term
    e(c1.1, -a2·aux_y[j]) ·            // Cancel Y randomness
    e(-a1·aux_x[i], c2.1) ·            // Cancel X randomness
    e(-a1·aux_x[i], -a2·aux_y[j])      // Cross-term cancellation
```

Where:
- `c1 = (r·u₀, r·u₁ + X)` - X-commitment
- `c2 = (s·v₀, s·v₁ + Y)` - Y-commitment
- `a1·aux_x = r·u₁` (randomizer on var row)
- `a2·aux_y = s·v₁` (randomizer on var row)

**Key Insight**: All randomness cancels algebraically, leaving pure `e(X,Y)`.

**Commitment Requirements**:
- Use VAR row for both limbs (not RAND row)
- Explicit randomizers: `r[i] = 0` for constants, `r[i] = random` for witnesses
- Same for Y-commitments with `s[j]`

### Full-GS Prover

```rust
pub fn commit_and_prove_full_gs(
    xvars: &[E::G1Affine],
    yvars: &[E::G2Affine],
    r: &[E::ScalarField],  // Explicit randomizers
    s: &[E::ScalarField],  // Explicit randomizers
    crs: &CRS<E>,
) -> CProof<E> {
    // Commit using VAR rows
    let xcoms = commit_g1_full_gs(xvars, crs, r);
    let ycoms = commit_g2_full_gs(yvars, crs, s);
    
    // Compute aux legs
    let aux_x = r.iter().enumerate()
        .map(|(i, r_i)| crs.u_for_slot(i).1.0 * r_i)
        .collect();
    let aux_y = s.iter().enumerate()
        .map(|(j, s_j)| crs.v_for_slot(j).1.0 * s_j)
        .collect();
    
    CProof { xcoms, ycoms, equ_proofs: vec![EquProof {
        theta: vec![],  // Not used in full-GS
        pi: vec![],     // Not used in full-GS  
        aux_x,
        aux_y,
        ...
    }]}
}
```

### Full-GS Verifier

```rust
pub fn verify_full_gs(
    proof: &CProof<E>,
    crs: &CRS<E>,
) -> (bool, PairingOutput<E>) {
    let mut M = PairingOutput::zero();
    
    for i in 0..m {
        for j in 0..n {
            if gamma[i][j].is_zero() { continue; }
            
            let c1 = &proof.xcoms.coms[i];
            let c2 = &proof.ycoms.coms[j];
            let aux_x = proof.equ_proofs[0].aux_x[i];
            let aux_y = proof.equ_proofs[0].aux_y[j];
            
            // 4-term recomposition
            let a1_aux_x = aux_x * crs.a1;
            let a2_aux_y = aux_y * crs.a2;
            
            let r1 = e(c1.1, c2.1);
            let r2 = e(c1.1, -a2_aux_y);
            let r3 = e(-a1_aux_x, c2.1);
            let r4 = e(-a1_aux_x, -a2_aux_y);
            
            M += (r1 + r2 + r3 + r4) * gamma[i][j];
        }
    }
    
    (M == target, M)  // Return (verifies, extracted_value)
}
```

**PVUGC Extraction**: DECAPPER computes `K = M^ρ` where `M` comes from verifier.


**Code**: 
- `groth-sahai/src/prover/commit.rs::commit_g1_full_gs()`, `commit_g2_full_gs()`
- `groth-sahai/src/prover/prove.rs::commit_and_prove_full_gs()`
- `groth-sahai/src/verifier.rs::verify_full_gs()`
- `groth-sahai/src/pvugc.rs::test_pvugc_3x3_identity_with_real_groth16()`

---

## Security Assumptions

### GT-XPDH (External Pairing Diffie-Hellman in GT)

**Assumption**: Given `g₁ ∈ G₁`, `g₂ ∈ G₂`, `e(g₁,g₂)^ρ ∈ G_T`, and `e(g₁,g₂) ∈ G_T`, it is hard to compute `ρ ∈ F_r`.

**Consequence**: DECAPPER can extract `K = target^ρ` but cannot learn `ρ`.

### Soundness Requirements

1. **Binding CRS**: `u_{i,1} = a1·u_{i,0}` enforced per slot
2. **Valid Attestation**: GS proof must verify before extraction
3. **Correct Γ**: Coefficient matrix must match PPE structure
4. **Honest ARMER**: `ρ` generated uniformly at random

### Witness Indistinguishability

**Randomized Commitments**: Each commitment uses independent randomness `r_i`, `s_j`.

**Zero-Knowledge Property**: DECAPPER learns `K = target^ρ` but:
- Cannot learn witness values `X_i`, `Y_j`
- Cannot distinguish between different witnesses satisfying the same PPE
- Randomizers `r_i`, `s_j` hide witness structure

**Non-Randomized Alternative**: For debugging/testing only (see `NONRANDOMIZED_COMMITMENTS_SECURITY.md`)

---

## API Usage Examples

### Example 1: Rank-Decomposition PVUGC (General PPE)

```rust
use groth_sahai::generator::CRS;
use groth_sahai::statement::PPE;
use groth_sahai::rank_decomp::RankDecomp;
use groth_sahai::base_construction::RankDecompPpeBases;
use groth_sahai::pvugc::{pvugc_arm, pvugc_decap};

// ARMER: One-time setup
let mut rng = test_rng();
let crs = CRS::<Bls12_381>::generate_crs_per_slot(&mut rng, m, n);

// Define PPE: Σ Γ_{i,j} · e(X_i, Y_j) = target
let ppe = PPE { gamma, a_consts, b_consts, target };

// Decompose Γ and build bases
let decomp = RankDecomp::decompose(&ppe.gamma);
let bases = RankDecompPpeBases::build(&crs, &ppe, &decomp);

// Arm with secret ρ
let rho = Fr::rand(&mut rng);
let armed_bases = pvugc_arm(&bases, &rho);

// Publish: (crs, armed_bases, target)
// Secret: rho (stays with ARMER)

// PROVER: Generate attestation
let proof = ppe.commit_and_prove_rank_decomp(&x_vars, &y_vars, &crs, &mut rng);

// DECAPPER: Extract key
let k = pvugc_decap(&proof, &armed_bases);
assert_eq!(k, target * rho);  // K = target^ρ
```

### Example 2: Full-GS PVUGC (Groth16)

```rust
use groth_sahai::generator::CRS;
use groth_sahai::statement::PPE;

// ARMER: One-time setup
let crs = CRS::<Bls12_381>::generate_crs_per_slot(&mut rng, 3, 3);

// Groth16 → PPE compilation
let ppe = PPE {
    gamma: identity_3x3(),  // Γ = I for Groth16
    a_consts: vec![zero; 3],
    b_consts: vec![zero; 3],
    target: pairing(alpha, beta),  // e(α,β)
};

// PROVER: Generate attestation with aux legs
let x_vars = vec![A, C, L_x];  // Groth16 proof elements
let y_vars = vec![B, delta_inv, gamma_inv];
let r = vec![random, random, zero];  // Randomize A,C; L(x) constant
let s = vec![random, zero, zero];    // Randomize B; δ⁻¹,γ⁻¹ constant

let proof = ppe.commit_and_prove_full_gs(&x_vars, &y_vars, &r, &s, &crs, &mut rng);

// DECAPPER: Verify and extract
let (verifies, M) = ppe.verify_full_gs(&proof, &crs, &bases);
assert!(verifies);
assert_eq!(M, target);  // M = e(α,β)

// Extract key (with ρ from armed setup)
let k = M * rho;  // K = e(α,β)^ρ
```

---

## File Organization

### Core Protocol Implementation

- `groth-sahai/src/generator.rs` - Phase 1: Per-slot CRS generation
- `groth-sahai/src/rank_decomp.rs` - Phase 2: Γ decomposition
- `groth-sahai/src/base_construction.rs` - Phases 2-3: Verifier bases
- `groth-sahai/src/verifier.rs` - Phase 3: Four-bucket verifier
- `groth-sahai/src/pvugc.rs` - Phases 4-6: Arming, decapping, tests
- `groth-sahai/src/prover/commit.rs` - Phase 7: Full-GS commitments
- `groth-sahai/src/prover/prove.rs` - Prover implementations

### Documentation

- `PVUGC_PROTOCOL.md` - This document (complete protocol)
- `PHASE1_PER_SLOT_CRS.md` - Per-slot CRS design
- `PHASE2_COMPLETE.md` - Rank decomposition
- `PHASE3_COMPLETE.md` - Four-bucket verifier
- `PHASE4_STATUS.md` - PVUGC arming
- `PHASE5_SUCCESS.md` - PVUGC decapping
- `PHASE6_COMPLETE.md` - Soundness validation
- `NONRANDOMIZED_COMMITMENTS_SECURITY.md` - Security considerations

### Tests

- `groth-sahai/src/pvugc.rs::tests` - Complete PVUGC test suite
- `groth-sahai/src/generator.rs::tests` - CRS validation
- `groth-sahai/src/base_construction.rs::tests` - Base construction

---

## Current Status

### Production-Ready (Phases 1-6)
- Per-slot CRS with binding structure
- Rank-decomposition PPE verifier
- PVUGC arming and decapping
- Randomized commitments
- Full test coverage (125 passing tests)

### Experimental (Phase 7)
- Groth16 integration with 4-term aux recomposition
- Full-GS prover and verifier
- Working test with real Groth16 proofs
- Requires further integration for production use

### Not Yet Implemented
- KEM wrapper API for Phase 7 (full-GS path)
- Threshold secret sharing for `ρ`
- Multi-party ARMER protocols

---

## Contributing

This is an academic research codebase. When contributing:

1. Maintain algebraic correctness - verify all formulas
2. Add tests for new features
3. Document security assumptions
4. Follow existing code structure
5. No emojis or informal comments (academic style)

## References

- Groth, J., & Sahai, A. (2008). Efficient Non-interactive Proof Systems for Bilinear Groups
- Development history in `PHASE*_*.md` files

