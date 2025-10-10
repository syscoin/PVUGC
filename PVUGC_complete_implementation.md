# PVUGC Complete Implementation - All Code Changes

## Problem Statement
Two distinct Groth16 proofs for the same `(vk, x)` were yielding different KEM keys. Expert analysis identified we were missing the **gamma cross term** (5th bucket) that must be explicitly raised to ρ.

## All Code Changes Made

### 1. GSAttestation Structure Update
**File**: `src/gs_commitments.rs`

```rust
// BEFORE:
#[derive(Clone, Debug)]
pub struct GSAttestation {
    pub c1_commitments: Vec<Com1<Bls12_381>>,
    pub c2_commitments: Vec<Com2<Bls12_381>>,
    pub proof_data: Vec<u8>,
    pub randomness_used: Vec<Fr>,
    pub ppe_target: Fq12,
}

// AFTER:
#[derive(Clone, Debug)]
pub struct GSAttestation {
    pub c1_commitments: Vec<Com1<Bls12_381>>,
    pub c2_commitments: Vec<Com2<Bls12_381>>,
    pub pi: Vec<Com2<Bls12_381>>,      // Added: Equation proof π (in G2)
    pub theta: Vec<Com1<Bls12_381>>,   // Added: Equation proof θ (in G1)
    pub proof_data: Vec<u8>,
    pub randomness_used: Vec<Fr>,
    pub ppe_target: Fq12,
}
```

### 2. Extract Equation Proofs in commit_arkworks_proof
**File**: `src/gs_commitments.rs`

```rust
// In commit_arkworks_proof method:
let attestation_proof = ppe.commit_and_prove(&xvars, &yvars, &self.crs, &mut rng);

// Extract commitments and equation proofs
let c1_commitments = attestation_proof.xcoms.coms;
let c2_commitments = attestation_proof.ycoms.coms;
let pi = attestation_proof.equ_proofs[0].pi.clone();      // Added
let theta = attestation_proof.equ_proofs[0].theta.clone(); // Added

Ok(GSAttestation {
    c1_commitments,
    c2_commitments,
    pi,        // Added
    theta,     // Added
    proof_data,
    randomness_used: randomness,
    ppe_target,
})
```

### 3. Complete KEM Evaluation Implementation
**File**: `groth_sahai/src/kem_eval.rs`

```rust
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::AffineRepr;
use ark_ff::{PrimeField, Zero};

use crate::data_structures::{Com1, Com2, BT};
use crate::generator::CRS;
use crate::statement::PPE;

/// Simplified ppe_eval_bases - removes sign flipping logic
pub fn ppe_eval_bases<E: Pairing>(_ppe: &PPE<E>, crs: &CRS<E>) -> EvalBases<E> {
    // X-side: u_dual (dual to CRS.u, in G2)
    let x_g2_pairs: Vec<(E::G2Affine, E::G2Affine)> = crs.u_dual.iter()
        .map(|c| (c.0, c.1))
        .collect();
    
    // Y-side: v_dual (dual to CRS.v, in G1)
    let v_pairs: Vec<(E::G1Affine, E::G1Affine)> = crs.v_dual.iter()
        .map(|c| (c.0, c.1))
        .collect();
    
    // Invariants (debug only): pairing-compatibility holds for exported pairs
    #[cfg(debug_assertions)]
    {
        use ark_ff::One;
        for (j, u_pair) in crs.u.iter().enumerate() {
            let (g2a, g2b) = x_g2_pairs[j];
            let PairingOutput(p0) = E::pairing(u_pair.0, g2a);
            let PairingOutput(p1) = E::pairing(u_pair.1, g2b);
            debug_assert_eq!(p0 * p1, E::TargetField::one(), "u/x_g2 pair {} invariant failed", j);
        }
        for (k, v_pair) in crs.v.iter().enumerate() {
            let (g1a, g1b) = v_pairs[k];
            let PairingOutput(p0) = E::pairing(g1a, v_pair.0);
            let PairingOutput(p1) = E::pairing(g1b, v_pair.1);
            debug_assert_eq!(p0 * p1, E::TargetField::one(), "v/v_pairs pair {} invariant failed", k);
        }
    }

    EvalBases { x_g2_pairs, v_pairs }
}

/// Struct to hold all masked CRS bases
pub struct MaskedBases<E: Pairing> {
    pub u_dual_rho: Vec<(E::G2Affine, E::G2Affine)>, // G2 (dual of u) ^ ρ
    pub v_dual_rho: Vec<(E::G1Affine, E::G1Affine)>, // G1 (dual of v) ^ ρ
    pub u_rho: Vec<Com1<E>>,                          // G1 primaries ^ ρ (as Com1 for pairing_sum)
    pub v_rho: Vec<Com2<E>>,                          // G2 primaries ^ ρ (as Com2 for pairing_sum)
}

/// Mask ALL CRS pairs as the expert suggested
pub fn mask_all_crs_pairs<E: Pairing>(crs: &CRS<E>, rho: E::ScalarField) -> MaskedBases<E> {
    use ark_ec::CurveGroup;

    let u_dual_rho = crs.u_dual.iter().map(|p| (
        (p.0.into_group() * rho).into_affine(),
        (p.1.into_group() * rho).into_affine(),
    )).collect();

    let v_dual_rho = crs.v_dual.iter().map(|p| (
        (p.0.into_group() * rho).into_affine(),
        (p.1.into_group() * rho).into_affine(),
    )).collect();

    let u_rho: Vec<Com1<E>> = crs.u.iter().map(|p| Com1::<E>(
        (p.0.into_group() * rho).into_affine(),
        (p.1.into_group() * rho).into_affine(),
    )).collect();

    let v_rho: Vec<Com2<E>> = crs.v.iter().map(|p| Com2::<E>(
        (p.0.into_group() * rho).into_affine(),
        (p.1.into_group() * rho).into_affine(),
    )).collect();

    MaskedBases { u_dual_rho, v_dual_rho, u_rho, v_rho }
}

/// Evaluate the gamma cross term and raise it to rho
/// This is the missing piece for proof-agnostic determinism
fn eval_gamma_term_pow_rho<E: Pairing>(
    ppe: &PPE<E>,
    c1: &[Com1<E>], // X commitments (G1 pairs)
    c2: &[Com2<E>], // Y commitments (G2 pairs)
    rho: E::ScalarField,
) -> E::TargetField {
    use ark_ff::{One, Field};
    let mut g = E::TargetField::one();

    // γ has shape |X| × |Y|  (rows = X vars, cols = Y vars)
    #[cfg(debug_assertions)]
    eprintln!("Debug: gamma matrix dimensions: {}x{}", ppe.gamma.len(), 
              if ppe.gamma.is_empty() { 0 } else { ppe.gamma[0].len() });
    
    for j in 0..ppe.gamma.len() {
        for k in 0..ppe.gamma[j].len() {
            let coeff = ppe.gamma[j][k];
            if coeff.is_zero() { 
                #[cfg(debug_assertions)]
                eprintln!("  gamma[{}][{}] = 0, skipping", j, k);
                continue; 
            }

            #[cfg(debug_assertions)]
            eprintln!("  Processing gamma[{}][{}] = {:?}", j, k, coeff);

            // In the stock GS 2×2 encoding, the cross term multiplies the like slots:
            // e(C1[j].0, C2[k].0) * e(C1[j].1, C2[k].1), all raised to γ_{j,k}.
            let PairingOutput(p00) = E::pairing(c1[j].0, c2[k].0);
            let PairingOutput(p11) = E::pairing(c1[j].1, c2[k].1);
            let term = p00 * p11;

            #[cfg(debug_assertions)]
            eprintln!("    term before pow = {:?}", term);
            
            g *= term.pow(coeff.into_bigint());
        }
    }
    
    #[cfg(debug_assertions)]
    eprintln!("  gamma term before ^rho = {:?}", g);

    // We must also raise γ-term to ρ so the whole LHS becomes (unmasked LHS)^ρ.
    g.pow(rho.into_bigint())
}

/// Full GS evaluation with all FIVE pairing buckets (including gamma cross term)
/// This includes the missing gamma term that must be explicitly raised to ρ
pub fn ppe_eval_full_masked_with_gamma<E: Pairing>(
    ppe: &PPE<E>,

    // attestation payload
    c1: &[Com1<E>],         // commitments for X vars (len = |X|)
    c2: &[Com2<E>],         // commitments for Y vars (len = |Y|)
    pi: &[Com2<E>],         // equation proof π (len = |X|, in G2^2)
    theta: &[Com1<E>],      // equation proof θ (len = |Y|, in G1^2)

    // CRS + mask
    crs: &CRS<E>,
    rho: E::ScalarField,
) -> PairingOutput<E> {
    use ark_ff::{One, Field};
    
    // Sanity checks
    assert_eq!(ppe.gamma.len(), c1.len(), "gamma rows must match |X|");
    assert!(!ppe.gamma.is_empty(), "gamma must not be empty");
    assert_eq!(ppe.gamma[0].len(), c2.len(), "gamma cols must match |Y|");
    assert_eq!(pi.len(), c1.len(), "len(pi) must equal |X|");
    assert_eq!(theta.len(), c2.len(), "len(theta) must equal |Y|");
    assert_eq!(crs.u.len(), c1.len(), "CRS.u must match |X|");
    assert_eq!(crs.v.len(), c2.len(), "CRS.v must match |Y|");
    assert_eq!(crs.u_dual.len(), c1.len(), "CRS.u_dual must match |X|");
    assert_eq!(crs.v_dual.len(), c2.len(), "CRS.v_dual must match |Y|");

    // Mask everything that involves CRS by ρ
    let masks = mask_all_crs_pairs(crs, rho);

    // Bucket 1: ∏_j e(C1_j, U*_j^ρ)
    let mut acc = E::TargetField::one();
    for (j, c1j) in c1.iter().enumerate() {
        let PairingOutput(p0) = E::pairing(c1j.0, masks.u_dual_rho[j].0);
        let PairingOutput(p1) = E::pairing(c1j.1, masks.u_dual_rho[j].1);
        acc *= p0 * p1;
    }

    // Bucket 2: ∏_k e(V*_k^ρ, C2_k)
    for (k, c2k) in c2.iter().enumerate() {
        let PairingOutput(p0) = E::pairing(masks.v_dual_rho[k].0, c2k.0);
        let PairingOutput(p1) = E::pairing(masks.v_dual_rho[k].1, c2k.1);
        acc *= p0 * p1;
    }

    // Bucket 3 & 4: Use ComT::pairing_sum and extract [1][1] as in original verifier
    use crate::data_structures::ComT;
    
    // Bucket 3: e(U^ρ, π)
    let com_pi = ComT::<E>::pairing_sum(&masks.u_rho, pi);
    let pi_matrix = com_pi.as_matrix();
    let PairingOutput(pi_val) = pi_matrix[1][1]; // Target lives in [1][1]
    acc *= pi_val;
    
    // Bucket 4: e(θ, V^ρ)  
    let com_theta = ComT::<E>::pairing_sum(theta, &masks.v_rho);
    let theta_matrix = com_theta.as_matrix();
    let PairingOutput(theta_val) = theta_matrix[1][1]; // Target lives in [1][1]
    acc *= theta_val;

    // Missing piece in your patch: the γ cross term, *also* to the power ρ.
    let g_rho = eval_gamma_term_pow_rho::<E>(ppe, c1, c2, rho);
    
    #[cfg(debug_assertions)]
    {
        eprintln!("Debug: gamma cross term^rho = {:?}", g_rho);
        eprintln!("Debug: acc before gamma = {:?}", acc);
    }
    
    acc *= g_rho;
    
    #[cfg(debug_assertions)]
    {
        eprintln!("Debug: final acc after gamma = {:?}", acc);
    }

    PairingOutput(acc)
}

/// Helper function to raise GT element to power
pub fn pow_gt<E: Pairing>(gt: E::TargetField, rho: E::ScalarField) -> E::TargetField {
    use ark_ff::Field;
    gt.pow(rho.into_bigint())
}
```

### 4. Library Exports Update
**File**: `groth_sahai/src/lib.rs`

```rust
pub use crate::kem_eval::{
    ppe_instance_bases,
    ppe_eval_bases,
    ppe_eval_with_masked_pairs,
    ppe_eval_full_masked_with_gamma,  // Added
    mask_all_crs_pairs,                // Added
    InstanceBases,
    EvalBases,
    MaskedBases,                       // Added
};
```

### 5. Test Implementation Update
**File**: `tests/test_pvugc.rs`

```rust
#[test]
fn test_two_distinct_groth16_proofs_same_output() {
    // ... setup code ...

    // Add import
    use ark_bls12_381::{Bls12_381, Fr, G1Affine, G2Affine, Fq12};

    // Create the same PPE structure used in commit_arkworks_proof
    // This is a 2x2 diagonal PPE for Groth16
    use groth_sahai::{ppe_eval_full_masked_with_gamma};
    use ark_ff::{One, Zero};
    
    let ppe = PPE::<Bls12_381> {
        a_consts: vec![G1Affine::zero(), G1Affine::zero()],
        b_consts: vec![G2Affine::zero(), G2Affine::zero()],
        gamma: vec![
            vec![Fr::one(), Fr::zero()],   // [1, 0]
            vec![Fr::zero(), Fr::one()]    // [0, 1] - diagonal matrix
        ],
        target: PairingOutput(att1.ppe_target),  // Wrap in PairingOutput
    };
    
    // Use FULL evaluation with all 5 pairing buckets (including gamma term)
    let PairingOutput(m1_full) = ppe_eval_full_masked_with_gamma::<Bls12_381>(
        &ppe,
        &att1.c1_commitments,
        &att1.c2_commitments,
        &att1.pi,
        &att1.theta,
        gs.get_crs(),
        rho,
    );
    
    let PairingOutput(m2_full) = ppe_eval_full_masked_with_gamma::<Bls12_381>(
        &ppe,
        &att2.c1_commitments,
        &att2.c2_commitments,
        &att2.pi,
        &att2.theta,
        gs.get_crs(),
        rho,
    );

    // Both should equal target^rho
    let expected_masked = pow_gt::<Bls12_381>(att1.ppe_target, rho);
    
    // Verify proof-agnostic property
    assert_eq!(att1.ppe_target, att2.ppe_target, "PPE targets must be identical for same (vk,x)");
    assert_eq!(m1_full, m2_full, "Two distinct proofs for same (vk,x) must yield identical M with full evaluation");
    assert_eq!(m1_full, expected_masked, "m1_full should be target^rho");
    assert_eq!(m2_full, expected_masked, "m2_full should be target^rho");
}
```

### 6. Update fake_attestation in Test
**File**: `tests/test_pvugc.rs`

```rust
// In test_negative_invalid_attestation_cannot_decrypt:
let fake_attestation = GSAttestation {
    c1_commitments: vec![/* ... */],
    c2_commitments: vec![/* ... */],
    pi: vec![],        // Added empty pi
    theta: vec![],     // Added empty theta
    proof_data: vec![],
    randomness_used: vec![],
    ppe_target: Fq12::one(),
};
```

## 5-Bucket Evaluation Formula

The complete evaluation now includes:

```
M = (∏_j e(C1_j, U*_j^ρ))           // Bucket 1: X-commitments × masked duals
  × (∏_k e(V*_k^ρ, C2_k))           // Bucket 2: masked duals × Y-commitments  
  × e(U^ρ, π)[1][1]                 // Bucket 3: masked primaries × eq-proof
  × e(θ, V^ρ)[1][1]                 // Bucket 4: eq-proof × masked primaries
  × (∏_{j,k} e(C1_j,C2_k)^γ_{j,k})^ρ // Bucket 5: gamma cross term raised to ρ
```

## Current Status

**STILL FAILING**: Despite implementing all 5 buckets exactly as specified:
- Two different proofs for same `(vk, x)` produce different `M` values
- Neither equals `target^ρ`

## Debug Output Shows

```
Target: [same for both attestations] ✓
Expected (target^ρ): [correctly computed] ✓
Gamma term: [different for each proof - expected] ✓
Gamma term^ρ: [different for each proof] ✓
Final m1_full: [different value] ✗
Final m2_full: [different value] ✗
m1_full ≠ m2_full ✗
```

## Potential Issues

1. **PPE Structure**: The PPE created in the test might not exactly match the one used in `commit_arkworks_proof`
2. **Equation Proof Extraction**: The way we extract pi and theta from the attestation proof might be incorrect
3. **ComT Handling**: Using [1][1] component extraction might not be the right approach for our specific PPE
4. **Fundamental Issue**: There might be a deeper issue with how GS randomness is being used in the commitment generation

## Expert's Diagnosis Was Correct But...

The expert correctly identified the missing gamma term, but even with it implemented, determinism isn't achieved. This suggests either:
- The implementation details of the gamma term computation need adjustment for our specific commitment structure
- There's an additional issue beyond the missing gamma term
- The underlying GS commitment/proof generation has issues that prevent the verification equation from holding properly
