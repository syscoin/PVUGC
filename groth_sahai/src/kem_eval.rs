//! KEM evaluation functions for PVUGC
//! Extracts the deterministic GT value from GS verification for proof-agnostic KEM

use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;

use crate::data_structures::{Com1, Com2};
use crate::generator::CRS;
use crate::statement::PPE;

/// Evaluate the KEM product using masked dual bases
/// Simplified version that works with u_dual + v_dual (proof-agnostic)
pub fn ppe_eval_with_masked_pairs<E: Pairing>(
    c1_proof_order: &[Com1<E>],
    c2_proof_order: &[Com2<E>],
    u_pairs_masked_var: &[(E::G2Affine, E::G2Affine)],  // u_dual^ρ
    v_pairs_masked_var: &[(E::G1Affine, E::G1Affine)],  // v_dual^ρ  
) -> PairingOutput<E> {
    use ark_ff::One;
    let mut result = E::TargetField::one();
    
    // X side: ∏_j e(C1_j, u_dual^ρ_j)
    for (j, c1) in c1_proof_order.iter().enumerate() {
        let u = u_pairs_masked_var[j];
        let PairingOutput(p0) = E::pairing(c1.0, u.0);
        let PairingOutput(p1) = E::pairing(c1.1, u.1);
        result *= p0 * p1;
    }
    
    // Y side: ∏_i e(v_dual^ρ_i, C2_i)
    for (i, c2) in c2_proof_order.iter().enumerate() {
        let v = v_pairs_masked_var[i];
        let PairingOutput(p0) = E::pairing(v.0, c2.0);
        let PairingOutput(p1) = E::pairing(v.1, c2.1);
        result *= p0 * p1;
    }
    
    PairingOutput(result)
}

/// Export evaluation bases for KEM (X side: u_dual in G2, Y side: v_dual in G1)
/// Uses dual bases which produce proof-agnostic values (proven by find_correct_base_formula test)
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


/// Export instance bases for KEM (Y side: v_dual in G1)
pub fn ppe_instance_bases<E: Pairing>(_ppe: &PPE<E>, crs: &CRS<E>) -> InstanceBases<E> {
    // Y-side: v_dual (dual to CRS.v, in G1)
    let v_pairs: Vec<(E::G1Affine, E::G1Affine)> = crs.v_dual.iter()
        .map(|c| (c.0, c.1))
        .collect();
    
    #[cfg(debug_assertions)]
    {
        use ark_ff::One;
        for (k, v_pair) in crs.v.iter().enumerate() {
            let (g1a, g1b) = v_pairs[k];
            let PairingOutput(p0) = E::pairing(g1a, v_pair.0);
            let PairingOutput(p1) = E::pairing(g1b, v_pair.1);
            debug_assert_eq!(p0 * p1, E::TargetField::one(), "v/v_pairs pair {} invariant failed", k);
        }
    }

    InstanceBases { v_pairs }
}

/// Bases for KEM evaluation (X side)
pub struct EvalBases<E: Pairing> {
    pub x_g2_pairs: Vec<(E::G2Affine, E::G2Affine)>,
    pub v_pairs: Vec<(E::G1Affine, E::G1Affine)>,
}

/// Bases for KEM instance (Y side)
pub struct InstanceBases<E: Pairing> {
    pub v_pairs: Vec<(E::G1Affine, E::G1Affine)>,
}

/// Mask a G1 pair with a scalar (for V pairs)
pub fn mask_g1_pair<E: Pairing>(
    pair: (E::G1Affine, E::G1Affine),
    rho: E::ScalarField,
) -> (E::G1Affine, E::G1Affine) {
    use ark_ec::CurveGroup;
    (
        (pair.0.into_group() * rho).into_affine(),
        (pair.1.into_group() * rho).into_affine(),
    )
}

/// Mask a G2 pair with a scalar (for U pairs)
pub fn mask_g2_pair<E: Pairing>(
    pair: (E::G2Affine, E::G2Affine),
    rho: E::ScalarField,
) -> (E::G2Affine, E::G2Affine) {
    use ark_ec::CurveGroup;
    (
        (pair.0.into_group() * rho).into_affine(),
        (pair.1.into_group() * rho).into_affine(),
    )
}

/// Compute GT^rho for testing
pub fn pow_gt<E: Pairing>(gt: E::TargetField, rho: E::ScalarField) -> E::TargetField {
    use ark_ff::Field;
    gt.pow(rho.into_bigint())
}
