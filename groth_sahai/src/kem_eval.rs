//! KEM evaluation functions for PVUGC
//! Extracts the deterministic GT value from GS verification for proof-agnostic KEM

use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::AffineRepr;
use ark_ff::{PrimeField, Zero};

use crate::data_structures::{Com1, Com2, BT};
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

/// Evaluate the gamma cross term and raise it to rho
/// This is the missing piece for proof-agnostic determinism
/// Correct γ-term: match verifier's structure exactly, then ^ρ
fn gamma_term_pow_rho<E: Pairing>(
    ppe: &PPE<E>,
    x_coms: &[Com1<E>],  // X commitments (G1^2)
    y_coms: &[Com2<E>],  // Y commitments (G2^2)
    rho: E::ScalarField,
) -> E::TargetField {
    use crate::data_structures::{vec_to_col_vec, col_vec_to_vec, Matrix, ComT, Mat};
    use ark_ff::Field;
    
    #[cfg(debug_assertions)]
    {
        eprintln!("Debug: Computing gamma cross term (verifier style)...");
        eprintln!("  |X| = {}, |Y| = {}", x_coms.len(), y_coms.len());
        eprintln!("  gamma shape = {}x{}", ppe.gamma.len(), 
                  if ppe.gamma.is_empty() { 0 } else { ppe.gamma[0].len() });
    }
    
    // 1) Same as verifier: (gamma * y_coms)
    let is_parallel = false; // Single-threaded for clarity
    let stmt_com_y: Matrix<Com2<E>> = 
        vec_to_col_vec(y_coms).left_mul(&ppe.gamma, is_parallel);
    
    #[cfg(debug_assertions)]
    eprintln!("  stmt_com_y dimensions: rows={}, cols={}", 
              stmt_com_y.len(), 
              if stmt_com_y.is_empty() { 0 } else { stmt_com_y[0].len() });
    
    // 2) Pair X against (gamma * Y)
    let com_x_stmt_com_y: ComT<E> = 
        ComT::<E>::pairing_sum(x_coms, &col_vec_to_vec(&stmt_com_y));
    
    #[cfg(debug_assertions)]
    {
        let matrix = com_x_stmt_com_y.as_matrix();
        eprintln!("  ComT matrix:");
        eprintln!("    [0][0] = {:?}", matrix[0][0]);
        eprintln!("    [0][1] = {:?}", matrix[0][1]);
        eprintln!("    [1][0] = {:?}", matrix[1][0]);
        eprintln!("    [1][1] = {:?}", matrix[1][1]);
    }
    
    // 3) Extract the (1,1) slot (where the PPE target "lives")
    let PairingOutput(term_11) = com_x_stmt_com_y.as_matrix()[1][1];
    
    #[cfg(debug_assertions)]
    eprintln!("  gamma term before ^ρ (slot [1][1]) = {:?}", term_11);
    
    // 4) Raise the γ-term to ρ (so the whole LHS scales by ρ)
    let result = term_11.pow(rho.into_bigint());
    
    #[cfg(debug_assertions)]
    eprintln!("  gamma term after ^ρ = {:?}", result);
    
    result
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

    // Bucket 3 & 4: Use diagonal product of ComT (not just [1][1])
    use crate::data_structures::ComT;
    
    // Helper to compute diagonal product of ComT
    let diag_product = |t: &ComT<E>| -> E::TargetField {
        let m = t.as_matrix();
        let PairingOutput(a00) = m[0][0];
        let PairingOutput(a11) = m[1][1];
        #[cfg(debug_assertions)]
        {
            eprintln!("  ComT diagonal: [0][0]={:?}", a00);
            eprintln!("                 [1][1]={:?}", a11);
            eprintln!("  diagonal product={:?}", a00 * a11);
        }
        a00 * a11
    };
    
    // Bucket 3: e(U^ρ, π) - use diagonal product
    #[cfg(debug_assertions)]
    eprintln!("Debug: Bucket 3 (pi):");
    let com_pi = ComT::<E>::pairing_sum(&masks.u_rho, pi);
    let pi_diag = diag_product(&com_pi);
    #[cfg(debug_assertions)]
    eprintln!("  acc before pi: {:?}", acc);
    acc *= pi_diag;
    #[cfg(debug_assertions)]
    eprintln!("  acc after pi: {:?}", acc);
    
    // Bucket 4: e(θ, V^ρ) - use diagonal product
    #[cfg(debug_assertions)]
    eprintln!("Debug: Bucket 4 (theta):");
    let com_theta = ComT::<E>::pairing_sum(theta, &masks.v_rho);
    let theta_diag = diag_product(&com_theta);
    #[cfg(debug_assertions)]
    eprintln!("  acc before theta: {:?}", acc);
    acc *= theta_diag;
    #[cfg(debug_assertions)]
    eprintln!("  acc after theta: {:?}", acc);

    // Missing piece in your patch: the γ cross term, *also* to the power ρ.
    let g_rho = gamma_term_pow_rho::<E>(ppe, c1, c2, rho);
    
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
