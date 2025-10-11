//! Canonical masked evaluator for proof-agnostic KEM extraction
//! 
//! This module provides the canonical masked verifier evaluator that applies ρ
//! to CRS constants/primaries (not commitments) and post-exponentiates the γ ComT.

use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField};

use crate::data_structures::{Com1, Com2, ComT, vec_to_col_vec, col_vec_to_vec, BT, B1, B2, Mat};
use crate::generator::CRS;
use crate::statement::PPE;

/// Scale a vector of Com1/Com2 (CRS-side) by rho (used only for CRS constants and primaries).
fn scale_com1<E: Pairing>(v: &[Com1<E>], rho: E::ScalarField) -> Vec<Com1<E>> {
    v.iter().map(|c| {
        Com1::<E>(
            (c.0.into_group() * rho).into_affine(),
            (c.1.into_group() * rho).into_affine(),
        )
    }).collect()
}

fn scale_com2<E: Pairing>(v: &[Com2<E>], rho: E::ScalarField) -> Vec<Com2<E>> {
    v.iter().map(|d| {
        Com2::<E>(
            (d.0.into_group() * rho).into_affine(),
            (d.1.into_group() * rho).into_affine(),
        )
    }).collect()
}

/// Raise every GT cell of a ComT to rho (post-exponentiation).
fn comt_pow_cells<E: Pairing>(m: &ComT<E>, rho: E::ScalarField) -> [[E::TargetField; 2]; 2] {
    let mm = m.as_matrix();
    [
        [ mm[0][0].0.pow(rho.into_bigint()), mm[0][1].0.pow(rho.into_bigint()) ],
        [ mm[1][0].0.pow(rho.into_bigint()), mm[1][1].0.pow(rho.into_bigint()) ],
    ]
}

/// Canonical masked verifier evaluator (proof-agnostic under fixed (vk,x)).
/// 
/// IMPORTANT:
/// - We DO NOT scale commitments X/Y by rho.
/// - We DO scale CRS constants a,b and primaries U,V by rho.
/// - We post-exponentiate the γ cross ComT to rho.
/// - Optionally, you can add dual-helper buckets by pairing with U*^rho, V*^rho (not needed for equality).
pub fn masked_verifier_matrix_canonical<E: Pairing>(
    ppe: &PPE<E>,
    crs: &CRS<E>,
    xcoms: &[Com1<E>],
    ycoms: &[Com2<E>],
    pi: &[Com2<E>],
    theta: &[Com1<E>],
    rho: E::ScalarField,
) -> [[E::TargetField; 2]; 2] {
    // 1) Linear legs with rho on CRS constants, NOT on commitments
    // PPE should now be 2-variable to match GS CRS size
    let i1_a      = Com1::<E>::batch_linear_map(&ppe.a_consts);
    let i2_b      = Com2::<E>::batch_linear_map(&ppe.b_consts);
    let i1_a_rho  = scale_com1::<E>(&i1_a, rho);
    let i2_b_rho  = scale_com2::<E>(&i2_b, rho);

    let a_y_rho   = ComT::<E>::pairing_sum(&i1_a_rho, ycoms);     // e(a^ρ, Y)
    let x_b_rho   = ComT::<E>::pairing_sum(xcoms, &i2_b_rho);     // e(X, b^ρ)

    // 2) γ cross leg: compute unmasked, then ^ρ on GT cells (post-exp)
    // PPE should now be 2-variable to match GS CRS size
    let stmt_y    = vec_to_col_vec(ycoms).left_mul(&ppe.gamma, false);  // Γ·Y
    let cross     = ComT::<E>::pairing_sum(xcoms, &col_vec_to_vec(&stmt_y)); // e(X, ΓY)
    let cross_rho = comt_pow_cells::<E>(&cross, rho);                    // e(X, ΓY)^ρ

    // 3) Proof legs with rho on CRS primaries (U,V), NOT on π/θ
    // GS CRS is fixed at 2 elements, matching PPE size
    let u_rho     = scale_com1::<E>(&crs.u, rho);
    let v_rho     = scale_com2::<E>(&crs.v, rho);
    
    let upi_rho   = ComT::<E>::pairing_sum(&u_rho, pi);                 // e(U^ρ, π)
    let thv_rho   = ComT::<E>::pairing_sum(theta, &v_rho);              // e(θ, V^ρ)

    // 4) Build masked cross leg as ComT
    let cross_rho_comt = ComT::<E>::from(vec![
        vec![
            PairingOutput::<E>(cross_rho[0][0]),
            PairingOutput::<E>(cross_rho[0][1]),
        ],
        vec![
            PairingOutput::<E>(cross_rho[1][0]),
            PairingOutput::<E>(cross_rho[1][1]),
        ],
    ]);

    // 5) Reconstruct masked verifier LHS and subtract masked proof legs
    let lhs_mask = (a_y_rho + x_b_rho) + cross_rho_comt;
    let rhs_mask = lhs_mask - upi_rho - thv_rho;

    // 6) Return raw GT cells of masked RHS (should equal target^ρ)
    let rhs_matrix = rhs_mask.as_matrix();
    [
        [rhs_matrix[0][0].0, rhs_matrix[0][1].0],
        [rhs_matrix[1][0].0, rhs_matrix[1][1].0],
    ]
}

/// Convenience: expected RHS matrix = linear_map_PPE(target^ρ)
pub fn rhs_masked_matrix<E: Pairing>(ppe: &PPE<E>, rho: E::ScalarField) -> [[E::TargetField;2];2] {
    use ark_ff::Field;
    let PairingOutput(tgt) = ppe.target;
    let rhs = ComT::<E>::linear_map_PPE(&PairingOutput::<E>(tgt.pow(rho.into_bigint())));
    let m = rhs.as_matrix();
    [[ m[0][0].0, m[0][1].0 ], [ m[1][0].0, m[1][1].0 ]]
}

/// Strict 2×2 canonical masked verifier as per Groth16→GS 2-slot mapping
/// Mapping requirements (must be ensured by caller when constructing the PPE):
/// - X = [π_A, π_C] (G1)
/// - Y = [π_B, -δ]  (G2)  ← δ NEGATED
/// - Γ = diag(1,1), A = [0,0], B = [0,0]
/// - target = e(α,β)·e(IC(x),γ)
/// Masking rules (proof-agnostic):
/// LHS(ρ) = i1(A)⊗Y^ρ  ⊕  X^ρ⊗i2(B)  ⊕  X⊗(Γ·Y^ρ)  ⊕  U^ρ⊗π  ⊕  θ⊗V^ρ
pub fn masked_verifier_comt_2x2<E: Pairing>(
    ppe: &PPE<E>,
    crs: &CRS<E>,
    x: &[Com1<E>],
    y: &[Com2<E>],
    pi: &[Com2<E>],
    theta: &[Com1<E>],
    rho: E::ScalarField,
) -> ComT<E> {
    use ark_ec::CurveGroup;
    use crate::data_structures::{vec_to_col_vec, col_vec_to_vec};

    // Mask primaries (U,V)
    let u_rho: Vec<Com1<E>> = crs.u.iter().map(|u| Com1::<E>(
        (u.0.into_group()*rho).into_affine(),
        (u.1.into_group()*rho).into_affine(),
    )).collect();
    let v_rho: Vec<Com2<E>> = crs.v.iter().map(|v| Com2::<E>(
        (v.0.into_group()*rho).into_affine(),
        (v.1.into_group()*rho).into_affine(),
    )).collect();

    // Mask variables where required
    let x_rho: Vec<Com1<E>> = x.iter().map(|c| Com1::<E>(
        (c.0.into_group()*rho).into_affine(),
        (c.1.into_group()*rho).into_affine(),
    )).collect();
    let y_rho: Vec<Com2<E>> = y.iter().map(|d| Com2::<E>(
        (d.0.into_group()*rho).into_affine(),
        (d.1.into_group()*rho).into_affine(),
    )).collect();

    // Linear legs from constants A,B (zeros in our mapping, but keep generic)
    let i1_a: Vec<Com1<E>> = Com1::<E>::batch_linear_map(&ppe.a_consts);
    let i2_b: Vec<Com2<E>> = Com2::<E>::batch_linear_map(&ppe.b_consts);

    // 1) i1(A) ⊗ Y^ρ
    let a_y_rho = ComT::<E>::pairing_sum(&i1_a, &y_rho);
    // 2) X^ρ ⊗ i2(B)
    let x_rho_b = ComT::<E>::pairing_sum(&x_rho, &i2_b);
    // 3) X ⊗ (Γ·Y^ρ)  [post-exp γ pushed into Y]
    let stmt_y_rho = vec_to_col_vec(&y_rho).left_mul(&ppe.gamma, false);
    let cross = ComT::<E>::pairing_sum(x, &col_vec_to_vec(&stmt_y_rho));
    // 4) U^ρ ⊗ π
    let u_pi_rho = ComT::<E>::pairing_sum(&u_rho, pi);
    // 5) θ ⊗ V^ρ
    let th_v_rho = ComT::<E>::pairing_sum(theta, &v_rho);

    (((a_y_rho + x_rho_b) + cross) + u_pi_rho) + th_v_rho
}

/// Matrix form of the strict 2×2 canonical masked verifier
pub fn masked_verifier_matrix_canonical_2x2<E: Pairing>(
    ppe: &PPE<E>,
    crs: &CRS<E>,
    x: &[Com1<E>],
    y: &[Com2<E>],
    pi: &[Com2<E>],
    theta: &[Com1<E>],
    rho: E::ScalarField,
) -> [[E::TargetField; 2]; 2] {
    let comt = masked_verifier_comt_2x2::<E>(ppe, crs, x, y, pi, theta, rho);
    comt_to_cells::<E>(&comt)
}
