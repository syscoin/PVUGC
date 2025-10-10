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

/// Convert a ComT to a raw 2×2 GT matrix (to allow cellwise multiplication).
fn comt_to_cells<E: Pairing>(m: &ComT<E>) -> [[E::TargetField; 2]; 2] {
    let mm = m.as_matrix();
    [[ mm[0][0].0, mm[0][1].0 ], [ mm[1][0].0, mm[1][1].0 ]]
}

/// Cellwise multiply 2×2 GT matrices (ComT's additive notation is multiplicative in GT).
fn mul_cells<E: Pairing>(
    a: [[E::TargetField; 2]; 2],
    b: [[E::TargetField; 2]; 2],
) -> [[E::TargetField; 2]; 2] {
    [
        [ a[0][0] * b[0][0], a[0][1] * b[0][1] ],
        [ a[1][0] * b[1][0], a[1][1] * b[1][1] ],
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
    let i1_a      = Com1::<E>::batch_linear_map(&ppe.a_consts);
    let i2_b      = Com2::<E>::batch_linear_map(&ppe.b_consts);
    let i1_a_rho  = scale_com1::<E>(&i1_a, rho);
    let i2_b_rho  = scale_com2::<E>(&i2_b, rho);

    let aY_rho    = ComT::<E>::pairing_sum(&i1_a_rho, ycoms);           // e(a^ρ, Y)
    let Xb_rho    = ComT::<E>::pairing_sum(xcoms, &i2_b_rho);           // e(X, b^ρ)

    // 2) γ cross leg: compute unmasked, then ^ρ on GT cells (post-exp)
    let stmt_y    = vec_to_col_vec(ycoms).left_mul(&ppe.gamma, false);  // Γ·Y
    let cross     = ComT::<E>::pairing_sum(xcoms, &col_vec_to_vec(&stmt_y)); // e(X, ΓY)
    let cross_rho = comt_pow_cells::<E>(&cross, rho);                    // e(X, ΓY)^ρ

    // 3) Proof legs with rho on CRS primaries (U,V), NOT on π/θ
    let u_rho     = scale_com1::<E>(&crs.u, rho);
    let v_rho     = scale_com2::<E>(&crs.v, rho);
    let upi_rho   = ComT::<E>::pairing_sum(&u_rho, pi);                 // e(U^ρ, π)
    let thv_rho   = ComT::<E>::pairing_sum(theta, &v_rho);              // e(θ, V^ρ)

    // 4) Sum in ComT-world (cellwise multiply in GT), using 2×2 raw GT cells
    let mut acc   = comt_to_cells::<E>(&aY_rho);
    acc           = mul_cells::<E>(acc, comt_to_cells::<E>(&Xb_rho));
    acc           = mul_cells::<E>(acc, cross_rho);
    acc           = mul_cells::<E>(acc, comt_to_cells::<E>(&upi_rho));
    acc           = mul_cells::<E>(acc, comt_to_cells::<E>(&thv_rho));
    acc
}

/// Convenience: expected RHS matrix = linear_map_PPE(target^ρ)
pub fn rhs_masked_matrix<E: Pairing>(ppe: &PPE<E>, rho: E::ScalarField) -> [[E::TargetField;2];2] {
    use ark_ff::Field;
    let PairingOutput(tgt) = ppe.target;
    let rhs = ComT::<E>::linear_map_PPE(&PairingOutput::<E>(tgt.pow(rho.into_bigint())));
    let m = rhs.as_matrix();
    [[ m[0][0].0, m[0][1].0 ], [ m[1][0].0, m[1][1].0 ]]
}
