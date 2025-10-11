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

/// Extract raw GT cells for matrix comparisons.
fn comt_to_cells<E: Pairing>(m: &ComT<E>) -> [[E::TargetField; 2]; 2] {
    let mm = m.as_matrix();
    [
        [mm[0][0].0, mm[0][1].0],
        [mm[1][0].0, mm[1][1].0],
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
    comt_to_cells(&rhs_mask)
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
    masked_verifier_comt(ppe, crs, x, y, pi, theta, rho, false)
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
    masked_verifier_matrix_canonical(ppe, crs, x, y, pi, theta, rho)
}

/// Build masked verifier-style ComT: (X⊗ΓY)^ρ ⊕ (U^ρ⊗π) ⊕ (θ⊗V^ρ) [⊕ dual-helper buckets]
pub fn masked_verifier_comt<E: Pairing>(
    ppe: &PPE<E>,
    crs: &CRS<E>,
    x_coms: &[Com1<E>],
    y_coms: &[Com2<E>],
    pi: &[Com2<E>],
    theta: &[Com1<E>],
    rho: E::ScalarField,
    _include_dual_helpers: bool,
) -> ComT<E> {
    let cross_rho = comt_gamma_cross_pow_rho::<E>(x_coms, y_coms, &ppe.gamma, rho);
    let u_rho = scale_u_by_rho::<E>(crs, rho);
    let v_rho = scale_v_by_rho::<E>(crs, rho);
    let u_pi_rho = ComT::<E>::pairing_sum(&u_rho, pi);
    let th_v_rho = ComT::<E>::pairing_sum(theta, &v_rho);
    // Constants legs: apply ρ on CRS constants (a,b), not on commitments
    let i1_a: Vec<Com1<E>> = Com1::batch_linear_map(&ppe.a_consts);
    let i2_b: Vec<Com2<E>> = Com2::batch_linear_map(&ppe.b_consts);
    let i1_a_rho = scale_com1::<E>(&i1_a, rho);
    let i2_b_rho = scale_com2::<E>(&i2_b, rho);
    let a_y_rho = ComT::<E>::pairing_sum(&i1_a_rho, y_coms);
    let x_b_rho = ComT::<E>::pairing_sum(x_coms, &i2_b_rho);

    // Return the masked verifier LHS (no dual helpers needed anymore)
    ((a_y_rho + x_b_rho) + cross_rho) - u_pi_rho - th_v_rho
}
/*pub fn masked_verifier_comt<E: Pairing>(
    ppe: &PPE<E>,
    crs: &CRS<E>,
    x: &[Com1<E>],
    y: &[Com2<E>],
    pi: &[Com2<E>],
    theta: &[Com1<E>],
    u_rho: &[Com1<E>],
    v_rho: &[Com2<E>],
) -> ComT<E> {
    // 1) LHS commitment side (no rho here)
    let i1_a = Com1::batch_linear_map(&ppe.a_consts);   // zeros in plain Groth16
    let i2_b = Com2::batch_linear_map(&ppe.b_consts);   // zeros in plain Groth16
    let lhs_a = ComT::pairing_sum(&i1_a, y);
    let lhs_b = ComT::pairing_sum(x, &i2_b);
    let stmt_y = vec_to_col_vec(y).left_mul(&ppe.gamma, false); // Γ·Y
    let cross = ComT::pairing_sum(x, &col_vec_to_vec(&stmt_y));
    let lhs_commit = lhs_a + lhs_b + cross;

    // 2) Proof legs with masked primaries (this is where ρ enters)
    let u_pi_rho = ComT::pairing_sum(u_rho, pi);    // U^ρ ⊗ π
    let theta_v_rho = ComT::pairing_sum(theta, v_rho); // θ ⊗ V^ρ

    // 3) Isolate masked target by subtraction
    let masked_target = lhs_commit - u_pi_rho - theta_v_rho;

    masked_target
}*/

fn scale_u_by_rho<E: Pairing>(crs: &CRS<E>, rho: E::ScalarField) -> Vec<Com1<E>> {
    crs.u.iter().map(|u| Com1::<E>(
        (u.0.into_group()*rho).into_affine(),
        (u.1.into_group()*rho).into_affine(),
    )).collect()
}

fn scale_v_by_rho<E: Pairing>(crs: &CRS<E>, rho: E::ScalarField) -> Vec<Com2<E>> {
    crs.v.iter().map(|v| Com2::<E>(
        (v.0.into_group()*rho).into_affine(),
        (v.1.into_group()*rho).into_affine(),
    )).collect()
}

fn comt_gamma_cross_pow_rho<E: Pairing>(x: &[Com1<E>], y: &[Com2<E>], gamma: &Vec<Vec<E::ScalarField>>, rho: E::ScalarField) -> ComT<E> {
    // Compute unmasked cross leg X ⊗ (Γ·Y), then post-exponentiate each GT cell by ρ
    let stmt_y = vec_to_col_vec(y).left_mul(gamma, false);
    let cross = ComT::<E>::pairing_sum(x, &col_vec_to_vec(&stmt_y));
    let mm = cross.as_matrix();
    ComT::<E>::from(vec![
        vec![
            PairingOutput::<E>(mm[0][0].0.pow(rho.into_bigint())),
            PairingOutput::<E>(mm[0][1].0.pow(rho.into_bigint())),
        ],
        vec![
            PairingOutput::<E>(mm[1][0].0.pow(rho.into_bigint())),
            PairingOutput::<E>(mm[1][1].0.pow(rho.into_bigint())),
        ],
    ])
}

use ark_serialize::CanonicalSerialize;
use sha2::{Sha256, Digest};

/// Deterministic 32‑byte key from a masked ComT (full matrix, row-major) with domain separation
pub fn kdf_from_comt<E: Pairing>(
    comt: &ComT<E>,
    crs_digest: &[u8],
    ppe_digest: &[u8],
    vk_hash: &[u8],
    x_hash: &[u8],
    deposit_id: &[u8],
    version: u8,
) -> [u8; 32] {
    let m = comt.as_matrix();
    let mut h = Sha256::new();
    h.update(b"PVUGC-KEM-ComT-v");
    h.update([version]);
    h.update(crs_digest);
    h.update(ppe_digest);
    h.update(vk_hash);
    h.update(x_hash);
    h.update(deposit_id);
    for r in 0..2 {
        for c in 0..2 {
            let mut buf = Vec::new();
            m[r][c].0.serialize_compressed(&mut buf).unwrap();
            h.update(buf);
        }
    }
    let out = h.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out[..32]);
    key
}
