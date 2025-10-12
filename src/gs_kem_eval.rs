//! Canonical masked evaluator for proof-agnostic KEM extraction
//!
//! This module provides the canonical masked verifier evaluator that applies ρ
//! to CRS constants/primaries (not commitments) and post-exponentiates the γ ComT.

use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField};

use groth_sahai::data_structures::{
    col_vec_to_vec, vec_to_col_vec, Com1, Com2, ComT, Mat, B1, B2, BT,
};
use groth_sahai::generator::CRS;
use groth_sahai::statement::PPE;

/// Scale a vector of Com1/Com2 (CRS-side) by rho (used only for CRS constants and primaries).
fn scale_com1<E: Pairing>(v: &[Com1<E>], rho: E::ScalarField) -> Vec<Com1<E>> {
    v.iter()
        .map(|c| {
            Com1::<E>(
                (c.0.into_group() * rho).into_affine(),
                (c.1.into_group() * rho).into_affine(),
            )
        })
        .collect()
}

fn scale_com2<E: Pairing>(v: &[Com2<E>], rho: E::ScalarField) -> Vec<Com2<E>> {
    v.iter()
        .map(|d| {
            Com2::<E>(
                (d.0.into_group() * rho).into_affine(),
                (d.1.into_group() * rho).into_affine(),
            )
        })
        .collect()
}

/// Raise every GT cell of a ComT to rho (post-exponentiation).
fn comt_pow_cells<E: Pairing>(m: &ComT<E>, rho: E::ScalarField) -> [[E::TargetField; 2]; 2] {
    let mm = m.as_matrix();
    [
        [
            mm[0][0].0.pow(rho.into_bigint()),
            mm[0][1].0.pow(rho.into_bigint()),
        ],
        [
            mm[1][0].0.pow(rho.into_bigint()),
            mm[1][1].0.pow(rho.into_bigint()),
        ],
    ]
}

/// Extract raw GT cells for matrix comparisons.
fn comt_to_cells<E: Pairing>(m: &ComT<E>) -> [[E::TargetField; 2]; 2] {
    let mm = m.as_matrix();
    [[mm[0][0].0, mm[0][1].0], [mm[1][0].0, mm[1][1].0]]
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
    let i1_a = Com1::<E>::batch_linear_map(&ppe.a_consts);
    let i2_b = Com2::<E>::batch_linear_map(&ppe.b_consts);
    let i1_a_rho = scale_com1::<E>(&i1_a, rho);
    let i2_b_rho = scale_com2::<E>(&i2_b, rho);

    let a_y_rho = ComT::<E>::pairing_sum(&i1_a_rho, ycoms); // e(a^ρ, Y)
    let x_b_rho = ComT::<E>::pairing_sum(xcoms, &i2_b_rho); // e(X, b^ρ)

    // 2) γ cross leg: compute unmasked, then ^ρ on GT cells (post-exp)
    // PPE should now be 2-variable to match GS CRS size
    let stmt_y = vec_to_col_vec(ycoms).left_mul(&ppe.gamma, false); // Γ·Y
    let cross = ComT::<E>::pairing_sum(xcoms, &col_vec_to_vec(&stmt_y)); // e(X, ΓY)
    let cross_rho = comt_pow_cells::<E>(&cross, rho); // e(X, ΓY)^ρ

    // 3) Proof legs with rho on CRS primaries (U,V), NOT on π/θ
    // GS CRS is fixed at 2 elements, matching PPE size
    let u_rho = scale_com1::<E>(&crs.u, rho);
    let v_rho = scale_com2::<E>(&crs.v, rho);

    let upi_rho = ComT::<E>::pairing_sum(&u_rho, pi); // e(U^ρ, π)
    let thv_rho = ComT::<E>::pairing_sum(theta, &v_rho); // e(θ, V^ρ)

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
pub fn rhs_masked_matrix<E: Pairing>(
    ppe: &PPE<E>,
    rho: E::ScalarField,
) -> [[E::TargetField; 2]; 2] {
    use ark_ff::Field;
    let PairingOutput(tgt) = ppe.target;
    let rhs = ComT::<E>::linear_map_PPE(&PairingOutput::<E>(tgt.pow(rho.into_bigint())));
    let m = rhs.as_matrix();
    [[m[0][0].0, m[0][1].0], [m[1][0].0, m[1][1].0]]
}

use ark_serialize::CanonicalSerialize;
use sha2::{Digest, Sha256};

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
