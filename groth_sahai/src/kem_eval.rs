//! KEM evaluation functions for PVUGC
//! Extracts the deterministic GT value from GS verification for proof-agnostic KEM

use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField, One, Zero};

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

/// A single 1×1 equation (your attestation should expose these)
pub struct GSEquation<E: Pairing> {
    pub c1: Com1<E>,                 // X-side commitment (G1 pair) for this equation
    pub c2: Com2<E>,                 // Y-side commitment (G2 pair) for this equation
    pub pi: Vec<Com2<E>>,            // equation proof π, length == crs.u.len() (typically 2)
    pub theta: Vec<Com1<E>>,         // equation proof θ, length == crs.v.len() (typically 2)
}

/// Compute the unmasked "anchor" for a single 1×1 equation using a specific (row, col).
/// anchor(j,k) = e(C1,C2) · e(U_j, π_j) · e(θ_k, V_k)
fn eq_anchor_unmasked<E: Pairing>(
    eq: &GSEquation<E>,
    crs: &CRS<E>,
    x_row: usize,
    y_col: usize,
) -> E::TargetField {
    // γ-term for 1×1 is e(C1.0, C2.0) * e(C1.1, C2.1)
    let PairingOutput(g00) = E::pairing(eq.c1.0, eq.c2.0);
    let PairingOutput(g11) = E::pairing(eq.c1.1, eq.c2.1);
    let gamma_term = g00 * g11;

    // e(U_row, π_row)
    let u = crs.u[x_row];
    let pi = eq.pi[x_row];
    let PairingOutput(up0) = E::pairing(u.0, pi.0);
    let PairingOutput(up1) = E::pairing(u.1, pi.1);

    // e(θ_col, V_col)
    let v = crs.v[y_col];
    let th = eq.theta[y_col];
    let PairingOutput(tv0) = E::pairing(th.0, v.0);
    let PairingOutput(tv1) = E::pairing(th.1, v.1);

    gamma_term * up0 * up1 * tv0 * tv1
}

/// Compute the masked value for a 1×1 equation with the **same** (row, col).
/// M_eq(j,k) = (e(C1,C2))^ρ · e(U_j^ρ, π_j) · e(θ_k, V_k^ρ)
fn eq_masked_with_indices<E: Pairing>(
    eq: &GSEquation<E>,
    crs: &CRS<E>,
    x_row: usize,
    y_col: usize,
    rho: E::ScalarField,
) -> E::TargetField {
    // (e(C1,C2))^ρ
    let PairingOutput(g00) = E::pairing(eq.c1.0, eq.c2.0);
    let PairingOutput(g11) = E::pairing(eq.c1.1, eq.c2.1);
    let gamma_term = (g00 * g11).pow(rho.into_bigint());

    // e(U_j^ρ, π_j)
    let pi = eq.pi[x_row];
    let u = crs.u[x_row];
    let u0_r = (u.0.into_group() * rho).into_affine();
    let u1_r = (u.1.into_group() * rho).into_affine();
    let PairingOutput(up0) = E::pairing(u0_r, pi.0);
    let PairingOutput(up1) = E::pairing(u1_r, pi.1);

    // e(θ_k, V_k^ρ)
    let th = eq.theta[y_col];
    let v = crs.v[y_col];
    let v0_r = (v.0.into_group() * rho).into_affine();
    let v1_r = (v.1.into_group() * rho).into_affine();
    let PairingOutput(tv0) = E::pairing(th.0, v0_r);
    let PairingOutput(tv1) = E::pairing(th.1, v1_r);

    gamma_term * up0 * up1 * tv0 * tv1
}

/// Given two **1×1** equations (AB and CD) and attestation target T = e(α,β)·e(IC,γ),
/// find the (row,col) indices for each equation such that:
///   anchor_AB(rowA,colA) * anchor_CD(rowC,colC) == T
/// Then return the masked product:
///   M = M_AB(rowA,colA) * M_CD(rowC,colC) = T^ρ
pub fn eval_two_1x1_masked_auto<E: Pairing>(
    eq_ab: &GSEquation<E>,
    eq_cd: &GSEquation<E>,
    crs: &CRS<E>,
    rho: E::ScalarField,
    attestation_total_target: E::TargetField, // e(α,β)·e(IC,γ)
) -> PairingOutput<E> {
    // Sanity: pi/theta length should match CRS dimensionality (typically 2)
    assert_eq!(eq_ab.pi.len(), crs.u.len(), "eq_ab π length mismatch");
    assert_eq!(eq_ab.theta.len(), crs.v.len(), "eq_ab θ length mismatch");
    assert_eq!(eq_cd.pi.len(), crs.u.len(), "eq_cd π length mismatch");
    assert_eq!(eq_cd.theta.len(), crs.v.len(), "eq_cd θ length mismatch");
    assert!(crs.u.len() >= 2 && crs.v.len() >= 2, "expected 2-wide CRS");

    // Precompute all anchors (unmasked) for both equations
    let mut anchors_ab = [[E::TargetField::one(); 2]; 2];
    let mut anchors_cd = [[E::TargetField::one(); 2]; 2];
    for j in 0..2 {
        for k in 0..2 {
            anchors_ab[j][k] = eq_anchor_unmasked::<E>(eq_ab, crs, j, k);
            anchors_cd[j][k] = eq_anchor_unmasked::<E>(eq_cd, crs, j, k);
        }
    }

    // Find the unique (j,k),(j2,k2) such that product equals attestation_total_target
    let mut choice: Option<((usize,usize),(usize,usize))> = None;
    'outer: for j in 0..2 {
        for k in 0..2 {
            let a = anchors_ab[j][k];
            for j2 in 0..2 {
                for k2 in 0..2 {
                    let prod = a * anchors_cd[j2][k2];
                    if prod == attestation_total_target {
                        choice = Some(((j,k),(j2,k2)));
                        break 'outer;
                    }
                }
            }
        }
    }

    // Debug: print what we found
    if choice.is_none() {
        eprintln!("\n❌ Could not find indices that match target!");
        eprintln!("Target: {:?}", attestation_total_target);
        eprintln!("\nAB anchors:");
        for j in 0..2 {
            for k in 0..2 {
                eprintln!("  [{}][{}]: {:?}", j, k, anchors_ab[j][k]);
            }
        }
        eprintln!("\nCD anchors:");
        for j in 0..2 {
            for k in 0..2 {
                eprintln!("  [{}][{}]: {:?}", j, k, anchors_cd[j][k]);
            }
        }
        eprintln!("\nProducts tested:");
        for j in 0..2 {
            for k in 0..2 {
                for j2 in 0..2 {
                    for k2 in 0..2 {
                        let prod = anchors_ab[j][k] * anchors_cd[j2][k2];
                        eprintln!("  AB[{}][{}] * CD[{}][{}] = {:?}", j, k, j2, k2, prod);
                    }
                }
            }
        }
    }
    
    let ((j_ab,k_ab),(j_cd,k_cd)) = choice.expect("could not align 1×1 equations to total target");

    // Compute masked results with the selected indices
    let m_ab = eq_masked_with_indices::<E>(eq_ab, crs, j_ab, k_ab, rho);
    let m_cd = eq_masked_with_indices::<E>(eq_cd, crs, j_cd, k_cd, rho);

    PairingOutput(m_ab * m_cd)
}

/// Helper: product of the diagonal entries of a ComT matrix (binding-mode extraction)
fn comt_diag_product<E: Pairing>(m: &crate::data_structures::ComT<E>) -> E::TargetField {
    let mat = m.as_matrix();
    let ark_ec::pairing::PairingOutput(p00) = mat[0][0];
    let ark_ec::pairing::PairingOutput(p11) = mat[1][1];
    p00 * p11
}

/// Evaluate a single 1×1 equation mirroring verifier algebra, with masking on primaries and γ^ρ
pub fn eval_single_1x1_verifier_masked<E: Pairing>(
    eq: &GSEquation<E>,
    crs: &CRS<E>,
    rho: E::ScalarField,
) -> PairingOutput<E> {
    use ark_ec::CurveGroup;

    // γ term from commitments, explicitly raised to ρ
    let ark_ec::pairing::PairingOutput(g00) = E::pairing(eq.c1.0, eq.c2.0);
    let ark_ec::pairing::PairingOutput(g11) = E::pairing(eq.c1.1, eq.c2.1);
    let gamma_rho = (g00 * g11).pow(rho.into_bigint());

    // Mask U and V primaries by ρ (use first two CRS entries, as library requires len=2)
    debug_assert!(crs.u.len() >= 2 && crs.v.len() >= 2);
    let u_rho: Vec<Com1<E>> = crs.u.iter().take(2).map(|u| Com1::<E>(
        (u.0.into_group() * rho).into_affine(),
        (u.1.into_group() * rho).into_affine(),
    )).collect();
    let v_rho: Vec<Com2<E>> = crs.v.iter().take(2).map(|v| Com2::<E>(
        (v.0.into_group() * rho).into_affine(),
        (v.1.into_group() * rho).into_affine(),
    )).collect();

    // Proof legs using verifier's ComT pairing_sum structure
    let com_pi = BT::pairing_sum(&u_rho, &eq.pi);
    let com_theta = BT::pairing_sum(&eq.theta, &v_rho);
    let pi_val = comt_diag_product::<E>(&com_pi);
    let theta_val = comt_diag_product::<E>(&com_theta);

    PairingOutput(gamma_rho * pi_val * theta_val)
}

/// Evaluate two 1×1 equations and multiply, verifier-style
pub fn eval_two_1x1_verifier_masked<E: Pairing>(
    eq_ab: &GSEquation<E>,
    eq_cd: &GSEquation<E>,
    crs: &CRS<E>,
    rho: E::ScalarField,
) -> PairingOutput<E> {
    let PairingOutput(m1) = eval_single_1x1_verifier_masked::<E>(eq_ab, crs, rho);
    let PairingOutput(m2) = eval_single_1x1_verifier_masked::<E>(eq_cd, crs, rho);
    PairingOutput(m1 * m2)
}

/// Evaluate 2×2 PPE using five explicit buckets (no ComT):
/// 1) ∏_j e(C1_j, U*_j^ρ)
/// 2) ∏_k e(V*_k^ρ, C2_k)
/// 3) ∏_j e(U_j^ρ, π_j)  [diagonal per Com1/Com2 slots]
/// 4) ∏_k e(θ_k, V_k^ρ)  [diagonal per Com1/Com2 slots]
/// 5) (∏_{j,k} [e(C1_j.0,C2_k.0)·e(C1_j.1,C2_k.1)]^{γ_{j,k}})^ρ
pub fn eval_5_buckets_explicit<E: Pairing>(
    c1: &[Com1<E>],
    c2: &[Com2<E>],
    pi: &[Com2<E>],
    theta: &[Com1<E>],
    crs: &crate::generator::CRS<E>,
    gamma: &Vec<Vec<E::ScalarField>>,
    rho: E::ScalarField,
) -> PairingOutput<E> {
    use ark_ec::CurveGroup;
    use ark_ff::{Field, Zero};
    let mut acc = E::TargetField::one();

    // Precompute masked duals and primaries
    let u_dual_rho: Vec<(E::G2Affine, E::G2Affine)> = crs.u_dual.iter().map(|d| (
        (d.0.into_group() * rho).into_affine(),
        (d.1.into_group() * rho).into_affine(),
    )).collect();
    let v_dual_rho: Vec<(E::G1Affine, E::G1Affine)> = crs.v_dual.iter().map(|d| (
        (d.0.into_group() * rho).into_affine(),
        (d.1.into_group() * rho).into_affine(),
    )).collect();
    let u_rho: Vec<Com1<E>> = crs.u.iter().map(|u| Com1::<E>(
        (u.0.into_group() * rho).into_affine(),
        (u.1.into_group() * rho).into_affine(),
    )).collect();
    let v_rho: Vec<Com2<E>> = crs.v.iter().map(|v| Com2::<E>(
        (v.0.into_group() * rho).into_affine(),
        (v.1.into_group() * rho).into_affine(),
    )).collect();

    // 1) X vs dual (masked duals)
    for j in 0..c1.len() {
        let PairingOutput(p0) = E::pairing(c1[j].0, u_dual_rho[j].0);
        let PairingOutput(p1) = E::pairing(c1[j].1, u_dual_rho[j].1);
        acc *= p0 * p1;
    }
    // 2) dual vs Y (masked duals)
    for k in 0..c2.len() {
        let PairingOutput(p0) = E::pairing(v_dual_rho[k].0, c2[k].0);
        let PairingOutput(p1) = E::pairing(v_dual_rho[k].1, c2[k].1);
        acc *= p0 * p1;
    }
    // 3) U^ρ vs π (per-row diagonal)
    for j in 0..pi.len() {
        let PairingOutput(p0) = E::pairing(u_rho[j].0, pi[j].0);
        let PairingOutput(p1) = E::pairing(u_rho[j].1, pi[j].1);
        acc *= p0 * p1;
    }
    // 4) θ vs V^ρ (per-col diagonal)
    for k in 0..theta.len() {
        let PairingOutput(p0) = E::pairing(theta[k].0, v_rho[k].0);
        let PairingOutput(p1) = E::pairing(theta[k].1, v_rho[k].1);
        acc *= p0 * p1;
    }
    // 5) γ cross term, then ^ρ
    let mut g = E::TargetField::one();
    for j in 0..gamma.len() {
        for k in 0..gamma[j].len() {
            let coeff = gamma[j][k];
            if coeff.is_zero() { continue; }
            let PairingOutput(p00) = E::pairing(c1[j].0, c2[k].0);
            let PairingOutput(p11) = E::pairing(c1[j].1, c2[k].1);
            let term = (p00 * p11).pow(coeff.into_bigint());
            g *= term;
        }
    }
    acc *= g.pow(rho.into_bigint());
    PairingOutput(acc)
}

/// Mirror the verifier LHS with ComT, ρ‑mask the proof legs, and give Γ a ^ρ.
/// Returns the masked acceptor cell that equals target^ρ when the acceptor cell is chosen correctly.
pub fn ppe_eval_masked_parity<E: Pairing>(
    ppe: &PPE<E>,
    x: &[Com1<E>],           // commitments (X)
    y: &[Com2<E>],           // commitments (Y)
    pi: &[Com2<E>],          // equation proof π
    theta: &[Com1<E>],       // equation proof θ
    crs: &CRS<E>,
    rho: E::ScalarField,
    accept_cell: (usize, usize),
) -> PairingOutput<E> {
    use crate::data_structures::{ComT, Mat, Matrix, col_vec_to_vec, vec_to_col_vec};
    use ark_ec::CurveGroup;

    // Γ-mix on Y, then X ⊗ (ΓY)
    let stmt_y: Matrix<Com2<E>> = vec_to_col_vec(y).left_mul(&ppe.gamma, false);
    let x_gamma_y = ComT::<E>::pairing_sum(x, &col_vec_to_vec(&stmt_y));

    // Mask primaries for proof legs
    let u_rho: Vec<Com1<E>> = crs.u.iter().map(|u| Com1::<E>(
        (u.0.into_group() * rho).into_affine(),
        (u.1.into_group() * rho).into_affine(),
    )).collect();
    let v_rho: Vec<Com2<E>> = crs.v.iter().map(|v| Com2::<E>(
        (v.0.into_group() * rho).into_affine(),
        (v.1.into_group() * rho).into_affine(),
    )).collect();

    // Proof legs (masked primaries)
    let u_pi_r = ComT::<E>::pairing_sum(&u_rho, pi);
    let th_v_r = ComT::<E>::pairing_sum(theta, &v_rho);

    // Extract acceptor cell and combine (Γ gets ^ρ)
    let (r,c) = accept_cell;
    let gamma_cell_rho = x_gamma_y.as_matrix()[r][c].0.pow(rho.into_bigint());
    let pi_cell = u_pi_r.as_matrix()[r][c].0;
    let th_cell = th_v_r.as_matrix()[r][c].0;

    PairingOutput(gamma_cell_rho * pi_cell * th_cell)
}

// --- Verifier-style masked ComT helpers (exact algebra) ---
use crate::data_structures::{ComT, vec_to_col_vec, col_vec_to_vec, Mat};
use crate::{B1, B2};

fn scale_com1<E: Pairing>(v: &[Com1<E>], rho: E::ScalarField) -> Vec<Com1<E>> {
    v.iter().map(|c| Com1::<E>(
        (c.0.into_group()*rho).into_affine(),
        (c.1.into_group()*rho).into_affine(),
    )).collect()
}

fn scale_com2<E: Pairing>(v: &[Com2<E>], rho: E::ScalarField) -> Vec<Com2<E>> {
    v.iter().map(|c| Com2::<E>(
        (c.0.into_group()*rho).into_affine(),
        (c.1.into_group()*rho).into_affine(),
    )).collect()
}

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

fn comt_x_with_u_dual_rho<E: Pairing>(x: &[Com1<E>], crs: &CRS<E>, rho: E::ScalarField) -> ComT<E> {
    let ustar_rho: Vec<Com2<E>> = crs.u_dual.iter().map(|d| Com2::<E>(
        (d.0.into_group()*rho).into_affine(),
        (d.1.into_group()*rho).into_affine(),
    )).collect();
    ComT::<E>::pairing_sum(x, &ustar_rho)
}

fn comt_v_dual_rho_with_y<E: Pairing>(y: &[Com2<E>], crs: &CRS<E>, rho: E::ScalarField) -> ComT<E> {
    let vstar_rho: Vec<Com1<E>> = crs.v_dual.iter().map(|d| Com1::<E>(
        (d.0.into_group()*rho).into_affine(),
        (d.1.into_group()*rho).into_affine(),
    )).collect();
    ComT::<E>::pairing_sum(&vstar_rho, y)
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

/// Build masked verifier-style ComT: (X⊗ΓY)^ρ ⊕ (U^ρ⊗π) ⊕ (θ⊗V^ρ) [⊕ dual-helper buckets]
pub fn masked_verifier_comt<E: Pairing>(
    ppe: &PPE<E>,
    crs: &CRS<E>,
    x_coms: &[Com1<E>],
    y_coms: &[Com2<E>],
    pi: &[Com2<E>],
    theta: &[Com1<E>],
    rho: E::ScalarField,
    include_dual_helpers: bool,
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

    let mut acc = (((cross_rho + u_pi_rho) + th_v_rho) + a_y_rho) + x_b_rho;
    if include_dual_helpers {
        acc = acc + comt_x_with_u_dual_rho::<E>(x_coms, crs, rho)
                  + comt_v_dual_rho_with_y::<E>(y_coms, crs, rho);
    }
    acc
}

/// Variant: allow using Γ^T in the cross leg
pub fn masked_verifier_comt_with_gamma_mode<E: Pairing>(
    ppe: &PPE<E>,
    crs: &CRS<E>,
    x_coms: &[Com1<E>],
    y_coms: &[Com2<E>],
    pi: &[Com2<E>],
    theta: &[Com1<E>],
    rho: E::ScalarField,
    use_gamma_transpose: bool,
) -> ComT<E> {
    let gamma_ref = if use_gamma_transpose {
        // Transpose gamma
        let mut gt = vec![vec![E::ScalarField::zero(); ppe.gamma.len()]; ppe.gamma[0].len()];
        for i in 0..ppe.gamma.len() { for j in 0..ppe.gamma[0].len() { gt[j][i] = ppe.gamma[i][j]; } }
        gt
    } else { ppe.gamma.clone() };

    let cross_rho = comt_gamma_cross_pow_rho::<E>(x_coms, y_coms, &gamma_ref, rho);
    let u_rho = scale_u_by_rho::<E>(crs, rho);
    let v_rho = scale_v_by_rho::<E>(crs, rho);
    let u_pi_rho = ComT::<E>::pairing_sum(&u_rho, pi);
    let th_v_rho = ComT::<E>::pairing_sum(theta, &v_rho);
    let i1_a: Vec<Com1<E>> = Com1::batch_linear_map(&ppe.a_consts);
    let i2_b: Vec<Com2<E>> = Com2::batch_linear_map(&ppe.b_consts);
    let i1_a_rho = scale_com1::<E>(&i1_a, rho);
    let i2_b_rho = scale_com2::<E>(&i2_b, rho);
    let a_y_rho = ComT::<E>::pairing_sum(&i1_a_rho, y_coms);
    let x_b_rho = ComT::<E>::pairing_sum(x_coms, &i2_b_rho);
    (((cross_rho + u_pi_rho) + th_v_rho) + a_y_rho) + x_b_rho
}

/// Build unmasked verifier LHS ComT exactly as verifier.rs, then exponentiate each cell by ρ and return the 2×2 matrix.
pub fn masked_verifier_matrix_postexp<E: Pairing>(
    ppe: &PPE<E>,
    crs: &CRS<E>,
    x_coms: &[Com1<E>],
    y_coms: &[Com2<E>],
    pi: &[Com2<E>],
    theta: &[Com1<E>],
    rho: E::ScalarField,
) -> [[E::TargetField; 2]; 2] {
    // i1(a)·Y
    let i1_a: Vec<Com1<E>> = Com1::batch_linear_map(&ppe.a_consts);
    let a_y = ComT::<E>::pairing_sum(&i1_a, y_coms);
    // X·i2(b)
    let i2_b: Vec<Com2<E>> = Com2::batch_linear_map(&ppe.b_consts);
    let x_b = ComT::<E>::pairing_sum(x_coms, &i2_b);
    // X·(Γ·Y)
    let stmt_y = vec_to_col_vec(y_coms).left_mul(&ppe.gamma, false);
    let cross = ComT::<E>::pairing_sum(x_coms, &col_vec_to_vec(&stmt_y));
    // U·π and θ·V
    let u_pi = ComT::<E>::pairing_sum(&crs.u, pi);
    let th_v = ComT::<E>::pairing_sum(theta, &crs.v);
    // LHS unmasked
    let lhs = ((a_y + x_b) + cross) + (u_pi + th_v);
    let mm = lhs.as_matrix();
    let mut out = [[E::TargetField::one(); 2]; 2];
    for r in 0..2 { for c in 0..2 {
        let ark_ec::pairing::PairingOutput(cell) = mm[r][c];
        out[r][c] = cell.pow(rho.into_bigint());
    }}
    out
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
/// Full-matrix masked ComT evaluator that mirrors the verifier’s sum-based pipeline.
/// Returns the 2×2 matrix of GT cells after masking (X⊗ΓY)^ρ, (U^ρ⊗π), (θ⊗V^ρ) and component-wise multiplication.
pub fn ppe_eval_masked_comt_full<E: Pairing>(
    ppe: &PPE<E>,
    x: &[Com1<E>],
    y: &[Com2<E>],
    pi: &[Com2<E>],
    theta: &[Com1<E>],
    crs: &CRS<E>,
    rho: E::ScalarField,
) -> [[E::TargetField; 2]; 2] {
    use crate::data_structures::{ComT, Mat, Matrix, col_vec_to_vec, vec_to_col_vec};
    use ark_ec::CurveGroup;

    // Γ-mix on Y, then X ⊗ (ΓY)
    let stmt_y: Matrix<Com2<E>> = vec_to_col_vec(y).left_mul(&ppe.gamma, false);
    let x_gamma_y = ComT::<E>::pairing_sum(x, &col_vec_to_vec(&stmt_y));

    // Mask primaries
    let u_rho: Vec<Com1<E>> = crs.u.iter().map(|u| Com1::<E>(
        (u.0.into_group() * rho).into_affine(),
        (u.1.into_group() * rho).into_affine(),
    )).collect();
    let v_rho: Vec<Com2<E>> = crs.v.iter().map(|v| Com2::<E>(
        (v.0.into_group() * rho).into_affine(),
        (v.1.into_group() * rho).into_affine(),
    )).collect();

    // Proof legs with masked primaries
    let u_pi_r = ComT::<E>::pairing_sum(&u_rho, pi);
    let th_v_r = ComT::<E>::pairing_sum(theta, &v_rho);

    // Component-wise combine; Γ leg needs ^ρ per cell
    let xgy = x_gamma_y.as_matrix();
    let upi = u_pi_r.as_matrix();
    let thv = th_v_r.as_matrix();
    let mut out = [[E::TargetField::one(); 2]; 2];
    for r in 0..2 {
        for c in 0..2 {
            let PairingOutput(g) = xgy[r][c];
            let PairingOutput(a) = upi[r][c];
            let PairingOutput(b) = thv[r][c];
            out[r][c] = g.pow(rho.into_bigint()) * a * b;
        }
    }
    out
}
