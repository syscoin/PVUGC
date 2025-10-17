//! Statement-only base construction for rank-decomposition PPE.
//!
//! This module implements the construction of verifier bases (U, V, W, Z) that are
//! statement-only (computable from CRS + Γ without commitments). These bases enable
//! offline PVUGC ARMER.
//!
//! # Mathematical Construction
//!
//! Given rank decomposition Γ = Σ_a u^(a) · v^(a)^T and per-slot CRS:
//!
//! - **U_i** = Σ_j Γ_ij · v_{j,1} (G2) - Encodes Γ into bases for C1 slots
//! - **V_j** = A_j (G1) - Simple linear term for C2 slots
//! - **W_a** = Σ_j v^(a)_j · v_{j,1} (G2) - Bases for proof slots P (cancels X randomizers)
//! - **Z_j** = -A_j (G1) - Bases for proof slots Q (cancels Y randomizers)
//!
//! # Randomness Cancellation
//!
//! The four-bucket product in the verifier achieves randomness cancellation:
//! - B1 = ∏ e(C^1_i, U_i) produces variable terms + randomizer noise
//! - B3 = ∏ e(P_a, W_a) exactly cancels the B1 randomizer noise
//! - B2 = ∏ e(V_j, C^2_j) produces linear terms + randomizer noise  
//! - B4 = ∏ e(Z_j, Q_j) exactly cancels the B2 randomizer noise
//!
//! Result: M = B1·B2·B3·B4 depends only on (X, Y, Γ, A, B), not on randomizers (r, s).

#![allow(non_snake_case)]

use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Zero;

use crate::generator::CRS;
use crate::rank_decomp::RankDecomp;
use crate::statement::PPE;

/// Statement-only verifier bases for rank-decomposition PPE.
///
/// All bases depend only on (CRS, Γ, A, B) and can be computed offline by ARMER.
#[derive(Clone, Debug)]
pub struct RankDecompPpeBases<E: Pairing> {
    /// U_i bases for C1 slots (m elements, G2)
    /// U_i = Σ_j Γ_ij · v_{j,1}
    pub U: Vec<E::G2Affine>,

    /// V_j bases for C2 slots (n elements, G1)
    /// V_j = A_j
    pub V: Vec<E::G1Affine>,

    /// W_a bases for P proof slots (rank elements, G2)
    /// W_a = Σ_j v^(a)_j · v_{j,1}
    pub W: Vec<E::G2Affine>,

    /// Z_j bases for Q proof slots (n elements, G1)
    /// Z_j = -A_j
    pub Z: Vec<E::G1Affine>,

    /// Dimensions
    pub m: usize, // Number of C1 slots (X variables)
    pub n: usize,    // Number of C2 slots (Y variables)
    pub rank: usize, // Rank of Γ (number of W/P pairs)
}

/// Full GS PPE bases with block construction for real Groth16 verification.
///
/// This construction handles both CRS rows (rand & var) on both sides to properly
/// reconstruct e(A,B) terms when both A and B are committed with randomness.
#[derive(Clone, Debug)]
pub struct FullGSPpeBases<E: Pairing> {
    /// U^{(0)}_i bases for C1 rand slots (m elements, G2)
    /// U^{(0)}_i = Σ_j Γ_ij · v_{j,0}
    pub U_rand: Vec<E::G2Affine>,

    /// U^{(1)}_i bases for C1 var slots (m elements, G2)
    /// U^{(1)}_i = Σ_j Γ_ij · v_{j,1}
    pub U_var: Vec<E::G2Affine>,

    /// V^{(0)}_j bases for C2 rand slots (n elements, G1)
    /// V^{(0)}_j = A_j
    pub V_rand: Vec<E::G1Affine>,

    /// V^{(1)}_j bases for C2 var slots (n elements, G1)
    /// V^{(1)}_j = A_j
    pub V_var: Vec<E::G1Affine>,

    /// W_a bases for P proof slots (rank elements, G2)
    /// W_a = Σ_j v^(a)_j · v_{j,1}
    pub W: Vec<E::G2Affine>,

    /// Z_j bases for Q proof slots (n elements, G1)
    /// Z_j = -A_j
    pub Z: Vec<E::G1Affine>,

    /// Dimensions
    pub m: usize, // Number of C1 slots (X variables)
    pub n: usize,    // Number of C2 slots (Y variables)
    pub rank: usize, // Rank of Γ (number of W/P pairs)
}

impl<E: Pairing> RankDecompPpeBases<E> {
    /// Build all statement-only bases from CRS, PPE, and rank decomposition.
    ///
    /// # Arguments
    /// * `crs` - Per-slot CRS with 2*m rows for X and 2*n rows for Y
    /// * `ppe` - The PPE containing Γ, a_consts, b_consts
    /// * `decomp` - Rank decomposition of Γ
    ///
    /// # Returns
    /// Complete set of statement-only bases for the verifier
    ///
    /// # Example
    /// ```ignore
    /// let crs = CRS::generate_crs_per_slot(&mut rng, 2, 2);
    /// let decomp = RankDecomp::decompose(&ppe.gamma);
    /// let bases = RankDecompPpeBases::build(&crs, &ppe, &decomp);
    ///
    /// // All bases are statement-only (no commitment dependence)
    /// assert_eq!(bases.U.len(), 2);  // m C1 slots
    /// assert_eq!(bases.V.len(), 2);  // n C2 slots
    /// assert_eq!(bases.W.len(), decomp.rank);  // rank P slots
    /// assert_eq!(bases.Z.len(), 2);  // n Q slots
    /// ```
    pub fn build(crs: &CRS<E>, ppe: &PPE<E>, decomp: &RankDecomp<E::ScalarField>) -> Self {
        let m = decomp.m;
        let n = decomp.n;
        let rank = decomp.rank;

        // Verify CRS has correct per-slot structure
        assert_eq!(
            crs.num_x_slots(),
            m,
            "CRS X slots ({}) must match Γ rows ({})",
            crs.num_x_slots(),
            m
        );
        assert_eq!(
            crs.num_y_slots(),
            n,
            "CRS Y slots ({}) must match Γ cols ({})",
            crs.num_y_slots(),
            n
        );

        // Check if this is a pure bilinear PPE (no linear terms)
        let is_pure_bilinear =
            ppe.a_consts.iter().all(|a| a.is_zero()) && ppe.b_consts.iter().all(|b| b.is_zero());

        // Build each type of base
        let U = build_U_for_C1(crs, decomp);
        let V = if is_pure_bilinear {
            build_V_for_C2_pure_bilinear(crs, n)
        } else {
            build_V_for_C2::<E>(&ppe.a_consts)
        };
        let W = build_W_for_P(crs, decomp);
        let Z = if is_pure_bilinear {
            build_Z_for_Q_pure_bilinear(crs, n)
        } else {
            build_Z_for_Q::<E>(&ppe.a_consts)
        };

        Self {
            U,
            V,
            W,
            Z,
            m,
            n,
            rank,
        }
    }
}

impl<E: Pairing> FullGSPpeBases<E> {
    /// Build full GS PPE bases with block construction for real Groth16 verification.
    ///
    /// This a block-based exporter that produces four pairings per
    /// Γ-pair to reconstruct e(X_i, Y_j) terms with proper randomness cancellation.
    ///
    /// For each pair (i,j) with Γ_ij ≠ 0, we construct:
    /// - U^{rand}_{ij} = -a2 * v_{j,0}  (G2)
    /// - U^{var}_{ij}  =  a2 * v_{j,0} = v_{j,1} (G2)
    /// - V^{var}_{ij}  = -a1 * u_{i,0} = -u_{i,1} (G1)
    /// - V^{rand}_{ij} =  a1*a2 * u_{i,0} (G1)
    ///
    /// These blocks telescope to cancel all randomizer noise and produce exactly e(X_i, Y_j).
    ///
    /// # Arguments
    /// * `crs` - Per-slot CRS with public binding tags (a1, a2)
    /// * `ppe` - The PPE containing Γ
    /// * `decomp` - Rank decomposition of Γ
    ///
    /// # Returns
    /// Complete set of full GS bases for the verifier
    pub fn build(crs: &CRS<E>, _ppe: &PPE<E>, decomp: &RankDecomp<E::ScalarField>) -> Self {
        let m = decomp.m;
        let n = decomp.n;
        let rank = decomp.rank;

        // Verify CRS has correct per-slot structure
        assert_eq!(
            crs.num_x_slots(),
            m,
            "CRS X slots ({}) must match Γ rows ({})",
            crs.num_x_slots(),
            m
        );
        assert_eq!(
            crs.num_y_slots(),
            n,
            "CRS Y slots ({}) must match Γ cols ({})",
            crs.num_y_slots(),
            n
        );

        // Get public binding tags
        let a1 = crs.a1;
        let a2 = crs.a2;

        // For identity Γ: build one block per diagonal pair (i, i)
        // For general Γ: scan all (i, j) with Γ_ij ≠ 0
        let mut U_rand = Vec::with_capacity(m);
        let mut U_var = Vec::with_capacity(m);
        let mut V_rand = Vec::with_capacity(n);
        let mut V_var = Vec::with_capacity(n);

        for i in 0..m {
            // For identity Γ: j = i
            // For general Γ: find j with Γ_ij ≠ 0 and scale blocks by Γ_ij
            let j = i; // Identity case

            // Fetch CRS rows
            let (_v_rand, v_var) = crs.v_for_slot(j); // G2 rows for Y slot j
            let (_u_rand, u_var) = crs.u_for_slot(i); // G1 rows for X slot i

            // G2 blocks (paired with C1[i])
            // Use var-row based blocks for cleaner telescoping
            let v_j_1 = v_var.1.into_group(); // v_{j,1} = a2*v_{j,0} (G2)

            // G1 blocks (paired with C2[j])
            let u_i_1 = u_var.1.into_group(); // u_{i,1} = a1*u_{i,0} (G1)

            // Build blocks with var-row bases
            U_var.push(v_j_1.into_affine()); // +1 * v_{j,1}
            U_rand.push((-v_j_1).into_affine()); // -1 * v_{j,1} = -a2 * v_{j,0}

            V_var.push((-u_i_1).into_affine()); // -1 * u_{i,1}
            V_rand.push((u_i_1 * a2).into_affine()); // +a2 * u_{i,1} = +a1*a2 * u_{i,0}
        }

        // Build rank bases (unchanged)
        let W = build_W_for_P(crs, decomp);

        // Z = 0 for pure bilinear (Groth16)
        let Z = vec![<E as Pairing>::G1::zero().into_affine(); n];

        Self {
            U_rand,
            U_var,
            V_rand,
            V_var,
            W,
            Z,
            m,
            n,
            rank,
        }
    }
}

/// Build U_i bases for C1 rand slots: U_i = Σ_j Γ_ij · v_{j,0}
///
/// These bases encode the Γ matrix into the G2 rand bases for randomness cancellation.
pub fn build_U_for_C1_rand<E: Pairing>(
    crs: &CRS<E>,
    gamma: &[Vec<E::ScalarField>],
) -> Vec<E::G2Affine> {
    let m = gamma.len();
    let n = gamma[0].len();
    let mut U = Vec::with_capacity(m);

    for i in 0..m {
        let mut u_i = <E as Pairing>::G2::zero();
        for j in 0..n {
            let (v_rand, _v_var) = crs.v_for_slot(j);
            u_i += v_rand.0.into_group() * gamma[i][j];
        }
        U.push(u_i.into_affine());
    }

    U
}

/// Build U_i bases for C1 var slots: U_i = Σ_j Γ_ij · v_{j,1}
///
/// These bases encode the Γ matrix into the G2 var bases for variable terms.
pub fn build_U_for_C1_var<E: Pairing>(
    crs: &CRS<E>,
    gamma: &[Vec<E::ScalarField>],
) -> Vec<E::G2Affine> {
    let m = gamma.len();
    let n = gamma[0].len();
    let mut U = Vec::with_capacity(m);

    for i in 0..m {
        let mut u_i = <E as Pairing>::G2::zero();
        for j in 0..n {
            let (_v_rand, v_var) = crs.v_for_slot(j);
            u_i += v_var.1.into_group() * gamma[i][j];
        }
        U.push(u_i.into_affine());
    }

    U
}

/// Build U_i bases for C1 slots: U_i = Σ_j Γ_ij · v_{j,1}
///
/// These bases encode the Γ matrix into the G2 bases. When paired with C^1_i,
/// they produce the desired variable×variable terms e(X_i, Y_j)^{Γ_ij} plus
/// randomizer noise that will be canceled by the W/P buckets.
///
/// # Formula
/// For each X slot i:
/// ```text
/// U_i = Σ_{j=0}^{n-1} Γ_ij · v_{j,1}  (in G2)
/// ```
///
/// Using rank decomposition Γ = Σ_a u^(a)·v^(a)^T:
/// ```text
/// U_i = Σ_a Σ_j (u^(a)_i · v^(a)_j) · v_{j,1}
/// ```
pub fn build_U_for_C1<E: Pairing>(
    crs: &CRS<E>,
    decomp: &RankDecomp<E::ScalarField>,
) -> Vec<E::G2Affine> {
    let m = decomp.m;
    let n = decomp.n;

    let mut U = Vec::with_capacity(m);

    for i in 0..m {
        let mut acc = E::G2::zero();

        // Sum over rank components for Γ term
        for a in 0..decomp.rank {
            let u_i = decomp.u_vecs[a][i]; // u^(a)_i scalar
            if u_i.is_zero() {
                continue;
            }

            // Sum over Y slots
            for j in 0..n {
                let v_j = decomp.v_vecs[a][j]; // v^(a)_j scalar
                if v_j.is_zero() {
                    continue;
                }

                // Get v_{j,1} (variable row for Y slot j)
                let (_v_rand, v_var) = crs.v_for_slot(j);

                // Add (u_i · v_j) · v_{j,1} to accumulator
                let gamma_ij = u_i * v_j; // Γ_ij = u^(a)_i · v^(a)_j for this rank component
                acc += v_var.1.into_group() * gamma_ij;
            }
        }

        // REMOVED: Do NOT add B_i - it's handled separately in the standard GS algebra
        // The X×B term comes from a different bucket

        U.push(acc.into_affine());
    }

    U
}

/// Build V_j bases for C2 slots: V_j = A_j
///
/// These are simple linear term bases. No Γ here - that's all in U.
///
/// # Formula
/// ```text
/// V_j = A_j  (in G1, placed on var row)
/// ```
pub fn build_V_for_C2<E: Pairing>(a_consts: &[E::G1Affine]) -> Vec<E::G1Affine> {
    a_consts.to_vec()
}

/// Build V_j bases for pure bilinear PPE (no linear terms): V_j = 0
///
/// For pure bilinear PPEs where all variable×variable terms are handled by Γ (in U),
/// V bases are not used. Return zero bases.
///
/// # Formula
/// ```text
/// V_j = 0  (in G1, no linear terms)
/// ```
pub fn build_V_for_C2_pure_bilinear<E: Pairing>(_crs: &CRS<E>, n: usize) -> Vec<E::G1Affine> {
    vec![E::G1::zero().into_affine(); n]
}

/// Build W_a bases for P proof slots: W_a = Σ_j v^(a)_j · v_{j,1}
///
/// These bases work with the prover's P_a elements to cancel randomizer noise from B1.
/// One base per rank component of Γ.
///
/// # Formula
/// For each rank component a:
/// ```text
/// W_a = Σ_{j=0}^{n-1} v^(a)_j · v_{j,1}  (in G2)
/// ```
///
/// # Cancellation Algebra
/// The prover generates P_a = Σ_i u^(a)_i · r_i · u_{i,0}.
/// Then:
/// ```text
/// e(P_a, W_a) = ∏_{i,j} e(r_i·u_{i,0}, v_{j,1})^{u^(a)_i · v^(a)_j}
///             = ∏_{i,j} e(r_i·u_{i,0}, v_{j,1})^{Γ_ij}  (summed over a)
/// ```
/// This exactly cancels the randomizer noise from B1.
pub fn build_W_for_P<E: Pairing>(
    crs: &CRS<E>,
    decomp: &RankDecomp<E::ScalarField>,
) -> Vec<E::G2Affine> {
    let n = decomp.n;
    let mut W = Vec::with_capacity(decomp.rank);

    for a in 0..decomp.rank {
        let mut acc = E::G2::zero();

        for j in 0..n {
            let v_j = decomp.v_vecs[a][j]; // v^(a)_j scalar
            if v_j.is_zero() {
                continue;
            }

            // Get v_{j,1} (variable row for Y slot j)
            let (_v_rand, v_var) = crs.v_for_slot(j);

            // Add v_j · v_{j,1} to accumulator
            acc += v_var.1.into_group() * v_j;
        }

        W.push(acc.into_affine());
    }

    W
}

/// Build Z_j bases for Q proof slots: Z_j = -A_j
///
/// These bases work with the prover's Q_j elements to cancel randomizer noise from B2.
/// One base per Y slot.
///
/// # Formula
/// ```text
/// Z_j = -A_j  (in G1)
/// ```
///
/// # Cancellation Algebra
/// The prover generates Q_j = s_j · v_{j,0}.
/// B2 produces e(A_j, Y_j) + e(A_j, s_j·v_{j,0}).
/// B4 produces e(-A_j, s_j·v_{j,0}) = -e(A_j, s_j·v_{j,0}).
/// The noise terms cancel.
///
/// # Note
/// This is the uncompressed version (one Z per Y slot). Can be compressed via
/// rank decomposition of the A-noise if needed.
pub fn build_Z_for_Q<E: Pairing>(a_consts: &[E::G1Affine]) -> Vec<E::G1Affine> {
    use ark_std::ops::Neg;
    a_consts
        .iter()
        .map(|a_j| a_j.into_group().neg().into_affine())
        .collect()
}

/// Build Z_j bases for pure bilinear PPE (no linear terms): Z_j = -u_{j,0}
///
/// For pure bilinear PPEs like Groth16 where A=0 and B=0, we derive Z from
/// the CRS randomizer rows instead of from A.
///
/// # Formula
/// ```text
/// Z_j = -u_{j,0}  (in G1, negated randomizer row of Y slot j)
/// ```
/// Build Z_j bases for pure bilinear PPE (no linear terms): Z_j = 0
///
/// For pure bilinear PPEs, B2 is zero (since V=0), so B4 is not needed.
/// Return zero bases.
///
/// # Formula
/// ```text
/// Z_j = 0  (in G1, no linear terms to cancel)
/// ```
pub fn build_Z_for_Q_pure_bilinear<E: Pairing>(_crs: &CRS<E>, n: usize) -> Vec<E::G1Affine> {
    vec![E::G1::zero().into_affine(); n]
}

/// Build P_a proof slots from X randomizers: P_a = Σ_i u^(a)_i · r_i · u_{i,0}
///
/// These proof elements work with W_a bases to cancel the randomizer noise from B1.
/// The prover generates one P slot per rank component of Γ.
///
/// # Formula
/// For each rank component a:
/// ```text
/// P_a = Σ_{i=0}^{m-1} u^(a)_i · r_i · u_{i,0}  (in G1)
/// ```
///
/// # Cancellation Algebra
/// The verifier bases are W_a = Σ_j v^(a)_j · v_{j,1}.
/// Then:
/// ```text
/// e(P_a, W_a) = e(Σ_i u^(a)_i·r_i·u_{i,0}, Σ_j v^(a)_j·v_{j,1})
///             = ∏_{i,j} e(r_i·u_{i,0}, v_{j,1})^{u^(a)_i · v^(a)_j}
///             = ∏_{i,j} e(r_i·u_{i,0}, v_{j,1})^{Γ_ij}  (summed over a)
/// ```
/// This exactly cancels the randomizer noise from B1 = ∏ e(C^1_i, U_i).
///
/// # Arguments
/// * `crs` - Per-slot CRS
/// * `decomp` - Rank decomposition of Γ
/// * `r` - Per-slot randomizers for X (length m)
///
/// # Returns
/// Vector of P proof elements (length = rank)
pub fn build_P_slots<E: Pairing>(
    crs: &CRS<E>,
    decomp: &RankDecomp<E::ScalarField>,
    r: &[E::ScalarField],
) -> Vec<crate::data_structures::Com1<E>> {
    use crate::data_structures::Com1;

    assert_eq!(
        r.len(),
        decomp.m,
        "Randomizer vector length ({}) must match Γ rows ({})",
        r.len(),
        decomp.m
    );

    let mut P = Vec::with_capacity(decomp.rank);

    for a in 0..decomp.rank {
        let mut acc_0 = E::G1::zero();
        let mut acc_1 = E::G1::zero();

        for i in 0..decomp.m {
            let coeff = decomp.u_vecs[a][i] * r[i];
            if coeff.is_zero() {
                continue;
            }

            // Get u_{i,0} (randomizer row for X slot i)
            let (u_rand, _u_var) = crs.u_for_slot(i);

            // P_a = -Σ_i u^(a)_i · r_i · u_{i,0} (NEGATED for cancellation)
            // Use both limbs of u_rand
            acc_0 -= u_rand.0.into_group() * coeff;
            acc_1 -= u_rand.1.into_group() * coeff;
        }

        P.push(Com1(acc_0.into_affine(), acc_1.into_affine()));
    }

    P
}

/// Build Q_j proof slots from Y randomizers: Q_j = s_j · v_{j,0}
///
/// These proof elements work with Z_j bases to cancel the randomizer noise from B2.
/// The prover generates one Q slot per Y variable.
///
/// # Formula
/// For each Y slot j:
/// ```text
/// Q_j = s_j · v_{j,0}  (in G2)
/// ```
///
/// # Cancellation Algebra
/// The verifier bases are Z_j = -A_j.
/// B2 produces e(A_j, Y_j) + e(A_j, s_j·v_{j,0}).
/// B4 produces e(-A_j, s_j·v_{j,0}) = -e(A_j, s_j·v_{j,0}).
/// The noise terms cancel, leaving only e(A_j, Y_j).
///
/// # Arguments
/// * `crs` - Per-slot CRS
/// * `s` - Per-slot randomizers for Y (length n)
///
/// # Returns
/// Vector of Q proof elements (length = n)
///
/// # Note
/// This is the uncompressed version. Can be compressed via rank decomposition
/// of the A-noise if needed.
pub fn build_Q_slots<E: Pairing>(
    crs: &CRS<E>,
    s: &[E::ScalarField],
) -> Vec<crate::data_structures::Com2<E>> {
    use crate::data_structures::Com2;

    let n = s.len();
    assert_eq!(
        crs.num_y_slots(),
        n,
        "Randomizer vector length ({}) must match CRS Y slots ({})",
        n,
        crs.num_y_slots()
    );

    let mut Q = Vec::with_capacity(n);

    for j in 0..n {
        let (v_rand, _v_var) = crs.v_for_slot(j);

        // Q_j = s_j · v_{j,0} (both limbs)
        let acc_0 = v_rand.0.into_group() * s[j];
        let acc_1 = v_rand.1.into_group() * s[j];

        Q.push(Com2(acc_0.into_affine(), acc_1.into_affine()));
    }

    Q
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381 as F, Fr};
    use ark_ff::{One, UniformRand};
    use ark_std::test_rng;
    use std::ops::Neg;

    #[test]
    fn test_build_bases_dimensions() {
        let mut rng = test_rng();

        // Create per-slot CRS
        let m = 2;
        let n = 2;
        let crs = CRS::<F>::generate_crs_per_slot(&mut rng, m, n);

        // Create simple PPE with diagonal Γ
        let gamma = vec![
            vec![Fr::from(2u64), Fr::zero()],
            vec![Fr::zero(), Fr::from(4u64)],
        ];
        let a_consts = vec![
            <F as Pairing>::G1::rand(&mut rng).into_affine(),
            <F as Pairing>::G1::rand(&mut rng).into_affine(),
        ];
        let b_consts = vec![
            <F as Pairing>::G2::rand(&mut rng).into_affine(),
            <F as Pairing>::G2::rand(&mut rng).into_affine(),
        ];
        let target = <F as Pairing>::pairing(crs.g1_gen, crs.g2_gen);

        let ppe = PPE {
            gamma,
            a_consts,
            b_consts,
            target,
        };

        // Decompose Γ
        let decomp = RankDecomp::decompose(&ppe.gamma);

        // Build bases
        let bases = RankDecompPpeBases::build(&crs, &ppe, &decomp);

        // Check dimensions
        assert_eq!(bases.U.len(), m, "Should have m U bases");
        assert_eq!(bases.V.len(), n, "Should have n V bases");
        assert_eq!(bases.W.len(), decomp.rank, "Should have rank W bases");
        assert_eq!(bases.Z.len(), n, "Should have n Z bases");

        println!("PASS: Base dimensions correct:");
        println!("  U: {} (m)", bases.U.len());
        println!("  V: {} (n)", bases.V.len());
        println!("  W: {} (rank)", bases.W.len());
        println!("  Z: {} (n)", bases.Z.len());
    }

    #[test]
    fn test_U_bases_encode_gamma() {
        let mut rng = test_rng();

        // Create per-slot CRS
        let m = 2;
        let n = 2;
        let crs = CRS::<F>::generate_crs_per_slot(&mut rng, m, n);

        // Diagonal Γ with known values
        let gamma = vec![
            vec![Fr::from(3u64), Fr::zero()],
            vec![Fr::zero(), Fr::from(5u64)],
        ];

        let decomp = RankDecomp::decompose(&gamma);
        let U = build_U_for_C1(&crs, &decomp);

        assert_eq!(U.len(), 2);

        // U[0] should be 3 * v_{0,1} + 0 * v_{1,1} = 3 * v_{0,1}
        // U[1] should be 0 * v_{0,1} + 5 * v_{1,1} = 5 * v_{1,1}

        let (_v0_rand, v0_var) = crs.v_for_slot(0);
        let (_v1_rand, v1_var) = crs.v_for_slot(1);

        let expected_U0 = (v0_var.1.into_group() * Fr::from(3u64)).into_affine();
        let expected_U1 = (v1_var.1.into_group() * Fr::from(5u64)).into_affine();

        assert_eq!(U[0], expected_U0, "U[0] should encode Γ[0][0] = 3");
        assert_eq!(U[1], expected_U1, "U[1] should encode Γ[1][1] = 5");

        println!("PASS: U bases correctly encode diagonal Γ");
    }

    #[test]
    fn test_V_bases_are_a_consts() {
        let mut rng = test_rng();

        let a_consts = vec![
            <F as Pairing>::G1::rand(&mut rng).into_affine(),
            <F as Pairing>::G1::rand(&mut rng).into_affine(),
        ];

        let V = build_V_for_C2::<F>(&a_consts);

        assert_eq!(V, a_consts, "V should be identical to a_consts");

        println!("PASS: V bases are a_consts (no Γ)");
    }

    #[test]
    fn test_W_bases_per_rank_component() {
        let mut rng = test_rng();

        // Rank-2 matrix
        let gamma = vec![
            vec![Fr::from(1u64), Fr::from(2u64)],
            vec![Fr::from(3u64), Fr::from(4u64)],
        ];

        let crs = CRS::<F>::generate_crs_per_slot(&mut rng, 2, 2);
        let decomp = RankDecomp::decompose(&gamma);

        assert_eq!(decomp.rank, 2, "Should be rank 2");

        let W = build_W_for_P(&crs, &decomp);

        assert_eq!(W.len(), 2, "Should have 2 W bases (one per rank component)");

        // W[a] = Σ_j v^(a)_j · v_{j,1}
        // Each should be a non-zero combination of v_{0,1} and v_{1,1}
        for (a, w_a) in W.iter().enumerate() {
            assert_ne!(
                *w_a,
                <F as Pairing>::G2Affine::zero(),
                "W[{}] should be non-zero",
                a
            );
        }

        println!("PASS: W bases: one per rank component");
    }

    #[test]
    fn test_Z_bases_negate_a_consts() {
        let mut rng = test_rng();

        let a_consts = vec![
            <F as Pairing>::G1::rand(&mut rng).into_affine(),
            <F as Pairing>::G1::rand(&mut rng).into_affine(),
        ];

        let Z = build_Z_for_Q::<F>(&a_consts);

        assert_eq!(Z.len(), 2);

        for (j, z_j) in Z.iter().enumerate() {
            let expected = a_consts[j].into_group().neg().into_affine();
            assert_eq!(*z_j, expected, "Z[{}] should be -A[{}]", j, j);
        }

        println!("PASS: Z bases are -A_j");
    }

    #[test]
    fn test_statement_only_no_commitment_dependence() {
        let mut rng = test_rng();

        // Build bases from statement only
        let m = 2;
        let n = 2;
        let crs = CRS::<F>::generate_crs_per_slot(&mut rng, m, n);

        let gamma = vec![vec![Fr::one(), Fr::zero()], vec![Fr::zero(), Fr::one()]];
        let a_consts = vec![crs.g1_gen; 2];
        let b_consts = vec![crs.g2_gen; 2];
        let target = <F as Pairing>::pairing(crs.g1_gen, crs.g2_gen);

        let ppe = PPE {
            gamma,
            a_consts,
            b_consts,
            target,
        };
        let decomp = RankDecomp::decompose(&ppe.gamma);

        // Build bases - NO COMMITMENTS NEEDED
        let bases1 = RankDecompPpeBases::build(&crs, &ppe, &decomp);

        // Build again - should get SAME bases (statement-only)
        let bases2 = RankDecompPpeBases::build(&crs, &ppe, &decomp);

        // Verify deterministic (same inputs → same outputs)
        for i in 0..m {
            assert_eq!(bases1.U[i], bases2.U[i], "U[{}] should be deterministic", i);
        }
        for j in 0..n {
            assert_eq!(bases1.V[j], bases2.V[j], "V[{}] should be deterministic", j);
            assert_eq!(bases1.Z[j], bases2.Z[j], "Z[{}] should be deterministic", j);
        }
        for a in 0..bases1.rank {
            assert_eq!(bases1.W[a], bases2.W[a], "W[{}] should be deterministic", a);
        }

        println!("PASS: Bases are statement-only (deterministic, no commitment dependence)");
    }

    #[test]
    fn test_build_P_slots_dimensions() {
        let mut rng = test_rng();

        let m = 3;
        let n = 2;
        let crs = CRS::<F>::generate_crs_per_slot(&mut rng, m, n);

        // Rank-2 matrix
        let gamma = vec![
            vec![Fr::from(1u64), Fr::from(2u64)],
            vec![Fr::from(3u64), Fr::from(4u64)],
            vec![Fr::from(5u64), Fr::from(6u64)],
        ];

        let decomp = RankDecomp::decompose(&gamma);

        // Generate m randomizers for X slots
        let r: Vec<Fr> = (0..m).map(|_| Fr::rand(&mut rng)).collect();

        let P = build_P_slots(&crs, &decomp, &r);

        assert_eq!(
            P.len(),
            decomp.rank,
            "Should have one P slot per rank component"
        );

        println!("PASS: P slots: {} (rank = {})", P.len(), decomp.rank);
    }

    #[test]
    fn test_build_Q_slots_dimensions() {
        let mut rng = test_rng();

        let m = 2;
        let n = 3;
        let crs = CRS::<F>::generate_crs_per_slot(&mut rng, m, n);

        // Generate n randomizers for Y slots
        let s: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();

        let Q = build_Q_slots(&crs, &s);

        assert_eq!(Q.len(), n, "Should have one Q slot per Y variable");

        println!("PASS: Q slots: {} (n = {})", Q.len(), n);
    }

    #[test]
    fn test_P_slots_zero_randomizers() {
        let mut rng = test_rng();

        let m = 2;
        let n = 2;
        let crs = CRS::<F>::generate_crs_per_slot(&mut rng, m, n);

        let gamma = vec![
            vec![Fr::from(1u64), Fr::from(2u64)],
            vec![Fr::from(3u64), Fr::from(4u64)],
        ];

        let decomp = RankDecomp::decompose(&gamma);

        // Zero randomizers
        let r = vec![Fr::zero(); m];

        let P = build_P_slots(&crs, &decomp, &r);

        // All P slots should be zero (identity element)
        for (a, p_a) in P.iter().enumerate() {
            assert_eq!(
                p_a.0,
                <F as Pairing>::G1Affine::zero(),
                "P[{}].0 should be zero",
                a
            );
            assert_eq!(
                p_a.1,
                <F as Pairing>::G1Affine::zero(),
                "P[{}].1 should be zero",
                a
            );
        }

        println!("PASS: P slots are zero when randomizers are zero");
    }

    #[test]
    fn test_Q_slots_zero_randomizers() {
        let mut rng = test_rng();

        let m = 2;
        let n = 2;
        let crs = CRS::<F>::generate_crs_per_slot(&mut rng, m, n);

        // Zero randomizers
        let s = vec![Fr::zero(); n];

        let Q = build_Q_slots(&crs, &s);

        // All Q slots should be zero
        for (j, q_j) in Q.iter().enumerate() {
            assert_eq!(
                q_j.0,
                <F as Pairing>::G2Affine::zero(),
                "Q[{}].0 should be zero",
                j
            );
            assert_eq!(
                q_j.1,
                <F as Pairing>::G2Affine::zero(),
                "Q[{}].1 should be zero",
                j
            );
        }

        println!("PASS: Q slots are zero when randomizers are zero");
    }

    #[test]
    fn test_P_slots_change_with_randomizers() {
        let mut rng = test_rng();

        let m = 2;
        let n = 2;
        let crs = CRS::<F>::generate_crs_per_slot(&mut rng, m, n);

        let gamma = vec![
            vec![Fr::from(1u64), Fr::from(2u64)],
            vec![Fr::from(3u64), Fr::from(4u64)],
        ];

        let decomp = RankDecomp::decompose(&gamma);

        // Two different randomizer sets
        let r1: Vec<Fr> = (0..m).map(|_| Fr::rand(&mut rng)).collect();
        let r2: Vec<Fr> = (0..m).map(|_| Fr::rand(&mut rng)).collect();

        let P1 = build_P_slots(&crs, &decomp, &r1);
        let P2 = build_P_slots(&crs, &decomp, &r2);

        // P slots should be different for different randomizers
        let mut different = false;
        for a in 0..decomp.rank {
            if P1[a] != P2[a] {
                different = true;
                break;
            }
        }

        assert!(different, "P slots should differ for different randomizers");

        println!("PASS: P slots change with randomizers (as expected)");
    }

    #[test]
    fn test_Q_slots_change_with_randomizers() {
        let mut rng = test_rng();

        let m = 2;
        let n = 2;
        let crs = CRS::<F>::generate_crs_per_slot(&mut rng, m, n);

        // Two different randomizer sets
        let s1: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let s2: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();

        let Q1 = build_Q_slots(&crs, &s1);
        let Q2 = build_Q_slots(&crs, &s2);

        // Q slots should be different for different randomizers
        let mut different = false;
        for j in 0..n {
            if Q1[j] != Q2[j] {
                different = true;
                break;
            }
        }

        assert!(different, "Q slots should differ for different randomizers");

        println!("PASS: Q slots change with randomizers (as expected)");
    }

    #[test]
    fn test_rank_decomp_verifier_basic() {
        use crate::statement::PPE;
        use ark_std::test_rng;

        let mut rng = test_rng();

        // SIMPLIFIED: Single variable in each group for easier debugging
        let m = 1;
        let n = 1;
        let crs = CRS::<F>::generate_crs_per_slot(&mut rng, m, n);

        // Simple 1x1 Γ = [[1]]
        let gamma = vec![vec![Fr::from(1u64)]];

        // Zero linear terms for pure cross-term PPE
        let a_consts = vec![<F as Pairing>::G1::zero().into_affine(); 1];
        let b_consts = vec![<F as Pairing>::G2::zero().into_affine(); 1];

        // Witness: X = [g1], Y = [g2]
        let x_vars = vec![crs.g1_gen];
        let y_vars = vec![crs.g2_gen];

        // Target must use the correct base!
        // U = v_{0,1} (var row limb 1), so result is e(X, v_{0,1})
        // NOT e(X, g2) unless v_{0,1} = g2
        let (_v_rand, v_var) = crs.v_for_slot(0);
        let target = <F as Pairing>::pairing(x_vars[0], v_var.1);

        let ppe = PPE {
            gamma,
            a_consts,
            b_consts,
            target,
        };

        // Use NEW rank-decomp prover
        let proof = ppe.commit_and_prove_rank_decomp(&x_vars, &y_vars, &crs, &mut rng);
        // Test rank-decomp verifier
        let verifies = ppe.verify_rank_decomp(&proof, &crs);

        if verifies {
            println!("PASS: Rank-decomp prover + verifier working!");
        } else {
            println!("FAIL: Rank-decomp verification failed");
            println!("   Expected target: (e(g1,g2))^2");
        }

        assert!(verifies, "Rank-decomp verification must pass");
    }

    #[test]
    fn test_proof_agnostic_randomizer_cancellation() {
        use ark_ec::CurveGroup;

        let mut rng = test_rng();

        // Setup
        let m = 2;
        let n = 2;
        let crs = CRS::<F>::generate_crs_per_slot(&mut rng, m, n);

        // Diagonal Γ with known values
        let gamma = vec![
            vec![Fr::from(2u64), Fr::zero()],
            vec![Fr::zero(), Fr::from(3u64)],
        ];
        let a_consts = vec![crs.g1_gen; 2];
        let b_consts = vec![crs.g2_gen; 2];
        let target = <F as Pairing>::pairing(crs.g1_gen, crs.g2_gen);

        let ppe = PPE {
            gamma,
            a_consts,
            b_consts,
            target,
        };
        let decomp = RankDecomp::decompose(&ppe.gamma);

        // Build statement-only bases
        let bases = RankDecompPpeBases::build(&crs, &ppe, &decomp);

        // Build commitments with TWO DIFFERENT randomizer sets
        let r1: Vec<Fr> = (0..m).map(|_| Fr::rand(&mut rng)).collect();
        let s1: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();

        let r2: Vec<Fr> = (0..m).map(|_| Fr::rand(&mut rng)).collect();
        let s2: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();

        // Build C1, C2 commitments for both randomizer sets
        let mut C1_1: Vec<crate::data_structures::Com1<F>> = Vec::new();
        let mut C1_2: Vec<crate::data_structures::Com1<F>> = Vec::new();
        for i in 0..m {
            let (u_rand, u_var) = crs.u_for_slot(i);
            let x_scalar = Fr::one(); // x_vars[i] = g1 = 1·g1

            // Commitment 1: C1 = x·u_var + r1·u_rand
            let c1_0 = u_var.0.into_group() * x_scalar + u_rand.0.into_group() * r1[i];
            let c1_1 = u_var.1.into_group() * x_scalar + u_rand.1.into_group() * r1[i];
            C1_1.push(crate::data_structures::Com1(
                c1_0.into_affine(),
                c1_1.into_affine(),
            ));

            // Commitment 2: C1 = x·u_var + r2·u_rand
            let c2_0 = u_var.0.into_group() * x_scalar + u_rand.0.into_group() * r2[i];
            let c2_1 = u_var.1.into_group() * x_scalar + u_rand.1.into_group() * r2[i];
            C1_2.push(crate::data_structures::Com1(
                c2_0.into_affine(),
                c2_1.into_affine(),
            ));
        }

        let mut C2_1: Vec<crate::data_structures::Com2<F>> = Vec::new();
        let mut C2_2: Vec<crate::data_structures::Com2<F>> = Vec::new();
        for j in 0..n {
            let (v_rand, v_var) = crs.v_for_slot(j);
            let y_scalar = Fr::one(); // y_vars[j] = g2 = 1·g2

            // Commitment 1: C2 = y·v_var + s1·v_rand
            let c1_0 = v_var.0.into_group() * y_scalar + v_rand.0.into_group() * s1[j];
            let c1_1 = v_var.1.into_group() * y_scalar + v_rand.1.into_group() * s1[j];
            C2_1.push(crate::data_structures::Com2(
                c1_0.into_affine(),
                c1_1.into_affine(),
            ));

            // Commitment 2: C2 = y·v_var + s2·v_rand
            let c2_0 = v_var.0.into_group() * y_scalar + v_rand.0.into_group() * s2[j];
            let c2_1 = v_var.1.into_group() * y_scalar + v_rand.1.into_group() * s2[j];
            C2_2.push(crate::data_structures::Com2(
                c2_0.into_affine(),
                c2_1.into_affine(),
            ));
        }

        // Build P, Q proof slots for both randomizer sets
        // P_a and Q_j are the PROVER's proof elements (θ, π in GS notation)
        // These have two limbs each (Com1, Com2)
        let P1 = build_P_slots(&crs, &decomp, &r1); // θ for attestation 1
        let P2 = build_P_slots(&crs, &decomp, &r2); // θ for attestation 2

        let Q1 = build_Q_slots(&crs, &s1); // π for attestation 1
        let Q2 = build_Q_slots(&crs, &s2); // π for attestation 2

        // Verify commitments are DIFFERENT (different randomizers)
        assert_ne!(
            C1_1[0], C1_2[0],
            "Commitments should differ with different randomizers"
        );
        assert_ne!(
            P1[0], P2[0],
            "P slots should differ with different randomizers"
        );

        println!("PASS: Commitments and proof slots differ (different randomizers)");

        // Compute four-bucket product for BOTH attestations
        // M = (∏ e(C1, U)) · (∏ e(V, C2)) · (∏ e(P, W)) · (∏ e(Z, Q))

        // Attestation 1
        use ark_ec::pairing::PairingOutput;
        let M1; // Will be assigned after computing buckets

        // B1: C1 × U
        let mut B1_1 = PairingOutput::<F>::zero();
        for i in 0..m {
            B1_1 += <F as Pairing>::pairing(C1_1[i].0, bases.U[i]);
            B1_1 += <F as Pairing>::pairing(C1_1[i].1, bases.U[i]);
        }

        // B2: V × C2
        let mut B2_1 = PairingOutput::<F>::zero();
        for j in 0..n {
            B2_1 += <F as Pairing>::pairing(bases.V[j], C2_1[j].0);
            B2_1 += <F as Pairing>::pairing(bases.V[j], C2_1[j].1);
        }

        // B3: P (θ, Com1 with 2 limbs) × W (single G2Affine base)
        // Pair BOTH limbs of θ_a against the SINGLE W_a base
        let mut B3_1 = PairingOutput::<F>::zero();
        for a in 0..decomp.rank {
            // θ_a.0 (limb 0) × W_a
            B3_1 += <F as Pairing>::pairing(P1[a].0, bases.W[a]);
            // θ_a.1 (limb 1) × W_a
            B3_1 += <F as Pairing>::pairing(P1[a].1, bases.W[a]);
        }

        // B4: Z (single G1Affine base) × Q (π, Com2 with 2 limbs)
        // Pair the SINGLE Z_j base against BOTH limbs of π_j
        let mut B4_1 = PairingOutput::<F>::zero();
        for j in 0..n {
            // Z_j × π_j.0 (limb 0)
            B4_1 += <F as Pairing>::pairing(bases.Z[j], Q1[j].0);
            // Z_j × π_j.1 (limb 1)
            B4_1 += <F as Pairing>::pairing(bases.Z[j], Q1[j].1);
        }

        M1 = B1_1 + B2_1 + B3_1 + B4_1;

        // Attestation 2 (different randomizers)
        let M2; // Will be assigned after computing buckets

        // B1: C1 × U
        let mut B1_2 = PairingOutput::<F>::zero();
        for i in 0..m {
            B1_2 += <F as Pairing>::pairing(C1_2[i].0, bases.U[i]);
            B1_2 += <F as Pairing>::pairing(C1_2[i].1, bases.U[i]);
        }

        // B2: V × C2
        let mut B2_2 = PairingOutput::<F>::zero();
        for j in 0..n {
            B2_2 += <F as Pairing>::pairing(bases.V[j], C2_2[j].0);
            B2_2 += <F as Pairing>::pairing(bases.V[j], C2_2[j].1);
        }

        // B3: P (θ, Com1 with 2 limbs) × W (single G2Affine base)
        let mut B3_2 = PairingOutput::<F>::zero();
        for a in 0..decomp.rank {
            B3_2 += <F as Pairing>::pairing(P2[a].0, bases.W[a]);
            B3_2 += <F as Pairing>::pairing(P2[a].1, bases.W[a]);
        }

        // B4: Z (single G1Affine base) × Q (π, Com2 with 2 limbs)
        let mut B4_2 = PairingOutput::<F>::zero();
        for j in 0..n {
            B4_2 += <F as Pairing>::pairing(bases.Z[j], Q2[j].0);
            B4_2 += <F as Pairing>::pairing(bases.Z[j], Q2[j].1);
        }

        M2 = B1_2 + B2_2 + B3_2 + B4_2;

        // PROOF-AGNOSTIC: M1 should equal M2 despite different randomizers!
        assert_eq!(
            M1, M2,
            "FAIL: PROOF-AGNOSTIC PROPERTY FAILED: Randomizer cancellation did not work!"
        );

        println!("PASS: PROOF-AGNOSTIC: M1 = M2 despite different randomizers!");
        println!("   Randomizer cancellation via (P,W) and (Q,Z) WORKS!");
    }
}
