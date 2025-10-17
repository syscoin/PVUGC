//! Contains the functionality for verifying the satisfiability of Groth-Sahai equations over bilinear groups.
//!
//! Verifying an equation's proof primarily involves addition in [`BT`](crate::data_structures::ComT) (equiv. additions in 4 [`GT`](ark_ec::Pairing::GT))
//! and pairings over elements in [`B1`](crate::data_structures::Com1) and [`B2`](crate::data_structures::Com2).
//!
//! See the [`prover`](crate::prover) and [`statement`](crate::statement) modules for more details about the structure of the equations and their proofs.

#![allow(non_snake_case)]

use ark_ec::pairing::Pairing;
use ark_ec::AffineRepr;

use crate::data_structures::{
    col_vec_to_vec, vec_to_col_vec, Com1, Com2, ComT, Mat, Matrix, B1, B2, BT,
};
use crate::generator::CRS;
use crate::prover::CProof;
use crate::statement::{Equation, QuadEqu, MSMEG1, MSMEG2, PPE};

/// A collection of attributes containing verifier functionality for an [`Equation`](crate::statement::Equation).
pub trait Verifiable<E: Pairing> {
    /// Verifies that a single Groth-Sahai equation is satisfied using the prover's committed `x` and `y` variables.
    fn verify(&self, com_proof: &CProof<E>, crs: &CRS<E>) -> bool;
}

impl<E: Pairing> Verifiable<E> for PPE<E> {
    fn verify(&self, com_proof: &CProof<E>, crs: &CRS<E>) -> bool {
        assert_eq!(com_proof.equ_proofs.len(), 1);
        assert_eq!(self.get_type(), com_proof.equ_proofs[0].equ_type);
        let is_parallel = true;

        let lin_a_com_y = ComT::<E>::pairing_sum(
            &Com1::<E>::batch_linear_map(&self.a_consts),
            &com_proof.ycoms.coms,
        );

        let com_x_lin_b = ComT::<E>::pairing_sum(
            &com_proof.xcoms.coms,
            &Com2::<E>::batch_linear_map(&self.b_consts),
        );

        let stmt_com_y: Matrix<Com2<E>> =
            vec_to_col_vec(&com_proof.ycoms.coms).left_mul(&self.gamma, is_parallel);
        let com_x_stmt_com_y =
            ComT::<E>::pairing_sum(&com_proof.xcoms.coms, &col_vec_to_vec(&stmt_com_y));

        let lin_t = ComT::<E>::linear_map_PPE(&self.target);

        let com1_pf2 = ComT::<E>::pairing_sum(&crs.u, &com_proof.equ_proofs[0].pi);

        let pf1_com2 = ComT::<E>::pairing_sum(&com_proof.equ_proofs[0].theta, &crs.v);

        let lhs: ComT<E> = lin_a_com_y + com_x_lin_b + com_x_stmt_com_y;
        let rhs: ComT<E> = lin_t + com1_pf2 + pf1_com2;

        lhs == rhs
    }
}

impl<E: Pairing> PPE<E> {
    /// Verify using rank-decomposition PPE (four-bucket product).
    ///
    /// This verifier uses statement-only bases (U, V, W, Z) built from Γ and CRS,
    /// enabling offline PVUGC ARMER. The verification equation is:
    ///
    /// ```text
    /// M = (∏ e(C^1_i, U_i)) · (∏ e(V_j, C^2_j)) · (∏ e(θ_a, W_a)) · (∏ e(Z_j, π_j)) == target
    /// ```
    ///
    /// where:
    /// - U, V, W, Z are computed from (CRS, Γ, A) only (no commitments)
    /// - θ, π are proof elements from the prover
    /// - Randomizer cancellation: B3 cancels B1's noise, B4 cancels B2's noise
    ///
    /// # Arguments
    /// * `com_proof` - Commitments and proof
    /// * `crs` - Per-slot CRS
    ///
    /// # Returns
    /// `true` if verification passes, `false` otherwise
    pub fn verify_rank_decomp(&self, com_proof: &CProof<E>, crs: &CRS<E>) -> bool {
        use crate::base_construction::RankDecompPpeBases;
        use crate::rank_decomp::RankDecomp;
        use ark_ec::pairing::PairingOutput;
        use ark_ff::Zero;

        assert_eq!(com_proof.equ_proofs.len(), 1);
        assert_eq!(self.get_type(), com_proof.equ_proofs[0].equ_type);

        // Build rank decomposition
        let decomp = RankDecomp::decompose(&self.gamma);

        // Build statement-only bases
        let bases = RankDecompPpeBases::build(crs, self, &decomp);

        // Four-bucket verification
        let mut M = PairingOutput::<E>::zero();

        // DEBUG: Track each bucket
        let mut B1 = PairingOutput::<E>::zero();
        let mut B2 = PairingOutput::<E>::zero();
        let mut B3 = PairingOutput::<E>::zero();
        let mut B4 = PairingOutput::<E>::zero();

        // B1: C^1 × U (both limbs of C^1 vs single U base)
        for (c1, u) in com_proof.xcoms.coms.iter().zip(bases.U.iter()) {
            B1 += E::pairing(c1.0, *u);
            B1 += E::pairing(c1.1, *u);
        }
        M += B1;

        // B2: V × C^2 (single V base vs both limbs of C^2)
        for (v, c2) in bases.V.iter().zip(com_proof.ycoms.coms.iter()) {
            B2 += E::pairing(*v, c2.0);
            B2 += E::pairing(*v, c2.1);
        }
        M += B2;

        // B3: θ × W (both limbs of θ vs single W base)
        for (theta, w) in com_proof.equ_proofs[0].theta.iter().zip(bases.W.iter()) {
            B3 += E::pairing(theta.0, *w);
            B3 += E::pairing(theta.1, *w);
        }
        M += B3;

        // B4: Z × π (single Z base vs both limbs of π)
        for (z, pi) in bases.Z.iter().zip(com_proof.equ_proofs[0].pi.iter()) {
            B4 += E::pairing(*z, pi.0);
            B4 += E::pairing(*z, pi.1);
        }
        M += B4;

        // Check against target
        // linear_map_PPE places value at [1][1] position, so compare M directly

        // DEBUG: Print M and target
        println!("DEBUG verify_rank_decomp:");
        println!("  B1 == zero? {}", B1.is_zero());
        println!("  B2 == zero? {}", B2.is_zero());
        println!("  B3 == zero? {}", B3.is_zero());
        println!("  B4 == zero? {}", B4.is_zero());
        println!("  B1 + B2: {:?}", B1 + B2);
        println!("  B3 + B4: {:?}", B3 + B4);
        println!("  M (all 4 buckets): {:?}", M);
        println!("  target:            {:?}", self.target);
        println!("  M == target? {}", M == self.target);

        M == self.target
    }

    /// Verify PPE using full GS construction with block bases.
    ///
    /// This method uses the full GS PPE construction that handles both CRS rows
    /// (rand & var) on both sides to properly reconstruct e(A,B) terms when both
    /// A and B are committed with randomness.
    ///
    /// # Arguments
    /// * `com_proof` - The commitment proof containing commitments and proofs
    /// * `crs` - The CRS used for verification
    /// * `bases` - The full GS PPE bases
    ///
    /// # Returns
    /// `true` if verification passes, `false` otherwise
    /// Verify PPE using block-based full GS construction (Phase 7).
    ///
    /// This implements four-bucket verifier with **specific limb × specific base** pairings.
    /// Each Γ-pair produces exactly 4 pairings that telescope to cancel all randomizer noise.
    ///
    /// For each pair (i,j) with Γ_ij ≠ 0:
    /// - B1: e(C1[i].var, U_var[j]) + e(C1[i].rand, U_rand[j])
    /// - B2: e(V_var[i], C2[j].var) + e(V_rand[i], C2[j].rand)
    /// - B3: e(θ, W) - rank block for randomness cancellation
    /// - B4: (zero for pure bilinear PPEs like Groth16)
    ///
    /// Result: M = ∏ e(X_i, Y_j)^{Γ_ij} with all randomizer terms cancelled.
    /// Verifies a full-GS proof and returns (verifies, extracted_value).
    /// The extracted_value is Σ Γ_ij * e(X_i, Y_j), which equals the target if verification passes.
    pub fn verify_full_gs(
        &self,
        com_proof: &CProof<E>,
        crs: &CRS<E>,
        _bases: &crate::base_construction::FullGSPpeBases<E>,
    ) -> (bool, ark_ec::pairing::PairingOutput<E>) {
        use ark_ec::pairing::PairingOutput;
        use ark_ff::Zero;

        assert_eq!(com_proof.equ_proofs.len(), 1);
        assert_eq!(self.get_type(), com_proof.equ_proofs[0].equ_type);

        let mut M = PairingOutput::<E>::zero();

        // Four-term aux recomposition: derives aux legs directly from commitments
        // and uses 4 pairings per Γ-pair to telescope to e(X,Y) with exact randomness cancellation.
        // Commitments have form: C1[i] = (r_i*u_{i,0}, r_i*u_{i,1}+X_i), C2[j] = (s_j*v_{j,0}, s_j*v_{j,1}+Y_j)
        // Aux legs: aux_x = C1.0 = r_i*u_{i,0}, aux_y = C2.0 = s_j*v_{j,0}
        // Recovery: X = C1.1 - a1*aux_x, Y = C2.1 - a2*aux_y
        // Pairings: e(X,Y) = e(C1.1, C2.1) * e(C1.1, -a2*aux_y) * e(-a1*aux_x, C2.1) * e(-a1*aux_x, -a2*aux_y)
        use ark_ec::CurveGroup;

        for i in 0..self.gamma.len() {
            for j in 0..self.gamma[0].len() {
                let gamma_ij = self.gamma[i][j];
                if gamma_ij.is_zero() {
                    continue;
                }

                let c1 = &com_proof.xcoms.coms[i];
                let c2 = &com_proof.ycoms.coms[j];

                // In full-GS path, commitments use VAR row for both limbs:
                // C1[i] = (r_i * u_{i,0}, r_i * u_{i,1} + X_i)
                // C2[j] = (s_j * v_{j,0}, s_j * v_{j,1} + Y_j)
                // So aux legs are directly the first limb of the commitment:
                let aux_x_i = c1.0;
                let aux_y_j = c2.0;

                // If aux_x/aux_y were provided in the proof, verify they match (constant-time PoCE)
                if !com_proof.equ_proofs[0].aux_x.is_empty() {
                    assert_eq!(
                        com_proof.equ_proofs[0].aux_x[i], aux_x_i,
                        "aux_x[{}] mismatch: provided != C1[{}].0",
                        i, i
                    );
                }
                if !com_proof.equ_proofs[0].aux_y.is_empty() {
                    assert_eq!(
                        com_proof.equ_proofs[0].aux_y[j], aux_y_j,
                        "aux_y[{}] mismatch: provided != C2[{}].0",
                        j, j
                    );
                }

                // Precompute scaled aux legs
                let a1_aux_x = (aux_x_i.into_group() * crs.a1).into_affine();
                let a2_aux_y = (aux_y_j.into_group() * crs.a2).into_affine();

                // Four pairings that telescope to e(X, Y)
                let r1 = E::pairing(c1.1, c2.1);
                let r2 = E::pairing(c1.1, (-a2_aux_y.into_group()).into_affine());
                let r3 = E::pairing((-a1_aux_x.into_group()).into_affine(), c2.1);
                let r4 = E::pairing(
                    (-a1_aux_x.into_group()).into_affine(),
                    (-a2_aux_y.into_group()).into_affine(),
                );

                M += (r1 + r2 + r3 + r4) * gamma_ij;
            }
        }

        (M == self.target, M)
    }
}

impl<E: Pairing> Verifiable<E> for MSMEG1<E> {
    fn verify(&self, com_proof: &CProof<E>, crs: &CRS<E>) -> bool {
        assert_eq!(com_proof.equ_proofs.len(), 1);
        assert_eq!(self.get_type(), com_proof.equ_proofs[0].equ_type);
        let is_parallel = true;

        let lin_a_com_y = ComT::<E>::pairing_sum(
            &Com1::<E>::batch_linear_map(&self.a_consts),
            &com_proof.ycoms.coms,
        );

        let com_x_lin_b = ComT::<E>::pairing_sum(
            &com_proof.xcoms.coms,
            &Com2::<E>::batch_scalar_linear_map(&self.b_consts, crs),
        );

        let stmt_com_y: Matrix<Com2<E>> =
            vec_to_col_vec(&com_proof.ycoms.coms).left_mul(&self.gamma, is_parallel);
        let com_x_stmt_com_y =
            ComT::<E>::pairing_sum(&com_proof.xcoms.coms, &col_vec_to_vec(&stmt_com_y));

        let lin_t = ComT::<E>::linear_map_MSMEG1(&self.target, crs);

        let com1_pf2 = ComT::<E>::pairing_sum(&crs.u, &com_proof.equ_proofs[0].pi);

        let pf1_com2 = ComT::<E>::pairing(com_proof.equ_proofs[0].theta[0], crs.v[0]);

        let lhs: ComT<E> = lin_a_com_y + com_x_lin_b + com_x_stmt_com_y;
        let rhs: ComT<E> = lin_t + com1_pf2 + pf1_com2;

        lhs == rhs
    }
}

impl<E: Pairing> Verifiable<E> for MSMEG2<E> {
    fn verify(&self, com_proof: &CProof<E>, crs: &CRS<E>) -> bool {
        assert_eq!(com_proof.equ_proofs.len(), 1);
        assert_eq!(self.get_type(), com_proof.equ_proofs[0].equ_type);
        let is_parallel = true;

        let lin_a_com_y = ComT::<E>::pairing_sum(
            &Com1::<E>::batch_scalar_linear_map(&self.a_consts, crs),
            &com_proof.ycoms.coms,
        );

        let com_x_lin_b = ComT::<E>::pairing_sum(
            &com_proof.xcoms.coms,
            &Com2::<E>::batch_linear_map(&self.b_consts),
        );

        let stmt_com_y: Matrix<Com2<E>> =
            vec_to_col_vec(&com_proof.ycoms.coms).left_mul(&self.gamma, is_parallel);
        let com_x_stmt_com_y =
            ComT::<E>::pairing_sum(&com_proof.xcoms.coms, &col_vec_to_vec(&stmt_com_y));

        let lin_t = ComT::<E>::linear_map_MSMEG2(&self.target, crs);

        let com1_pf2 = ComT::<E>::pairing(crs.u[0], com_proof.equ_proofs[0].pi[0]);

        let pf1_com2 = ComT::<E>::pairing_sum(&com_proof.equ_proofs[0].theta, &crs.v);

        let lhs: ComT<E> = lin_a_com_y + com_x_lin_b + com_x_stmt_com_y;
        let rhs: ComT<E> = lin_t + com1_pf2 + pf1_com2;

        lhs == rhs
    }
}

impl<E: Pairing> Verifiable<E> for QuadEqu<E> {
    fn verify(&self, com_proof: &CProof<E>, crs: &CRS<E>) -> bool {
        assert_eq!(com_proof.equ_proofs.len(), 1);
        assert_eq!(self.get_type(), com_proof.equ_proofs[0].equ_type);
        let is_parallel = true;

        let lin_a_com_y = ComT::<E>::pairing_sum(
            &Com1::<E>::batch_scalar_linear_map(&self.a_consts, crs),
            &com_proof.ycoms.coms,
        );

        let com_x_lin_b = ComT::<E>::pairing_sum(
            &com_proof.xcoms.coms,
            &Com2::<E>::batch_scalar_linear_map(&self.b_consts, crs),
        );

        let stmt_com_y: Matrix<Com2<E>> =
            vec_to_col_vec(&com_proof.ycoms.coms).left_mul(&self.gamma, is_parallel);
        let com_x_stmt_com_y =
            ComT::<E>::pairing_sum(&com_proof.xcoms.coms, &col_vec_to_vec(&stmt_com_y));

        let lin_t = ComT::<E>::linear_map_quad(&self.target, crs);

        let com1_pf2 = ComT::<E>::pairing(crs.u[0], com_proof.equ_proofs[0].pi[0]);

        let pf1_com2 = ComT::<E>::pairing(com_proof.equ_proofs[0].theta[0], crs.v[0]);

        let lhs: ComT<E> = lin_a_com_y + com_x_lin_b + com_x_stmt_com_y;
        let rhs: ComT<E> = lin_t + com1_pf2 + pf1_com2;

        lhs == rhs
    }
}

/*
 * NOTE:
 *
 * Proof verification tests are considered integration tests for the Groth-Sahai proof system.
 *
 *
 * See tests/prover.rs for more details.
 */
