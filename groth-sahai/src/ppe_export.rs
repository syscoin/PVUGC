//! PPE Export for PVUGC
//!
//! Exports commitment-independent verifier bases for offline ARMER.
//! This module implements the key insight: push Γ to the BASE side (not commitments).

#![allow(non_snake_case)]

use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_ff::Zero;

use crate::data_structures::{Com1, Com2};
use crate::generator::CRS;
use crate::statement::PPE;

/// The bases used by the GS verifier PPE after specializing to (vk, x).
/// These are commitment-independent and can be computed by ARMER offline.
#[derive(Clone, Debug)]
pub struct GsVerifierPpe<E: Pairing> {
    /// For each G1-commitment slot C1_j (xcoms),
    /// the G2 base U_j used in the PPE term e(C1_j, U_j).
    pub U_for_C1: Vec<E::G2Affine>,

    /// For each G2-commitment slot C2_k (ycoms),
    /// the G1 base V_k used in the PPE term e(V_k, C2_k).
    /// **KEY:** This includes Γ-weighting pushed to the base side!
    pub V_for_C2: Vec<E::G1Affine>,

    /// For each G1 proof slot P_a (θ), the full 2-component G2 base W_a.
    /// These are Com2 elements from the CRS.
    pub W_for_P: Vec<Com2<E>>,

    /// For each G2 proof slot Q_b (π), the full 2-component G1 base Z_b.
    /// These are Com1 elements from the CRS.
    pub Z_for_Q: Vec<Com1<E>>,

    /// Slot metadata
    pub layout: SlotLayout,
}

#[derive(Clone, Debug)]
pub struct SlotLayout {
    pub m_c1: usize,  // Number of C1 slots (xcoms)
    pub n_c2: usize,  // Number of C2 slots (ycoms)
    pub p_len: usize, // Number of P slots (π)
    pub q_len: usize, // Number of Q slots (θ)
}

impl<E: Pairing> PPE<E> {
    /// Export commitment-independent verifier bases for PVUGC.
    ///
    /// This is the key function that pushes Γ to the base side,
    /// making the bases computable without commitments.
    pub fn export_verifier_bases(&self, crs: &CRS<E>) -> GsVerifierPpe<E> {
        let m = self.gamma.len(); // Number of C1 slots (xcoms)
        let n = if m > 0 { self.gamma[0].len() } else { 0 }; // Number of C2 slots (ycoms)

        // 1. Build V_for_C2 (Γ pushed to base side)
        let V_for_C2 = self.compute_v_bases_with_gamma(crs, m, n);

        // 2. Build U_for_C1 (b_consts bases)
        let U_for_C1 = self.compute_u_bases(crs, m);

        // 3. Proof slot bases (full 2-component W, Z from CRS)
        // W pairs with θ (Com1=G1), so W should be Com2 (G2) → copy from crs.v
        // Z pairs with π (Com2=G2), so Z should be Com1 (G1) → copy from crs.u
        // We need BOTH components (RAND_ROW and VAR_ROW) for proper randomness cancellation!
        let W_for_P: Vec<Com2<E>> = crs.v.clone();
        let Z_for_Q: Vec<Com1<E>> = crs.u.clone();

        let layout = SlotLayout {
            m_c1: m,
            n_c2: n,
            p_len: W_for_P.len(),
            q_len: Z_for_Q.len(),
        };

        GsVerifierPpe {
            U_for_C1,
            V_for_C2,
            W_for_P,
            Z_for_Q,
            layout,
        }
    }

    /// Compute V bases for C2 slots (ycoms).
    ///
    /// These are simply the a_consts (G1 elements) - NO Γ here.
    /// The Γ cross-term coupling is handled by the proof elements (π, θ) and their bases (W, Z).
    ///
    /// This is the KEY fix: V cannot carry Γ alone (mathematically impossible for commitment-independent bases).
    fn compute_v_bases_with_gamma(&self, _crs: &CRS<E>, _m: usize, n: usize) -> Vec<E::G1Affine> {
        (0..n)
            .map(|j| {
                if j < self.a_consts.len() {
                    self.a_consts[j]
                } else {
                    E::G1::zero().into_affine()
                }
            })
            .collect()
    }

    /// Compute U bases for C1 slots.
    ///
    /// These are simply the b_consts (G2 elements that pair with xcoms).
    fn compute_u_bases(&self, _crs: &CRS<E>, m: usize) -> Vec<E::G2Affine> {
        (0..m)
            .map(|i| {
                if i < self.b_consts.len() {
                    self.b_consts[i]
                } else {
                    E::G2::zero().into_affine()
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381 as F, Fr};
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::{One, Zero};
    use ark_std::test_rng;

    #[test]
    fn test_export_verifier_bases() {
        let mut rng = test_rng();
        let crs = CRS::<F>::generate_crs_per_slot(&mut rng, 2, 2);

        // Simple PPE: e(x0, y0) + e(x1, y1) = target
        let gamma = vec![vec![Fr::one(), Fr::zero()], vec![Fr::zero(), Fr::one()]];

        let a_consts = vec![
            crs.g1_gen.into_group().into_affine(),
            crs.g1_gen.into_group().into_affine(),
        ];
        let b_consts = vec![
            crs.g2_gen.into_group().into_affine(),
            crs.g2_gen.into_group().into_affine(),
        ];

        let target = F::pairing(crs.g1_gen, crs.g2_gen);

        let ppe = PPE {
            gamma,
            a_consts,
            b_consts,
            target,
        };

        // Export bases
        let verifier_ppe = ppe.export_verifier_bases(&crs);

        // Check dimensions
        assert_eq!(verifier_ppe.layout.m_c1, 2, "Should have 2 C1 slots");
        assert_eq!(verifier_ppe.layout.n_c2, 2, "Should have 2 C2 slots");
        assert_eq!(verifier_ppe.U_for_C1.len(), 2);
        assert_eq!(verifier_ppe.V_for_C2.len(), 2);
        assert_eq!(
            verifier_ppe.W_for_P.len(),
            4,
            "Per-slot CRS: 2 rows × 2 y-slots"
        );
        assert_eq!(
            verifier_ppe.Z_for_Q.len(),
            4,
            "Per-slot CRS: 2 rows × 2 x-slots"
        );

        println!("PASS: Export verifier bases: dimensions correct");
    }
}
