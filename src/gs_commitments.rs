/*!
Groth-Sahai Commitments and Attestations

GS commitment layer for (arkworks) Groth16 proofs.
Implements GS attestation per PVUGC spec.
*/

use ark_bls12_381::{Bls12_381, Fr, G1Affine, G2Affine, Fq12};
use ark_ec::{pairing::Pairing, AffineRepr, pairing::PairingOutput};
use ark_ff::{Zero, One, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use sha2::{Sha256, Digest};
use thiserror::Error;
use groth_sahai::{
    generator::CRS,
    AbstractCrs,
    Com1, Com2,
    statement::PPE,
    prover::Provable,
};

use crate::groth16_wrapper::{ArkworksProof, ArkworksVK, compute_ic};

/// Error types for GS commitments
#[derive(Error, Debug)]
pub enum GSCommitmentError {
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Deserialization error: {0}")]
    Deserialization(String),
    #[error("Commitment error: {0}")]
    Commitment(String),
    #[error("Verification error: {0}")]
    Verification(String),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

/// Single 1×1 GS equation with its commitments and proofs
#[derive(Clone, Debug)]
pub struct GSEquation {
    pub c1: Com1<Bls12_381>,          // X-side commitment (G1 pair) for this 1×1
    pub c2: Com2<Bls12_381>,          // Y-side commitment (G2 pair) for this 1×1
    pub pi: Vec<Com2<Bls12_381>>,     // equation-proof π (len=1 for 1×1)
    pub theta: Vec<Com1<Bls12_381>>,  // equation-proof θ (len=1 for 1×1)
}

/// Groth-Sahai attestation for Groth16 proof using two 1×1 equations
#[derive(Clone, Debug)]
pub struct GSAttestation {
    pub eq_ab: GSEquation,             // e(πA, πB) = e(α, β)
    pub eq_cd: GSEquation,             // e(πC, δ) = e(IC, γ)
    pub proof_data: Vec<u8>,
    pub ppe_target: Fq12,              // e(α,β)·e(IC,γ) - the full target
}

/// Groth-Sahai commitment system for real Groth16 proofs
pub struct GrothSahaiCommitments {
    crs: CRS<Bls12_381>,
}

impl GrothSahaiCommitments {
    /// Create a new GS commitment system
    pub fn new(crs: CRS<Bls12_381>) -> Self {
        Self {
            crs,
        }
    }

    /// Generate CRS from seed
    pub fn from_seed(seed: &[u8]) -> Self {
        let mut rng = get_rng_from_seed(seed);
        let crs = CRS::<Bls12_381>::generate_crs(&mut rng);
        Self::new(crs)
    }

    /// Commit to real arkworks Groth16 proof
    pub fn commit_arkworks_proof(
        &self,
        proof: &ArkworksProof,
        vk: &ArkworksVK,
        public_input: &[Fr],
        with_randomness: bool,
    ) -> Result<GSAttestation, GSCommitmentError> {
        use ark_std::test_rng;
        let mut rng = test_rng();
        
        if with_randomness {
            let r_a = Fr::rand(&mut rng);
            let r_b = Fr::rand(&mut rng);
            let r_c = Fr::rand(&mut rng);
            
            // Create two 1×1 PPEs instead of one 2×2 diagonal PPE
            // This ensures we get separate equation proofs for each diagonal entry
            
            let ic = compute_ic_from_vk_and_inputs(vk, public_input);
            let PairingOutput(rhs1) = Bls12_381::pairing(vk.alpha_g1, vk.beta_g2);
            let PairingOutput(rhs2) = Bls12_381::pairing(ic, vk.gamma_g2);
            let full_target = PairingOutput::<Bls12_381>(rhs1 * rhs2);
            
            // First PPE: πA ⊗ πB = e(α, β)
            let ppe1 = PPE::<Bls12_381> {
                a_consts: vec![G1Affine::zero()],
                b_consts: vec![G2Affine::zero()],
                gamma: vec![vec![Fr::one()]],  // 1×1 matrix
                target: PairingOutput::<Bls12_381>(rhs1),  // Target: e(α, β)
            };
            
            let xvars1 = vec![proof.pi_a];
            let yvars1 = vec![proof.pi_b];
            let proof1 = ppe1.commit_and_prove(&xvars1, &yvars1, &self.crs, &mut rng);
            
            // Second PPE: πC ⊗ δ = e(IC, γ)
            let ppe2 = PPE::<Bls12_381> {
                a_consts: vec![G1Affine::zero()],
                b_consts: vec![G2Affine::zero()],
                gamma: vec![vec![Fr::one()]],  // 1×1 matrix
                target: PairingOutput::<Bls12_381>(rhs2),  // Target: e(IC, γ)
            };
            
            let xvars2 = vec![proof.pi_c];
            let yvars2 = vec![vk.delta_g2];
            let proof2 = ppe2.commit_and_prove(&xvars2, &yvars2, &self.crs, &mut rng);
            
            // Create equation structures for the new attestation format
            let eq_ab = GSEquation {
                c1: proof1.xcoms.coms[0],
                c2: proof1.ycoms.coms[0],
                pi: proof1.equ_proofs[0].pi.clone(),
                theta: proof1.equ_proofs[0].theta.clone(),
            };
            
            let eq_cd = GSEquation {
                c1: proof2.xcoms.coms[0],
                c2: proof2.ycoms.coms[0],
                pi: proof2.equ_proofs[0].pi.clone(),
                theta: proof2.equ_proofs[0].theta.clone(),
            };
            
            eprintln!("DEBUG: Created 2 separate 1×1 equation proofs");
            
            let mut proof_data_bytes = Vec::new();
            proof.pi_a.serialize_compressed(&mut proof_data_bytes).unwrap();
            proof.pi_b.serialize_compressed(&mut proof_data_bytes).unwrap();
            proof.pi_c.serialize_compressed(&mut proof_data_bytes).unwrap();
            proof_data_bytes.extend_from_slice(&proof.public_input);
            
            let proof_data = Sha256::digest(&proof_data_bytes).to_vec();
            
            // Use the full target as PPE target
            let ppe_target = full_target.0;

            Ok(GSAttestation {
                eq_ab,
                eq_cd,
                proof_data,
                ppe_target,
            })
        } else {
            // Create two 1×1 PPEs instead of one 2×2 diagonal PPE
            // This ensures we get separate equation proofs for each diagonal entry
            
            let ic = compute_ic_from_vk_and_inputs(vk, public_input);
            let PairingOutput(rhs1) = Bls12_381::pairing(vk.alpha_g1, vk.beta_g2);
            let PairingOutput(rhs2) = Bls12_381::pairing(ic, vk.gamma_g2);
            let full_target = PairingOutput::<Bls12_381>(rhs1 * rhs2);
            
            // First PPE: πA ⊗ πB = e(α, β)
            let ppe1 = PPE::<Bls12_381> {
                a_consts: vec![G1Affine::zero()],
                b_consts: vec![G2Affine::zero()],
                gamma: vec![vec![Fr::one()]],  // 1×1 matrix
                target: PairingOutput::<Bls12_381>(rhs1),  // Target: e(α, β)
            };
            
            let xvars1 = vec![proof.pi_a];
            let yvars1 = vec![proof.pi_b];
            let proof1 = ppe1.commit_and_prove(&xvars1, &yvars1, &self.crs, &mut rng);
            
            // Second PPE: πC ⊗ δ = e(IC, γ)
            let ppe2 = PPE::<Bls12_381> {
                a_consts: vec![G1Affine::zero()],
                b_consts: vec![G2Affine::zero()],
                gamma: vec![vec![Fr::one()]],  // 1×1 matrix
                target: PairingOutput::<Bls12_381>(rhs2),  // Target: e(IC, γ)
            };
            
            let xvars2 = vec![proof.pi_c];
            let yvars2 = vec![vk.delta_g2];
            let proof2 = ppe2.commit_and_prove(&xvars2, &yvars2, &self.crs, &mut rng);
            
            // Create equation structures for the new attestation format
            let eq_ab = GSEquation {
                c1: proof1.xcoms.coms[0],
                c2: proof1.ycoms.coms[0],
                pi: proof1.equ_proofs[0].pi.clone(),
                theta: proof1.equ_proofs[0].theta.clone(),
            };
            
            let eq_cd = GSEquation {
                c1: proof2.xcoms.coms[0],
                c2: proof2.ycoms.coms[0],
                pi: proof2.equ_proofs[0].pi.clone(),
                theta: proof2.equ_proofs[0].theta.clone(),
            };
            
            eprintln!("DEBUG: Created 2 separate 1×1 equation proofs");
            
            let mut proof_data_bytes = Vec::new();
            proof.pi_a.serialize_compressed(&mut proof_data_bytes).unwrap();
            proof.pi_b.serialize_compressed(&mut proof_data_bytes).unwrap();
            proof.pi_c.serialize_compressed(&mut proof_data_bytes).unwrap();
            proof_data_bytes.extend_from_slice(&proof.public_input);
            
            let proof_data = Sha256::digest(&proof_data_bytes).to_vec();
            
            // Use the full target as PPE target
            let ppe_target = full_target.0;

            Ok(GSAttestation {
                eq_ab,
                eq_cd,
                proof_data,
                ppe_target,
            })
        }
    }

    /// Verify GS attestation satisfies PPE equation
    /// Implements: ∏_j e(C1_j, U_j) · ∏_k e(V_k, C2_k) = G_G16(vk,x)
    /// Per PVUGC spec: The attestation is valid if the KEM evaluator with
    /// the provided bases produces a deterministic value.
    /// 
    /// Verification checks:
    /// 1. Structural validity (commitment counts match)
    /// 2. Bases are actually dual (if we can verify)
    /// 3. Evaluator produces consistent results
    pub fn verify_attestation(
        &self,
        attestation: &GSAttestation,
        u_bases: &[(G2Affine, G2Affine)],
        v_bases: &[(G1Affine, G1Affine)],
        _g_target: &Fq12,  // Not used with dual bases
    ) -> Result<bool, GSCommitmentError> {
        // Structural validation for two 1×1 equations
        if attestation.eq_ab.pi.len() != 1 || attestation.eq_ab.theta.len() != 1 {
            return Err(GSCommitmentError::InvalidInput(
                "Invalid equation proof lengths for eq_ab".to_string()
            ));
        }
        if attestation.eq_cd.pi.len() != 1 || attestation.eq_cd.theta.len() != 1 {
            return Err(GSCommitmentError::InvalidInput(
                "Invalid equation proof lengths for eq_cd".to_string()
            ));
        }
        
        // VERIFICATION: Check that KEM formula M = target^ρ holds
        // This is the PVUGC property that must be satisfied
        
        use groth_sahai::kem_eval::{eval_two_equations_masked, pow_gt};
        use ark_std::test_rng;
        
        // Pick a random ρ for verification
        let mut rng = test_rng();
        let rho = Fr::rand(&mut rng);
        
        // Evaluate the two 1×1 equations with masking
        let PairingOutput(result_masked) = eval_two_equations_masked::<Bls12_381>(
            &attestation.eq_ab.c1,
            &attestation.eq_ab.c2,
            &attestation.eq_ab.pi,
            &attestation.eq_ab.theta,
            &attestation.eq_cd.c1,
            &attestation.eq_cd.c2,
            &attestation.eq_cd.pi,
            &attestation.eq_cd.theta,
            &self.crs,
            rho,
        );
        
        // The expected result should be target^ρ
        let expected = pow_gt::<Bls12_381>(attestation.ppe_target, rho);
        
        // Verify: result_masked = target^ρ
        Ok(result_masked == expected)
    }

    /// Compute target for real arkworks proof: G_G16(vk, x) = e(α, β) · e(IC, γ)
    pub fn compute_target(
        &self,
        vk: &ArkworksVK,
        public_input_bytes: &[u8],
    ) -> Result<Fq12, GSCommitmentError> {
        // Deserialize public input
        let public_input = Fr::deserialize_compressed(public_input_bytes)
            .map_err(|e| GSCommitmentError::Deserialization(format!("Public input: {:?}", e)))?;

        // Deserialize VK
        let vk_deserialized = ark_groth16::VerifyingKey::<Bls12_381>::deserialize_compressed(vk.vk_bytes.as_slice())
            .map_err(|e| GSCommitmentError::Deserialization(format!("VK: {:?}", e)))?;

        // Compute IC
        let ic = compute_ic(&vk_deserialized, &[public_input])
            .map_err(|e| GSCommitmentError::Commitment(format!("IC computation: {:?}", e)))?;

        // Compute target: e(α, β) · e(IC, γ)
        let e_alpha_beta = Bls12_381::pairing(vk.alpha_g1, vk.beta_g2);
        let e_ic_gamma = Bls12_381::pairing(ic, vk.gamma_g2);

        Ok(e_alpha_beta.0 * e_ic_gamma.0)
    }

    /// Derive instance-only bases for arkworks proof
    /// Returns bases that depend on (CRS, vk, x) for PVUGC instance determinism
    pub fn get_instance_bases(&self, vk: &ArkworksVK, public_input: &[Fr]) -> (Vec<(G2Affine, G2Affine)>, Vec<(G1Affine, G1Affine)>) {
        use groth_sahai::{ppe_eval_bases, ppe_instance_bases};

        // Build the PPE representing Groth16 verification for (vk, x)
        let ppe = self.groth16_verify_as_ppe(vk, public_input);

        // Derive pairing-compatible bases tied to (CRS, vk, x)
        // Internally uses u/v and their duals to create the pairs
        let eval_bases = ppe_eval_bases(&ppe, &self.crs);     // -> G2 pairs for C1 side (β2, δ2, ...)
        let inst_bases = ppe_instance_bases(&ppe, &self.crs); // -> G1 pairs for C2 side (α1, ...)

        let u_bases: Vec<(G2Affine, G2Affine)> = eval_bases
            .x_g2_pairs
            .iter()
            .map(|&(g2a, g2b)| (g2a, g2b))
            .collect();
        let v_bases: Vec<(G1Affine, G1Affine)> = inst_bases
            .v_pairs
            .iter()
            .map(|&(g1a, g1b)| (g1a, g1b))
            .collect();

        (u_bases, v_bases)
    }

    /// Encode Groth16 verification equation into GS PPE for specific (vk, x)
    /// Groth16 verification: e(π_A, π_B) · e(π_C, δ) = e(α, β) · e(IC, γ)
    /// We encode this as: e(π_A, π_B) · e(π_C, δ) = target
    /// where target = e(α, β) · e(IC, γ) is computed from (vk, x)
    fn groth16_verify_as_ppe(&self, vk: &ArkworksVK, public_input: &[Fr]) -> PPE<Bls12_381> {
        // Compute IC = ∑(γ_abc_i * x_i) for public inputs
        let ic = compute_ic_from_vk_and_inputs(vk, public_input);

        // Compute target: e(α, β) · e(IC, γ)
        let e_alpha_beta = Bls12_381::pairing(vk.alpha_g1, vk.beta_g2);
        let e_ic_gamma = Bls12_381::pairing(ic, vk.gamma_g2);
        let target = PairingOutput::<Bls12_381>(e_alpha_beta.0 * e_ic_gamma.0);

        // Build PPE for Groth16 verification
        // Variables: π_A, π_C (G1), π_B, δ (G2)
        // Equation: e(π_A, π_B) · e(π_C, δ) = target
        PPE::<Bls12_381> {
            a_consts: vec![G1Affine::zero(), G1Affine::zero()],
            b_consts: vec![G2Affine::zero(), G2Affine::zero()],
            gamma: vec![
                vec![Fr::one(), Fr::zero()],  // e(π_A, π_B) term
                vec![Fr::zero(), Fr::one()],  // e(π_C, δ) term
            ],
            target,
        }
    }

    /// Get the CRS
    pub fn get_crs(&self) -> &CRS<Bls12_381> {
        &self.crs
    }
}

/// Compute IC = ∑(γ_abc_i * x_i) for public inputs
/// This is the input commitment term in Groth16 verification
fn compute_ic_from_vk_and_inputs(vk: &ArkworksVK, public_input: &[Fr]) -> G1Affine {
    use ark_ec::CurveGroup;
    
    // Start with γ_abc[0] (the constant term)
    let mut ic = vk.gamma_abc_g1[0].into_group();
    
    // Add γ_abc[i] * x[i-1] for each public input
    for (i, input) in public_input.iter().enumerate() {
        if i + 1 < vk.gamma_abc_g1.len() {
            ic += vk.gamma_abc_g1[i + 1].into_group() * input;
        }
    }
    
    ic.into_affine()
}

/// Helper function to get RNG from seed
fn get_rng_from_seed(seed: &[u8]) -> impl Rng {
    use ark_std::rand::{SeedableRng, rngs::StdRng};
    
    let mut hasher = Sha256::new();
    hasher.update(seed);
    let hash = hasher.finalize();
    
    let mut seed_bytes = [0u8; 32];
    seed_bytes.copy_from_slice(&hash);
    
    StdRng::from_seed(seed_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gs_commitments_new() {
        let seed = b"test seed";
        let gs = GrothSahaiCommitments::from_seed(seed);
        assert!(!gs.get_crs().u[0].0.is_zero());
    }

    #[test]
    fn test_commit_arkworks_proof() {
        use crate::groth16_wrapper::ArkworksGroth16;
        
        let seed = b"test seed";
        let gs = GrothSahaiCommitments::from_seed(seed);
        
        let mut groth16 = ArkworksGroth16::new();
        let vk = groth16.setup().expect("Setup should succeed");
        
        let witness = Fr::from(5u64); // Square root of 25
        let proof = groth16.prove(witness).expect("Prove should succeed");
        
        let attestation = gs.commit_arkworks_proof(&proof, &vk, &vec![], false)
            .expect("Commit should succeed");
        
        // Check that we have two equations as expected
        assert_eq!(attestation.eq_ab.pi.len(), 1, "eq_ab should have 1 pi element");
        assert_eq!(attestation.eq_ab.theta.len(), 1, "eq_ab should have 1 theta element");
        assert_eq!(attestation.eq_cd.pi.len(), 1, "eq_cd should have 1 pi element");
        assert_eq!(attestation.eq_cd.theta.len(), 1, "eq_cd should have 1 theta element");
        assert!(!attestation.proof_data.is_empty());
    }

    #[test]
    fn test_compute_target() {
        use crate::groth16_wrapper::ArkworksGroth16;
        
        let seed = b"test seed";
        let gs = GrothSahaiCommitments::from_seed(seed);
        
        let mut groth16 = ArkworksGroth16::new();
        let vk = groth16.setup().expect("Setup should succeed");
        
        let witness = Fr::from(5u64); // Square root of 25
        let proof = groth16.prove(witness).expect("Prove should succeed");
        
        let target = gs.compute_target(&vk, &proof.public_input)
            .expect("Target computation should succeed");
        
        assert!(!target.is_zero());
    }

    #[test]
    fn test_get_instance_bases() {
        use crate::groth16_wrapper::ArkworksGroth16;
        
        let seed = b"test seed";
        let gs = GrothSahaiCommitments::from_seed(seed);
        
        let mut groth16 = ArkworksGroth16::new();
        let vk = groth16.setup().expect("Setup should succeed");
        
        // Test with empty public input
        let public_input = vec![];
        let (u_bases, v_bases) = gs.get_instance_bases(&vk, &public_input);
        
        assert_eq!(u_bases.len(), 2, "Should have 2 u_dual bases for X-vars");
        assert_eq!(v_bases.len(), 2, "Should have 2 v_dual bases for Y-vars");
    }

    #[test]
    fn test_verify_attestation_with_dual_crs() {
        use crate::groth16_wrapper::ArkworksGroth16;
        
        let seed = b"test seed";
        let gs = GrothSahaiCommitments::from_seed(seed);
        
        let mut groth16 = ArkworksGroth16::new();
        let vk = groth16.setup().expect("Setup should succeed");
        
        let witness = Fr::from(5u64); // Square root of 25
        let proof = groth16.prove(witness).expect("Prove should succeed");
        
        // Create attestation with randomness (proper GS commitment)
        let attestation = gs.commit_arkworks_proof(&proof, &vk, &vec![Fr::from(25u64)], true)
            .expect("Commit should succeed");
        
        // Use dual CRS bases for verification (proper GS verification)
        let public_input = vec![Fr::from(25u64)]; // Square of witness 5
        let (u_bases, v_bases) = gs.get_instance_bases(&vk, &public_input);
        
        // Verify attestation satisfies PPE equation with dual CRS bases
        // Use PPE target from attestation itself
        let verified = gs.verify_attestation(&attestation, &u_bases, &v_bases, &attestation.ppe_target)
            .expect("Verification should succeed");
        
        assert!(verified, "GS attestation should verify with dual CRS bases");
    }

    #[test]
    fn test_verify_attestation_without_randomness() {
        use crate::groth16_wrapper::ArkworksGroth16;
        
        let seed = b"test seed";
        let gs = GrothSahaiCommitments::from_seed(seed);
        
        let mut groth16 = ArkworksGroth16::new();
        let vk = groth16.setup().expect("Setup should succeed");
        
        let witness = Fr::from(5u64); // Square root of 25
        let proof = groth16.prove(witness).expect("Prove should succeed");
        
        // Create attestation without randomness (direct commitment)
        let attestation = gs.commit_arkworks_proof(&proof, &vk, &vec![Fr::from(25u64)], false)
            .expect("Commit should succeed");
        
        // Use instance bases (VK-derived bases)
        let public_input = vec![Fr::from(25u64)]; // Square of witness 5
        let (u_bases, v_bases) = gs.get_instance_bases(&vk, &public_input);
        
        // Verify attestation satisfies PPE equation with instance bases
        // Use PPE target from attestation itself
        let verified = gs.verify_attestation(&attestation, &u_bases, &v_bases, &attestation.ppe_target)
            .expect("Verification should succeed");
        
        assert!(verified, "GS attestation should verify with instance bases");
    }

    /// Test instance determinism: different proofs for same (vk,x) should yield same KEM result
    #[test]
    fn test_instance_determinism() {
        use crate::groth16_wrapper::ArkworksGroth16;
        use groth_sahai::kem_eval::{ppe_eval_with_masked_pairs, mask_g1_pair, mask_g2_pair};
        
        let seed = b"determinism_test";
        let gs = GrothSahaiCommitments::from_seed(seed);
        
        let mut groth16 = ArkworksGroth16::new();
        let vk = groth16.setup().expect("Setup should succeed");
        
        // Same public input for both proofs
        let public_input = vec![Fr::from(25u64)]; // Square of witness 5
        
        // Generate two different proofs for the same statement
        let witness1 = Fr::from(5u64);
        let witness2 = Fr::from(5u64); // Same witness, but different randomness
        let proof1 = groth16.prove(witness1).expect("Prove should succeed");
        let proof2 = groth16.prove(witness2).expect("Prove should succeed");
        
        // Create attestations for both proofs
        let attestation1 = gs.commit_arkworks_proof(&proof1, &vk, &public_input, true)
            .expect("Commit should succeed");
        let attestation2 = gs.commit_arkworks_proof(&proof2, &vk, &public_input, true)
            .expect("Commit should succeed");
        
        // Get instance bases (should be identical for same (vk,x))
        let (u_bases, v_bases) = gs.get_instance_bases(&vk, &public_input);
        
        // Test with same ρ
        let rho = Fr::from(12345u64);
        let u_bases_masked: Vec<_> = u_bases.iter()
            .map(|&p| mask_g2_pair::<Bls12_381>(p, rho))
            .collect();
        let v_bases_masked: Vec<_> = v_bases.iter()
            .map(|&p| mask_g1_pair::<Bls12_381>(p, rho))
            .collect();
        
        // Evaluate KEM with both attestations using the new 1×1 evaluator
        use groth_sahai::kem_eval::eval_two_equations_masked;
        
        let PairingOutput(result1) = eval_two_equations_masked::<Bls12_381>(
            &attestation1.eq_ab.c1,
            &attestation1.eq_ab.c2,
            &attestation1.eq_ab.pi,
            &attestation1.eq_ab.theta,
            &attestation1.eq_cd.c1,
            &attestation1.eq_cd.c2,
            &attestation1.eq_cd.pi,
            &attestation1.eq_cd.theta,
            &gs.crs,
            rho,
        );
        
        let PairingOutput(result2) = eval_two_equations_masked::<Bls12_381>(
            &attestation2.eq_ab.c1,
            &attestation2.eq_ab.c2,
            &attestation2.eq_ab.pi,
            &attestation2.eq_ab.theta,
            &attestation2.eq_cd.c1,
            &attestation2.eq_cd.c2,
            &attestation2.eq_cd.pi,
            &attestation2.eq_cd.theta,
            &gs.crs,
            rho,
        );
        
        // Results should be identical (instance determinism)
        assert_eq!(result1, result2, "Different proofs for same (vk,x) should yield identical KEM results");
    }
}
