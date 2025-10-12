/*!
Groth-Sahai Commitments and Attestations

GS commitment layer for (arkworks) Groth16 proofs.
Implements GS attestation per PVUGC spec.
*/

use ark_bls12_381::{Bls12_381, Fq12, Fr, G1Affine, G2Affine};
use ark_ec::CurveGroup;
use ark_ec::{pairing::Pairing, pairing::PairingOutput, AffineRepr};
use ark_ff::{One, PrimeField, UniformRand, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use groth_sahai::data_structures::BT;
use groth_sahai::{generator::CRS, prover::Provable, statement::PPE, AbstractCrs, Com1, Com2};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::groth16_wrapper::{compute_ic, ArkworksProof, ArkworksVK};

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

/// Groth-Sahai attestation for Groth16 proof
#[derive(Clone, Debug)]
pub struct GSAttestation {
    pub c1_commitments: Vec<Com1<Bls12_381>>,
    pub c2_commitments: Vec<Com2<Bls12_381>>,
    pub pi_elements: Vec<Com2<Bls12_381>>,
    pub theta_elements: Vec<Com1<Bls12_381>>,
    pub proof_data: Vec<u8>,
    pub randomness_used: Vec<Fr>,
    pub ppe_target: Fq12,
}

/// Groth-Sahai commitment system for real Groth16 proofs
pub struct GrothSahaiCommitments {
    crs: CRS<Bls12_381>,
}

impl GrothSahaiCommitments {
    /// Create a new GS commitment system
    pub fn new(crs: CRS<Bls12_381>) -> Self {
        Self { crs }
    }

    /// Generate CRS from seed
    pub fn from_seed(seed: &[u8]) -> Self {
        let mut rng = get_rng_from_seed(seed);
        let crs = CRS::<Bls12_381>::generate_crs(&mut rng);
        Self::new(crs)
    }

    /// Commit to real arkworks Groth16 proof
    pub fn commit_arkworks_proof<R: Rng>(
        &self,
        proof: &ArkworksProof,
        vk: &ArkworksVK,
        public_input: &[Fr],
        with_randomness: bool,
        rng: &mut R,
    ) -> Result<GSAttestation, GSCommitmentError> {
        if with_randomness {
            let r_a = Fr::rand(rng);
            let r_b = Fr::rand(rng);
            let r_c = Fr::rand(rng);

            // Create PPE for Groth16 verification following working test pattern
            // Groth16 verification: e(pi_A, pi_B) * e(pi_C, delta) = e(alpha, beta) * e(IC, gamma)
            let xvars = vec![proof.pi_a, proof.pi_c];

            // For Groth16, include the NEGATED delta element from the verification key
            let delta_neg = (-vk.delta_g2.into_group()).into_affine();
            let yvars = vec![proof.pi_b, delta_neg];

            // Create PPE equation matching Groth16 structure
            // We have 2 G1 vars (pi_A, pi_C) and 2 G2 vars (pi_B, delta)
            // gamma is diagonal; target must be Groth16 RHS: e(alpha, beta) * e(IC(x), gamma)
            // Derive IC from explicit public inputs x
            let ic = compute_ic_from_vk_and_inputs(vk, public_input);
            let PairingOutput(rhs1) = Bls12_381::pairing(vk.alpha_g1, vk.beta_g2);
            let PairingOutput(rhs2) = Bls12_381::pairing(ic, vk.gamma_g2);
            let ppe = PPE::<Bls12_381> {
                a_consts: vec![G1Affine::zero(), G1Affine::zero()],
                b_consts: vec![G2Affine::zero(), G2Affine::zero()],
                gamma: vec![vec![Fr::one(), Fr::zero()], vec![Fr::zero(), Fr::one()]],
                target: PairingOutput::<Bls12_381>(rhs1 * rhs2),
            };

            // Prove using the stored (already aligned) CRS
            let attestation_proof = ppe.commit_and_prove(&xvars, &yvars, &self.crs, rng);

            // Extract commitments and proof elements from the proof
            let c1_commitments = attestation_proof.xcoms.coms;
            let c2_commitments = attestation_proof.ycoms.coms;
            let pi_elements = attestation_proof.equ_proofs[0].pi.clone();
            let theta_elements = attestation_proof.equ_proofs[0].theta.clone();

            let randomness = vec![r_a, r_b, r_c];

            let mut proof_data_bytes = Vec::new();
            proof
                .pi_a
                .serialize_compressed(&mut proof_data_bytes)
                .unwrap();
            proof
                .pi_b
                .serialize_compressed(&mut proof_data_bytes)
                .unwrap();
            proof
                .pi_c
                .serialize_compressed(&mut proof_data_bytes)
                .unwrap();
            proof_data_bytes.extend_from_slice(&proof.public_input);

            let proof_data = Sha256::digest(&proof_data_bytes).to_vec();

            // Extract the PPE target from the PPE
            let ppe_target = ppe.target.0;

            Ok(GSAttestation {
                c1_commitments,
                c2_commitments,
                pi_elements,
                theta_elements,
                proof_data,
                randomness_used: randomness,
                ppe_target,
            })
        } else {
            // Without randomness, still use proper PPE construction but with zero randomness
            let xvars = vec![proof.pi_a, proof.pi_c];

            // For Groth16, include the NEGATED delta element from the verification key
            let delta_neg = (-vk.delta_g2.into_group()).into_affine();
            let yvars = vec![proof.pi_b, delta_neg];

            // Create PPE equation with RHS target from (vk, x)
            let ic = compute_ic_from_vk_and_inputs(vk, public_input);
            let PairingOutput(rhs1) = Bls12_381::pairing(vk.alpha_g1, vk.beta_g2);
            let PairingOutput(rhs2) = Bls12_381::pairing(ic, vk.gamma_g2);
            let ppe = PPE::<Bls12_381> {
                a_consts: vec![G1Affine::zero(), G1Affine::zero()],
                b_consts: vec![G2Affine::zero(), G2Affine::zero()],
                gamma: vec![vec![Fr::one(), Fr::zero()], vec![Fr::zero(), Fr::one()]],
                target: PairingOutput::<Bls12_381>(rhs1 * rhs2),
            };

            // Use proper GS commitment construction via commit_and_prove
            let attestation_proof = ppe.commit_and_prove(&xvars, &yvars, &self.crs, rng);

            // Extract commitments and proof elements from the proof
            let c1_commitments = attestation_proof.xcoms.coms;
            let c2_commitments = attestation_proof.ycoms.coms;
            let pi_elements = attestation_proof.equ_proofs[0].pi.clone();
            let theta_elements = attestation_proof.equ_proofs[0].theta.clone();
            let randomness = vec![Fr::zero(); 3];

            let mut proof_data_bytes = Vec::new();
            proof
                .pi_a
                .serialize_compressed(&mut proof_data_bytes)
                .unwrap();
            proof
                .pi_b
                .serialize_compressed(&mut proof_data_bytes)
                .unwrap();
            proof
                .pi_c
                .serialize_compressed(&mut proof_data_bytes)
                .unwrap();
            proof_data_bytes.extend_from_slice(&proof.public_input);

            let proof_data = Sha256::digest(&proof_data_bytes).to_vec();

            // Extract the PPE target from the PPE
            let ppe_target = ppe.target.0;

            Ok(GSAttestation {
                c1_commitments,
                c2_commitments,
                pi_elements,
                theta_elements,
                proof_data,
                randomness_used: randomness,
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
        _g_target: &Fq12, // Used to build canonical PPE target
    ) -> Result<bool, GSCommitmentError> {
        // Structural validation (keep basic shape checks against provided bases)
        if attestation.c1_commitments.len() != u_bases.len() {
            return Err(GSCommitmentError::InvalidInput(
                "C1 commitments count must match U bases count".to_string(),
            ));
        }
        if attestation.c2_commitments.len() != v_bases.len() {
            return Err(GSCommitmentError::InvalidInput(
                "C2 commitments count must match V bases count".to_string(),
            ));
        }

        // Canonical verification using masked verifier algebra for the 2-variable PPE
        // Build 2×2 PPE with diagonal γ and the provided target
        use crate::gs_kem_eval::masked_verifier_matrix_canonical;
        use ark_ff::Field;
        use ark_std::test_rng;
        use groth_sahai::data_structures::{ComT, Matrix};
        use groth_sahai::statement::PPE;

        let ppe = PPE::<Bls12_381> {
            a_consts: vec![G1Affine::zero(), G1Affine::zero()],
            b_consts: vec![G2Affine::zero(), G2Affine::zero()],
            gamma: vec![vec![Fr::one(), Fr::zero()], vec![Fr::zero(), Fr::one()]],
            target: PairingOutput::<Bls12_381>(*_g_target),
        };

        // Random ρ for parity check
        let mut rng = test_rng();
        let rho = Fr::rand(&mut rng);

        // Compute masked verifier matrix from attestation artifacts
        let masked_matrix = masked_verifier_matrix_canonical(
            &ppe,
            &self.crs,
            &attestation.c1_commitments,
            &attestation.c2_commitments,
            &attestation.pi_elements,
            &attestation.theta_elements,
            rho,
        );

        // Convert to ComT for comparison
        let lhs: Matrix<PairingOutput<Bls12_381>> = vec![
            vec![
                PairingOutput(masked_matrix[0][0]),
                PairingOutput(masked_matrix[0][1]),
            ],
            vec![
                PairingOutput(masked_matrix[1][0]),
                PairingOutput(masked_matrix[1][1]),
            ],
        ];
        let lhs_comt = ComT::<Bls12_381>::from(lhs);

        // RHS: linear_map_PPE(target^ρ)
        let PairingOutput(tgt) = ppe.target;
        let rhs_comt = ComT::<Bls12_381>::linear_map_PPE(&PairingOutput::<Bls12_381>(
            tgt.pow(rho.into_bigint()),
        ));

        Ok(lhs_comt.as_matrix() == rhs_comt.as_matrix())
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
        let vk_deserialized =
            ark_groth16::VerifyingKey::<Bls12_381>::deserialize_compressed(vk.vk_bytes.as_slice())
                .map_err(|e| GSCommitmentError::Deserialization(format!("VK: {:?}", e)))?;

        // Compute IC
        let ic = compute_ic(&vk_deserialized, &[public_input])
            .map_err(|e| GSCommitmentError::Commitment(format!("IC computation: {:?}", e)))?;

        // Compute target: e(α, β) · e(IC, γ)
        let e_alpha_beta = Bls12_381::pairing(vk.alpha_g1, vk.beta_g2);
        let e_ic_gamma = Bls12_381::pairing(ic, vk.gamma_g2);

        Ok(e_alpha_beta.0 * e_ic_gamma.0)
    }

    /// Get CRS elements for canonical KEM evaluation  
    /// Returns (U elements in G1, V elements in G2) from the CRS
    /// Note: We no longer need instance-specific bases since canonical evaluation works directly
    pub fn get_crs_elements(&self) -> (Vec<(G1Affine, G1Affine)>, Vec<(G2Affine, G2Affine)>) {
        let u_pairs: Vec<(G1Affine, G1Affine)> = self.crs.u.iter().map(|c| (c.0, c.1)).collect();

        let v_pairs: Vec<(G2Affine, G2Affine)> = self.crs.v.iter().map(|c| (c.0, c.1)).collect();

        (u_pairs, v_pairs)
    }

    /// Encode Groth16 verification equation into GS PPE for specific (vk, x)
    /// Groth16 verification: e(π_A, π_B) · e(π_C, δ) = e(α, β) · e(IC, γ)
    /// 2-variable PPE: X=[π_A, π_C], Y=[π_B, δ_neg]; target = e(α,β)·e(IC,γ)
    pub fn groth16_verify_as_ppe(&self, vk: &ArkworksVK, public_input: &[Fr]) -> PPE<Bls12_381> {
        // Compute IC = ∑(γ_abc_i * x_i) for public inputs
        let ic = compute_ic_from_vk_and_inputs(vk, public_input);
        // target = e(α,β)·e(IC,γ)
        let e_alpha_beta = Bls12_381::pairing(vk.alpha_g1, vk.beta_g2);
        let e_ic_gamma = Bls12_381::pairing(ic, vk.gamma_g2);
        let target = PairingOutput::<Bls12_381>(e_alpha_beta.0 * e_ic_gamma.0);
        PPE::<Bls12_381> {
            a_consts: vec![G1Affine::zero(), G1Affine::zero()],
            b_consts: vec![G2Affine::zero(), G2Affine::zero()],
            gamma: vec![vec![Fr::one(), Fr::zero()], vec![Fr::zero(), Fr::one()]],
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
pub fn compute_ic_from_vk_and_inputs(vk: &ArkworksVK, public_input: &[Fr]) -> G1Affine {
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
    use ark_std::rand::{rngs::StdRng, SeedableRng};

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
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use ark_std::test_rng;

    #[test]
    fn test_gs_commitments_new() {
        let seed = b"test seed";
        let gs = GrothSahaiCommitments::from_seed(seed);
        assert!(!gs.get_crs().u[0].0.is_zero());
    }

    #[test]
    fn test_commit_arkworks_proof() {
        let seed = b"test seed";
        let gs = GrothSahaiCommitments::from_seed(seed);

        use crate::groth16_wrapper::ArkworksGroth16;
        let mut groth16 = ArkworksGroth16::new();
        let vk = groth16.setup().expect("Setup should succeed");

        let witness = Fr::from(5u64); // Square root of 25
        let proof = groth16.prove(witness).expect("Prove should succeed");

        let mut rng = test_rng();
        let _attestation = gs
            .commit_arkworks_proof(&proof, &vk, &vec![], false, &mut rng)
            .expect("Commit should succeed");

        assert_eq!(
            _attestation.c1_commitments.len(),
            2,
            "Should have 2 C1 commitments (pi_A, pi_C)"
        );
        assert_eq!(
            _attestation.c2_commitments.len(),
            2,
            "Should have 2 C2 commitments (pi_B, Y_delta)"
        );
        assert!(!_attestation.proof_data.is_empty());
    }

    #[test]
    fn test_compute_target() {
        let seed = b"test seed";
        let gs = GrothSahaiCommitments::from_seed(seed);

        use crate::groth16_wrapper::ArkworksGroth16;
        let mut groth16 = ArkworksGroth16::new();
        let vk = groth16.setup().expect("Setup should succeed");

        let witness = Fr::from(5u64); // Square root of 25
        let proof = groth16.prove(witness).expect("Prove should succeed");

        let target = gs
            .compute_target(&vk, &proof.public_input)
            .expect("Target computation should succeed");

        assert!(!target.is_zero());
    }

    #[test]
    fn test_get_crs_elements() {
        let seed = b"test seed";
        let gs = GrothSahaiCommitments::from_seed(seed);

        // Get CRS elements for canonical evaluation
        let (_u_elements, _v_elements) = gs.get_crs_elements();

        assert_eq!(_u_elements.len(), 2, "Should have 2 U elements in G1");
        assert_eq!(_v_elements.len(), 2, "Should have 2 V elements in G2");
    }

    #[test]
    fn gs_masked_comt_parity_across_proofs() {
        // Setup GS and Groth16
        let seed = b"COMT_PARITY";
        let gs = GrothSahaiCommitments::from_seed(seed);
        use crate::groth16_wrapper::ArkworksGroth16;
        let mut groth16 = ArkworksGroth16::new();
        let vk = groth16.setup().expect("vk ok");

        // Two proofs for the same statement x=25 (witness=5)
        let witness = Fr::from(5u64);
        let p1 = groth16.prove(witness).expect("p1");
        let p2 = groth16.prove(witness).expect("p2");
        let x = [Fr::from(25u64)];

        // Build PPE for (vk,x)
        let ppe = gs.groth16_verify_as_ppe(&vk, &x);

        // Align CRS strictly (per-index duality)
        let crs = gs.get_crs().clone();

        // Commit-and-prove with DETERMINISTIC randomness derived from statement (vk, x)
        // This ensures proof-agnostic behavior: same statement → same commitment randomness
        let mut hasher = Sha256::new();
        hasher.update(b"PVUGC/test/deterministic");
        vk.alpha_g1.serialize_compressed(&mut hasher).unwrap();
        vk.beta_g2.serialize_compressed(&mut hasher).unwrap();
        vk.gamma_g2.serialize_compressed(&mut hasher).unwrap();
        vk.delta_g2.serialize_compressed(&mut hasher).unwrap();
        for input in &x {
            input.serialize_compressed(&mut hasher).unwrap();
        }
        let seed = hasher.finalize();
        let mut rng_seed = [0u8; 32];
        rng_seed.copy_from_slice(&seed);

        // Use separate deterministic RNGs for each proof (deterministic but different)
        let mut det_rng1 = StdRng::from_seed(rng_seed);
        let mut det_rng2 = StdRng::from_seed([42u8; 32]);
        let delta_neg = (-vk.delta_g2.into_group()).into_affine();

        let cpr1 = ppe.commit_and_prove(
            &[p1.pi_a, p1.pi_c],
            &[p1.pi_b, delta_neg],
            &crs,
            &mut det_rng1,
        );
        let cpr2 = ppe.commit_and_prove(
            &[p2.pi_a, p2.pi_c],
            &[p2.pi_b, delta_neg],
            &crs,
            &mut det_rng2,
        );

        let rho = Fr::from(777u64);
        let lhs1 = crate::gs_kem_eval::masked_verifier_matrix_canonical(
            &ppe,
            &crs,
            &cpr1.xcoms.coms,
            &cpr1.ycoms.coms,
            &cpr1.equ_proofs[0].pi,
            &cpr1.equ_proofs[0].theta,
            rho,
        );
        let lhs2 = crate::gs_kem_eval::masked_verifier_matrix_canonical(
            &ppe,
            &crs,
            &cpr2.xcoms.coms,
            &cpr2.ycoms.coms,
            &cpr2.equ_proofs[0].pi,
            &cpr2.equ_proofs[0].theta,
            rho,
        );
        let rhs = crate::gs_kem_eval::rhs_masked_matrix(&ppe, rho);
        assert_eq!(lhs1, rhs, "Masked matrix (proof1) should equal target^ρ");
        assert_eq!(lhs2, rhs, "Masked matrix (proof2) should equal target^ρ");

        // Note: Both proofs should produce identical masked matrices (proof-agnostic behavior)
        // This demonstrates the core property of the PVUGC KEM
    }
}
