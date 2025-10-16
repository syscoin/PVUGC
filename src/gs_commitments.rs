/*!
Groth-Sahai Commitments and Attestations

GS commitment layer for (arkworks) Groth16 proofs.
Implements GS attestation per PVUGC spec.
*/

use ark_bls12_381::{Bls12_381, Fq12, Fr, G1Affine, G2Affine};
use ark_ec::CurveGroup;
use ark_ec::{pairing::Pairing, pairing::PairingOutput, AffineRepr};
use ark_ff::{One, Zero, UniformRand};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::Rng;
use groth_sahai::prover::CProof;
use groth_sahai::{generator::CRS, statement::PPE, Com1, Com2};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::groth16_wrapper::{ArkworksProof, ArkworksVK};

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
    #[error("Crypto error: {0}")]
    Crypto(String),
    #[error("Encryption error: {0}")]
    Encryption(String),
    #[error("Decryption error: {0}")]
    Decryption(String),
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
    pub cproof: CProof<Bls12_381>, // full GS proof for canonical verification
}

/// Groth-Sahai commitment system for real Groth16 proofs
/// Uses rank-decomposition approach for offline PVUGC arming
pub struct GrothSahaiCommitments {
    crs: CRS<Bls12_381>,
}

impl GrothSahaiCommitments {
    /// Create a new GS commitment system with default CRS
    pub fn new() -> Self {
        use ark_std::test_rng;
        let mut rng = test_rng();
        let crs = CRS::<Bls12_381>::generate_crs_per_slot(&mut rng, 3, 3);
        Self { crs }
    }

    /// Generate GS system from seed (creates deterministic CRS)
    pub fn from_seed(_seed: &[u8]) -> Self {
        use ark_std::rand::{rngs::StdRng, SeedableRng};
        let mut rng = StdRng::from_seed([42u8; 32]);
        let crs = CRS::<Bls12_381>::generate_crs_per_slot(&mut rng, 3, 3);
        Self { crs }
    }

    /// Get the CRS
    pub fn get_crs(&self) -> &CRS<Bls12_381> {
        &self.crs
    }


    /// Get CRS elements
    pub fn get_crs_elements(&self) -> (Vec<Com1<Bls12_381>>, Vec<Com2<Bls12_381>>) {
        (self.crs.u.clone(), self.crs.v.clone())
    }

    /// Compute target for Groth16 verification
    pub fn compute_target(&self, vk: &ArkworksVK, public_input: &[Fr]) -> Result<Fq12, GSCommitmentError> {
        let ppe = self.groth16_verify_as_ppe(vk, public_input, &self.crs);
        Ok(ppe.target.0)
    }

    /// Commit to real arkworks Groth16 proof using full-GS (with CRS parameter)
    /// 
    /// # Arguments
    /// * `proof` - The Groth16 proof to commit
    /// * `vk` - The verification key
    /// * `public_input` - Public inputs to the circuit
    /// * `crs_per_slot` - The per-slot CRS to use (must be 3x3 for Groth16)
    /// * `rng` - Random number generator
    /// 
    /// # Notes
    /// The CRS must be the same one used by ARMER for offline setup to ensure
    /// DECAPPER can extract with the armed bases.
    /// Uses full-GS commitment (VAR row bases) for real Groth16 verification.
    pub fn commit_arkworks_proof<R: Rng>(
        &self,
        proof: &ArkworksProof,
        vk: &ArkworksVK,
        public_input: &[Fr],
        crs_per_slot: &CRS<Bls12_381>,
        rng: &mut R,
    ) -> Result<GSAttestation, GSCommitmentError> {
        
        // Get the PPE with actual Groth16 target e(α, β)
        let ppe = self.groth16_verify_as_ppe(vk, public_input, crs_per_slot);
        
        // Compute constants
        let ic = compute_ic_from_vk_and_inputs(vk, public_input);
        let delta_neg = (-vk.delta_g2.into_group()).into_affine();
        let gamma_neg = (-vk.gamma_g2.into_group()).into_affine();
        
        // Build all 3 X-slots and 3 Y-slots
        // For Groth16: A and C are witnesses (randomized), L(x) is constant (zero randomizer)
        //              B is witness (randomized), δ⁻¹ and γ⁻¹ are constants (zero randomizers)
        let x_vars = vec![
            proof.pi_a,  // A (witness)
            proof.pi_c,  // C (witness)
            ic,          // L(x) (constant)
        ];
        let y_vars = vec![
            proof.pi_b,  // B (witness)
            delta_neg,   // δ⁻¹ (constant)
            gamma_neg,   // γ⁻¹ (constant)
        ];

        // Use randomness for witness slots, zero for constant slots
        let r_a = Fr::rand(rng);
        let r_c = Fr::rand(rng);
        let r_l = Fr::zero();  // L(x) is constant
        let r = vec![r_a, r_c, r_l];
        
        let s_b = Fr::rand(rng);
        let s_delta = Fr::zero();  // δ⁻¹ is constant
        let s_gamma = Fr::zero();  // γ⁻¹ is constant
        let s = vec![s_b, s_delta, s_gamma];
        
        // Use the PPE's built-in full-GS prover (same as GS library test)
        let attestation_proof = ppe.commit_and_prove_full_gs(&x_vars, &y_vars, &r, &s, crs_per_slot, rng);

        // Extract commitments and proof elements from the proof
        let c1_commitments = attestation_proof.xcoms.coms.clone();
        let c2_commitments = attestation_proof.ycoms.coms.clone();
        let pi_elements = attestation_proof.equ_proofs[0].pi.clone();
        let theta_elements = attestation_proof.equ_proofs[0].theta.clone();

        let randomness = vec![Fr::zero(); 3]; // Randomness is internal to rank-decomposition

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
            cproof: attestation_proof,
        })
    }

    /// Verify GS attestation using full-GS verifier
    /// 
    /// # Arguments
    /// * `attestation` - The GS attestation to verify
    /// * `ppe` - The PPE equation (must match the one used for proving)
    /// * `crs_per_slot` - The per-slot CRS (must match the one used for proving)
    /// 
    /// # Returns
    /// `Ok(true)` if attestation is valid, `Ok(false)` otherwise
    pub fn verify_attestation(
        &self,
        attestation: &GSAttestation,
        ppe: &PPE<Bls12_381>,
        crs_per_slot: &CRS<Bls12_381>,
    ) -> Result<bool, GSCommitmentError> {
        use groth_sahai::rank_decomp::RankDecomp;
        use groth_sahai::base_construction::FullGSPpeBases;
        
        // Build full-GS bases for verification
        let decomp = RankDecomp::decompose(&ppe.gamma);
        let bases = FullGSPpeBases::build(crs_per_slot, ppe, &decomp);
        
        // Use full-GS verifier
        let (ok, _extracted_m) = ppe.verify_full_gs(&attestation.cproof, crs_per_slot, &bases);
        Ok(ok)
    }
    
    /// Verify attestation and extract M for KEM decapsulation
    /// 
    /// # Returns
    /// `Ok((verifies, M))` where M is the extracted pairing target
    pub fn verify_and_extract(
        &self,
        attestation: &GSAttestation,
        ppe: &PPE<Bls12_381>,
        crs_per_slot: &CRS<Bls12_381>,
    ) -> Result<(bool, PairingOutput<Bls12_381>), GSCommitmentError> {
        use groth_sahai::rank_decomp::RankDecomp;
        use groth_sahai::base_construction::FullGSPpeBases;
        
        // Build full-GS bases for verification
        let decomp = RankDecomp::decompose(&ppe.gamma);
        let bases = FullGSPpeBases::build(crs_per_slot, ppe, &decomp);
        
        // Use full-GS verifier and extract M
        let (ok, m_extracted) = ppe.verify_full_gs(&attestation.cproof, crs_per_slot, &bases);
        Ok((ok, m_extracted))
    }
    
    /// KEM Encapsulate: Create attestation and encrypt share
    /// 
    /// # Arguments
    /// * `proof` - The Groth16 proof
    /// * `vk` - The verification key
    /// * `public_input` - Public inputs
    /// * `crs_per_slot` - The CRS
    /// * `share` - The secret share to encrypt (as Fr)
    /// * `rho` - The KEM secret scalar
    /// * `ctx_hash` - Context hash for key derivation
    /// * `rng` - Random number generator
    /// 
    /// # Returns
    /// `Ok((attestation, ciphertext))` 
    pub fn kem_encapsulate<R: Rng>(
        &self,
        proof: &ArkworksProof,
        vk: &ArkworksVK,
        public_input: &[Fr],
        crs_per_slot: &CRS<Bls12_381>,
        share: Fr,
        rho: Fr,
        ctx_hash: &[u8],
        rng: &mut R,
    ) -> Result<(GSAttestation, Vec<u8>), GSCommitmentError> {
        use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Nonce};
        use ark_serialize::CanonicalSerialize;
        use ark_ff::BigInteger;
        
        // Create GS attestation
        let attestation = self.commit_arkworks_proof(proof, vk, public_input, crs_per_slot, rng)?;
        
        // Compute target^rho for key derivation
        let ppe = self.groth16_verify_as_ppe(vk, public_input, crs_per_slot);
        let target_rho = ppe.target * rho;
        
        // Derive encryption key from target^rho
        let mut target_rho_bytes = Vec::new();
        target_rho.serialize_compressed(&mut target_rho_bytes)
            .map_err(|e| GSCommitmentError::Serialization(e.to_string()))?;
        
        let key_material = Sha256::digest(&[ctx_hash, &target_rho_bytes].concat()).to_vec();
        let key: [u8; 32] = key_material[..32].try_into()
            .map_err(|_| GSCommitmentError::Crypto("Key derivation failed".into()))?;
        
        // Encrypt the share
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|e| GSCommitmentError::Encryption(e.to_string()))?;
        let nonce = Nonce::from_slice(&[0u8; 12]);
        
        use ark_ff::PrimeField;
        let share_bytes = share.into_bigint().to_bytes_be();
        let ciphertext = cipher.encrypt(nonce, share_bytes.as_ref())
            .map_err(|e| GSCommitmentError::Encryption(e.to_string()))?;
        
        Ok((attestation, ciphertext))
    }
    
    /// KEM Decapsulate: Verify attestation and decrypt share
    /// 
    /// # Arguments
    /// * `attestation` - The GS attestation
    /// * `vk` - The verification key
    /// * `public_input` - Public inputs
    /// * `crs_per_slot` - The CRS
    /// * `ciphertext` - The encrypted share
    /// * `target_rho` - The pre-computed target^rho (K = M^rho), provided by ARMER
    /// * `ctx_hash` - Context hash for key derivation
    /// 
    /// # Returns
    /// `Ok(share)` as Fr
    /// 
    /// # Note
    /// In the full PVUGC protocol, the DECAPPER receives K = target^rho from the ARMER
    /// without ever learning rho itself. For full-GS, the ARMER can compute this offline
    /// since target = e(α,β) depends only on the VK.
    pub fn kem_decapsulate(
        &self,
        attestation: &GSAttestation,
        vk: &ArkworksVK,
        public_input: &[Fr],
        crs_per_slot: &CRS<Bls12_381>,
        ciphertext: &[u8],
        target_rho: PairingOutput<Bls12_381>,
        ctx_hash: &[u8],
    ) -> Result<Fr, GSCommitmentError> {
        use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Nonce};
        use ark_serialize::CanonicalSerialize;
        
        // Build PPE and verify, extracting M
        let ppe = self.groth16_verify_as_ppe(vk, public_input, crs_per_slot);
        let (verifies, m_extracted) = self.verify_and_extract(attestation, &ppe, crs_per_slot)?;
        
        if !verifies || m_extracted != ppe.target {
            return Err(GSCommitmentError::Verification("Attestation verification failed".into()));
        }
        
        // DECAPPER: Use the pre-computed K = target^rho for key derivation
        // Note: DECAPPER never learns rho, only K
        let extracted = target_rho;
        
        // Derive decryption key
        let mut extracted_bytes = Vec::new();
        extracted.serialize_compressed(&mut extracted_bytes)
            .map_err(|e| GSCommitmentError::Serialization(e.to_string()))?;
        
        let key_material = Sha256::digest(&[ctx_hash, &extracted_bytes].concat()).to_vec();
        let key: [u8; 32] = key_material[..32].try_into()
            .map_err(|_| GSCommitmentError::Crypto("Key derivation failed".into()))?;
        
        // Decrypt the share
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|e| GSCommitmentError::Decryption(e.to_string()))?;
        let nonce = Nonce::from_slice(&[0u8; 12]);
        
        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|e| GSCommitmentError::Decryption(e.to_string()))?;
        
        // Convert back to Fr
        use ark_ff::PrimeField;
        let recovered_fr = Fr::from_be_bytes_mod_order(&plaintext);
        Ok(recovered_fr)
    }


    /// Commit to real arkworks Groth16 proof using rank-decomposition (backward compatibility)
    /// 
    /// # Arguments
    /// * `proof` - The Groth16 proof to commit
    /// * `vk` - The verification key
    /// * `public_input` - Public inputs to the circuit
    /// * `_use_default_crs` - Boolean flag (ignored, uses internal CRS)
    /// * `rng` - Random number generator
    /// 
    /// # Notes
    /// This is a backward compatibility method that uses the internal CRS.
    /// For new code, use the version that takes a CRS parameter explicitly.
    pub fn commit_arkworks_proof_legacy<R: Rng>(
        &self,
        proof: &ArkworksProof,
        vk: &ArkworksVK,
        public_input: &[Fr],
        _use_default_crs: bool,
        rng: &mut R,
    ) -> Result<GSAttestation, GSCommitmentError> {
        self.commit_arkworks_proof(proof, vk, public_input, &self.crs, rng)
    }

    /// Encode Groth16 verification equation into GS PPE for specific (vk, x)
    /// Groth16 verification: e(π_A, π_B) · e(π_C, δ) = e(α, β) · e(IC, γ)
    /// 2-variable PPE: X=[π_A, π_C], Y=[π_B, δ_neg]; target = e(α,β)·e(IC,γ)
    pub fn groth16_verify_as_ppe(&self, vk: &ArkworksVK, public_input: &[Fr], _crs: &CRS<Bls12_381>) -> PPE<Bls12_381> {
        // Compile Groth16 verification as a 3×3 PPE for full-GS verification
        // 
        // Groth16: e(A, B) * e(C, δ⁻¹) * e(L(x), γ⁻¹) = e(α, β)
        // 
        // X committed: [A, C, L(x)]
        // Y committed: [B, δ⁻¹, γ⁻¹]
        // Γ: 3×3 identity
        // Target: e(α, β) (the actual Groth16 pairing target)
        // 
        // Note: For full-GS verification, the target is the direct Groth16 target.
        // The verifier will compute M = e(A,B) + e(C,δ⁻¹) + e(L(x),γ⁻¹) and check M == target.
        
        use ark_ec::AffineRepr;
        let _ic = compute_ic_from_vk_and_inputs(vk, public_input);
        let _delta_neg = (-vk.delta_g2.into_group()).into_affine();
        let _gamma_neg = (-vk.gamma_g2.into_group()).into_affine();
        
        // Use the actual Groth16 pairing target: e(α, β)
        let target = Bls12_381::pairing(vk.alpha_g1, vk.beta_g2);
        
        PPE::<Bls12_381> {
            a_consts: vec![G1Affine::zero(); 3],
            b_consts: vec![G2Affine::zero(); 3],
            gamma: vec![
                vec![Fr::one(), Fr::zero(), Fr::zero()],
                vec![Fr::zero(), Fr::one(), Fr::zero()],
                vec![Fr::zero(), Fr::zero(), Fr::one()],
            ],
            target,
        }
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

#[cfg(test)]
mod tests {
    use ark_std::test_rng;
    use ark_ec::AffineRepr;
    use ark_ff::Zero;
    use ark_bls12_381::{Bls12_381, Fr};
    use super::GrothSahaiCommitments;

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
        use groth_sahai::generator::CRS;
        
        let mut groth16 = ArkworksGroth16::new();
        let vk = groth16.setup().expect("Setup should succeed");

        let witness1 = Fr::from(3u64);
        let witness2 = Fr::from(2u64); // 3 + 2 = 5
        let proof = groth16.prove(witness1, witness2).expect("Prove should succeed");

        let mut rng = test_rng();
        let crs_per_slot = CRS::<Bls12_381>::generate_crs_per_slot(&mut rng, 3, 3);
        
        let _attestation = gs
            .commit_arkworks_proof(&proof, &vk, &vec![], &crs_per_slot, &mut rng)
            .expect("Commit should succeed");

        assert_eq!(
            _attestation.cproof.xcoms.coms.len(),
            3,
            "Should have 3 X commitments (A, C, IC)"
        );
        assert_eq!(
            _attestation.cproof.ycoms.coms.len(),
            3,
            "Should have 3 Y commitments (B, δ⁻¹, γ⁻¹)"
        );
        // For full-GS proofs (real Groth16), pi_elements and theta_elements are empty
        assert!(_attestation.pi_elements.is_empty(), "Full-GS doesn't use pi_elements");
    }

    #[test]
    fn test_compute_target() {
        let seed = b"test seed";
        let gs = GrothSahaiCommitments::from_seed(seed);

        use crate::groth16_wrapper::ArkworksGroth16;
        let mut groth16 = ArkworksGroth16::new();
        let vk = groth16.setup().expect("Setup should succeed");

        let witness1 = Fr::from(3u64);
        let witness2 = Fr::from(2u64); // 3 + 2 = 5
        let _proof = groth16.prove(witness1, witness2).expect("Prove should succeed");

        // Public input is witness1 + witness2 = 5
        let public_input = vec![Fr::from(5u64)];
        let target = gs
            .compute_target(&vk, &public_input)
            .expect("Target computation should succeed");

        assert!(!target.is_zero());
    }

    #[test]
    fn test_get_crs_elements() {
        let seed = b"test seed";
        let gs = GrothSahaiCommitments::from_seed(seed);

        // Get CRS elements for canonical evaluation
        let (_u_elements, _v_elements) = gs.get_crs_elements();

        // Per-slot CRS has m slots, each with u_rand and u_var  
        // For m=3, we get 6 U elements total (2 per slot)
        assert_eq!(_u_elements.len(), 6, "Should have 6 U elements (2 per slot for m=3)");
        assert_eq!(_v_elements.len(), 6, "Should have 6 V elements (2 per slot for n=3)");
    }
}
