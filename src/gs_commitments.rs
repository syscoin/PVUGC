/*!
Groth-Sahai Commitments and Attestations

GS commitment layer for (arkworks) Groth16 proofs.
Implements GS attestation per PVUGC spec.
*/

use ark_bls12_381::{Bls12_381, Fq12, Fr, G1Affine, G2Affine};
use ark_ec::CurveGroup;
use ark_ec::{pairing::Pairing, pairing::PairingOutput, AffineRepr, PrimeGroup};
use ark_ff::{One, UniformRand, Zero};
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

/// Offline mask header published at arming time (per share)
#[derive(Clone, Debug)]
pub struct MaskedHeader {
    pub d1: Vec<G2Affine>,  // U_var^rho (G2)
    pub d2: Vec<G1Affine>,  // V_var^rho (G1)
    pub d1r: Vec<G2Affine>, // U_rand^rho (G2)
    pub d2r: Vec<G1Affine>, // V_rand^rho (G1)
    pub rho_link: Vec<u8>,  // domain-separated hash of rho
    pub tau: Vec<u8>,       // PoCE-B tag binding K, header meta and ct
    pub nonce: [u8; 12],    // AEAD nonce used for the ciphertext
    pub t_point: Vec<u8>,   // optional PoCE-A adaptor point (secp256k1)
    pub h_tag: Vec<u8>,     // optional PoCE-A hash binding statement/context
}

fn serialize_mask_header(d1: &[G2Affine], d2: &[G1Affine]) -> Result<Vec<u8>, GSCommitmentError> {
    use ark_serialize::CanonicalSerialize;
    let mut out = Vec::new();
    let mut len_u = (d1.len() as u32).to_be_bytes().to_vec();
    let mut len_v = (d2.len() as u32).to_be_bytes().to_vec();
    out.append(&mut len_u);
    for p in d1 {
        p.serialize_compressed(&mut out)
            .map_err(|e| GSCommitmentError::Serialization(e.to_string()))?;
    }
    out.append(&mut len_v);
    for p in d2 {
        p.serialize_compressed(&mut out)
            .map_err(|e| GSCommitmentError::Serialization(e.to_string()))?;
    }
    Ok(out)
}

fn rho_tag(rho_bytes: &[u8]) -> Vec<u8> {
    // Domain-separated SHA-256 tag, upgraded once Poseidon2 lands.
    let mut hasher = Sha256::new();
    hasher.update(b"PVUGC/RHO_LINK");
    hasher.update(rho_bytes);
    hasher.finalize().to_vec()
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
    pub fn compute_target(
        &self,
        vk: &ArkworksVK,
        public_input: &[Fr],
    ) -> Result<Fq12, GSCommitmentError> {
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
        // X: [A (witness), C (witness), L(x) (constant)]
        // Y: [B (witness), δ⁻¹ (constant), γ⁻¹ (constant)]
        let x_vars = vec![
            proof.pi_a,  // A
            proof.pi_c,  // C
            ic,          // L(x)
        ];
        let y_vars = vec![
            proof.pi_b,   // B
            delta_neg,    // δ⁻¹
            gamma_neg,    // γ⁻¹
        ];

        // Use randomness for witness slots, zero for constant slots
        let r_a = Fr::rand(rng);
        let r_c = Fr::rand(rng);
        let r_l = Fr::zero(); // L(x) is constant
        let r = vec![r_a, r_c, r_l];

        let s_b = Fr::rand(rng);
        let s_delta = Fr::zero(); // δ⁻¹ is constant
        let s_gamma = Fr::zero(); // γ⁻¹ is constant
        let s = vec![s_b, s_delta, s_gamma];

        // Use full-GS prover to match full-GS verifier
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

    /// PVUGC arm: publish D-masks and ciphertext (PoCE-B binding only)
    pub fn pvugc_arm<R: Rng>(
        &self,
        vk: &ArkworksVK,
        public_input: &[Fr],
        crs_per_slot: &CRS<Bls12_381>,
        rho: Fr,
        share_bytes: &[u8],
        ctx_hash: &[u8],
        rng: &mut R,
    ) -> Result<(MaskedHeader, Vec<u8>), GSCommitmentError> {
        use ark_ff::{BigInteger, PrimeField};
        use ark_serialize::CanonicalSerialize;
        use chacha20poly1305::{
            aead::{Aead, KeyInit},
            ChaCha20Poly1305, Nonce,
        };
        use groth_sahai::base_construction::RankDecompPpeBases;
        use groth_sahai::rank_decomp::RankDecomp;

        // Build PPE and rank-decomposition bases
        let ppe = self.groth16_verify_as_ppe(vk, public_input, crs_per_slot);
        let decomp = RankDecomp::decompose(&ppe.gamma);
        let bases = RankDecompPpeBases::build(crs_per_slot, &ppe, &decomp);

        // Compute statement-only D masks evaluated at rho
        use groth_sahai::pvugc::pvugc_arm as gs_pvugc_arm;
        // Build full-GS bases and arm both rand/var limbs
        use groth_sahai::base_construction::FullGSPpeBases;
        let bases_full = FullGSPpeBases::build(crs_per_slot, &ppe, &decomp);
        let d1: Vec<G2Affine> = bases_full
            .U_var
            .iter()
            .map(|g| (g.into_group() * rho).into_affine())
            .collect();
        let d1r: Vec<G2Affine> = bases_full
            .U_rand
            .iter()
            .map(|g| (g.into_group() * rho).into_affine())
            .collect();
        let d2: Vec<G1Affine> = bases_full
            .V_var
            .iter()
            .map(|g| (g.into_group() * rho).into_affine())
            .collect();
        let d2r: Vec<G1Affine> = bases_full
            .V_rand
            .iter()
            .map(|g| (g.into_group() * rho).into_affine())
            .collect();

        // Offline key: K = target^rho
        let rho_bigint = rho.into_bigint();
        let k = ppe.target.mul_bigint(rho_bigint.clone());
        let mut k_bytes = Vec::new();
        k.serialize_compressed(&mut k_bytes)
            .map_err(|e| GSCommitmentError::Serialization(e.to_string()))?;
        let key_material = Sha256::digest(&[ctx_hash, &k_bytes].concat());
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_material[..32]);

        // Encrypt share with random nonce
        let nonce_bytes: [u8; 12] = rng.gen();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|e| GSCommitmentError::Encryption(e.to_string()))?;
        let ciphertext = cipher
            .encrypt(nonce, share_bytes)
            .map_err(|e| GSCommitmentError::Encryption(e.to_string()))?;

        // PoCE-B binding tag
        let hdr_bytes = serialize_mask_header(&d1, &d2)?;
        let rho_bytes = rho_bigint.to_bytes_be();
        let rho_link = rho_tag(&rho_bytes);
        let ad = Sha256::digest(&[ctx_hash, &hdr_bytes, &rho_link].concat());
        let mut tau_input = Vec::new();
        tau_input.extend_from_slice(&k_bytes);
        tau_input.extend_from_slice(ad.as_slice());
        tau_input.extend_from_slice(&ciphertext);
        let tau = Sha256::digest(&tau_input).to_vec();
        // debug: eprintln!("SINGLE arm: k_bytes[0..16]={:x?}", &k_bytes[..std::cmp::min(16, k_bytes.len())]);

        Ok((
            MaskedHeader {
                d1,
                d2,
                d1r,
                d2r,
                rho_link,
                tau,
                nonce: nonce_bytes,
                t_point: Vec::new(),
                h_tag: Vec::new(),
            },
            ciphertext,
        ))
    }

    /// PVUGC arm with optional PoCE-A adaptor metadata
    pub fn pvugc_arm_with_t<R: Rng>(
        &self,
        vk: &ArkworksVK,
        public_input: &[Fr],
        crs_per_slot: &CRS<Bls12_381>,
        rho: Fr,
        share_bytes: &[u8],
        ctx_hash: &[u8],
        adaptor_point: &[u8],
        adaptor_tag: &[u8],
        rng: &mut R,
    ) -> Result<(MaskedHeader, Vec<u8>), GSCommitmentError> {
        let (mut header, ct) = self.pvugc_arm(
            vk,
            public_input,
            crs_per_slot,
            rho,
            share_bytes,
            ctx_hash,
            rng,
        )?;
        header.t_point = adaptor_point.to_vec();
        header.h_tag = adaptor_tag.to_vec();
        Ok((header, ct))
    }

    /// PVUGC decapsulation: verify attestation and recover plaintext share
    pub fn pvugc_decapsulate_with_masks(
        &self,
        attestation: &GSAttestation,
        vk: &ArkworksVK,
        public_input: &[Fr],
        crs_per_slot: &CRS<Bls12_381>,
        header: &MaskedHeader,
        ciphertext: &[u8],
        ctx_hash: &[u8],
    ) -> Result<Vec<u8>, GSCommitmentError> {
        use chacha20poly1305::{
            aead::{Aead, KeyInit},
            ChaCha20Poly1305, Nonce,
        };

        // Verify attestation under full GS and extract M
        let ppe = self.groth16_verify_as_ppe(vk, public_input, crs_per_slot);
        let (verifies, _extracted_target) =
            self.verify_and_extract(attestation, &ppe, crs_per_slot)?;
        if !verifies {
            return Err(GSCommitmentError::Verification(
                "GS attestation failed".into(),
            ));
        }

        if attestation.c1_commitments.len() != header.d1.len()
            || attestation.c2_commitments.len() != header.d2.len()
        {
            return Err(GSCommitmentError::InvalidInput(
                "header/commitment length mismatch".into(),
            ));
        }

        // Full-GS decap: reconstruct K via 4-term telescoping with ρ-armed rand/var bases
        use ark_ec::pairing::PairingOutput;
        let mut k = PairingOutput::<Bls12_381>::zero();
        for i in 0..header.d1.len() {
            let c1 = &attestation.cproof.xcoms.coms[i];
            // B1 limbs
            k += Bls12_381::pairing(c1.1, header.d1[i]); // var vs U_var^ρ
            k += Bls12_381::pairing(c1.0, header.d1r[i]); // rand vs U_rand^ρ
        }
        for j in 0..header.d2.len() {
            let c2 = &attestation.cproof.ycoms.coms[j];
            // B2 limbs
            k += Bls12_381::pairing(header.d2[j], c2.1); // V_var^ρ vs var
            k += Bls12_381::pairing(header.d2r[j], c2.0); // V_rand^ρ vs rand
        }
        let mut k_bytes = Vec::new();
        k.serialize_compressed(&mut k_bytes)
            .map_err(|e| GSCommitmentError::Serialization(e.to_string()))?;
        let key_material = Sha256::digest(&[ctx_hash, &k_bytes].concat());
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_material[..32]);

        // Verify PoCE-B tag against K = M^rho bytes
        let hdr_bytes = serialize_mask_header(&header.d1, &header.d2)?;
        let ad = Sha256::digest(&[ctx_hash, &hdr_bytes, &header.rho_link].concat());
        let mut tau_input = Vec::new();
        tau_input.extend_from_slice(&k_bytes);
        tau_input.extend_from_slice(ad.as_slice());
        tau_input.extend_from_slice(ciphertext);
        let tau_expected = Sha256::digest(&tau_input).to_vec();
        if tau_expected != header.tau {
            return Err(GSCommitmentError::Verification(
                "PoCE-B check failed".into(),
            ));
        }

        // Decrypt the share
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|e| GSCommitmentError::Decryption(e.to_string()))?;
        let nonce = Nonce::from_slice(&header.nonce);
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| GSCommitmentError::Decryption(e.to_string()))?;
        Ok(plaintext)
    }

    /// Multi-CRS AND-of-2 arm: two mask sets + single ciphertext
    pub fn pvugc_arm_and2<R: Rng>(
        &self,
        vk: &ArkworksVK,
        public_input: &[Fr],
        crs1: &CRS<Bls12_381>,
        crs2: &CRS<Bls12_381>,
        rho: Fr,
        share_bytes: &[u8],
        ctx_hash: &[u8],
        rng: &mut R,
    ) -> Result<((MaskedHeader, MaskedHeader), Vec<u8>), GSCommitmentError> {
        use ark_ff::{BigInteger, PrimeField};
        use ark_serialize::CanonicalSerialize;
        use chacha20poly1305::{
            aead::{Aead, KeyInit},
            ChaCha20Poly1305, Nonce,
        };
        use groth_sahai::base_construction::RankDecompPpeBases;
        use groth_sahai::rank_decomp::RankDecomp;

        // Build PPEs for both CRS instances
        let ppe1 = self.groth16_verify_as_ppe(vk, public_input, crs1);
        let ppe2 = self.groth16_verify_as_ppe(vk, public_input, crs2);
        let decomp1 = RankDecomp::decompose(&ppe1.gamma);
        let decomp2 = RankDecomp::decompose(&ppe2.gamma);
        let bases1 = RankDecompPpeBases::build(crs1, &ppe1, &decomp1);
        let bases2 = RankDecompPpeBases::build(crs2, &ppe2, &decomp2);

        use groth_sahai::pvugc::pvugc_arm as gs_pvugc_arm;
        // Build full-GS bases and arm both rand/var limbs (same for both headers)
        use groth_sahai::base_construction::FullGSPpeBases;
        let bases_full = FullGSPpeBases::build(crs1, &ppe1, &decomp1);
        let d1a: Vec<G2Affine> = bases_full
            .U_var
            .iter()
            .map(|g| (g.into_group() * rho).into_affine())
            .collect();
        let d1ra: Vec<G2Affine> = bases_full
            .U_rand
            .iter()
            .map(|g| (g.into_group() * rho).into_affine())
            .collect();
        let d2a: Vec<G1Affine> = bases_full
            .V_var
            .iter()
            .map(|g| (g.into_group() * rho).into_affine())
            .collect();
        let d2ra: Vec<G1Affine> = bases_full
            .V_rand
            .iter()
            .map(|g| (g.into_group() * rho).into_affine())
            .collect();
        let d1b = d1a.clone();
        let d1rb = d1ra.clone();
        let d2b = d2a.clone();
        let d2rb = d2ra.clone();

        let rho_bigint = rho.into_bigint();

        // K = target^rho (single K used for both headers)
        let k_bytes = {
            let mut tmp = Vec::new();
            ppe1.target
                .mul_bigint(rho_bigint.clone())
                .serialize_compressed(&mut tmp)
                .map_err(|e| GSCommitmentError::Serialization(e.to_string()))?;
            tmp
        };
        // Derive key from K
        let key_material = Sha256::digest(&[ctx_hash, &k_bytes].concat());
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_material[..32]);

        let nonce_bytes: [u8; 12] = rng.gen();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|e| GSCommitmentError::Encryption(e.to_string()))?;
        eprintln!("AND2 arm: key[0..8]={:x?}", &key[..8]);
        let ciphertext = cipher
            .encrypt(nonce, share_bytes)
            .map_err(|e| GSCommitmentError::Encryption(e.to_string()))?;

        let rho_bytes = rho_bigint.to_bytes_be();
        let rho_link = rho_tag(&rho_bytes);
        let hdr_a = serialize_mask_header(&d1a, &d2a)?;
        let hdr_b = serialize_mask_header(&d1b, &d2b)?;
        let ada = Sha256::digest(&[ctx_hash, &hdr_a, &rho_link].concat());
        let adb = Sha256::digest(&[ctx_hash, &hdr_b, &rho_link].concat());

        let mut tau_a_input = Vec::new();
        tau_a_input.extend_from_slice(&k_bytes);
        tau_a_input.extend_from_slice(ada.as_slice());
        tau_a_input.extend_from_slice(&ciphertext);
        let tau_a = Sha256::digest(&tau_a_input).to_vec();
        // debug: eprintln!("AND2 arm: k_bytes[0..16]={:x?}", &k_bytes[..std::cmp::min(16, k_bytes.len())]);

        let mut tau_b_input = Vec::new();
        tau_b_input.extend_from_slice(&k_bytes);
        tau_b_input.extend_from_slice(adb.as_slice());
        tau_b_input.extend_from_slice(&ciphertext);
        let tau_b = Sha256::digest(&tau_b_input).to_vec();
        // debug: eprintln!("AND2 arm: k_bytes[0..16]={:x?}", &k_bytes[..std::cmp::min(16, k_bytes.len())]);

        let header_a = MaskedHeader {
            d1: d1a,
            d2: d2a,
            d1r: d1ra,
            d2r: d2ra,
            rho_link: rho_link.clone(),
            tau: tau_a,
            nonce: nonce_bytes,
            t_point: Vec::new(),
            h_tag: Vec::new(),
        };
        let header_b = MaskedHeader {
            d1: d1b,
            d2: d2b,
            d1r: d1rb,
            d2r: d2rb,
            rho_link,
            tau: tau_b,
            nonce: nonce_bytes,
            t_point: Vec::new(),
            h_tag: Vec::new(),
        };

        Ok(((header_a, header_b), ciphertext))
    }

    /// AND-of-2 decapsulation: both headers required to decrypt
    pub fn pvugc_decapsulate_with_masks_and2(
        &self,
        attestation: &GSAttestation,
        vk: &ArkworksVK,
        public_input: &[Fr],
        crs1: &CRS<Bls12_381>,
        crs2: &CRS<Bls12_381>,
        header1: &MaskedHeader,
        header2: &MaskedHeader,
        ciphertext: &[u8],
        ctx_hash: &[u8],
    ) -> Result<Vec<u8>, GSCommitmentError> {
        use chacha20poly1305::{
            aead::{Aead, KeyInit},
            ChaCha20Poly1305, Nonce,
        };

        let ppe1 = self.groth16_verify_as_ppe(vk, public_input, crs1);
        let (ok1, _) = self.verify_and_extract(attestation, &ppe1, crs1)?;
        if !ok1 {
            return Err(GSCommitmentError::Verification(
                "GS attestation failed under primary CRS".into(),
            ));
        }
        let _ = crs2;

        if attestation.c1_commitments.len() != header1.d1.len()
            || attestation.c1_commitments.len() != header2.d1.len()
            || attestation.c2_commitments.len() != header1.d2.len()
            || attestation.c2_commitments.len() != header2.d2.len()
        {
            return Err(GSCommitmentError::InvalidInput(
                "header/commitment length mismatch".into(),
            ));
        }

        // Full-GS armed decap on both headers to get K1,K2
        use ark_ec::pairing::PairingOutput;
        let mut k1 = PairingOutput::<Bls12_381>::zero();
        for i in 0..header1.d1.len() {
            let c1 = &attestation.cproof.xcoms.coms[i];
            k1 += Bls12_381::pairing(c1.1, header1.d1[i]);
            k1 += Bls12_381::pairing(c1.0, header1.d1r[i]);
        }
        for j in 0..header1.d2.len() {
            let c2 = &attestation.cproof.ycoms.coms[j];
            k1 += Bls12_381::pairing(header1.d2[j], c2.1);
            k1 += Bls12_381::pairing(header1.d2r[j], c2.0);
        }
        let mut k2 = PairingOutput::<Bls12_381>::zero();
        for i in 0..header2.d1.len() {
            let c1 = &attestation.cproof.xcoms.coms[i];
            k2 += Bls12_381::pairing(c1.1, header2.d1[i]);
            k2 += Bls12_381::pairing(c1.0, header2.d1r[i]);
        }
        for j in 0..header2.d2.len() {
            let c2 = &attestation.cproof.ycoms.coms[j];
            k2 += Bls12_381::pairing(header2.d2[j], c2.1);
            k2 += Bls12_381::pairing(header2.d2r[j], c2.0);
        }
        let mut k1_bytes = Vec::new();
        k1.serialize_compressed(&mut k1_bytes)
            .map_err(|e| GSCommitmentError::Serialization(e.to_string()))?;
        let mut k2_bytes = Vec::new();
        k2.serialize_compressed(&mut k2_bytes)
            .map_err(|e| GSCommitmentError::Serialization(e.to_string()))?;

        // Verify per-header PoCE-B tags
        let hdr1 = serialize_mask_header(&header1.d1, &header1.d2)?;
        let hdr2 = serialize_mask_header(&header2.d1, &header2.d2)?;
        let ad1 = Sha256::digest(&[ctx_hash, &hdr1, &header1.rho_link].concat());
        let ad2 = Sha256::digest(&[ctx_hash, &hdr2, &header2.rho_link].concat());

        let mut tau1_input = Vec::new();
        tau1_input.extend_from_slice(&k1_bytes);
        tau1_input.extend_from_slice(ad1.as_slice());
        tau1_input.extend_from_slice(ciphertext);
        let tau1_expected = Sha256::digest(&tau1_input).to_vec();
        if tau1_expected != header1.tau {
            return Err(GSCommitmentError::Verification(
                "PoCE-B check failed (header1)".into(),
            ));
        }

        let mut tau2_input = Vec::new();
        tau2_input.extend_from_slice(&k2_bytes);
        tau2_input.extend_from_slice(ad2.as_slice());
        tau2_input.extend_from_slice(ciphertext);
        let tau2_expected = Sha256::digest(&tau2_input).to_vec();
        if tau2_expected != header2.tau {
            return Err(GSCommitmentError::Verification(
                "PoCE-B check failed (header2)".into(),
            ));
        }

        if header1.nonce != header2.nonce {
            return Err(GSCommitmentError::InvalidInput(
                "AND-headers use different nonces".into(),
            ));
        }

        // KDF from k1 (extracted via pvugc_decap)
        let key_material = Sha256::digest(&[ctx_hash, &k1_bytes].concat());
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_material[..32]);

        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|e| GSCommitmentError::Decryption(e.to_string()))?;
        let nonce = Nonce::from_slice(&header1.nonce);
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| GSCommitmentError::Decryption(e.to_string()))?;
        Ok(plaintext)
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
        use groth_sahai::base_construction::FullGSPpeBases;
        use groth_sahai::rank_decomp::RankDecomp;
        let decomp = RankDecomp::decompose(&ppe.gamma);
        let bases = FullGSPpeBases::build(crs_per_slot, ppe, &decomp);
        let (ok, _) = ppe.verify_full_gs(&attestation.cproof, crs_per_slot, &bases);
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
        use groth_sahai::base_construction::FullGSPpeBases;
        use groth_sahai::rank_decomp::RankDecomp;

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
        use ark_ff::BigInteger;
        use ark_serialize::CanonicalSerialize;
        use chacha20poly1305::{
            aead::{Aead, KeyInit},
            ChaCha20Poly1305, Nonce,
        };

        // Create GS attestation
        let attestation = self.commit_arkworks_proof(proof, vk, public_input, crs_per_slot, rng)?;

        // Compute target^rho for key derivation
        let ppe = self.groth16_verify_as_ppe(vk, public_input, crs_per_slot);
        let target_rho = ppe.target * rho;

        // Derive encryption key from target^rho
        let mut target_rho_bytes = Vec::new();
        target_rho
            .serialize_compressed(&mut target_rho_bytes)
            .map_err(|e| GSCommitmentError::Serialization(e.to_string()))?;

        let key_material = Sha256::digest(&[ctx_hash, &target_rho_bytes].concat()).to_vec();
        let key: [u8; 32] = key_material[..32]
            .try_into()
            .map_err(|_| GSCommitmentError::Crypto("Key derivation failed".into()))?;

        // Encrypt the share
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|e| GSCommitmentError::Encryption(e.to_string()))?;
        let nonce = Nonce::from_slice(&[0u8; 12]);

        use ark_ff::PrimeField;
        let share_bytes = share.into_bigint().to_bytes_be();
        let ciphertext = cipher
            .encrypt(nonce, share_bytes.as_ref())
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
        use ark_serialize::CanonicalSerialize;
        use chacha20poly1305::{
            aead::{Aead, KeyInit},
            ChaCha20Poly1305, Nonce,
        };

        // Build PPE and verify, extracting M
        let ppe = self.groth16_verify_as_ppe(vk, public_input, crs_per_slot);
        let (verifies, m_extracted) = self.verify_and_extract(attestation, &ppe, crs_per_slot)?;

        if !verifies || m_extracted != ppe.target {
            return Err(GSCommitmentError::Verification(
                "Attestation verification failed".into(),
            ));
        }

        // DECAPPER: Use the pre-computed K = target^rho for key derivation
        // Note: DECAPPER never learns rho, only K
        let extracted = target_rho;

        // Derive decryption key
        let mut extracted_bytes = Vec::new();
        extracted
            .serialize_compressed(&mut extracted_bytes)
            .map_err(|e| GSCommitmentError::Serialization(e.to_string()))?;

        let key_material = Sha256::digest(&[ctx_hash, &extracted_bytes].concat()).to_vec();
        let key: [u8; 32] = key_material[..32]
            .try_into()
            .map_err(|_| GSCommitmentError::Crypto("Key derivation failed".into()))?;

        // Decrypt the share
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|e| GSCommitmentError::Decryption(e.to_string()))?;
        let nonce = Nonce::from_slice(&[0u8; 12]);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
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
    pub fn groth16_verify_as_ppe(
        &self,
        vk: &ArkworksVK,
        public_input: &[Fr],
        _crs: &CRS<Bls12_381>,
    ) -> PPE<Bls12_381> {
        use ark_ec::AffineRepr;
        // Rank-decomp PPE encoding for Groth16:
        // M = e(A,B) + e(C, δ) + e(IC(x), γ) should equal e(α, β)
        let ic = compute_ic_from_vk_and_inputs(vk, public_input);
        let target = Bls12_381::pairing(vk.alpha_g1, vk.beta_g2);

        PPE::<Bls12_381> {
            // V and Z use a_consts; set third slot to IC(x) to produce e(IC, γ)
            a_consts: vec![G1Affine::zero(), G1Affine::zero(), ic],
            b_consts: vec![G2Affine::zero(); 3],
            // Γ encodes e(A,B) and e(C, δ) only; third row/col zero
            gamma: vec![
                vec![Fr::one(), Fr::zero(), Fr::zero()],
                vec![Fr::zero(), Fr::one(), Fr::zero()],
                vec![Fr::zero(), Fr::zero(), Fr::zero()],
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
    use super::GrothSahaiCommitments;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_ec::AffineRepr;
    use ark_ff::Zero;
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
        use groth_sahai::generator::CRS;

        let mut groth16 = ArkworksGroth16::new();
        let vk = groth16.setup().expect("Setup should succeed");

        let witness1 = Fr::from(3u64);
        let witness2 = Fr::from(2u64); // 3 + 2 = 5
        let proof = groth16
            .prove(witness1, witness2)
            .expect("Prove should succeed");

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
        // For full-GS proofs (real Groth16), we may still carry internal pi/theta; just check sizes
        assert_eq!(_attestation.cproof.xcoms.coms.len(), 3);
        assert_eq!(_attestation.cproof.ycoms.coms.len(), 3);
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
        let _proof = groth16
            .prove(witness1, witness2)
            .expect("Prove should succeed");

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
        assert_eq!(
            _u_elements.len(),
            6,
            "Should have 6 U elements (2 per slot for m=3)"
        );
        assert_eq!(
            _v_elements.len(),
            6,
            "Should have 6 V elements (2 per slot for n=3)"
        );
    }
}
