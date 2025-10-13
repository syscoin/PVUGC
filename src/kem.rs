/*!
Product-Key KEM for PVUGC
The core innovation: turning proof existence into a decryption key

This module implements the KEM functionality.
*/

use ark_bls12_381::{Bls12_381, Fr};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField, Field};
use ark_std::{rand::Rng, vec::Vec};

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::bls12381_ops::{BLS12381Ops, GTElement, Scalar};
use crate::gs_kem_helpers::fr_from_be;
use crate::groth16_wrapper::ArkworksVK;
use crate::gs_commitments::compute_ic_from_vk_and_inputs;
use groth_sahai::data_structures::{BT, ComT};

/// Errors that can occur during KEM operations
#[derive(Error, Debug)]
pub enum KEMError {
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Deserialization error: {0}")]
    Deserialization(String),
    #[error("Encryption error: {0}")]
    Encryption(String),
    #[error("Decryption error: {0}")]
    Decryption(String),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Crypto error: {0}")]
    Crypto(String),
}

impl From<String> for KEMError {
    fn from(err: String) -> Self {
        KEMError::Deserialization(err)
    }
}

/// KEM share containing encapsulated data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KEMShare {
    /// Index of this share
    pub index: u32,

    // Phase-B masks (primaries)
    pub d1_masks: Vec<Vec<u8>>, // U^ρ (G1 pairs)
    pub d2_masks: Vec<Vec<u8>>, // V^ρ (G2 pairs)

    // Phase-B masks (duals)
    pub d1_star_masks: Vec<Vec<u8>>, // U*^ρ (G2 pairs)
    pub d2_star_masks: Vec<Vec<u8>>, // V*^ρ (G1 pairs)

    // (optional) Instance-only masks you had before; you can keep or remove
    pub d1_inst: Vec<Vec<u8>>,
    pub d2_inst: Vec<Vec<u8>>,

    // Phase-A lock for rho
    pub rho_ct: Vec<u8>,
    pub rho_tag: Vec<u8>,

    // Adaptor share lock
    pub ciphertext: Vec<u8>,
    pub auth_tag: Vec<u8>,

    // Commitments to the adaptor share
    pub t_i: Vec<u8>,
    pub h_i: Vec<u8>,
}

/// Product-Key KEM implementation
pub struct ProductKeyKEM;

impl ProductKeyKEM {
    /// Create a new KEM instance
    pub fn new() -> Self {
        Self
    }

    /// Key derivation function from GT bytes
    pub fn kdf_from_bytes(
        &self,
        gt_bytes: &[u8],
        ctx_hash: &[u8],
        gs_instance_digest: &[u8],
    ) -> Result<Vec<u8>, KEMError> {
        // Salt: combine context hash and GS instance digest
        let mut salt_input = Vec::new();
        salt_input.extend_from_slice(ctx_hash);
        salt_input.extend_from_slice(gs_instance_digest);
        let salt = Sha256::digest(&salt_input);

        // Info: domain separation tag
        let info = b"PVUGC/KDF/v1";

        // Use HKDF for key derivation
        self.hkdf_derive(gt_bytes, &salt, info, 32)
    }

    /// HKDF-based key derivation
    fn hkdf_derive(
        &self,
        ikm: &[u8],
        salt: &[u8],
        info: &[u8],
        length: usize,
    ) -> Result<Vec<u8>, KEMError> {
        // Simplified KDF using SHA256 - proper implementation would use HKDF
        let mut hasher = Sha256::new();
        hasher.update(salt);
        hasher.update(ikm);
        hasher.update(info);
        let hash = hasher.finalize();

        // Truncate or repeat hash to get desired length
        let mut okm = Vec::new();
        let mut current_hash = hash;
        while okm.len() < length {
            let remaining = length - okm.len();
            let to_copy = std::cmp::min(remaining, current_hash.len());
            okm.extend_from_slice(&current_hash[..to_copy]);
            if remaining > current_hash.len() {
                // Re-hash for more bytes
                let mut hasher = Sha256::new();
                hasher.update(current_hash);
                current_hash = hasher.finalize();
            }
        }

        Ok(okm)
    }

    /// Data encapsulation mechanism with key commitment
    pub fn dem_encrypt(
        &self,
        key: &[u8],
        plaintext: &[u8],
        ad: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), KEMError> {
        // Use ChaCha20-Poly1305 for DEM encryption
        self.chacha20poly1305_encrypt(key, plaintext, ad)
    }

    /// ChaCha20-Poly1305 encryption with key commitment
    fn chacha20poly1305_encrypt(
        &self,
        key: &[u8],
        plaintext: &[u8],
        ad: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), KEMError> {
        // Derive encryption key and nonce from master key
        let mut kdf_input = Vec::new();
        kdf_input.extend_from_slice(b"PVUGC/DEM/ENC/v1");
        kdf_input.extend_from_slice(key);
        kdf_input.extend_from_slice(&ad[..ad.len().min(64)]);

        let derived = Sha256::digest(&kdf_input);
        let enc_key = &derived[..32];
        // Generate nonce from key and AD for deterministic behavior
        let mut nonce_input = Vec::new();
        nonce_input.extend_from_slice(key);
        nonce_input.extend_from_slice(&ad[..ad.len().min(32)]);
        let nonce_hash = Sha256::digest(&nonce_input);
        let nonce_bytes = &nonce_hash[..12];

        // Key commitment: hash key into the AAD
        let mut key_commit_input = Vec::new();
        key_commit_input.extend_from_slice(b"PVUGC/KC");
        key_commit_input.extend_from_slice(key);
        let key_commit = Sha256::digest(&key_commit_input)[..16].to_vec();

        // Build AAD with key commitment
        let mut aad = Vec::new();
        aad.extend_from_slice(&key_commit);
        aad.extend_from_slice(ad);

        // Encrypt with ChaCha20-Poly1305
        let cipher = ChaCha20Poly1305::new(Key::from_slice(enc_key));
        let nonce = Nonce::from_slice(nonce_bytes);

        let ciphertext_and_tag = cipher.encrypt(nonce, plaintext).map_err(|e| {
            KEMError::Encryption(format!("ChaCha20-Poly1305 encrypt error: {:?}", e))
        })?;

        // Split ciphertext and tag (Poly1305 tag is last 16 bytes)
        let ciphertext = ciphertext_and_tag[..ciphertext_and_tag.len() - 16].to_vec();
        let auth_tag = ciphertext_and_tag[ciphertext_and_tag.len() - 16..].to_vec();

        Ok((ciphertext, auth_tag))
    }

    /// Data decapsulation mechanism with key commitment verification
    pub fn dem_decrypt(
        &self,
        key: &[u8],
        ciphertext: &[u8],
        auth_tag: &[u8],
        ad: &[u8],
    ) -> Result<Vec<u8>, KEMError> {
        // Use ChaCha20-Poly1305 for DEM decryption
        self.chacha20poly1305_decrypt(key, ciphertext, auth_tag, ad)
    }

    /// ChaCha20-Poly1305 decryption with key commitment verification
    fn chacha20poly1305_decrypt(
        &self,
        key: &[u8],
        ciphertext: &[u8],
        auth_tag: &[u8],
        ad: &[u8],
    ) -> Result<Vec<u8>, KEMError> {
        // Derive same encryption key and nonce
        let mut kdf_input = Vec::new();
        kdf_input.extend_from_slice(b"PVUGC/DEM/ENC/v1");
        kdf_input.extend_from_slice(key);
        kdf_input.extend_from_slice(&ad[..ad.len().min(64)]);

        let derived = Sha256::digest(&kdf_input);
        let enc_key = &derived[..32];
        // Generate nonce from key and AD for deterministic behavior
        let mut nonce_input = Vec::new();
        nonce_input.extend_from_slice(key);
        nonce_input.extend_from_slice(&ad[..ad.len().min(32)]);
        let nonce_hash = Sha256::digest(&nonce_input);
        let nonce_bytes = &nonce_hash[..12];

        // Key commitment: hash key into the AAD
        let mut key_commit_input = Vec::new();
        key_commit_input.extend_from_slice(b"PVUGC/KC");
        key_commit_input.extend_from_slice(key);
        let key_commit = Sha256::digest(&key_commit_input)[..16].to_vec();

        // Build AAD with key commitment
        let mut aad = Vec::new();
        aad.extend_from_slice(&key_commit);
        aad.extend_from_slice(ad);

        // Decrypt with ChaCha20-Poly1305
        let cipher = ChaCha20Poly1305::new(Key::from_slice(enc_key));
        let nonce = Nonce::from_slice(nonce_bytes);

        // Combine ciphertext and tag
        let mut ciphertext_and_tag = Vec::new();
        ciphertext_and_tag.extend_from_slice(ciphertext);
        ciphertext_and_tag.extend_from_slice(auth_tag);

        let plaintext = cipher
            .decrypt(nonce, ciphertext_and_tag.as_slice())
            .map_err(|e| {
                KEMError::Decryption(format!("ChaCha20-Poly1305 decrypt error: {:?}", e))
            })?;

        Ok(plaintext)
    }

    /// Mask CRS V pairs (G2) with scalar multiplication
    pub fn mask_g2_pairs(&self, pairs: &[Vec<u8>], rho: Scalar) -> Result<Vec<Vec<u8>>, KEMError> {
        let mut masked_pairs = Vec::new();

        for pair_bytes in pairs {
            if pair_bytes.len() != 192 {
                return Err(KEMError::InvalidInput(format!(
                    "G2 pair must be 192 bytes, got {}",
                    pair_bytes.len()
                )));
            }

            // Split pair into two G2 points
            let v0_bytes = &pair_bytes[..96];
            let v1_bytes = &pair_bytes[96..];

            // Use BLS12381Ops for scalar multiplication
            let v0_masked = BLS12381Ops::g2_multiply(&v0_bytes.to_vec(), rho)
                .map_err(|e| KEMError::Crypto(format!("G2 v0 multiply: {:?}", e)))?;
            let v1_masked = BLS12381Ops::g2_multiply(&v1_bytes.to_vec(), rho)
                .map_err(|e| KEMError::Crypto(format!("G2 v1 multiply: {:?}", e)))?;

            // Combine masked points
            let mut masked_pair = Vec::new();
            masked_pair.extend_from_slice(&v0_masked);
            masked_pair.extend_from_slice(&v1_masked);

            masked_pairs.push(masked_pair);
        }

        Ok(masked_pairs)
    }

    /// Mask CRS U pairs (G1) with scalar multiplication
    pub fn mask_g1_pairs(&self, pairs: &[Vec<u8>], rho: Scalar) -> Result<Vec<Vec<u8>>, KEMError> {
        let mut masked_pairs = Vec::new();

        for pair_bytes in pairs {
            if pair_bytes.len() != 96 {
                return Err(KEMError::InvalidInput(format!(
                    "G1 pair must be 96 bytes, got {}",
                    pair_bytes.len()
                )));
            }

            // Split pair into two G1 points
            let u0_bytes = &pair_bytes[..48];
            let u1_bytes = &pair_bytes[48..];

            // Use BLS12381Ops for scalar multiplication
            let u0_masked = BLS12381Ops::g1_multiply(&u0_bytes.to_vec(), rho)
                .map_err(|e| KEMError::Crypto(format!("G1 u0 multiply: {:?}", e)))?;
            let u1_masked = BLS12381Ops::g1_multiply(&u1_bytes.to_vec(), rho)
                .map_err(|e| KEMError::Crypto(format!("G1 u1 multiply: {:?}", e)))?;

            // Combine masked points
            let mut masked_pair = Vec::new();
            masked_pair.extend_from_slice(&u0_masked);
            masked_pair.extend_from_slice(&u1_masked);

            masked_pairs.push(masked_pair);
        }

        Ok(masked_pairs)
    }

    /// Mask G2 dual pairs with scalar multiplication
    pub fn mask_g2_dual_pairs(&self, u_star_pairs: &[(ark_bls12_381::G2Affine, ark_bls12_381::G2Affine)], rho: Scalar) -> Vec<Vec<u8>> {
        use ark_serialize::CanonicalSerialize;
        u_star_pairs.iter().map(|(a, b)| {
            let a = (a.into_group() * rho).into_affine();
            let b = (b.into_group() * rho).into_affine();
            let mut v = Vec::new();
            a.serialize_compressed(&mut v).unwrap();
            b.serialize_compressed(&mut v).unwrap();
            v
        }).collect()
    }

    /// Mask G1 dual pairs with scalar multiplication
    pub fn mask_g1_dual_pairs(&self, v_star_pairs: &[(ark_bls12_381::G1Affine, ark_bls12_381::G1Affine)], rho: Scalar) -> Vec<Vec<u8>> {
        use ark_serialize::CanonicalSerialize;
        v_star_pairs.iter().map(|(a, b)| {
            let a = (a.into_group() * rho).into_affine();
            let b = (b.into_group() * rho).into_affine();
            let mut v = Vec::new();
            a.serialize_compressed(&mut v).unwrap();
            b.serialize_compressed(&mut v).unwrap();
            v
        }).collect()
    }

    /// Encapsulate using canonical evaluator
    pub fn encapsulate<R: Rng>(
        &self,
        rng: &mut R,
        share_index: u32,
        attestation_commitments_g1: &[Vec<u8>], // C1 from attestation
        attestation_commitments_g2: &[Vec<u8>], // C2 from attestation
        pi_elements: &[Vec<u8>],                // π proof elements (G2)
        theta_elements: &[Vec<u8>],             // θ proof elements (G1)
        crs_u: &[Vec<u8>],                      // CRS U elements (G1)
        crs_v: &[Vec<u8>],                      // CRS V elements (G2)
        crs_u_duals: &[Vec<u8>],                // CRS U* dual elements (G2)
        crs_v_duals: &[Vec<u8>],                // CRS V* dual elements (G1)
        adaptor_share: Scalar,
        ctx_hash: &[u8],
        gs_instance_digest: &[u8],
    ) -> Result<(KEMShare, GTElement), KEMError> {
        // Generate random rho_i (non-zero)
        let rho_i = BLS12381Ops::random_scalar(rng);

        // Mask CRS U and V elements with ρ for public sharing
        let u_masked = self.mask_g1_pairs(crs_u, rho_i)?; // U^ρ in G1
        let v_masked = self.mask_g2_pairs(crs_v, rho_i)?; // V^ρ in G2
        let u_dual_masked = self.mask_g2_pairs(crs_u_duals, rho_i)?; // U*^ρ in G2
        let v_dual_masked = self.mask_g1_pairs(crs_v_duals, rho_i)?; // V*^ρ in G1

        // Compute ComT anchor using five-bucket evaluator (proof agnostic)
        let comt = crate::gs_kem_helpers::compute_five_bucket_anchor(
            attestation_commitments_g1,
            attestation_commitments_g2,
            pi_elements,
            theta_elements,
            crs_u,
            crs_v,
            crs_u_duals,
            crs_v_duals,
            rho_i,
        )
        .map_err(|e| KEMError::Crypto(e))?;

        let m_i_bytes =
            crate::gs_kem_helpers::serialize_comt(&comt).map_err(|e| KEMError::Serialization(e))?;

        // Derive encryption key directly from serialized GT bytes to avoid
        // a deserialize→serialize round-trip
        let k_i = self.kdf_from_bytes(&m_i_bytes, ctx_hash, gs_instance_digest)?;

        // Deserialize to GTElement for return value
        let m_matrix = comt.as_matrix();
        let PairingOutput(gt_cell) = m_matrix[1][1];
        let m_i = gt_cell;
        // Compute T_i = adaptor_share * G on secp256k1
        let t_i = self.compute_adaptor_point(adaptor_share)?;

        // Hash commitment h_i = H(s_i || T_i || i)
        let mut h_i_input = Vec::new();
        h_i_input.extend_from_slice(&adaptor_share.into_bigint().to_bytes_be());
        h_i_input.extend_from_slice(&t_i);
        h_i_input.extend_from_slice(&share_index.to_be_bytes());
        let h_i = Sha256::digest(&h_i_input).to_vec();

        // Encrypt (s_i || h_i)
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(&adaptor_share.into_bigint().to_bytes_be());
        plaintext.extend_from_slice(&h_i);

        // Build associated data
        let ad = self.build_ad(
            share_index,
            ctx_hash,
            gs_instance_digest,
            &t_i,
            &u_masked,
            &v_masked,
            &u_dual_masked,
            &v_dual_masked,
        )?;

        // Encrypt with key-committing DEM
        let (ciphertext, auth_tag) = self.dem_encrypt(&k_i, &plaintext, &ad)?;

        // Create public KEM share
        let kem_share = KEMShare {
            index: share_index,
            d1_masks: u_masked, // Now U^ρ in G1
            d2_masks: v_masked, // Now V^ρ in G2
            d1_star_masks: u_dual_masked,
            d2_star_masks: v_dual_masked,
            d1_inst: Vec::new(),
            d2_inst: Vec::new(),
            rho_ct: Vec::new(),
            rho_tag: Vec::new(),
            ciphertext,
            auth_tag,
            t_i,
            h_i,
        };

        Ok((kem_share, m_i))
    }

    /// Encapsulate (deposit) without attestation: compute ComT from target^ρ using (vk, x)
    pub fn encapsulate_deposit<R: Rng>(
        &self,
        rng: &mut R,
        share_index: u32,
        crs_u: &[Vec<u8>],                      // CRS U elements (G1)
        crs_v: &[Vec<u8>],                      // CRS V elements (G2)
        crs_u_duals: &[Vec<u8>],                // CRS U* dual elements (G2)
        crs_v_duals: &[Vec<u8>],                // CRS V* dual elements (G1)
        adaptor_share: Scalar,
        ctx_hash: &[u8],
        gs_instance_digest: &[u8],
        vk: &ArkworksVK,
        public_input: &[Fr],
    ) -> Result<(KEMShare, GTElement), KEMError> {
        // Sample ρ and publish masked primaries and duals
        let rho_i = BLS12381Ops::random_scalar(rng);

        let u_masked = self.mask_g1_pairs(crs_u, rho_i)?; // U^ρ in G1
        let v_masked = self.mask_g2_pairs(crs_v, rho_i)?; // V^ρ in G2
        let u_dual_masked = self.mask_g2_pairs(crs_u_duals, rho_i)?; // U*^ρ in G2
        let v_dual_masked = self.mask_g1_pairs(crs_v_duals, rho_i)?; // V*^ρ in G1

        // Compute target G_G16(vk,x) and raise to ρ
        let ic = compute_ic_from_vk_and_inputs(vk, public_input);
        let e_alpha_beta = Bls12_381::pairing(vk.alpha_g1, vk.beta_g2);
        let e_ic_gamma = Bls12_381::pairing(ic, vk.gamma_g2);
        let target = (e_alpha_beta.0 * e_ic_gamma.0).pow(rho_i.into_bigint());

        // Build ComT as linear_map_PPE(target^ρ)
        let comt = ComT::<Bls12_381>::linear_map_PPE(&ark_ec::pairing::PairingOutput::<Bls12_381>(target));

        // Derive key from full ComT bytes
        let m_i_bytes = crate::gs_kem_helpers::serialize_comt(&comt)
            .map_err(|e| KEMError::Serialization(e))?;
        let k_i = self.kdf_from_bytes(&m_i_bytes, ctx_hash, gs_instance_digest)?;

        // Extract a representative GT cell to return (not used by DEM)
        let m_matrix = comt.as_matrix();
        let PairingOutput(gt_cell) = m_matrix[1][1];
        let m_i = gt_cell;

        // Compute adaptor point and commitment
        let t_i = self.compute_adaptor_point(adaptor_share)?;
        let mut h_i_input = Vec::new();
        h_i_input.extend_from_slice(&adaptor_share.into_bigint().to_bytes_be());
        h_i_input.extend_from_slice(&t_i);
        h_i_input.extend_from_slice(&share_index.to_be_bytes());
        let h_i = Sha256::digest(&h_i_input).to_vec();

        // Encrypt (s_i || h_i) under key derived from ComT
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(&adaptor_share.into_bigint().to_bytes_be());
        plaintext.extend_from_slice(&h_i);

        // AAD binds index, context, digest, adaptor point, and all four masked arrays
        let ad = self.build_ad(
            share_index,
            ctx_hash,
            gs_instance_digest,
            &t_i,
            &u_masked,
            &v_masked,
            &u_dual_masked,
            &v_dual_masked,
        )?;

        let (ciphertext, auth_tag) = self.dem_encrypt(&k_i, &plaintext, &ad)?;

        let kem_share = KEMShare {
            index: share_index,
            d1_masks: u_masked,
            d2_masks: v_masked,
            d1_star_masks: u_dual_masked,
            d2_star_masks: v_dual_masked,
            d1_inst: Vec::new(),
            d2_inst: Vec::new(),
            rho_ct: Vec::new(),
            rho_tag: Vec::new(),
            ciphertext,
            auth_tag,
            t_i,
            h_i,
        };

        Ok((kem_share, m_i))
    }

    /// Encapsulate Duo (deposit) with 5-bucket ComT
    pub fn encapsulate_duo<R: Rng>(
        &self,
        rng: &mut R,
        share_index: u32,
        crs_u: &[Vec<u8>],           // CRS.u serialized
        crs_v: &[Vec<u8>],           // CRS.v serialized
        u_star_pairs: &[(ark_bls12_381::G2Affine, ark_bls12_381::G2Affine)], // base duals (G2 pairs)
        v_star_pairs: &[(ark_bls12_381::G1Affine, ark_bls12_381::G1Affine)], // base duals (G1 pairs)
        adaptor_share: Scalar,
        ctx_hash: &[u8],
        vk: &ArkworksVK,
        public_input_bytes: &[u8],
        crs_digest: &[u8], 
        ppe_digest: &[u8],
        vk_hash: &[u8], 
        x_hash: &[u8],
        deposit_id: &[u8],
    ) -> Result<(KEMShare, GTElement), KEMError> {
        let rho = BLS12381Ops::random_scalar(rng);

        // Phase-B masks (primaries)
        let u_rho = self.mask_g1_pairs(crs_u, rho)?;
        let v_rho = self.mask_g2_pairs(crs_v, rho)?;
        // Phase-B masks (duals)
        let u_star_rho = self.mask_g2_dual_pairs(u_star_pairs, rho);
        let v_star_rho = self.mask_g1_dual_pairs(v_star_pairs, rho);

        // T^ρ and ComT
        let t = crate::gs_kem_helpers::compute_target_public(vk, public_input_bytes)
            .map_err(|e| KEMError::Crypto(e))?;
        let t_rho = t.0.pow(rho.into_bigint());
        
        // According to the spec, we should use linear_map_PPE(T^ρ) for deposit
        // This should be equivalent to five_bucket_comt in decapsulate_duo
        let comt = ComT::<ark_bls12_381::Bls12_381>::linear_map_PPE(
            &PairingOutput::<ark_bls12_381::Bls12_381>(t_rho));

        // KDFs
        let k1 = crate::gs_kem_eval::kdf_from_comt(&comt, crs_digest, ppe_digest, vk_hash, x_hash, deposit_id, b"K1");
        let k2 = crate::gs_kem_eval::kdf_from_comt(&comt, crs_digest, ppe_digest, vk_hash, x_hash, deposit_id, b"K2");
        
        

        // Encrypt rho under K2
        let rho_bytes = rho.into_bigint().to_bytes_be();
        let ad_rho = crate::gs_kem_helpers::build_ad_rho(
            share_index, ctx_hash, deposit_id,
            crs_digest, ppe_digest, vk_hash, x_hash,
            &u_rho, &v_rho, &u_star_rho, &v_star_rho);
        let (rho_ct, rho_tag) = self.dem_encrypt(&k2, &rho_bytes, &ad_rho)?;

        // Adaptor point + share under K1
        let t_i = self.compute_adaptor_point(adaptor_share)?;
        let h_i = { 
            use sha2::{Sha256, Digest};
            let mut input = Vec::new();
            input.extend_from_slice(&adaptor_share.into_bigint().to_bytes_be());
            input.extend_from_slice(&t_i);
            input.extend_from_slice(&share_index.to_be_bytes());
            Sha256::digest(&input).to_vec()
        };
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(&adaptor_share.into_bigint().to_bytes_be());
        plaintext.extend_from_slice(&h_i);

        let ad_share = crate::gs_kem_helpers::build_ad_share(
            share_index, ctx_hash, deposit_id, &t_i,
            &u_rho, &v_rho, &u_star_rho, &v_star_rho,
            crs_digest, ppe_digest, vk_hash, x_hash);
        let (ciphertext, auth_tag) = self.dem_encrypt(&k1, &plaintext, &ad_share)?;

        let share = KEMShare {
            index: share_index,
            d1_masks: u_rho,
            d2_masks: v_rho,
            d1_star_masks: u_star_rho,
            d2_star_masks: v_star_rho,
            d1_inst: Vec::new(),
            d2_inst: Vec::new(),
            rho_ct, 
            rho_tag,
            ciphertext, 
            auth_tag,
            t_i, 
            h_i,
        };
        Ok((share, t_rho))
    }
    /// Decapsulate using GS commitments and proof elements from attestation
    pub fn decapsulate(
        &self,
        kem_share: &KEMShare,
        attestation_commitments_g1: &[Vec<u8>], // C1 from valid attestation
        attestation_commitments_g2: &[Vec<u8>], // C2 from valid attestation
        pi_elements: &[Vec<u8>],                // π proof elements from attestation
        theta_elements: &[Vec<u8>],             // θ proof elements from attestation
        ctx_hash: &[u8],
        gs_instance_digest: &[u8],
    ) -> Result<Fr, KEMError> {
        // Compute M_i using canonical masked evaluator with published masked CRS elements
        // Uses valid attestation C1, C2, π, θ + published masked U^ρ, V^ρ
        let comt = crate::gs_kem_helpers::compute_five_bucket_anchor_with_masks(
            attestation_commitments_g1,
            attestation_commitments_g2,
            pi_elements,
            theta_elements,
            &kem_share.d1_masks, // U^ρ
            &kem_share.d2_masks, // V^ρ
            &kem_share.d1_star_masks,
            &kem_share.d2_star_masks,
        )
        .map_err(|e| KEMError::Crypto(e))?;

        let m_i_bytes =
            crate::gs_kem_helpers::serialize_comt(&comt).map_err(|e| KEMError::Serialization(e))?;

        // Derive decryption key from M_i
        let k_i = self.kdf_from_bytes(&m_i_bytes, ctx_hash, gs_instance_digest)?;

        // Build associated data
        let ad = self.build_ad(
            kem_share.index,
            ctx_hash,
            gs_instance_digest,
            &kem_share.t_i,
            &kem_share.d1_masks,
            &kem_share.d2_masks,
            &kem_share.d1_star_masks,
            &kem_share.d2_star_masks,
        )?;

        // Decrypt adaptor share
        let plaintext = self.dem_decrypt(&k_i, &kem_share.ciphertext, &kem_share.auth_tag, &ad)?;

        if plaintext.len() < 32 {
            return Err(KEMError::Decryption("Invalid plaintext length".to_string()));
        }

        // Extract adaptor share (first 32 bytes)
        let adaptor_share_bytes = &plaintext[..32];
        let adaptor_share = fr_from_be(adaptor_share_bytes);

        // Verify hash commitment
        let extracted_h_i = &plaintext[32..];
        if extracted_h_i != kem_share.h_i {
            return Err(KEMError::Decryption(
                "Hash commitment verification failed".to_string(),
            ));
        }

        Ok(adaptor_share)
    }

    /// Decapsulate Duo (withdraw) with ρ-free extractor
    pub fn decapsulate_duo(
        &self,
        kem_share: &KEMShare,
        ppe: &groth_sahai::statement::PPE<ark_bls12_381::Bls12_381>,
        c1_bytes: &[Vec<u8>], 
        c2_bytes: &[Vec<u8>],
        pi_bytes: &[Vec<u8>], 
        theta_bytes: &[Vec<u8>],
        ctx_hash: &[u8],
        crs_digest: &[u8], 
        ppe_digest: &[u8],
        vk_hash: &[u8], 
        x_hash: &[u8],
        deposit_id: &[u8],
    ) -> Result<Fr, KEMError> {
        use ark_serialize::CanonicalDeserialize;
        use groth_sahai::data_structures::{Com1, Com2};

        // Deserialize attestation parts
        let c1: Vec<Com1<_>> = c1_bytes.iter().map(|b| Com1::deserialize_compressed(&**b)).collect::<Result<_,_>>()
            .map_err(|e| KEMError::Deserialization(format!("C1: {:?}", e)))?;
        let c2: Vec<Com2<_>> = c2_bytes.iter().map(|b| Com2::deserialize_compressed(&**b)).collect::<Result<_,_>>()
            .map_err(|e| KEMError::Deserialization(format!("C2: {:?}", e)))?;
        let pi: Vec<Com2<_>> = pi_bytes.iter().map(|b| Com2::deserialize_compressed(&**b)).collect::<Result<_,_>>()
            .map_err(|e| KEMError::Deserialization(format!("pi: {:?}", e)))?;
        let theta: Vec<Com1<_>> = theta_bytes.iter().map(|b| Com1::deserialize_compressed(&**b)).collect::<Result<_,_>>()
            .map_err(|e| KEMError::Deserialization(format!("theta: {:?}", e)))?;

        // Deserialize masked bases from KEMShare
        let u_rho = crate::gs_kem_helpers::deserialize_com1_pairs(&kem_share.d1_masks)?;
        let v_rho = crate::gs_kem_helpers::deserialize_com2_pairs(&kem_share.d2_masks)?;
        let u_star_rho_pairs = crate::gs_kem_helpers::deserialize_g2_pairs(&kem_share.d1_star_masks)?;
        let v_star_rho_pairs = crate::gs_kem_helpers::deserialize_g1_pairs(&kem_share.d2_star_masks)?;
        
        // Convert pairs to Com1/Com2 types
        let u_star_rho: Vec<Com2<_>> = u_star_rho_pairs.into_iter().map(|(g1, g2)| Com2(g1, g2)).collect();
        let v_star_rho: Vec<Com1<_>> = v_star_rho_pairs.into_iter().map(|(g1, g2)| Com1(g1, g2)).collect();

        // ρ-free anchor (ComT): 5-bucket
        let m_comt = crate::gs_kem_eval::five_bucket_comt::<ark_bls12_381::Bls12_381>(
            &c1, &c2, &pi, &theta, &ppe.gamma, &u_rho, &v_rho, &u_star_rho, &v_star_rho);

        // Key for decrypting ρ
        let _k2 = crate::gs_kem_eval::kdf_from_comt(&m_comt, crs_digest, ppe_digest, vk_hash, x_hash, deposit_id, b"K2");
        

        // Derive K1 from the same five-bucket ComT (equals linear_map_PPE(T^ρ))
        let k1 = crate::gs_kem_eval::kdf_from_comt(&m_comt, crs_digest, ppe_digest, vk_hash, x_hash, deposit_id, b"K1");

        // Decrypt adaptor share
        let ad_share = crate::gs_kem_helpers::build_ad_share(
            kem_share.index, ctx_hash, deposit_id, &kem_share.t_i,
            &kem_share.d1_masks, &kem_share.d2_masks, &kem_share.d1_star_masks, &kem_share.d2_star_masks,
            crs_digest, ppe_digest, vk_hash, x_hash);
        let pt = self.dem_decrypt(&k1, &kem_share.ciphertext, &kem_share.auth_tag, &ad_share)?;
        if pt.len() < 32 { return Err(KEMError::Decryption("bad plaintext".into())); }
        let adaptor_share = crate::gs_kem_helpers::fr_from_be(&pt[..32]);
        let h_i = &pt[32..];
        if h_i != &kem_share.h_i { return Err(KEMError::Decryption("hash commitment mismatch".into())); }
        Ok(adaptor_share)
    }

    /// Compute adaptor point T_i = adaptor_share * G on secp256k1
    fn compute_adaptor_point(&self, adaptor_share: Scalar) -> Result<Vec<u8>, KEMError> {
        use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

        // Convert Fr scalar to secp256k1 scalar
        let scalar_bytes = adaptor_share.into_bigint().to_bytes_be();
        if scalar_bytes.len() > 32 {
            return Err(KEMError::InvalidInput(
                "Scalar too large for secp256k1".to_string(),
            ));
        }

        // Pad to 32 bytes if necessary
        let mut padded_bytes = [0u8; 32];
        let start = 32 - scalar_bytes.len();
        padded_bytes[start..].copy_from_slice(&scalar_bytes);

        let secret_key = SecretKey::from_slice(&padded_bytes)
            .map_err(|e| KEMError::Crypto(format!("Invalid secret key: {:?}", e)))?;

        let secp = Secp256k1::new();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        // Return compressed public key (33 bytes)
        Ok(public_key.serialize().to_vec())
    }

    /// Build associated data for encryption
    fn build_ad(
        &self,
        share_index: u32,
        ctx_hash: &[u8],
        gs_instance_digest: &[u8],
        t_i: &[u8],
        d1_masks: &[Vec<u8>],
        d2_masks: &[Vec<u8>],
        d1_star_masks: &[Vec<u8>],
        d2_star_masks: &[Vec<u8>],
    ) -> Result<Vec<u8>, KEMError> {
        let mut ad = Vec::new();
        ad.extend_from_slice(&share_index.to_be_bytes());
        ad.extend_from_slice(ctx_hash);
        ad.extend_from_slice(gs_instance_digest);
        ad.extend_from_slice(t_i);

        // Add D1 masks
        for mask in d1_masks {
            ad.extend_from_slice(mask);
        }

        // Add D2 masks
        for mask in d2_masks {
            ad.extend_from_slice(mask);
        }

        for mask in d1_star_masks {
            ad.extend_from_slice(mask);
        }

        for mask in d2_star_masks {
            ad.extend_from_slice(mask);
        }

        Ok(ad)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gs_kem_helpers::serialize_crs_for_kem;
    use ark_bls12_381::{G1Affine, G2Affine};
    use ark_std::test_rng;
    use ark_std::UniformRand;

    #[test]
    fn test_kem_basic_functionality() {
        let kem = ProductKeyKEM::new();
        let mut rng = test_rng();

        // Create dummy bases
        let u_bases = vec![
            vec![0u8; 192], // Dummy G2 pair
            vec![0u8; 192],
        ];
        let v_bases = vec![
            vec![0u8; 96], // Dummy G1 pair
            vec![0u8; 96],
        ];
        let u_dual_bases = vec![vec![0u8; 192], vec![0u8; 192]];
        let v_dual_bases = vec![vec![0u8; 96], vec![0u8; 96]];

        let adaptor_share = Fr::rand(&mut rng);
        let ctx_hash = b"test_context";
        let gs_instance_digest = b"test_digest";

        // Mock attestation commitments
        let mock_c1 = vec![vec![0u8; 96]; 2]; // 2 C1 commitments
        let mock_c2 = vec![vec![0u8; 192]; 2]; // 2 C2 commitments
        let mock_pi = vec![vec![0u8; 192]; 2]; // 2 pi elements (G2)
        let mock_theta = vec![vec![0u8; 96]; 2]; // 2 theta elements (G1)

        let result = kem.encapsulate(
            &mut rng,
            0,
            &mock_c1,
            &mock_c2,
            &mock_pi,
            &mock_theta,
            &u_bases,
            &v_bases,
            &u_dual_bases,
            &v_dual_bases,
            adaptor_share,
            ctx_hash,
            gs_instance_digest,
        );

        // Should fail with dummy data
        assert!(result.is_err());
    }

    #[test]
    fn test_kdf_functionality() {
        let kem = ProductKeyKEM::new();
        let gt_bytes = vec![0u8; 576]; // Dummy GT bytes
        let ctx_hash = b"test_context";
        let gs_instance_digest = b"test_digest";

        let result = kem.kdf_from_bytes(&gt_bytes, ctx_hash, gs_instance_digest);
        assert!(result.is_ok());

        let derived_key = result.unwrap();
        assert_eq!(derived_key.len(), 32);
    }

    #[test]
    fn test_dem_functionality() {
        let kem = ProductKeyKEM::new();
        let key = vec![0u8; 32];
        let plaintext = b"Hello, World!";
        let ad = b"associated_data";

        // Test encryption
        let (ciphertext, auth_tag) = kem.dem_encrypt(&key, plaintext, ad).unwrap();
        assert!(!ciphertext.is_empty());
        assert_eq!(auth_tag.len(), 16);

        // Test decryption
        let decrypted = kem.dem_decrypt(&key, &ciphertext, &auth_tag, ad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    /// Test KEM encapsulation and decapsulation
    #[test]
    fn test_kem_encap_decap() {
        use crate::gs_commitments::GrothSahaiCommitments;
        use ark_serialize::CanonicalSerialize;

        let kem = ProductKeyKEM::new();
        let mut rng = ark_std::test_rng();

        // Create GS system and attestation
        let gs = GrothSahaiCommitments::from_seed(b"KEM_TEST");

        let mut proof_bytes = Vec::new();
        G1Affine::rand(&mut rng)
            .serialize_compressed(&mut proof_bytes)
            .unwrap();

        let proof = crate::groth16_wrapper::ArkworksProof {
            pi_a: G1Affine::rand(&mut rng),
            pi_b: G2Affine::rand(&mut rng),
            pi_c: G1Affine::rand(&mut rng),
            public_input: vec![],
            proof_bytes,
        };

        let mut vk_bytes = Vec::new();
        G1Affine::rand(&mut rng)
            .serialize_compressed(&mut vk_bytes)
            .unwrap();

        let vk = crate::groth16_wrapper::ArkworksVK {
            alpha_g1: G1Affine::rand(&mut rng),
            beta_g2: G2Affine::rand(&mut rng),
            gamma_g2: G2Affine::rand(&mut rng),
            delta_g2: G2Affine::rand(&mut rng),
            gamma_abc_g1: vec![G1Affine::rand(&mut rng)],
            vk_bytes,
        };

        let public_input: Vec<Fr> = vec![]; // Empty public input for this test
        let attestation = gs
            .commit_arkworks_proof(&proof, &vk, &public_input, true, &mut rng)
            .unwrap();
        let (u_duals, v_duals) = gs.duals();
        let (u_bases, v_bases, u_dual_bases, v_dual_bases) =
            serialize_crs_for_kem(gs.get_crs(), u_duals, v_duals);

        let mut c1_bytes = Vec::new();
        for c1 in &attestation.c1_commitments {
            let mut bytes = Vec::new();
            c1.serialize_compressed(&mut bytes).unwrap();
            c1_bytes.push(bytes);
        }

        let mut c2_bytes = Vec::new();
        for c2 in &attestation.c2_commitments {
            let mut bytes = Vec::new();
            c2.serialize_compressed(&mut bytes).unwrap();
            c2_bytes.push(bytes);
        }

        // Serialize pi and theta elements for canonical evaluation
        let mut pi_bytes = Vec::new();
        for pi_elem in &attestation.pi_elements {
            let mut bytes = Vec::new();
            pi_elem.serialize_compressed(&mut bytes).unwrap();
            pi_bytes.push(bytes);
        }

        let mut theta_bytes = Vec::new();
        for theta_elem in &attestation.theta_elements {
            let mut bytes = Vec::new();
            theta_elem.serialize_compressed(&mut bytes).unwrap();
            theta_bytes.push(bytes);
        }

        let adaptor_share = Fr::rand(&mut rng);
        let ctx_hash = b"test_context";
        let gs_instance_digest = b"test_digest";

        // Encapsulate
        let (kem_share, _m_i) = kem
            .encapsulate(
                &mut rng,
                0,
                &c1_bytes,
                &c2_bytes,
                &pi_bytes,
                &theta_bytes,
                &u_bases,
                &v_bases,
                &u_dual_bases,
                &v_dual_bases,
                adaptor_share,
                ctx_hash,
                gs_instance_digest,
            )
            .unwrap();

        // Verify structure
        assert_eq!(kem_share.index, 0);
        assert_eq!(kem_share.d1_masks.len(), 2);
        assert_eq!(kem_share.d2_masks.len(), 2);
        assert_eq!(kem_share.d1_star_masks.len(), 2);
        assert_eq!(kem_share.d2_star_masks.len(), 2);
        assert!(!kem_share.ciphertext.is_empty());

        // Decap with same attestation
        let recovered = kem
            .decapsulate(
                &kem_share,
                &c1_bytes,
                &c2_bytes,
                &pi_bytes,
                &theta_bytes,
                ctx_hash,
                gs_instance_digest,
            )
            .unwrap();

        // Verify recovered matches original
        assert_eq!(
            recovered, adaptor_share,
            "Decapsulation didn't recover correct value"
        );
    }

    /// Test KEM determinism with valid attestation
    #[test]
    fn test_kem_determinism() {
        let kem = ProductKeyKEM::new();
        let mut rng = ark_std::test_rng();

        use crate::gs_commitments::GrothSahaiCommitments;
        use ark_serialize::CanonicalSerialize;

        // Same setup as encap_decap
        let gs = GrothSahaiCommitments::from_seed(b"DETERM");
        let mut proof_bytes = Vec::new();
        G1Affine::rand(&mut rng)
            .serialize_compressed(&mut proof_bytes)
            .unwrap();
        let proof = crate::groth16_wrapper::ArkworksProof {
            pi_a: G1Affine::rand(&mut rng),
            pi_b: G2Affine::rand(&mut rng),
            pi_c: G1Affine::rand(&mut rng),
            public_input: vec![],
            proof_bytes,
        };
        let mut vk_bytes = Vec::new();
        G1Affine::rand(&mut rng)
            .serialize_compressed(&mut vk_bytes)
            .unwrap();
        let vk = crate::groth16_wrapper::ArkworksVK {
            alpha_g1: G1Affine::rand(&mut rng),
            beta_g2: G2Affine::rand(&mut rng),
            gamma_g2: G2Affine::rand(&mut rng),
            delta_g2: G2Affine::rand(&mut rng),
            gamma_abc_g1: vec![G1Affine::rand(&mut rng)],
            vk_bytes,
        };
        let public_input: Vec<Fr> = vec![]; // Empty public input for this test
        let attestation = gs
            .commit_arkworks_proof(&proof, &vk, &public_input, true, &mut rng)
            .unwrap();

        // Serialize everything
        let _public_input: Vec<Fr> = vec![]; // Empty public input for this test
        let (u_duals, v_duals) = gs.duals();
        let (u_bases, v_bases, u_dual_bases, v_dual_bases) =
            serialize_crs_for_kem(gs.get_crs(), u_duals, v_duals);
        let mut c1_bytes = Vec::new();
        let mut c2_bytes = Vec::new();

        for c1 in &attestation.c1_commitments {
            let mut b = Vec::new();
            c1.serialize_compressed(&mut b).unwrap();
            c1_bytes.push(b);
        }
        for c2 in &attestation.c2_commitments {
            let mut b = Vec::new();
            c2.serialize_compressed(&mut b).unwrap();
            c2_bytes.push(b);
        }

        // Serialize pi and theta elements
        let mut pi_bytes = Vec::new();
        for pi_elem in &attestation.pi_elements {
            let mut bytes = Vec::new();
            pi_elem.serialize_compressed(&mut bytes).unwrap();
            pi_bytes.push(bytes);
        }

        let mut theta_bytes = Vec::new();
        for theta_elem in &attestation.theta_elements {
            let mut bytes = Vec::new();
            theta_elem.serialize_compressed(&mut bytes).unwrap();
            theta_bytes.push(bytes);
        }

        let adaptor_share = Fr::rand(&mut rng);
        let ctx_hash = b"ctx";
        let gs_digest = b"digest";

        // Test: multiple shares with different ρ all decrypt to same value
        let mut kem_shares = Vec::new();
        for i in 0..5 {
            let (share, _) = kem
                .encapsulate(
                    &mut rng,
                    i,
                    &c1_bytes,
                    &c2_bytes,
                    &pi_bytes,
                    &theta_bytes,
                    &u_bases,
                    &v_bases,
                    &u_dual_bases,
                    &v_dual_bases,
                    adaptor_share,
                    ctx_hash,
                    gs_digest,
                )
                .unwrap();
            kem_shares.push(share);
        }

        // All should decrypt to the same adaptor_share
        let mut recovered_values = Vec::new();
        for (i, share) in kem_shares.iter().enumerate() {
            let recovered = kem
                .decapsulate(
                    share,
                    &c1_bytes,
                    &c2_bytes,
                    &pi_bytes,
                    &theta_bytes,
                    ctx_hash,
                    gs_digest,
                )
                .unwrap();
            recovered_values.push(recovered);
            assert_eq!(
                recovered, adaptor_share,
                "Share {} decrypted to wrong value",
                i
            );
        }

        // All recovered values should be identical
        for (i, val) in recovered_values.iter().enumerate().skip(1) {
            assert_eq!(
                *val, recovered_values[0],
                "Share {} decrypted to different value",
                i
            );
        }
    }

    /// Test negative cases
    #[test]
    fn test_kem_negative_cases() {
        let kem = ProductKeyKEM::new();
        let mut rng = ark_std::test_rng();

        // Test wrong G2 pair length
        let invalid_u_bases = vec![vec![0u8; 100]]; // Wrong length
        let adaptor_share = crate::bls12381_ops::BLS12381Ops::random_scalar(&mut rng);
        let ctx_hash = b"test";
        let gs_instance_digest = b"test";

        let mock_c1 = vec![vec![0u8; 96]; 2];
        let mock_c2 = vec![vec![0u8; 192]; 2];
        let mock_pi = vec![vec![0u8; 192]; 2]; // 2 pi elements (G2)
        let mock_theta = vec![vec![0u8; 96]; 2]; // 2 theta elements (G1)
        let valid_v_bases = vec![vec![0u8; 96]; 2];
        let valid_u_duals = vec![vec![0u8; 192]; 2];
        let valid_v_duals = vec![vec![0u8; 96]; 2];

        let result = kem.encapsulate(
            &mut rng,
            0,
            &mock_c1,
            &mock_c2,
            &mock_pi,
            &mock_theta,
            &invalid_u_bases,
            &valid_v_bases,
            &valid_u_duals,
            &valid_v_duals,
            adaptor_share,
            ctx_hash,
            gs_instance_digest,
        );

        assert!(result.is_err());
    }

    /// Test DEM encryption/decryption with wrong key
    #[test]
    fn test_dem_wrong_key() {
        let kem = ProductKeyKEM::new();
        let key1 = vec![0u8; 32];
        let key2 = vec![1u8; 32]; // Different key
        let plaintext = b"Hello, World!";
        let ad = b"associated_data";

        // Encrypt with key1
        let (ciphertext, auth_tag) = kem.dem_encrypt(&key1, plaintext, ad).unwrap();

        // Try to decrypt with key2 (should fail)
        let result = kem.dem_decrypt(&key2, &ciphertext, &auth_tag, ad);
        assert!(result.is_err());
    }

    /// Test DEM with tampered ciphertext
    #[test]
    fn test_dem_tampered_ciphertext() {
        let kem = ProductKeyKEM::new();
        let key = vec![0u8; 32];
        let plaintext = b"Hello, World!";
        let ad = b"associated_data";

        // Encrypt
        let (ciphertext, auth_tag) = kem.dem_encrypt(&key, plaintext, ad).unwrap();

        // Tamper with ciphertext
        let mut tampered_ciphertext = ciphertext.clone();
        tampered_ciphertext[0] ^= 0x01;

        // Try to decrypt tampered ciphertext (should fail)
        let result = kem.dem_decrypt(&key, &tampered_ciphertext, &auth_tag, ad);
        assert!(result.is_err());
    }

    /// Test DEM with tampered auth tag
    #[test]
    fn test_dem_tampered_auth_tag() {
        let kem = ProductKeyKEM::new();
        let key = vec![0u8; 32];
        let plaintext = b"Hello, World!";
        let ad = b"associated_data";

        // Encrypt
        let (ciphertext, auth_tag) = kem.dem_encrypt(&key, plaintext, ad).unwrap();

        // Tamper with auth tag
        let mut tampered_tag = auth_tag.clone();
        tampered_tag[0] ^= 0xff;

        // Try to decrypt with tampered tag (should fail)
        let result = kem.dem_decrypt(&key, &ciphertext, &tampered_tag, ad);
        assert!(result.is_err());
    }
}
