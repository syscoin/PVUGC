/*!
Product-Key KEM for PVUGC
The core innovation: turning proof existence into a decryption key

This module implements the KEM functionality.
*/

use ark_bls12_381::{Bls12_381, Fq12, Fr};
use ark_ec::pairing::PairingOutput;
use ark_ff::{BigInteger, PrimeField};
use ark_std::{One, Zero};
use ark_serialize::CanonicalDeserialize;
use ark_std::{rand::Rng, vec::Vec};

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::bls12381_ops::{BLS12381Ops, Scalar};
use crate::gs_kem_eval::kdf_from_comt;
use crate::gs_kem_helpers::{
    deserialize_masked_u, deserialize_masked_v, fr_from_be, masked_verifier_from_masked,
    serialize_comt_matrix,
};
use groth_sahai::statement::PPE;
use groth_sahai::{Com1, Com2};

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

/// KEM share containing encapsulated data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KEMShare {
    /// Index of this share
    pub index: u32,
    /// Masked CRS U elements (U^ρ in G1, each pair is 96 bytes)
    pub d1_masks: Vec<Vec<u8>>,
    /// Masked CRS V elements (V^ρ in G2, each pair is 192 bytes)
    pub d2_masks: Vec<Vec<u8>>,
    /// Encrypted adaptor share
    pub ciphertext: Vec<u8>,
    /// Authentication tag
    pub auth_tag: Vec<u8>,
    /// Adaptor point T_i (secp256k1 public key)
    pub t_i: Vec<u8>,
    /// Hash commitment h_i
    pub h_i: Vec<u8>,
}

/// Product-Key KEM implementation
pub struct ProductKeyKEM;

impl ProductKeyKEM {
    /// Create a new KEM instance
    pub fn new() -> Self {
        Self
    }

    /// Deposit-time encapsulation: armer publishes only masked primaries
    pub fn encapsulate_deposit<R: Rng>(
        &self,
        rng: &mut R,
        share_index: u32,
        attestation_commitments_g1: &[Vec<u8>],
        attestation_commitments_g2: &[Vec<u8>],
        pi_elements: &[Vec<u8>],
        theta_elements: &[Vec<u8>],
        crs_u: &[Vec<u8>],
        crs_v: &[Vec<u8>],
        adaptor_share: Scalar,
        ctx_hash: &[u8],
        gs_instance_digest: &[u8],
    ) -> Result<(KEMShare, Vec<u8>), KEMError> {
        let rho_i = BLS12381Ops::random_scalar(rng);
        let u_masked = self.mask_g1_pairs(crs_u, rho_i)?; // U^ρ in G1
        let v_masked = self.mask_g2_pairs(crs_v, rho_i)?; // V^ρ in G2

        // Derive masked ComT using masked primaries (ρ-free at withdraw) to match decapsulation
        // 1) Deserialize attestation components
        let mut c1_coms = Vec::new();
        for bytes in attestation_commitments_g1 {
            let com = Com1::<Bls12_381>::deserialize_compressed(bytes.as_slice())
                .map_err(|e| KEMError::Deserialization(format!("C1 deser: {:?}", e)))?;
            c1_coms.push(com);
        }
        let mut c2_coms = Vec::new();
        for bytes in attestation_commitments_g2 {
            let com = Com2::<Bls12_381>::deserialize_compressed(bytes.as_slice())
                .map_err(|e| KEMError::Deserialization(format!("C2 deser: {:?}", e)))?;
            c2_coms.push(com);
        }
        let mut pi = Vec::new();
        for bytes in pi_elements {
            let com = Com2::<Bls12_381>::deserialize_compressed(bytes.as_slice())
                .map_err(|e| KEMError::Deserialization(format!("π deser: {:?}", e)))?;
            pi.push(com);
        }
        let mut theta = Vec::new();
        for bytes in theta_elements {
            let com = Com1::<Bls12_381>::deserialize_compressed(bytes.as_slice())
                .map_err(|e| KEMError::Deserialization(format!("θ deser: {:?}", e)))?;
            theta.push(com);
        }
        // 2) Deserialize masked CRS primaries we just produced
        let u_masked_coms = deserialize_masked_u(&u_masked)
            .map_err(|e| KEMError::Deserialization(format!("U^ρ deser: {}", e)))?;
        let v_masked_coms = deserialize_masked_v(&v_masked)
            .map_err(|e| KEMError::Deserialization(format!("V^ρ deser: {}", e)))?;
        // 3) Build Γ=diag(1,1) PPE (A=B=0); target unused for extractor
        let ppe_stub = PPE::<Bls12_381> {
            a_consts: vec![],
            b_consts: vec![],
            gamma: vec![vec![Fr::one(), Fr::zero()], vec![Fr::zero(), Fr::one()]],
            target: PairingOutput::<Bls12_381>(Fq12::one()),
        };
        // 4) Compute masked ComT using the extractor
        let masked_comt = masked_verifier_from_masked(
            &ppe_stub,
            &c1_coms,
            &c2_coms,
            &pi,
            &theta,
            &u_masked_coms,
            &v_masked_coms,
        );

        let key = kdf_from_comt(
            &masked_comt,
            ctx_hash,
            gs_instance_digest,
            b"vk",
            b"x",
            b"deposit",
            1,
        );
        let m_bytes = serialize_comt_matrix(&masked_comt).map_err(KEMError::Serialization)?;

        // Derive adaptor commitment
        let t_i = self.compute_adaptor_point(adaptor_share)?;
        let mut h_i_input = Vec::new();
        h_i_input.extend_from_slice(&adaptor_share.into_bigint().to_bytes_be());
        h_i_input.extend_from_slice(&t_i);
        h_i_input.extend_from_slice(&share_index.to_be_bytes());
        let h_i = Sha256::digest(&h_i_input).to_vec();

        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(&adaptor_share.into_bigint().to_bytes_be());
        plaintext.extend_from_slice(&h_i);
        let ad = self.build_ad(
            share_index,
            ctx_hash,
            gs_instance_digest,
            &t_i,
            &u_masked,
            &v_masked,
        )?;
        let (ciphertext, auth_tag) = self.dem_encrypt(&key, &plaintext, &ad)?;

        let kem_share = KEMShare {
            index: share_index,
            d1_masks: u_masked,
            d2_masks: v_masked,
            ciphertext,
            auth_tag,
            t_i,
            h_i,
        };

        Ok((kem_share, m_bytes))
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

        let payload = Payload { msg: plaintext, aad: &aad };
        let ciphertext_and_tag = cipher.encrypt(nonce, payload).map_err(|e| {
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

        let payload = Payload { msg: ciphertext_and_tag.as_slice(), aad: &aad };
        let plaintext = cipher
            .decrypt(nonce, payload)
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

    /// Decapsulate using GS commitments and proof elements from attestation
    pub fn decapsulate(
        &self,
        kem_share: &KEMShare,
        ppe: &PPE<Bls12_381>,
        attestation_commitments_g1: &[Vec<u8>],
        attestation_commitments_g2: &[Vec<u8>],
        pi_elements: &[Vec<u8>],
        theta_elements: &[Vec<u8>],
        ctx_hash: &[u8],
        gs_instance_digest: &[u8],
    ) -> Result<Fr, KEMError> {
        let mut c1_coms = Vec::new();
        for bytes in attestation_commitments_g1 {
            let com = Com1::<Bls12_381>::deserialize_compressed(bytes.as_slice())
                .map_err(|e| KEMError::Deserialization(format!("C1 deser: {:?}", e)))?;
            c1_coms.push(com);
        }

        let mut c2_coms = Vec::new();
        for bytes in attestation_commitments_g2 {
            let com = Com2::<Bls12_381>::deserialize_compressed(bytes.as_slice())
                .map_err(|e| KEMError::Deserialization(format!("C2 deser: {:?}", e)))?;
            c2_coms.push(com);
        }

        let mut pi = Vec::new();
        for bytes in pi_elements {
            let com = Com2::<Bls12_381>::deserialize_compressed(bytes.as_slice())
                .map_err(|e| KEMError::Deserialization(format!("π deser: {:?}", e)))?;
            pi.push(com);
        }

        let mut theta = Vec::new();
        for bytes in theta_elements {
            let com = Com1::<Bls12_381>::deserialize_compressed(bytes.as_slice())
                .map_err(|e| KEMError::Deserialization(format!("θ deser: {:?}", e)))?;
            theta.push(com);
        }

        let u_masked = deserialize_masked_u(&kem_share.d1_masks)
            .map_err(|e| KEMError::Deserialization(format!("U^ρ deser: {}", e)))?;
        let v_masked = deserialize_masked_v(&kem_share.d2_masks)
            .map_err(|e| KEMError::Deserialization(format!("V^ρ deser: {}", e)))?;

        let masked_comt =
            masked_verifier_from_masked(ppe, &c1_coms, &c2_coms, &pi, &theta, &u_masked, &v_masked);

        let key_material = kdf_from_comt(
            &masked_comt,
            ctx_hash,
            gs_instance_digest,
            b"vk",
            b"x",
            b"deposit",
            1,
        );
        let k_i = key_material.to_vec();

        // Build associated data
        let ad = self.build_ad(
            kem_share.index,
            ctx_hash,
            gs_instance_digest,
            &kem_share.t_i,
            &kem_share.d1_masks,
            &kem_share.d2_masks,
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

        Ok(ad)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{G1Affine, G2Affine};
    use ark_std::test_rng;
    use ark_std::UniformRand;

    #[test]
    fn test_kem_basic_functionality() {
        use ark_serialize::CanonicalSerialize;

        let kem = ProductKeyKEM::new();
        let mut rng = test_rng();

        // Random Groth16 VK just to satisfy inputs (public input empty)
        let mut vk_bytes = Vec::new();
        G1Affine::rand(&mut rng)
            .serialize_compressed(&mut vk_bytes)
            .unwrap();
        let _vk = crate::groth16_wrapper::ArkworksVK {
            alpha_g1: G1Affine::rand(&mut rng),
            beta_g2: G2Affine::rand(&mut rng),
            gamma_g2: G2Affine::rand(&mut rng),
            delta_g2: G2Affine::rand(&mut rng),
            gamma_abc_g1: vec![G1Affine::rand(&mut rng)],
            vk_bytes,
        };

        let adaptor_share = Fr::rand(&mut rng);
        let ctx_hash = b"test_context";
        let gs_instance_digest = b"test_digest";

        // Invalid CRS byte lengths should error before pairings
        let invalid_u = vec![vec![0u8; 191]]; // Not a valid compressed G2 pair
        let valid_v = vec![vec![0u8; 96]];

        let fake_c1 = {
            let mut bytes = Vec::new();
            G1Affine::rand(&mut rng).serialize_compressed(&mut bytes).unwrap();
            vec![bytes]
        };
        let fake_c2 = {
            let mut bytes = Vec::new();
            G2Affine::rand(&mut rng).serialize_compressed(&mut bytes).unwrap();
            vec![bytes]
        };
        let fake_pi = fake_c2.clone();
        let fake_theta = fake_c1.clone();

        let result = kem.encapsulate_deposit(
            &mut rng,
            0,
            &fake_c1,
            &fake_c2,
            &fake_pi,
            &fake_theta,
            &invalid_u,
            &valid_v,
            adaptor_share,
            ctx_hash,
            gs_instance_digest,
        );

        assert!(matches!(result, Err(KEMError::InvalidInput(_))));
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

    /// Test negative cases
    #[test]
    fn test_kem_negative_cases() {
        use ark_serialize::CanonicalSerialize;

        let kem = ProductKeyKEM::new();
        let mut rng = ark_std::test_rng();

        // Random Groth16 VK
        let mut vk_bytes = Vec::new();
        G1Affine::rand(&mut rng)
            .serialize_compressed(&mut vk_bytes)
            .unwrap();
        let _vk = crate::groth16_wrapper::ArkworksVK {
            alpha_g1: G1Affine::rand(&mut rng),
            beta_g2: G2Affine::rand(&mut rng),
            gamma_g2: G2Affine::rand(&mut rng),
            delta_g2: G2Affine::rand(&mut rng),
            gamma_abc_g1: vec![G1Affine::rand(&mut rng)],
            vk_bytes,
        };

        let adaptor_share = crate::bls12381_ops::BLS12381Ops::random_scalar(&mut rng);
        let ctx_hash = b"test";
        let gs_instance_digest = b"test";

        let fake_c1 = {
            let mut bytes = Vec::new();
            G1Affine::rand(&mut rng).serialize_compressed(&mut bytes).unwrap();
            vec![bytes]
        };
        let fake_c2 = {
            let mut bytes = Vec::new();
            G2Affine::rand(&mut rng).serialize_compressed(&mut bytes).unwrap();
            vec![bytes]
        };
        let fake_pi = fake_c2.clone();
        let fake_theta = fake_c1.clone();

        let invalid_u = vec![vec![0u8; 191]]; // Wrong length for G2 pair
        let valid_v = vec![vec![0u8; 96]];

        let err_u = kem.encapsulate_deposit(
            &mut rng,
            0,
            &fake_c1,
            &fake_c2,
            &fake_pi,
            &fake_theta,
            &invalid_u,
            &valid_v,
            adaptor_share,
            ctx_hash,
            gs_instance_digest,
        );
        assert!(err_u.is_err());

        let valid_u = vec![vec![0u8; 192]];
        let invalid_v = vec![vec![0u8; 95]]; // Wrong length for G1 pair
        let err_v = kem.encapsulate_deposit(
            &mut rng,
            0,
            &fake_c1,
            &fake_c2,
            &fake_pi,
            &fake_theta,
            &valid_u,
            &invalid_v,
            adaptor_share,
            ctx_hash,
            gs_instance_digest,
        );
        assert!(err_v.is_err());
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
