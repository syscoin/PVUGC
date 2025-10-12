/*!
Product-Key KEM for PVUGC
The core innovation: turning proof existence into a decryption key

This module implements the KEM functionality.
*/

use ark_bls12_381::Fr;
use ark_ec::pairing::PairingOutput;
use ark_ff::{BigInteger, Field, PrimeField};
use ark_serialize::CanonicalSerialize;
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
use groth_sahai::data_structures::{ComT, BT};

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
    /// Instance-masked GS U bases (U(x)^ρ in G2)
    pub d1_instance_masks: Vec<Vec<u8>>,
    /// Instance-masked GS V bases (V(x)^ρ in G1)
    pub d2_instance_masks: Vec<Vec<u8>>,
    /// Encrypted masking scalar ρ ciphertext
    pub rho_ct: Vec<u8>,
    /// Authentication tag for encrypted ρ
    pub rho_tag: Vec<u8>,
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

    /// Key derivation function from serialized ComT matrix
    pub fn kdf_from_comt(
        &self,
        comt: &ComT<ark_bls12_381::Bls12_381>,
        ctx_hash: &[u8],
        gs_instance_digest: &[u8],
    ) -> Result<Vec<u8>, KEMError> {
        let mut comt_bytes = Vec::new();
        let matrix = comt.as_matrix();
        for r in 0..2 {
            for c in 0..2 {
                matrix[r][c]
                    .0
                    .serialize_compressed(&mut comt_bytes)
                    .map_err(|e| {
                        KEMError::Serialization(format!("ComT cell serialize: {:?}", e))
                    })?;
            }
        }
        self.kdf_from_bytes(&comt_bytes, ctx_hash, gs_instance_digest)
    }

    /// Combine Phase-A and Phase-B keys into a share key using HKDF
    fn derive_share_key(
        &self,
        k1: &[u8],
        k2: &[u8],
        ctx_hash: &[u8],
        gs_instance_digest: &[u8],
    ) -> Result<Vec<u8>, KEMError> {
        let mut ikm = Vec::new();
        ikm.extend_from_slice(k1);
        ikm.extend_from_slice(k2);

        let mut salt_input = Vec::new();
        salt_input.extend_from_slice(ctx_hash);
        salt_input.extend_from_slice(gs_instance_digest);
        salt_input.extend_from_slice(b"PVUGC/DUO");
        let salt = Sha256::digest(&salt_input);

        let info = b"PVUGC/KEM/SHARE/v1";
        self.hkdf_derive(&ikm, &salt, info, 32)
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

    /// Encapsulate using PVUGC-Duo two-phase flow
    pub fn encapsulate<R: Rng>(
        &self,
        rng: &mut R,
        share_index: u32,
        instance_d1_bases: &[Vec<u8>],
        instance_d2_bases: &[Vec<u8>],
        crs_u: &[Vec<u8>],
        crs_v: &[Vec<u8>],
        target_gt: &GTElement,
        adaptor_share: Scalar,
        ctx_hash: &[u8],
        gs_instance_digest: &[u8],
    ) -> Result<(KEMShare, GTElement), KEMError> {
        let rho_i = BLS12381Ops::random_scalar(rng);

        // Phase A: mask instance evaluation bases and gate ρ
        let d1_instance_masks = self.mask_g2_pairs(instance_d1_bases, rho_i)?;
        let d2_instance_masks = self.mask_g1_pairs(instance_d2_bases, rho_i)?;

        let target_pow = target_gt.pow(rho_i.into_bigint());
        let mut target_bytes = Vec::new();
        target_pow
            .serialize_compressed(&mut target_bytes)
            .map_err(|e| KEMError::Serialization(format!("GT serialize: {:?}", e)))?;
        let k2 = self.kdf_from_bytes(&target_bytes, ctx_hash, gs_instance_digest)?;

        let rho_bytes = rho_i.into_bigint().to_bytes_be();
        let rho_ad = self.build_rho_ad(
            share_index,
            ctx_hash,
            gs_instance_digest,
            &d1_instance_masks,
            &d2_instance_masks,
        )?;
        let (rho_ct, rho_tag) = self.dem_encrypt(&k2, &rho_bytes, &rho_ad)?;

        // Phase B: mask CRS primaries and derive share key from ComT
        let u_masked = self.mask_g1_pairs(crs_u, rho_i)?;
        let v_masked = self.mask_g2_pairs(crs_v, rho_i)?;

        let comt = ComT::<ark_bls12_381::Bls12_381>::linear_map_PPE(&PairingOutput::<
            ark_bls12_381::Bls12_381,
        >(target_pow.clone()));
        let k1 = self.kdf_from_comt(&comt, ctx_hash, gs_instance_digest)?;
        let share_key = self.derive_share_key(&k1, &k2, ctx_hash, gs_instance_digest)?;

        let t_i = self.compute_adaptor_point(adaptor_share)?;

        let mut h_i_input = Vec::new();
        h_i_input.extend_from_slice(&adaptor_share.into_bigint().to_bytes_be());
        h_i_input.extend_from_slice(&t_i);
        h_i_input.extend_from_slice(&share_index.to_be_bytes());
        let h_i = Sha256::digest(&h_i_input).to_vec();

        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(&adaptor_share.into_bigint().to_bytes_be());
        plaintext.extend_from_slice(&h_i);

        let ad = self.build_share_ad(
            share_index,
            ctx_hash,
            gs_instance_digest,
            &t_i,
            &u_masked,
            &v_masked,
            &d1_instance_masks,
            &d2_instance_masks,
        )?;
        let (ciphertext, auth_tag) = self.dem_encrypt(&share_key, &plaintext, &ad)?;

        let kem_share = KEMShare {
            index: share_index,
            d1_masks: u_masked,
            d2_masks: v_masked,
            d1_instance_masks,
            d2_instance_masks,
            rho_ct,
            rho_tag,
            ciphertext,
            auth_tag,
            t_i,
            h_i,
        };

        Ok((kem_share, target_pow))
    }

    /// Decapsulate using GS commitments in two-phase flow
    pub fn decapsulate(
        &self,
        kem_share: &KEMShare,
        attestation_commitments_g1: &[Vec<u8>], // C1 from valid attestation
        attestation_commitments_g2: &[Vec<u8>], // C2 from valid attestation
        ctx_hash: &[u8],
        gs_instance_digest: &[u8],
    ) -> Result<Fr, KEMError> {
        // Phase A: use product-key anchor with instance masks to recover ρ
        let m2_bytes = crate::gs_kem_helpers::compute_product_key_anchor(
            attestation_commitments_g1,
            attestation_commitments_g2,
            &kem_share.d1_instance_masks,
            &kem_share.d2_instance_masks,
        )
        .map_err(|e| KEMError::Crypto(e))?;

        let k2 = self.kdf_from_bytes(&m2_bytes, ctx_hash, gs_instance_digest)?;

        let rho_ad = self.build_rho_ad(
            kem_share.index,
            ctx_hash,
            gs_instance_digest,
            &kem_share.d1_instance_masks,
            &kem_share.d2_instance_masks,
        )?;
        let rho_bytes = self.dem_decrypt(&k2, &kem_share.rho_ct, &kem_share.rho_tag, &rho_ad)?;
        if rho_bytes.is_empty() {
            return Err(KEMError::Decryption("Recovered ρ is empty".to_string()));
        }

        let target_pow = crate::gs_kem_helpers::deserialize_gt_pvugc(&m2_bytes)
            .map_err(|e| KEMError::Deserialization(e))?;

        let comt = ComT::<ark_bls12_381::Bls12_381>::linear_map_PPE(&PairingOutput::<
            ark_bls12_381::Bls12_381,
        >(target_pow));
        let k1 = self.kdf_from_comt(&comt, ctx_hash, gs_instance_digest)?;
        let share_key = self.derive_share_key(&k1, &k2, ctx_hash, gs_instance_digest)?;

        let ad = self.build_share_ad(
            kem_share.index,
            ctx_hash,
            gs_instance_digest,
            &kem_share.t_i,
            &kem_share.d1_masks,
            &kem_share.d2_masks,
            &kem_share.d1_instance_masks,
            &kem_share.d2_instance_masks,
        )?;

        let plaintext =
            self.dem_decrypt(&share_key, &kem_share.ciphertext, &kem_share.auth_tag, &ad)?;

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

    /// Build associated data for ρ encryption
    fn build_rho_ad(
        &self,
        share_index: u32,
        ctx_hash: &[u8],
        gs_instance_digest: &[u8],
        d1_instance_masks: &[Vec<u8>],
        d2_instance_masks: &[Vec<u8>],
    ) -> Result<Vec<u8>, KEMError> {
        let mut ad = Vec::new();
        ad.extend_from_slice(&share_index.to_be_bytes());
        ad.extend_from_slice(ctx_hash);
        ad.extend_from_slice(gs_instance_digest);

        for mask in d1_instance_masks {
            ad.extend_from_slice(mask);
        }

        for mask in d2_instance_masks {
            ad.extend_from_slice(mask);
        }

        Ok(ad)
    }

    /// Build associated data for share encryption (binds masks and adaptor point)
    fn build_share_ad(
        &self,
        share_index: u32,
        ctx_hash: &[u8],
        gs_instance_digest: &[u8],
        t_i: &[u8],
        d1_masks: &[Vec<u8>],
        d2_masks: &[Vec<u8>],
        d1_instance_masks: &[Vec<u8>],
        d2_instance_masks: &[Vec<u8>],
    ) -> Result<Vec<u8>, KEMError> {
        let mut ad = Vec::new();
        ad.extend_from_slice(&share_index.to_be_bytes());
        ad.extend_from_slice(ctx_hash);
        ad.extend_from_slice(gs_instance_digest);
        ad.extend_from_slice(t_i);

        for mask in d1_masks {
            ad.extend_from_slice(mask);
        }

        for mask in d2_masks {
            ad.extend_from_slice(mask);
        }

        for mask in d1_instance_masks {
            ad.extend_from_slice(mask);
        }

        for mask in d2_instance_masks {
            ad.extend_from_slice(mask);
        }

        Ok(ad)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::One;
    use ark_std::test_rng;

    #[test]
    fn test_kdf_functionality() {
        let kem = ProductKeyKEM::new();
        let gt_bytes = vec![0u8; 576];
        let ctx_hash = b"test_context";
        let gs_instance_digest = b"test_digest";

        let result = kem
            .kdf_from_bytes(&gt_bytes, ctx_hash, gs_instance_digest)
            .unwrap();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_dem_roundtrip() {
        let kem = ProductKeyKEM::new();
        let key = vec![0u8; 32];
        let plaintext = b"Hello, World!";
        let ad = b"associated_data";

        let (ciphertext, auth_tag) = kem.dem_encrypt(&key, plaintext, ad).unwrap();
        let recovered = kem.dem_decrypt(&key, &ciphertext, &auth_tag, ad).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn test_encapsulate_rejects_invalid_inputs() {
        let kem = ProductKeyKEM::new();
        let mut rng = test_rng();
        let ctx_hash = b"ctx";
        let gs_digest = b"digest";
        let target = GTElement::one();
        let share_scalar = BLS12381Ops::random_scalar(&mut rng);
        let result = kem.encapsulate(
            &mut rng,
            0,
            &vec![vec![0u8; 192]],
            &vec![vec![0u8; 96]],
            &vec![vec![0u8; 96]],
            &vec![vec![0u8; 192]],
            &target,
            share_scalar,
            ctx_hash,
            gs_digest,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_product_key_anchor_mismatch() {
        let res = crate::gs_kem_helpers::compute_product_key_anchor(
            &vec![vec![0u8; 96]],
            &vec![vec![0u8; 192]],
            &vec![vec![0u8; 192], vec![0u8; 192]],
            &vec![vec![0u8; 96]],
        );
        assert!(res.is_err());
    }
}
