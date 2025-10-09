/*!
Schnorr Adaptor Signatures for Bitcoin Taproot

This module provides a wrapper around schnorr_fun for adaptor signatures and MuSig2.
All cryptographic operations are handled by the schnorr_fun library.
*/

use schnorr_fun::{
    adaptor::{Adaptor, EncryptedSign, EncryptedSignature},
    fun::{marker::*, nonce, Scalar, Point},
    musig,
    Message, Schnorr,
};
use bitcoin::secp256k1::PublicKey;
use sha2::{Sha256, Digest};
use thiserror::Error;
use ark_std::{vec::Vec, rand::Rng};

/// Errors that can occur during Schnorr operations
#[derive(Error, Debug)]
pub enum SchnorrError {
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),
    #[error("Invalid private key: {0}")]
    InvalidPrivateKey(String),
    #[error("Invalid secret: {0}")]
    InvalidSecret(String),
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Crypto error: {0}")]
    Crypto(String),
}

/// Schnorr adaptor pre-signature wrapper
#[derive(Debug, Clone)]
pub struct AdaptorSignature {
    /// Inner encrypted signature from schnorr_fun
    pub encrypted_signature: EncryptedSignature,
    /// Adaptor point T (needed for verification and completion)
    pub t: [u8; 33],
}

/// Schnorr adaptor signature implementation using schnorr_fun
pub struct SchnorrAdaptor {
    pub schnorr: Schnorr<Sha256, nonce::Synthetic<Sha256, nonce::GlobalRng<rand::rngs::ThreadRng>>>,
    pub musig: musig::MuSig<Sha256, nonce::Synthetic<Sha256, nonce::GlobalRng<rand::rngs::ThreadRng>>>,
}

impl SchnorrAdaptor {
    /// Create a new SchnorrAdaptor instance
    pub fn new() -> Self {
        let nonce_gen = nonce::Synthetic::<Sha256, nonce::GlobalRng<rand::rngs::ThreadRng>>::default();
        let schnorr = Schnorr::<Sha256, _>::new(nonce_gen.clone());
        let musig = musig::MuSig::new(schnorr.clone());
        
        Self {
            schnorr,
            musig,
        }
    }

    /// BIP-340 tagged hash function
    pub fn tagged_hash(tag: &[u8], data: &[u8]) -> [u8; 32] {
        let tag_hash = Sha256::digest(tag);
        let mut input = Vec::new();
        input.extend_from_slice(&tag_hash);
        input.extend_from_slice(&tag_hash);
        input.extend_from_slice(data);
        Sha256::digest(&input).into()
    }

    /// Aggregate public keys using schnorr_fun MuSig
    pub fn aggregate_pubkeys(&self, pubkeys: &[[u8; 33]]) -> Result<[u8; 33], SchnorrError> {
        if pubkeys.is_empty() {
            return Err(SchnorrError::InvalidPublicKey("No public keys to aggregate".to_string()));
        }

        // Convert pubkeys to schnorr_fun format
        let mut verification_keys = Vec::new();
        for (i, pubkey_bytes) in pubkeys.iter().enumerate() {
            let pubkey = PublicKey::from_slice(pubkey_bytes)
                .map_err(|e| SchnorrError::InvalidPublicKey(format!("Invalid pubkey {}: {:?}", i, e)))?;
            
            // Convert to schnorr_fun verification key (Normal point for MuSig)
            let x_bytes: [u8; 32] = pubkey.serialize()[1..33].try_into()
                .map_err(|_| SchnorrError::Serialization("Invalid pubkey format".to_string()))?;
            
            // Convert x-only bytes to compressed format for Normal point
            let mut compressed_bytes = [0u8; 33];
            compressed_bytes[0] = 0x02; // Even y-coordinate
            compressed_bytes[1..].copy_from_slice(&x_bytes);
            let verification_key = Point::<Normal, Public>::from_bytes(compressed_bytes)
                .ok_or_else(|| SchnorrError::InvalidPublicKey("Invalid verification key".to_string()))?;
            
            verification_keys.push(verification_key);
        }

        // Use MuSig to aggregate keys
        let aggregated_key = self.musig.new_agg_key(verification_keys);

        // Convert back to compressed format
        Ok(aggregated_key.agg_public_key().to_bytes())
    }

    /// Aggregate adaptor points: T = Σ T_i using schnorr_fun
    pub fn aggregate_adaptor_points(&self, t_points: &[[u8; 33]]) -> Result<[u8; 33], SchnorrError> {
        if t_points.is_empty() {
            return Err(SchnorrError::InvalidPublicKey("No adaptor points".to_string()));
        }

        // Parse first adaptor point
        let mut aggregated_point = PublicKey::from_slice(&t_points[0])
            .map_err(|e| SchnorrError::InvalidPublicKey(format!("Invalid T point 0: {:?}", e)))?;

        // Add remaining adaptor points using secp256k1 point addition
        for (i, t_bytes) in t_points.iter().enumerate().skip(1) {
            let t_point = PublicKey::from_slice(t_bytes)
                .map_err(|e| SchnorrError::InvalidPublicKey(format!("Invalid T point {}: {:?}", i, e)))?;
            
            // Perform elliptic curve point addition: T_agg = T_agg + T_i
            aggregated_point = aggregated_point.combine(&t_point)
                .map_err(|e| SchnorrError::Crypto(format!("T point combination failed: {:?}", e)))?;
        }

        // Serialize as compressed public key
        Ok(aggregated_point.serialize())
    }

    /// Create MuSig2 adaptor pre-signature according to PVUGC spec
    /// This implements a simplified MuSig2 multisig adaptor signature protocol
    /// For production use, implement full BIP-327 MuSig2 with proper nonce generation
    pub fn create_presignature<R: Rng>(
        &self,
        _rng: &mut R,
        message: &[u8],
        aggregate_pubkey: &[u8; 33],
        aggregate_t: &[u8; 33],
        participants_secrets: &[[u8; 32]],
    ) -> Result<AdaptorSignature, SchnorrError> {
        // Convert adaptor point to schnorr_fun format
        let t_point = Point::<Normal, Public>::from_bytes(*aggregate_t)
            .ok_or_else(|| SchnorrError::Serialization("Invalid adaptor point".to_string()))?;

        // SIMPLIFIED IMPLEMENTATION: Aggregate private keys
        // In a real MuSig2, each participant would create partial signatures
        // Here we simulate a trusted dealer who knows all secrets
        let mut aggregated_secret = Scalar::<Secret, Zero>::zero();
        
        for (i, secret_bytes) in participants_secrets.iter().enumerate() {
            let secret_key = Scalar::<Secret, NonZero>::from_bytes(*secret_bytes)
                .ok_or_else(|| SchnorrError::InvalidPrivateKey(format!("Invalid secret {}", i)))?;
            aggregated_secret = schnorr_fun::fun::op::scalar_add(aggregated_secret, secret_key);
        }
        
        // Ensure the aggregated secret is non-zero
        let aggregated_secret_nonzero = Scalar::<Secret, NonZero>::from_bytes(aggregated_secret.to_bytes())
            .ok_or_else(|| SchnorrError::InvalidPrivateKey("Aggregated secret is zero".to_string()))?;
        
        // Create keypair from aggregated secret
        let aggregated_keypair = self.schnorr.new_keypair(aggregated_secret_nonzero);
        
        // Verify that the aggregated keypair's public key matches the provided aggregate_pubkey
        // This is a sanity check to ensure our key aggregation is correct
        let derived_pubkey = aggregated_keypair.public_key();
        let derived_pubkey_bytes = derived_pubkey.to_bytes();
        
        // The derived key might have different parity, so we compare x-coordinates only
        let provided_x = &aggregate_pubkey[1..];
        let derived_x = &derived_pubkey_bytes[1..];
        
        if provided_x != derived_x {
            return Err(SchnorrError::InvalidPublicKey(
                "Aggregated secret doesn't match aggregated pubkey".to_string()
            ));
        }
        
        // Create encrypted signature using the aggregated keypair
        let encrypted_signature = self.schnorr.encrypted_sign(
            &aggregated_keypair,
            &t_point,
            Message::<Public>::raw(message),
        );

        Ok(AdaptorSignature {
            encrypted_signature,
            t: *aggregate_t,
        })
    }

    /// Verify adaptor pre-signature using schnorr_fun
    pub fn verify_presignature(
        &self,
        message: &[u8],
        pubkey: &[u8; 33],
        adaptor: &AdaptorSignature,
    ) -> Result<bool, SchnorrError> {
        // Convert public key to schnorr_fun format
        let pubkey_point = PublicKey::from_slice(pubkey)
            .map_err(|e| SchnorrError::InvalidPublicKey(format!("Invalid pubkey: {:?}", e)))?;
        
        let x_bytes: [u8; 32] = pubkey_point.serialize()[1..33].try_into()
            .map_err(|_| SchnorrError::Serialization("Invalid pubkey format".to_string()))?;
        
        let verification_key = Point::<EvenY, Public>::from_xonly_bytes(x_bytes)
            .ok_or_else(|| SchnorrError::InvalidPublicKey("Invalid verification key".to_string()))?;

        // Convert adaptor point to schnorr_fun format
        let t_point = Point::<Normal, Public>::from_bytes(adaptor.t)
            .ok_or_else(|| SchnorrError::Serialization("Invalid adaptor point".to_string()))?;

        // Verify encrypted signature using schnorr_fun
        let is_valid = self.schnorr.verify_encrypted_signature(
            &verification_key,
            &t_point,
            Message::<Public>::raw(message),
            &adaptor.encrypted_signature,
        );

        Ok(is_valid)
    }

    /// Complete signature by revealing adaptor secret using schnorr_fun
    pub fn complete_signature(
        &self,
        adaptor: &AdaptorSignature,
        alpha: &[u8; 32],
    ) -> Result<([u8; 32], [u8; 32]), SchnorrError> {
        // Convert alpha to schnorr_fun scalar
        let alpha_scalar = Scalar::<Secret, NonZero>::from_bytes(*alpha)
            .ok_or_else(|| SchnorrError::InvalidSecret("Invalid alpha".to_string()))?;

        // Complete the signature using schnorr_fun
        let signature = self.schnorr.decrypt_signature(
            alpha_scalar,
            adaptor.encrypted_signature.clone(),
        );

        // Extract r and s from the signature
        let (r_point, s_scalar) = signature.as_tuple();
        let r_bytes = r_point.to_xonly_bytes();
        let s_bytes = s_scalar.to_bytes();

        Ok((r_bytes, s_bytes))
    }

    /// Verify completed Schnorr signature using schnorr_fun
    pub fn verify_schnorr(
        &self,
        message: &[u8],
        pubkey: &[u8; 33],
        signature: ([u8; 32], [u8; 32]),
    ) -> Result<bool, SchnorrError> {
        let (r_bytes, s_bytes) = signature;

        // Convert public key to schnorr_fun format
        let pubkey_point = PublicKey::from_slice(pubkey)
            .map_err(|e| SchnorrError::InvalidPublicKey(format!("Invalid pubkey: {:?}", e)))?;
        
        let x_bytes: [u8; 32] = pubkey_point.serialize()[1..33].try_into()
            .map_err(|_| SchnorrError::Serialization("Invalid pubkey format".to_string()))?;
        
        let verification_key = Point::<EvenY, Public>::from_xonly_bytes(x_bytes)
            .ok_or_else(|| SchnorrError::InvalidPublicKey("Invalid verification key".to_string()))?;

        // Create signature object from bytes
        let mut sig_bytes = [0u8; 64];
        sig_bytes[0..32].copy_from_slice(&r_bytes);
        sig_bytes[32..64].copy_from_slice(&s_bytes);
        
        let signature_obj = schnorr_fun::Signature::from_bytes(sig_bytes)
            .ok_or_else(|| SchnorrError::InvalidSignature("Invalid signature format".to_string()))?;

        // Verify signature using schnorr_fun
        let is_valid = self.schnorr.verify(
            &verification_key,
            Message::<Public>::raw(message),
            &signature_obj,
        );

        Ok(is_valid)
    }
}

// MuSig2 ceremony removed - use schnorr_fun directly

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;
    use bitcoin::secp256k1::Secp256k1;

    #[test]
    fn test_tagged_hash() {
        let tag = b"BIP0340/challenge";
        let data = b"test_data";
        let hash = SchnorrAdaptor::tagged_hash(tag, data);
        
        // Should produce a 32-byte hash
        assert_eq!(hash.len(), 32);
        
        // Should be deterministic
        let hash2 = SchnorrAdaptor::tagged_hash(tag, data);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_adaptor_signature_creation() {
        let mut rng = test_rng();
        let message = b"Hello, World!";
        let schnorr = SchnorrAdaptor::new();
        let secp = Secp256k1::new();
        
        // Create a single keypair and adaptor point
        let (sk, pk) = secp.generate_keypair(&mut rng);
        let (_, alpha_pk) = secp.generate_keypair(&mut rng);
        
        // Convert to schnorr_fun format
        let sk_scalar = Scalar::<Secret, NonZero>::from_bytes(sk.secret_bytes())
            .expect("Invalid secret key");
        let alpha_point = Point::<Normal, Public>::from_bytes(alpha_pk.serialize())
            .expect("Invalid adaptor point");
        
        // Create signing keypair
        let signing_keypair = schnorr.schnorr.new_keypair(sk_scalar);
        
        // Create encrypted signature directly
        let encrypted_signature = schnorr.schnorr.encrypted_sign(
            &signing_keypair,
            &alpha_point,
            Message::<Public>::raw(message),
        );
        
        // Create our AdaptorSignature wrapper
        let adaptor_sig = AdaptorSignature {
            encrypted_signature,
            t: alpha_pk.serialize(),
        };
        
        // Test verification
        let is_valid = schnorr.verify_presignature(message, &pk.serialize(), &adaptor_sig).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_signature_completion() {
        let mut rng = test_rng();
        let schnorr = SchnorrAdaptor::new();
        let message = b"Test message for completion";
        let secp = Secp256k1::new();
        
        // Create a real adaptor signature first
        let (sk, pk) = secp.generate_keypair(&mut rng);
        let (alpha_sk, alpha_pk) = secp.generate_keypair(&mut rng);
        
        // Convert to schnorr_fun format
        let sk_scalar = Scalar::<Secret, NonZero>::from_bytes(sk.secret_bytes())
            .expect("Invalid secret key");
        let alpha_point = Point::<Normal, Public>::from_bytes(alpha_pk.serialize())
            .expect("Invalid adaptor point");
        
        // Create signing keypair
        let signing_keypair = schnorr.schnorr.new_keypair(sk_scalar);
        
        // Create encrypted signature directly
        let encrypted_signature = schnorr.schnorr.encrypted_sign(
            &signing_keypair,
            &alpha_point,
            Message::<Public>::raw(message),
        );
        
        // Create our AdaptorSignature wrapper
        let adaptor_sig = AdaptorSignature {
            encrypted_signature,
            t: alpha_pk.serialize(),
        };
        
        // Test completion with real alpha
        let alpha = alpha_sk.secret_bytes();
        
        let result = schnorr.complete_signature(&adaptor_sig, &alpha);
        assert!(result.is_ok());
        
        let (r, s) = result.unwrap();
        assert_eq!(r.len(), 32);
        assert_eq!(s.len(), 32);
        
        // Verify the completed signature
        let is_valid = schnorr.verify_schnorr(message, &pk.serialize(), (r, s)).unwrap();
        assert!(is_valid);
    }
    
    #[test]
    fn test_verify_schnorr() {
        let mut rng = test_rng();
        let schnorr = SchnorrAdaptor::new();
        let secp = Secp256k1::new();
        let message = b"Test message for Schnorr verification";
        
        // Create a simple keypair and adaptor point
        let (sk, pk) = secp.generate_keypair(&mut rng);
        let (alpha_sk, alpha_pk) = secp.generate_keypair(&mut rng);
        
        // Convert to schnorr_fun format
        let sk_scalar = Scalar::<Secret, NonZero>::from_bytes(sk.secret_bytes())
            .expect("Invalid secret key");
        let alpha_point = Point::<Normal, Public>::from_bytes(alpha_pk.serialize())
            .expect("Invalid adaptor point");
        
        // Create signing keypair
        let signing_keypair = schnorr.schnorr.new_keypair(sk_scalar);
        
        // Create encrypted signature directly
        let encrypted_signature = schnorr.schnorr.encrypted_sign(
            &signing_keypair,
            &alpha_point,
            Message::<Public>::raw(message),
        );
        
        // Create our AdaptorSignature wrapper
        let adaptor_sig = AdaptorSignature {
            encrypted_signature,
            t: alpha_pk.serialize(),
        };
        
        // Complete the signature
        let alpha = alpha_sk.secret_bytes();
        let (r, s) = schnorr.complete_signature(&adaptor_sig, &alpha).unwrap();
        
        // Verify the completed signature
        let is_valid = schnorr.verify_schnorr(message, &pk.serialize(), (r, s)).unwrap();
        assert!(is_valid, "Schnorr signature verification should succeed");
        
        // Test with wrong message
        let wrong_message = b"Wrong message";
        let is_invalid = schnorr.verify_schnorr(wrong_message, &pk.serialize(), (r, s)).unwrap();
        assert!(!is_invalid, "Schnorr signature verification should fail with wrong message");
    }

    #[test]
    fn test_simple_adaptor_signature() {
        let mut rng = test_rng();
        let schnorr = SchnorrAdaptor::new();
        let secp = Secp256k1::new();
        let message = b"Simple test message";
        
        // Create a single keypair (no MuSig aggregation)
        let (sk, pk) = secp.generate_keypair(&mut rng);
        
        // Create adaptor keypair
        let (alpha_sk, alpha_pk) = secp.generate_keypair(&mut rng);
        
        // Convert to schnorr_fun format
        let sk_scalar = Scalar::<Secret, NonZero>::from_bytes(sk.secret_bytes())
            .expect("Invalid secret key");
        let alpha_point = Point::<Normal, Public>::from_bytes(alpha_pk.serialize())
            .expect("Invalid adaptor point");
        
        // Create signing keypair
        let signing_keypair = schnorr.schnorr.new_keypair(sk_scalar);
        
        // Create encrypted signature directly
        let encrypted_signature = schnorr.schnorr.encrypted_sign(
            &signing_keypair,
            &alpha_point,
            Message::<Public>::raw(message),
        );
        
        // Create our AdaptorSignature wrapper
        let adaptor_sig = AdaptorSignature {
            encrypted_signature,
            t: alpha_pk.serialize(),
        };
        
        // Test presignature verification
        let is_valid = schnorr.verify_presignature(message, &pk.serialize(), &adaptor_sig).unwrap();
        assert!(is_valid, "Presignature verification should succeed");
        
        // Test signature completion
        let alpha = alpha_sk.secret_bytes();
        let (r, s) = schnorr.complete_signature(&adaptor_sig, &alpha).unwrap();
        
        // Test final signature verification
        let is_final_valid = schnorr.verify_schnorr(message, &pk.serialize(), (r, s)).unwrap();
        assert!(is_final_valid, "Final signature verification should succeed");
    }

    #[test]
    fn test_musig2_key_aggregation() {
        let mut rng = test_rng();
        let schnorr = SchnorrAdaptor::new();
        let secp = Secp256k1::new();
        
        // Create multiple keypairs
        let (_sk1, pk1) = secp.generate_keypair(&mut rng);
        let (_sk2, pk2) = secp.generate_keypair(&mut rng);
        let (_sk3, pk3) = secp.generate_keypair(&mut rng);
        
        let pubkeys = vec![pk1.serialize(), pk2.serialize(), pk3.serialize()];
        
        // Test key aggregation
        let aggregate_pubkey = schnorr.aggregate_pubkeys(&pubkeys).unwrap();
        assert_eq!(aggregate_pubkey.len(), 33);
        
        // Test that aggregation is deterministic
        let aggregate_pubkey2 = schnorr.aggregate_pubkeys(&pubkeys).unwrap();
        assert_eq!(aggregate_pubkey, aggregate_pubkey2);
    }

    /// Test Schnorr adaptor signatures
    #[test]
    fn test_schnorr_adaptor_basic() {        // Test tagged hash
        let tag = b"BIP0340/challenge";
        let data = b"test_message";
        let hash = SchnorrAdaptor::tagged_hash(tag, data);
        assert_eq!(hash.len(), 32);
        
        // Test hash determinism
        let hash2 = SchnorrAdaptor::tagged_hash(tag, data);
        assert_eq!(hash, hash2);
    } 
}
