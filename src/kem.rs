/*!
PVUGC KEM - Legacy module

This module is deprecated. The active KEM implementation is in `gs_commitments.rs`
with methods `kem_encapsulate` and `kem_decapsulate`.

For working examples, see:
- `tests/test_pvugc.rs::test_complete_adaptor_signature_flow` - Full Groth16 + KEM integration
*/

// Re-export types that may still be used
pub use ark_bls12_381::Fr;

/// Errors that can occur during KEM operations  
#[derive(Debug)]
pub enum KEMError {
    Serialization(String),
    Deserialization(String),
    Encryption(String),
    Decryption(String),
    InvalidInput(String),
    Crypto(String),
}

impl std::fmt::Display for KEMError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KEMError::Serialization(s) => write!(f, "Serialization error: {}", s),
            KEMError::Deserialization(s) => write!(f, "Deserialization error: {}", s),
            KEMError::Encryption(s) => write!(f, "Encryption error: {}", s),
            KEMError::Decryption(s) => write!(f, "Decryption error: {}", s),
            KEMError::InvalidInput(s) => write!(f, "Invalid input: {}", s),
            KEMError::Crypto(s) => write!(f, "Crypto error: {}", s),
        }
    }
}

impl std::error::Error for KEMError {}

// Tests for KDF and DEM primitives (now in gs_commitments but we keep coverage here)
#[cfg(test)]
mod tests {
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        ChaCha20Poly1305, Nonce,
    };
    use sha2::{Digest, Sha256};

    // NOTE: Full KEM encap/decap test is in tests/test_pvugc.rs::test_complete_adaptor_signature_flow
    // These tests verify the basic cryptographic primitives

    #[test]
    fn test_kdf_functionality() {
        // Test basic KDF using SHA256 (same as used in gs_commitments)
        let gt_bytes = vec![0u8; 576]; // Dummy GT bytes
        let ctx_hash = b"test_context";

        let key_material = Sha256::digest(&[ctx_hash.as_slice(), &gt_bytes].concat()).to_vec();
        let key: [u8; 32] = key_material[..32].try_into().unwrap();

        assert_eq!(key.len(), 32);
        // Verify determinism
        let key_material2 = Sha256::digest(&[ctx_hash.as_slice(), &gt_bytes].concat()).to_vec();
        let key2: [u8; 32] = key_material2[..32].try_into().unwrap();
        assert_eq!(key, key2, "KDF should be deterministic");
    }

    #[test]
    fn test_dem_functionality() {
        // Test ChaCha20Poly1305 encryption/decryption (same as used in gs_commitments)
        let key = [0u8; 32];
        let plaintext = b"Hello, World!";
        let nonce = Nonce::from_slice(&[0u8; 12]);

        // Test encryption
        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();
        assert!(!ciphertext.is_empty());

        // Test decryption
        let decrypted = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_dem_wrong_key() {
        // Test that wrong key fails to decrypt
        let key1 = [0u8; 32];
        let mut key2 = [0u8; 32];
        key2[0] = 1; // Different key

        let plaintext = b"Secret message";
        let nonce = Nonce::from_slice(&[0u8; 12]);

        // Encrypt with key1
        let cipher1 = ChaCha20Poly1305::new_from_slice(&key1).unwrap();
        let ciphertext = cipher1.encrypt(nonce, plaintext.as_ref()).unwrap();

        // Try to decrypt with key2 (should fail)
        let cipher2 = ChaCha20Poly1305::new_from_slice(&key2).unwrap();
        let result = cipher2.decrypt(nonce, ciphertext.as_ref());
        assert!(result.is_err(), "Decryption with wrong key should fail");
    }

    #[test]
    fn test_dem_tampered_ciphertext() {
        // Test that tampered ciphertext fails to decrypt
        let key = [0u8; 32];
        let plaintext = b"Hello, World!";
        let nonce = Nonce::from_slice(&[0u8; 12]);

        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();

        // Tamper with ciphertext
        let mut tampered = ciphertext.clone();
        tampered[0] ^= 0x01;

        // Try to decrypt tampered ciphertext (should fail)
        let result = cipher.decrypt(nonce, tampered.as_ref());
        assert!(
            result.is_err(),
            "Decryption of tampered ciphertext should fail"
        );
    }

    #[test]
    fn test_dem_tampered_auth_tag() {
        // Test that authentication tag is properly verified
        let key = [0u8; 32];
        let plaintext = b"Hello, World!";
        let nonce = Nonce::from_slice(&[0u8; 12]);

        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();

        // The auth tag is included in the ciphertext (last 16 bytes)
        let mut tampered = ciphertext.clone();
        let len = tampered.len();
        tampered[len - 1] ^= 0xff; // Tamper with last byte of auth tag

        // Try to decrypt with tampered tag (should fail)
        let result = cipher.decrypt(nonce, tampered.as_ref());
        assert!(
            result.is_err(),
            "Decryption with tampered auth tag should fail"
        );
    }
}
