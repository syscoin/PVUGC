/*!
BLS12-381 Pairing Operations

Core cryptographic operations for PVUGC using Arkworks.
This module provides the equivalent functionality to pvugc_pairing_ops.py
*/

use ark_bls12_381::{Fr, G1Affine, G2Affine, Fq12};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Zero;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_std::{vec::Vec, rand::Rng, UniformRand};
use thiserror::Error;

/// Errors that can occur during BLS12-381 operations
#[derive(Error, Debug)]
pub enum BLS12381Error {
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Deserialization error: {0}")]
    Deserialization(String),
}

pub type G1Point = Vec<u8>;
pub type G2Point = Vec<u8>;
pub type GTElement = Fq12;
pub type Scalar = Fr;

/// BLS12-381 operations implementation
pub struct BLS12381Ops;

impl BLS12381Ops {
    /// Generate random non-zero scalar in Zr
    pub fn random_scalar<R: Rng>(rng: &mut R) -> Scalar {
        loop {
            let s = Fr::rand(rng);
            if !s.is_zero() {
                return s;
            }
        }
    }

    /// Scalar multiplication in G1
    pub fn g1_multiply(point: &G1Point, scalar: Scalar) -> Result<G1Point, BLS12381Error> {
        // Deserialize point
        let p = G1Affine::deserialize_compressed(point.as_slice())
            .map_err(|e| BLS12381Error::Deserialization(format!("G1 deserialize: {:?}", e)))?;
        
        // Multiply by scalar
        let result = (p.into_group() * scalar).into_affine();
        
        // Serialize result
        let mut compressed = Vec::new();
        result.serialize_compressed(&mut compressed)
            .map_err(|e| BLS12381Error::Serialization(format!("G1 serialize: {:?}", e)))?;
        
        Ok(compressed)
    }

    /// Scalar multiplication in G2
    pub fn g2_multiply(point: &G2Point, scalar: Scalar) -> Result<G2Point, BLS12381Error> {
        // Deserialize point
        let p = G2Affine::deserialize_compressed(point.as_slice())
            .map_err(|e| BLS12381Error::Deserialization(format!("G2 deserialize: {:?}", e)))?;
        
        // Multiply by scalar
        let result = (p.into_group() * scalar).into_affine();
        
        // Serialize result
        let mut compressed = Vec::new();
        result.serialize_compressed(&mut compressed)
            .map_err(|e| BLS12381Error::Serialization(format!("G2 serialize: {:?}", e)))?;
        
        Ok(compressed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;

    #[test]
    fn test_random_scalar() {
        let mut rng = test_rng();
        let scalar = BLS12381Ops::random_scalar(&mut rng);
        assert!(!scalar.is_zero());
    }

    #[test]
    fn test_g1_multiply() {
        let mut rng = test_rng();
        
        // Generate random G1 point
        let generator = G1Affine::generator();
        let mut compressed = Vec::new();
        generator.serialize_compressed(&mut compressed).unwrap();
        
        // Test scalar multiplication
        let scalar = BLS12381Ops::random_scalar(&mut rng);
        let multiplied = BLS12381Ops::g1_multiply(&compressed, scalar).unwrap();
        assert_eq!(multiplied.len(), 48);
    }

    #[test]
    fn test_g2_multiply() {
        let mut rng = test_rng();
        
        // Generate random G2 point
        let generator = G2Affine::generator();
        let mut compressed = Vec::new();
        generator.serialize_compressed(&mut compressed).unwrap();
        
        // Test scalar multiplication
        let scalar = BLS12381Ops::random_scalar(&mut rng);
        let multiplied = BLS12381Ops::g2_multiply(&compressed, scalar).unwrap();
        assert_eq!(multiplied.len(), 96);
    }

}
