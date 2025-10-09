/*!
BLS12-381 Pairing Operations

Core cryptographic operations for PVUGC using Arkworks.
This module provides the equivalent functionality to pvugc_pairing_ops.py
*/

use ark_bls12_381::{Bls12_381, Fr, G1Affine, G2Affine, Fq12};
use ark_ec::{AffineRepr, CurveGroup, pairing::Pairing};
use ark_ff::{PrimeField, Zero, One, Field};
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
    #[error("Invalid input: {0}")]
    InvalidInput(String),
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

    /// Point addition in G1
    pub fn g1_add(p1: &G1Point, p2: &G1Point) -> Result<G1Point, BLS12381Error> {
        // Deserialize points
        let a1 = G1Affine::deserialize_compressed(p1.as_slice())
            .map_err(|e| BLS12381Error::Deserialization(format!("G1 p1 deserialize: {:?}", e)))?;
        let a2 = G1Affine::deserialize_compressed(p2.as_slice())
            .map_err(|e| BLS12381Error::Deserialization(format!("G1 p2 deserialize: {:?}", e)))?;
        
        // Add points
        let result = (a1.into_group() + a2.into_group()).into_affine();
        
        // Serialize result
        let mut compressed = Vec::new();
        result.serialize_compressed(&mut compressed)
            .map_err(|e| BLS12381Error::Serialization(format!("G1 add serialize: {:?}", e)))?;
        
        Ok(compressed)
    }

    /// Point negation in G1 via scalar multiplication by -1
    pub fn g1_negate(point: &G1Point) -> Result<G1Point, BLS12381Error> {
        Self::g1_multiply(point, -Fr::one())
    }

    /// Point addition in G2
    pub fn g2_add(p1: &G2Point, p2: &G2Point) -> Result<G2Point, BLS12381Error> {
        // Deserialize points
        let a1 = G2Affine::deserialize_compressed(p1.as_slice())
            .map_err(|e| BLS12381Error::Deserialization(format!("G2 p1 deserialize: {:?}", e)))?;
        let a2 = G2Affine::deserialize_compressed(p2.as_slice())
            .map_err(|e| BLS12381Error::Deserialization(format!("G2 p2 deserialize: {:?}", e)))?;
        
        // Add points
        let result = (a1.into_group() + a2.into_group()).into_affine();
        
        // Serialize result
        let mut compressed = Vec::new();
        result.serialize_compressed(&mut compressed)
            .map_err(|e| BLS12381Error::Serialization(format!("G2 add serialize: {:?}", e)))?;
        
        Ok(compressed)
    }

    /// Compute pairing e(g1, g2) using arkworks
    pub fn compute_pairing(g1: &G1Point, g2: &G2Point) -> Result<GTElement, BLS12381Error> {
        // Deserialize points
        let p1 = G1Affine::deserialize_compressed(g1.as_slice())
            .map_err(|e| BLS12381Error::Deserialization(format!("G1 pairing deserialize: {:?}", e)))?;
        let p2 = G2Affine::deserialize_compressed(g2.as_slice())
            .map_err(|e| BLS12381Error::Deserialization(format!("G2 pairing deserialize: {:?}", e)))?;
        
        // Compute pairing
        Ok(Bls12_381::pairing(p1, p2).0)
    }


    /// Exponentiation in GT
    pub fn gt_multiply(elem: &GTElement, scalar: Scalar) -> GTElement {
        elem.pow(scalar.into_bigint())
    }

    /// Multiplication in GT
    pub fn gt_product(elem1: &GTElement, elem2: &GTElement) -> GTElement {
        *elem1 * *elem2
    }

    /// Inversion in GT
    pub fn gt_inverse(elem: &GTElement) -> GTElement {
        elem.inverse().unwrap_or_else(|| {
            // Use Fermat's little theorem: a^(p-1) = 1, so a^(p-2) = a^(-1)
            // Use a simpler approach - just use Fr::from(2) and subtract
            let p_minus_2 = Fr::from(2u64).inverse().unwrap();
            elem.pow(p_minus_2.into_bigint())
        })
    }

    /// Serialize GT element to bytes (canonical format)
    pub fn serialize_gt(elem: &GTElement) -> Vec<u8> {
        use crate::gs_kem_helpers::serialize_gt_pvugc;
        serialize_gt_pvugc(elem)
    }


    /// Generate random G1 point
    pub fn random_g1<R: Rng>(rng: &mut R) -> Result<G1Point, BLS12381Error> {
        let scalar = Self::random_scalar(rng);
        let generator = G1Affine::generator();
        let point = (generator * scalar).into_affine();
        
        let mut compressed = Vec::new();
        point.serialize_compressed(&mut compressed)
            .map_err(|e| BLS12381Error::Serialization(format!("G1 random serialize: {:?}", e)))?;
        
        Ok(compressed)
    }

    /// Generate random G2 point
    pub fn random_g2<R: Rng>(rng: &mut R) -> Result<G2Point, BLS12381Error> {
        let scalar = Self::random_scalar(rng);
        let generator = G2Affine::generator();
        let point = (generator * scalar).into_affine();
        
        let mut compressed = Vec::new();
        point.serialize_compressed(&mut compressed)
            .map_err(|e| BLS12381Error::Serialization(format!("G2 random serialize: {:?}", e)))?;
        
        Ok(compressed)
    }

    /// Multi-pairing computation
    pub fn multi_pairing(g1_points: &[G1Point], g2_points: &[G2Point]) -> Result<GTElement, BLS12381Error> {
        if g1_points.len() != g2_points.len() {
            return Err(BLS12381Error::InvalidInput(format!(
                "Mismatched point counts: G1={}, G2={}",
                g1_points.len(),
                g2_points.len()
            )));
        }

        let mut result = Fq12::one();
        
        for (g1, g2) in g1_points.iter().zip(g2_points.iter()) {
            let pairing = Self::compute_pairing(g1, g2)?;
            result = Self::gt_product(&result, &pairing);
        }
        
        Ok(result)
    }

    /// Return identity element in GT
    pub fn identity_gt() -> GTElement {
        Fq12::one()
    }

    /// Check if GT element is identity
    pub fn is_identity_gt(elem: &GTElement) -> bool {
        elem.is_one()
    }

    /// Hash to scalar using SHA-256
    pub fn hash_to_scalar(data: &[u8]) -> Scalar {
        use sha2::{Sha256, Digest};
        let hash = Sha256::digest(data);
        Fr::from_be_bytes_mod_order(&hash)
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
    fn test_g1_operations() {
        let mut rng = test_rng();
        
        // Generate random G1 point
        let point = BLS12381Ops::random_g1(&mut rng).unwrap();
        assert_eq!(point.len(), 48); // Compressed G1 size
        
        // Test scalar multiplication
        let scalar = BLS12381Ops::random_scalar(&mut rng);
        let multiplied = BLS12381Ops::g1_multiply(&point, scalar).unwrap();
        assert_eq!(multiplied.len(), 48);
        
        // Test point addition
        let point2 = BLS12381Ops::random_g1(&mut rng).unwrap();
        let added = BLS12381Ops::g1_add(&point, &point2).unwrap();
        assert_eq!(added.len(), 48);
        
        // Test negation
        let negated = BLS12381Ops::g1_negate(&point).unwrap();
        assert_eq!(negated.len(), 48);
    }

    #[test]
    fn test_g2_operations() {
        let mut rng = test_rng();
        
        // Generate random G2 point
        let point = BLS12381Ops::random_g2(&mut rng).unwrap();
        assert_eq!(point.len(), 96); // Compressed G2 size
        
        // Test scalar multiplication
        let scalar = BLS12381Ops::random_scalar(&mut rng);
        let multiplied = BLS12381Ops::g2_multiply(&point, scalar).unwrap();
        assert_eq!(multiplied.len(), 96);
        
        // Test point addition
        let point2 = BLS12381Ops::random_g2(&mut rng).unwrap();
        let added = BLS12381Ops::g2_add(&point, &point2).unwrap();
        assert_eq!(added.len(), 96);
    }

    #[test]
    fn test_pairing_operations() {
        let mut rng = test_rng();
        
        // Generate random points
        let g1_point = BLS12381Ops::random_g1(&mut rng).unwrap();
        let g2_point = BLS12381Ops::random_g2(&mut rng).unwrap();
        
        // Test pairing
        let pairing = BLS12381Ops::compute_pairing(&g1_point, &g2_point).unwrap();
        assert!(!pairing.is_one()); // Should not be identity
        
        // Test GT operations
        let scalar = BLS12381Ops::random_scalar(&mut rng);
        let multiplied = BLS12381Ops::gt_multiply(&pairing, scalar);
        let _product = BLS12381Ops::gt_product(&pairing, &multiplied);
        let _inverse = BLS12381Ops::gt_inverse(&pairing);
        
        // Test serialization
        let serialized = BLS12381Ops::serialize_gt(&pairing);
        assert_eq!(serialized.len(), 576); // Canonical GT size
    }

    #[test]
    fn test_multi_pairing() {
        let mut rng = test_rng();
        
        // Generate multiple points
        let g1_points = vec![
            BLS12381Ops::random_g1(&mut rng).unwrap(),
            BLS12381Ops::random_g1(&mut rng).unwrap(),
        ];
        let g2_points = vec![
            BLS12381Ops::random_g2(&mut rng).unwrap(),
            BLS12381Ops::random_g2(&mut rng).unwrap(),
        ];
        
        // Test multi-pairing
        let result = BLS12381Ops::multi_pairing(&g1_points, &g2_points).unwrap();
        assert!(!result.is_one());
        
        // Test error case
        let bad_g2_points = vec![BLS12381Ops::random_g2(&mut rng).unwrap()];
        let error_result = BLS12381Ops::multi_pairing(&g1_points, &bad_g2_points);
        assert!(error_result.is_err());
    }

    /// Test BLS12-381 operations edge cases
    #[test]
    fn test_bls12381_edge_cases() {
        let mut rng = test_rng();
        
        // Test zero scalar
        let zero_scalar = Fr::zero();
        let g1_point = BLS12381Ops::random_g1(&mut rng).unwrap();
        let result = BLS12381Ops::g1_multiply(&g1_point, zero_scalar);
        assert!(result.is_ok());
        
        // Test one scalar
        let one_scalar = Fr::one();
        let result = BLS12381Ops::g1_multiply(&g1_point, one_scalar);
        assert!(result.is_ok());
        
        // Test identity GT
        let identity = BLS12381Ops::identity_gt();
        assert!(BLS12381Ops::is_identity_gt(&identity));
        
        // Test GT serialization
        let serialized = BLS12381Ops::serialize_gt(&identity);
        assert_eq!(serialized.len(), 576);
    }

    /// Test hash to scalar functionality
    #[test]
    fn test_hash_to_scalar() {
        let data1 = b"test_data_1";
        let data2 = b"test_data_2";
        
        let scalar1 = BLS12381Ops::hash_to_scalar(data1);
        let scalar2 = BLS12381Ops::hash_to_scalar(data2);
        
        // Different inputs should produce different scalars
        assert_ne!(scalar1, scalar2);
        
        // Same input should produce same scalar
        let scalar1_again = BLS12381Ops::hash_to_scalar(data1);
        assert_eq!(scalar1, scalar1_again);
        
        // Scalars should be non-zero
        assert!(!scalar1.is_zero());
        assert!(!scalar2.is_zero());
    }
}
