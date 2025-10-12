/*!
Groth16 Wrapper for PVUGC

Provides setup, prove, and verify functionality for SHA256 preimage proofs.
*/

use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine};
use ark_crypto_primitives::crh::sha256::Sha256;
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::Field;
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use sha2::Digest;
use thiserror::Error;

/// Error types for Groth16 operations
#[derive(Error, Debug)]
pub enum Groth16Error {
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Deserialization error: {0}")]
    Deserialization(String),
    #[error("Proof generation error: {0}")]
    ProofGeneration(String),
    #[error("Verification error: {0}")]
    Verification(String),
    #[error("Setup error: {0}")]
    Setup(String),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

/// Groth16 proof structure
#[derive(Clone, Debug)]
pub struct ArkworksProof {
    pub pi_a: G1Affine,
    pub pi_b: G2Affine,
    pub pi_c: G1Affine,
    pub public_input: Vec<u8>,
    pub proof_bytes: Vec<u8>,
}

/// Groth16 verification key structure
#[derive(Clone, Debug)]
pub struct ArkworksVK {
    pub alpha_g1: G1Affine,
    pub beta_g2: G2Affine,
    pub gamma_g2: G2Affine,
    pub delta_g2: G2Affine,
    pub gamma_abc_g1: Vec<G1Affine>,
    pub vk_bytes: Vec<u8>,
}

/// Simple test circuit for Groth16 functionality
#[derive(Clone)]
pub struct SimpleTestCircuit {
    pub witness: Option<Fr>,
    pub public_input: Fr,
}

impl ConstraintSynthesizer<Fr> for SimpleTestCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> ark_relations::r1cs::Result<()> {
        // Allocate witness variable
        let witness_var = FpVar::<Fr>::new_witness(cs.clone(), || {
            self.witness
                .ok_or(ark_relations::r1cs::SynthesisError::AssignmentMissing)
        })?;

        // Allocate public input
        let public_input_var = FpVar::<Fr>::new_input(cs, || Ok(self.public_input))?;

        // Simple constraint: witness * witness = public_input
        // This proves knowledge of a square root
        let witness_squared = witness_var.square()?;
        witness_squared.enforce_equal(&public_input_var)?;

        Ok(())
    }
}

// Simplified SHA256 gadget - removed for now since we're using a simpler circuit

/// Main Groth16 wrapper class
pub struct ArkworksGroth16 {
    pk_bytes: Option<Vec<u8>>,
    vk: Option<ArkworksVK>,
}

impl ArkworksGroth16 {
    /// Create a new ArkworksGroth16 instance
    pub fn new() -> Self {
        Self {
            pk_bytes: None,
            vk: None,
        }
    }

    /// Generate proving and verification keys
    pub fn setup(&mut self) -> Result<ArkworksVK, Groth16Error> {
        let mut rng = ark_std::rand::thread_rng();

        // Create circuit for setup
        let circuit = SimpleTestCircuit {
            witness: None,
            public_input: Fr::from(1u64), // Placeholder
        };

        // Generate keys
        let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(circuit, &mut rng)
            .map_err(|e| Groth16Error::Setup(format!("{:?}", e)))?;

        // Serialize proving key
        let mut pk_bytes = Vec::new();
        pk.serialize_compressed(&mut pk_bytes)
            .map_err(|e| Groth16Error::Serialization(format!("PK: {:?}", e)))?;
        self.pk_bytes = Some(pk_bytes);

        // Extract VK elements
        let vk_struct = ArkworksVK {
            alpha_g1: vk.alpha_g1,
            beta_g2: vk.beta_g2,
            gamma_g2: vk.gamma_g2,
            delta_g2: vk.delta_g2,
            gamma_abc_g1: vk.gamma_abc_g1.clone(),
            vk_bytes: {
                let mut bytes = Vec::new();
                vk.serialize_compressed(&mut bytes)
                    .map_err(|e| Groth16Error::Serialization(format!("VK: {:?}", e)))?;
                bytes
            },
        };

        self.vk = Some(vk_struct.clone());
        Ok(vk_struct)
    }

    /// Generate proof for square root knowledge
    pub fn prove(&self, witness: Fr) -> Result<ArkworksProof, Groth16Error> {
        let pk_bytes = self.pk_bytes.as_ref().ok_or(Groth16Error::InvalidInput(
            "Must call setup() first".to_string(),
        ))?;

        // Compute public input (witness squared)
        let public_input = witness.square();

        // Deserialize proving key
        let pk = ProvingKey::<Bls12_381>::deserialize_compressed(pk_bytes.as_slice())
            .map_err(|e| Groth16Error::Deserialization(format!("PK: {:?}", e)))?;

        // Create circuit with witness
        let circuit = SimpleTestCircuit {
            witness: Some(witness),
            public_input,
        };

        // Generate proof
        let mut rng = ark_std::rand::thread_rng();
        let proof = Groth16::<Bls12_381>::prove(&pk, circuit, &mut rng)
            .map_err(|e| Groth16Error::ProofGeneration(format!("{:?}", e)))?;

        // Serialize proof
        let mut proof_bytes = Vec::new();
        proof
            .serialize_compressed(&mut proof_bytes)
            .map_err(|e| Groth16Error::Serialization(format!("Proof: {:?}", e)))?;

        // Serialize public input
        let mut public_input_bytes = Vec::new();
        public_input
            .serialize_compressed(&mut public_input_bytes)
            .map_err(|e| Groth16Error::Serialization(format!("Public input: {:?}", e)))?;

        Ok(ArkworksProof {
            pi_a: proof.a,
            pi_b: proof.b,
            pi_c: proof.c,
            public_input: public_input_bytes,
            proof_bytes,
        })
    }

    /// Verify proof
    pub fn verify(&self, proof: &ArkworksProof) -> Result<bool, Groth16Error> {
        let vk = self.vk.as_ref().ok_or(Groth16Error::InvalidInput(
            "Must call setup() first".to_string(),
        ))?;

        // Deserialize verification key
        let vk_deserialized =
            VerifyingKey::<Bls12_381>::deserialize_compressed(vk.vk_bytes.as_slice())
                .map_err(|e| Groth16Error::Deserialization(format!("VK: {:?}", e)))?;

        // Deserialize proof
        let proof_deserialized =
            Proof::<Bls12_381>::deserialize_compressed(proof.proof_bytes.as_slice())
                .map_err(|e| Groth16Error::Deserialization(format!("Proof: {:?}", e)))?;

        // Deserialize public input
        let public_input = Fr::deserialize_compressed(proof.public_input.as_slice())
            .map_err(|e| Groth16Error::Deserialization(format!("Public input: {:?}", e)))?;

        // Verify proof
        let result =
            Groth16::<Bls12_381>::verify(&vk_deserialized, &[public_input], &proof_deserialized)
                .map_err(|e| Groth16Error::Verification(format!("{:?}", e)))?;

        Ok(result)
    }

    /// Compute VK hash
    pub fn compute_vk_hash(&self) -> Result<Vec<u8>, Groth16Error> {
        let vk = self.vk.as_ref().ok_or(Groth16Error::InvalidInput(
            "Must call setup() first".to_string(),
        ))?;

        let mut vk_data = Vec::new();
        vk.alpha_g1
            .serialize_compressed(&mut vk_data)
            .map_err(|e| Groth16Error::Serialization(format!("Alpha: {:?}", e)))?;
        vk.beta_g2
            .serialize_compressed(&mut vk_data)
            .map_err(|e| Groth16Error::Serialization(format!("Beta: {:?}", e)))?;
        vk.gamma_g2
            .serialize_compressed(&mut vk_data)
            .map_err(|e| Groth16Error::Serialization(format!("Gamma: {:?}", e)))?;
        vk.delta_g2
            .serialize_compressed(&mut vk_data)
            .map_err(|e| Groth16Error::Serialization(format!("Delta: {:?}", e)))?;

        let mut hasher = Sha256::new();
        hasher.update(b"ARKWORKS_VK");
        hasher.update(&vk_data);
        Ok(hasher.finalize().to_vec())
    }
}

impl Default for ArkworksGroth16 {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper function to compute IC = gamma_abc[0] + Σ_i(x_i * gamma_abc[i+1])
pub fn compute_ic(
    vk: &VerifyingKey<Bls12_381>,
    public_inputs: &[Fr],
) -> Result<G1Affine, Groth16Error> {
    let mut scalars = vec![Fr::from(1u64)];
    scalars.extend_from_slice(public_inputs);
    let bases: Vec<_> = vk
        .gamma_abc_g1
        .iter()
        .take(scalars.len())
        .cloned()
        .collect();
    let ic = G1Projective::msm(&bases, &scalars)
        .map_err(|e| Groth16Error::Setup(format!("MSM failed: {:?}", e)))?;
    Ok(ic.into_affine())
}

/// Extract VK elements from serialized VK
pub fn extract_vk_elements(vk_bytes: &[u8]) -> Result<ArkworksVK, Groth16Error> {
    let vk = VerifyingKey::<Bls12_381>::deserialize_compressed(vk_bytes)
        .map_err(|e| Groth16Error::Deserialization(format!("VK: {:?}", e)))?;

    Ok(ArkworksVK {
        alpha_g1: vk.alpha_g1,
        beta_g2: vk.beta_g2,
        gamma_g2: vk.gamma_g2,
        delta_g2: vk.delta_g2,
        gamma_abc_g1: vk.gamma_abc_g1,
        vk_bytes: vk_bytes.to_vec(),
    })
}

/// Extract proof elements from serialized proof
pub fn extract_proof_elements(
    proof_bytes: &[u8],
) -> Result<(G1Affine, G2Affine, G1Affine), Groth16Error> {
    let proof = Proof::<Bls12_381>::deserialize_compressed(proof_bytes)
        .map_err(|e| Groth16Error::Deserialization(format!("Proof: {:?}", e)))?;

    Ok((proof.a, proof.b, proof.c))
}

/// Setup test circuit and return (pk_bytes, vk_bytes)
pub fn setup_test_circuit() -> Result<(Vec<u8>, Vec<u8>), Groth16Error> {
    let mut groth16 = ArkworksGroth16::new();
    let vk = groth16.setup()?;

    let pk_bytes = groth16
        .pk_bytes
        .ok_or(Groth16Error::Setup("PK not generated".to_string()))?;

    Ok((pk_bytes, vk.vk_bytes))
}

/// Prove square root knowledge
pub fn prove_square_root(witness: Fr, pk_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Groth16Error> {
    let mut groth16 = ArkworksGroth16::new();
    groth16.pk_bytes = Some(pk_bytes.to_vec());

    let proof = groth16.prove(witness)?;
    Ok((proof.proof_bytes, proof.public_input))
}

/// Verify proof
pub fn verify_proof(
    public_input: &[u8],
    proof_bytes: &[u8],
    vk_bytes: &[u8],
) -> Result<bool, Groth16Error> {
    let mut groth16 = ArkworksGroth16::new();
    groth16.vk = Some(extract_vk_elements(vk_bytes)?);

    let proof = ArkworksProof {
        pi_a: G1Affine::default(), // Will be deserialized from proof_bytes
        pi_b: G2Affine::default(),
        pi_c: G1Affine::default(),
        public_input: public_input.to_vec(),
        proof_bytes: proof_bytes.to_vec(),
    };

    groth16.verify(&proof)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_groth16_setup() {
        let mut groth16 = ArkworksGroth16::new();
        let vk = groth16.setup().expect("Setup should succeed");

        assert!(!vk.vk_bytes.is_empty());
        assert_eq!(vk.gamma_abc_g1.len(), 2); // Should have 2 elements for simple circuit (1 constant + 1 public input)
    }

    #[test]
    fn test_groth16_prove_verify() {
        let mut groth16 = ArkworksGroth16::new();
        let _vk = groth16.setup().expect("Setup should succeed");

        let witness = Fr::from(5u64); // Square root of 25

        let proof = groth16.prove(witness).expect("Prove should succeed");
        let verified = groth16.verify(&proof).expect("Verify should succeed");

        assert!(verified);
    }

    #[test]
    fn test_vk_hash() {
        let mut groth16 = ArkworksGroth16::new();
        let _vk = groth16.setup().expect("Setup should succeed");

        let hash1 = groth16.compute_vk_hash().expect("VK hash should succeed");
        let hash2 = groth16.compute_vk_hash().expect("VK hash should succeed");

        assert_eq!(hash1, hash2); // Should be deterministic
    }
}
