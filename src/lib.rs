pub mod gs_kem_helpers;
mod bls12381_ops;
pub mod kem;
pub mod schnorr;
pub mod groth16_wrapper;
pub mod gs_commitments;
pub mod gs_kem_eval;

// Re-export for external use
pub use groth16_wrapper::{ArkworksProof, ArkworksVK, ArkworksGroth16};
pub use gs_commitments::{GrothSahaiCommitments, GSAttestation};
pub use schnorr::{SchnorrAdaptor, AdaptorSignature};
pub use kem::{ProductKeyKEM, KEMShare};
pub use gs_kem_helpers::{serialize_attestation_for_kem, serialize_crs_for_kem};
pub use gs_kem_eval::{
    masked_verifier_matrix_canonical,
    rhs_masked_matrix,
    kdf_from_comt,
};
