//! Helper functions for GS KEM operations

use ark_bls12_381::{Bls12_381, Fr};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField, One, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;

use groth_sahai::data_structures::{Com1, Com2, ComT, vec_to_col_vec, col_vec_to_vec, BT, Mat};

use crate::groth16_wrapper::ArkworksVK;

/// Scale a vector of Com1/Com2 (CRS-side) by rho (used only for CRS constants and primaries).
fn scale_com1<E: Pairing>(v: &[Com1<E>], rho: E::ScalarField) -> Vec<Com1<E>> {
    v.iter().map(|c| {
        Com1::<E>(
            (c.0.into_group() * rho).into_affine(),
            (c.1.into_group() * rho).into_affine(),
        )
    }).collect()
}

fn scale_com2<E: Pairing>(v: &[Com2<E>], rho: E::ScalarField) -> Vec<Com2<E>> {
    v.iter().map(|d| {
        Com2::<E>(
            (d.0.into_group() * rho).into_affine(),
            (d.1.into_group() * rho).into_affine(),
        )
    }).collect()
}

/// Scale G1/G2 pairs by rho
fn scale_g1_pairs<E: Pairing>(pairs: &[(E::G1Affine, E::G1Affine)], rho: E::ScalarField) -> Vec<(E::G1Affine, E::G1Affine)> {
    pairs.iter().map(|(a, b)| {
        ((a.into_group() * rho).into_affine(), (b.into_group() * rho).into_affine())
    }).collect()
}

fn scale_g2_pairs<E: Pairing>(pairs: &[(E::G2Affine, E::G2Affine)], rho: E::ScalarField) -> Vec<(E::G2Affine, E::G2Affine)> {
    pairs.iter().map(|(a, b)| {
        ((a.into_group() * rho).into_affine(), (b.into_group() * rho).into_affine())
    }).collect()
}

/// Compute the five-bucket anchor using unmasked CRS elements and scalar ρ
pub fn compute_five_bucket_anchor(
    c1_bytes_list: &[Vec<u8>],
    c2_bytes_list: &[Vec<u8>],
    pi_bytes_list: &[Vec<u8>],
    theta_bytes_list: &[Vec<u8>],
    u_bytes_list: &[Vec<u8>],
    v_bytes_list: &[Vec<u8>],
    u_dual_bytes_list: &[Vec<u8>],
    v_dual_bytes_list: &[Vec<u8>],
    rho: Fr,
) -> Result<ComT<Bls12_381>, String> {
    let c1 = deserialize_com1_list(c1_bytes_list, "C1")?;
    let c2 = deserialize_com2_list(c2_bytes_list, "C2")?;
    let pi = deserialize_com2_list(pi_bytes_list, "pi")?;
    let theta = deserialize_com1_list(theta_bytes_list, "theta")?;
    let u = deserialize_com1_list(u_bytes_list, "U")?;
    let v = deserialize_com2_list(v_bytes_list, "V")?;
    let u_dual = deserialize_g2_pairs(u_dual_bytes_list)?;
    let v_dual = deserialize_g1_pairs(v_dual_bytes_list)?;

    let u_rho = scale_com1_list(&u, rho);
    let v_rho = scale_com2_list(&v, rho);
    let u_dual_rho = scale_g2_pairs::<Bls12_381>(&u_dual, rho);
    let v_dual_rho = scale_g1_pairs::<Bls12_381>(&v_dual, rho);

    compute_five_bucket_from_components(
        &c1,
        &c2,
        &pi,
        &theta,
        &u_rho,
        &v_rho,
        &u_dual_rho,
        &v_dual_rho,
    )
}

/// Compute the five-bucket anchor using already-masked CRS and dual elements
pub fn compute_five_bucket_anchor_with_masks(
    c1_bytes_list: &[Vec<u8>],
    c2_bytes_list: &[Vec<u8>],
    pi_bytes_list: &[Vec<u8>],
    theta_bytes_list: &[Vec<u8>],
    u_masked_bytes_list: &[Vec<u8>],
    v_masked_bytes_list: &[Vec<u8>],
    u_dual_masked_bytes_list: &[Vec<u8>],
    v_dual_masked_bytes_list: &[Vec<u8>],
) -> Result<ComT<Bls12_381>, String> {
    let c1 = deserialize_com1_list(c1_bytes_list, "C1")?;
    let c2 = deserialize_com2_list(c2_bytes_list, "C2")?;
    let pi = deserialize_com2_list(pi_bytes_list, "pi")?;
    let theta = deserialize_com1_list(theta_bytes_list, "theta")?;
    let u_masked = deserialize_com1_list(u_masked_bytes_list, "U^ρ")?;
    let v_masked = deserialize_com2_list(v_masked_bytes_list, "V^ρ")?;
    let u_dual_masked = deserialize_g2_pairs(u_dual_masked_bytes_list)?;
    let v_dual_masked = deserialize_g1_pairs(v_dual_masked_bytes_list)?;

    compute_five_bucket_from_components(
        &c1,
        &c2,
        &pi,
        &theta,
        &u_masked,
        &v_masked,
        &u_dual_masked,
        &v_dual_masked,
    )
}

fn compute_five_bucket_from_components(
    c1: &[Com1<Bls12_381>],
    c2: &[Com2<Bls12_381>],
    pi: &[Com2<Bls12_381>],
    theta: &[Com1<Bls12_381>],
    u_rho: &[Com1<Bls12_381>],
    v_rho: &[Com2<Bls12_381>],
    u_dual_rho: &[(ark_bls12_381::G2Affine, ark_bls12_381::G2Affine)],
    v_dual_rho: &[(ark_bls12_381::G1Affine, ark_bls12_381::G1Affine)],
) -> Result<ComT<Bls12_381>, String> {
    // Convert dual pairs to Com1/Com2 format for pairing
    let ustar_com2: Vec<Com2<Bls12_381>> = u_dual_rho.iter().map(|(a, b)| Com2(*a, *b)).collect();
    let vstar_com1: Vec<Com1<Bls12_381>> = v_dual_rho.iter().map(|(a, b)| Com1(*a, *b)).collect();

    // Five-bucket formula: (B1 + B2 + G) - B3 - B4
    let b1 = ComT::<Bls12_381>::pairing_sum(c1, &ustar_com2);  // e(C1, U*^ρ)
    let b2 = ComT::<Bls12_381>::pairing_sum(&vstar_com1, c2);  // e(V*^ρ, C2)
    let b3 = ComT::<Bls12_381>::pairing_sum(u_rho, pi);           // e(U^ρ, π)
    let b4 = ComT::<Bls12_381>::pairing_sum(theta, v_rho);       // e(θ, V^ρ)
    
    // G term: e(C1, γ·C2) - need PPE gamma matrix
    // For now, use identity matrix as placeholder
    let gamma: Vec<Vec<Fr>> = (0..c2.len()).map(|i| {
        (0..c2.len()).map(|j| if i == j { Fr::one() } else { Fr::zero() }).collect()
    }).collect();
    let gy = vec_to_col_vec(c2).left_mul(&gamma, false);
    let g = ComT::<Bls12_381>::pairing_sum(c1, &col_vec_to_vec(&gy));

    Ok((b1 + b2 + g) - b3 - b4)
}

/// Deserialize Com1 list from bytes
fn deserialize_com1_list(bytes_list: &[Vec<u8>], name: &str) -> Result<Vec<Com1<Bls12_381>>, String> {
    bytes_list.iter().enumerate().map(|(i, bytes)| {
        Com1::<Bls12_381>::deserialize_compressed(&**bytes)
            .map_err(|e| format!("{}[{}] deserialize: {:?}", name, i, e))
    }).collect()
}

/// Deserialize Com2 list from bytes
fn deserialize_com2_list(bytes_list: &[Vec<u8>], name: &str) -> Result<Vec<Com2<Bls12_381>>, String> {
    bytes_list.iter().enumerate().map(|(i, bytes)| {
        Com2::<Bls12_381>::deserialize_compressed(&**bytes)
            .map_err(|e| format!("{}[{}] deserialize: {:?}", name, i, e))
    }).collect()
}

/// Scale Com1 list by scalar
fn scale_com1_list(coms: &[Com1<Bls12_381>], rho: Fr) -> Vec<Com1<Bls12_381>> {
    scale_com1(coms, rho)
}

/// Scale Com2 list by scalar
fn scale_com2_list(coms: &[Com2<Bls12_381>], rho: Fr) -> Vec<Com2<Bls12_381>> {
    scale_com2(coms, rho)
}

/// Convert Fr scalar from big-endian bytes
pub fn fr_from_be(bytes: &[u8]) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}

/// Compute target public value from VK and public inputs
pub fn compute_target_public(vk: &ArkworksVK, public_input_bytes: &[u8]) -> Result<ark_ec::pairing::PairingOutput<Bls12_381>, String> {
    use crate::gs_commitments::compute_ic_from_vk_and_inputs;
    
    // Parse public input
    let public_input = Fr::from_be_bytes_mod_order(public_input_bytes);
    
    // Compute IC from VK and public input
    let ic = compute_ic_from_vk_and_inputs(vk, &[public_input]);
    
    // Compute target pairing: e(IC, γ_g2) * e(α_g1, β_g2)
    let e_ic_gamma = Bls12_381::pairing(ic, vk.gamma_g2);
    let e_alpha_beta = Bls12_381::pairing(vk.alpha_g1, vk.beta_g2);
    
    Ok(PairingOutput(e_ic_gamma.0 * e_alpha_beta.0))
}

/// Serialize entire ComT matrix into bytes (row-major, compressed GT cells)
pub fn serialize_comt(comt: &ComT<Bls12_381>) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    let matrix = comt.as_matrix();
    for row in &matrix {
        for cell in row {
            cell.0
                .serialize_compressed(&mut bytes)
                .map_err(|e| format!("ComT cell serialize: {:?}", e))?;
        }
    }
    Ok(bytes)
}

/// Build AAD for rho encryption
pub fn build_ad_rho(
    share_index: u32,
    ctx_hash: &[u8],
    deposit_id: &[u8],
    crs_digest: &[u8],
    ppe_digest: &[u8],
    vk_hash: &[u8],
    x_hash: &[u8],
    d1_masks: &[Vec<u8>],
    d2_masks: &[Vec<u8>],
    d1_star_masks: &[Vec<u8>],
    d2_star_masks: &[Vec<u8>],
) -> Vec<u8> {
    let mut ad = Vec::new();
    ad.extend_from_slice(&share_index.to_be_bytes());
    ad.extend_from_slice(ctx_hash);
    ad.extend_from_slice(deposit_id);
    ad.extend_from_slice(crs_digest);
    ad.extend_from_slice(ppe_digest);
    ad.extend_from_slice(vk_hash);
    ad.extend_from_slice(x_hash);
    
    // Add all masked arrays
    for mask in d1_masks {
        ad.extend_from_slice(mask);
    }
    for mask in d2_masks {
        ad.extend_from_slice(mask);
    }
    for mask in d1_star_masks {
        ad.extend_from_slice(mask);
    }
    for mask in d2_star_masks {
        ad.extend_from_slice(mask);
    }
    
    ad
}

/// Build AAD for adaptor share encryption
pub fn build_ad_share(
    share_index: u32,
    ctx_hash: &[u8],
    deposit_id: &[u8],
    t_i: &[u8],
    d1_masks: &[Vec<u8>],
    d2_masks: &[Vec<u8>],
    d1_star_masks: &[Vec<u8>],
    d2_star_masks: &[Vec<u8>],
    crs_digest: &[u8],
    ppe_digest: &[u8],
    vk_hash: &[u8],
    x_hash: &[u8],
) -> Vec<u8> {
    let mut ad = Vec::new();
    ad.extend_from_slice(&share_index.to_be_bytes());
    ad.extend_from_slice(ctx_hash);
    ad.extend_from_slice(deposit_id);
    ad.extend_from_slice(t_i);
    ad.extend_from_slice(crs_digest);
    ad.extend_from_slice(ppe_digest);
    ad.extend_from_slice(vk_hash);
    ad.extend_from_slice(x_hash);
    
    // Add all masked arrays
    for mask in d1_masks {
        ad.extend_from_slice(mask);
    }
    for mask in d2_masks {
        ad.extend_from_slice(mask);
    }
    for mask in d1_star_masks {
        ad.extend_from_slice(mask);
    }
    for mask in d2_star_masks {
        ad.extend_from_slice(mask);
    }
    
    ad
}

/// Deserialize Com1 pairs from bytes
pub fn deserialize_com1_pairs(pairs: &[Vec<u8>]) -> Result<Vec<Com1<Bls12_381>>, String> {
    pairs.iter().map(|bytes| {
        Com1::<Bls12_381>::deserialize_compressed(&**bytes)
            .map_err(|e| format!("Com1 deserialize: {:?}", e))
    }).collect()
}

/// Deserialize Com2 pairs from bytes
pub fn deserialize_com2_pairs(pairs: &[Vec<u8>]) -> Result<Vec<Com2<Bls12_381>>, String> {
    pairs.iter().map(|bytes| {
        Com2::<Bls12_381>::deserialize_compressed(&**bytes)
            .map_err(|e| format!("Com2 deserialize: {:?}", e))
    }).collect()
}

/// Deserialize G1 pairs from bytes
pub fn deserialize_g1_pairs(pairs: &[Vec<u8>]) -> Result<Vec<(ark_bls12_381::G1Affine, ark_bls12_381::G1Affine)>, String> {
    pairs.iter().map(|bytes| {
        if bytes.len() != 96 {
            return Err(format!("G1 pair must be 96 bytes, got {}", bytes.len()));
        }
        let a = ark_bls12_381::G1Affine::deserialize_compressed(&bytes[..48])
            .map_err(|e| format!("G1 deserialize a: {:?}", e))?;
        let b = ark_bls12_381::G1Affine::deserialize_compressed(&bytes[48..])
            .map_err(|e| format!("G1 deserialize b: {:?}", e))?;
        Ok((a, b))
    }).collect()
}

/// Deserialize G2 pairs from bytes
pub fn deserialize_g2_pairs(pairs: &[Vec<u8>]) -> Result<Vec<(ark_bls12_381::G2Affine, ark_bls12_381::G2Affine)>, String> {
    pairs.iter().map(|bytes| {
        if bytes.len() != 192 {
            return Err(format!("G2 pair must be 192 bytes, got {}", bytes.len()));
        }
        let a = ark_bls12_381::G2Affine::deserialize_compressed(&bytes[..96])
            .map_err(|e| format!("G2 deserialize a: {:?}", e))?;
        let b = ark_bls12_381::G2Affine::deserialize_compressed(&bytes[96..])
            .map_err(|e| format!("G2 deserialize b: {:?}", e))?;
        Ok((a, b))
    }).collect()
}

/// Serialize CRS elements for KEM operations
pub fn serialize_crs_for_kem(
    crs: &groth_sahai::generator::CRS<Bls12_381>,
    u_duals: &[Com2<Bls12_381>],
    v_duals: &[Com1<Bls12_381>],
) -> (Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>) {
    // Serialize CRS U elements (G1 pairs)
    let u_bases: Vec<Vec<u8>> = crs.u.iter().map(|com1| {
        let mut bytes = Vec::new();
        com1.0.serialize_compressed(&mut bytes).unwrap();
        com1.1.serialize_compressed(&mut bytes).unwrap();
        bytes
    }).collect();

    // Serialize CRS V elements (G2 pairs)
    let v_bases: Vec<Vec<u8>> = crs.v.iter().map(|com2| {
        let mut bytes = Vec::new();
        com2.0.serialize_compressed(&mut bytes).unwrap();
        com2.1.serialize_compressed(&mut bytes).unwrap();
        bytes
    }).collect();

    // Serialize U duals (G2 pairs)
    let u_dual_bases: Vec<Vec<u8>> = u_duals.iter().map(|com2| {
        let mut bytes = Vec::new();
        com2.0.serialize_compressed(&mut bytes).unwrap();
        com2.1.serialize_compressed(&mut bytes).unwrap();
        bytes
    }).collect();

    // Serialize V duals (G1 pairs)
    let v_dual_bases: Vec<Vec<u8>> = v_duals.iter().map(|com1| {
        let mut bytes = Vec::new();
        com1.0.serialize_compressed(&mut bytes).unwrap();
        com1.1.serialize_compressed(&mut bytes).unwrap();
        bytes
    }).collect();

    (u_bases, v_bases, u_dual_bases, v_dual_bases)
}

/// Serialize attestation for KEM operations
pub fn serialize_attestation_for_kem(
    attestation: &crate::gs_commitments::GSAttestation,
) -> (Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>) {
    // Serialize C1 commitments (G1 pairs)
    let c1_bytes: Vec<Vec<u8>> = attestation.c1_commitments.iter().map(|com1| {
        let mut bytes = Vec::new();
        com1.0.serialize_compressed(&mut bytes).unwrap();
        com1.1.serialize_compressed(&mut bytes).unwrap();
        bytes
    }).collect();

    // Serialize C2 commitments (G2 pairs)
    let c2_bytes: Vec<Vec<u8>> = attestation.c2_commitments.iter().map(|com2| {
        let mut bytes = Vec::new();
        com2.0.serialize_compressed(&mut bytes).unwrap();
        com2.1.serialize_compressed(&mut bytes).unwrap();
        bytes
    }).collect();

    // Serialize π proof elements (G2 pairs)
    let pi_bytes: Vec<Vec<u8>> = attestation.pi_elements.iter().map(|com2| {
        let mut bytes = Vec::new();
        com2.0.serialize_compressed(&mut bytes).unwrap();
        com2.1.serialize_compressed(&mut bytes).unwrap();
        bytes
    }).collect();

    // Serialize θ proof elements (G1 pairs)
    let theta_bytes: Vec<Vec<u8>> = attestation.theta_elements.iter().map(|com1| {
        let mut bytes = Vec::new();
        com1.0.serialize_compressed(&mut bytes).unwrap();
        com1.1.serialize_compressed(&mut bytes).unwrap();
        bytes
    }).collect();

    (c1_bytes, c2_bytes, pi_bytes, theta_bytes)
}