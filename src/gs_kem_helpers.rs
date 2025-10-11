use ark_bls12_381::{Bls12_381, Fr, Fq12};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_ec::pairing::PairingOutput;
use ark_ec::AffineRepr;

/// Compute canonical masked evaluation for KEM
/// Uses the canonical masked verifier approach that evaluates target^ρ
pub fn compute_canonical_masked_eval(
    c1_bytes_list: &[Vec<u8>],  // C1 commitments
    c2_bytes_list: &[Vec<u8>],  // C2 commitments
    pi_bytes_list: &[Vec<u8>],  // π proof elements
    theta_bytes_list: &[Vec<u8>],  // θ proof elements  
    u_bytes_list: &[Vec<u8>],   // CRS U elements
    v_bytes_list: &[Vec<u8>],   // CRS V elements
    rho: Fr,                     // Masking scalar
) -> Result<Vec<u8>, String> {
    use groth_sahai::data_structures::{Com1, Com2};
    
    // Deserialize commitments
    let mut c1_coms = Vec::new();
    for bytes in c1_bytes_list {
        let com = Com1::<Bls12_381>::deserialize_compressed(bytes.as_slice())
            .map_err(|e| format!("C1 deser: {:?}", e))?;
        c1_coms.push(com);
    }
    
    let mut c2_coms = Vec::new();
    for bytes in c2_bytes_list {
        let com = Com2::<Bls12_381>::deserialize_compressed(bytes.as_slice())
            .map_err(|e| format!("C2 deser: {:?}", e))?;
        c2_coms.push(com);
    }
    
    // Deserialize proof elements
    let mut pi = Vec::new();
    for bytes in pi_bytes_list {
        let com = Com2::<Bls12_381>::deserialize_compressed(bytes.as_slice())
            .map_err(|e| format!("π deser: {:?}", e))?;
        pi.push(com);
    }
    
    let mut theta = Vec::new();
    for bytes in theta_bytes_list {
        let com = Com1::<Bls12_381>::deserialize_compressed(bytes.as_slice())
            .map_err(|e| format!("θ deser: {:?}", e))?;
        theta.push(com);
    }
    
    // Deserialize CRS elements
    let mut u = Vec::new();
    for bytes in u_bytes_list {
        let com = Com1::<Bls12_381>::deserialize_compressed(bytes.as_slice())
            .map_err(|e| format!("U deser: {:?}", e))?;
        u.push(com);
    }
    
    let mut v = Vec::new();
    for bytes in v_bytes_list {
        let com = Com2::<Bls12_381>::deserialize_compressed(bytes.as_slice())
            .map_err(|e| format!("V deser: {:?}", e))?;
        v.push(com);
    }
    
    // For consistency with decapsulation, compute a simplified evaluation
    // Mask the CRS elements
    use ark_ec::CurveGroup;
    use groth_sahai::data_structures::{ComT, BT};
    use ark_ec::pairing::Pairing;
    use ark_ff::One;
    
    let u_masked: Vec<Com1<Bls12_381>> = u.iter().map(|ui| Com1::<Bls12_381>(
        (ui.0.into_group() * rho).into_affine(),
        (ui.1.into_group() * rho).into_affine(),
    )).collect();
    
    let v_masked: Vec<Com2<Bls12_381>> = v.iter().map(|vi| Com2::<Bls12_381>(
        (vi.0.into_group() * rho).into_affine(),
        (vi.1.into_group() * rho).into_affine(),
    )).collect();
    
    // Compute e(U^ρ, π) and e(θ, V^ρ)
    let u_pi_masked = ComT::<Bls12_381>::pairing_sum(&u_masked, &pi);
    let theta_v_masked = ComT::<Bls12_381>::pairing_sum(&theta, &v_masked);
    
    // Compute the commitment product (diagonal gamma)
    let mut gt_product = Fq12::one();
    for i in 0..c1_coms.len().min(c2_coms.len()) {
        let PairingOutput(p0) = Bls12_381::pairing(c1_coms[i].0, c2_coms[i].0);
        let PairingOutput(p1) = Bls12_381::pairing(c1_coms[i].1, c2_coms[i].1);
        gt_product *= p0 * p1;
    }
    
    // Combine: commitment_product * u_pi * theta_v
    let u_pi_mat = u_pi_masked.as_matrix();
    let theta_v_mat = theta_v_masked.as_matrix();
    
    // For KEM, we use the diagonal elements
    let final_gt = gt_product * u_pi_mat[0][0].0 * u_pi_mat[1][1].0 
                             * theta_v_mat[0][0].0 * theta_v_mat[1][1].0;
    
    let mut result_bytes = Vec::new();
    final_gt.serialize_compressed(&mut result_bytes)
        .map_err(|e| format!("Serialize GT: {:?}", e))?;
    
    Ok(result_bytes)
}

/// Compute canonical masked evaluation with already-masked CRS elements
/// Used during decapsulation where masked U^ρ and V^ρ are published
pub fn compute_canonical_masked_eval_with_masked_crs(
    c1_bytes_list: &[Vec<u8>],
    c2_bytes_list: &[Vec<u8>],
    pi_bytes_list: &[Vec<u8>],
    theta_bytes_list: &[Vec<u8>],
    u_masked_bytes_list: &[Vec<u8>],  // U^ρ
    v_masked_bytes_list: &[Vec<u8>],  // V^ρ
) -> Result<Vec<u8>, String> {
    use groth_sahai::data_structures::{Com1, Com2, ComT, BT};
    use ark_ec::pairing::Pairing;
    use ark_ff::One;
    
    // Deserialize commitments and proof elements
    let mut c1_coms = Vec::new();
    for bytes in c1_bytes_list {
        let com = Com1::<Bls12_381>::deserialize_compressed(bytes.as_slice())
            .map_err(|e| format!("C1 deser: {:?}", e))?;
        c1_coms.push(com);
    }
    
    let mut c2_coms = Vec::new();
    for bytes in c2_bytes_list {
        let com = Com2::<Bls12_381>::deserialize_compressed(bytes.as_slice())
            .map_err(|e| format!("C2 deser: {:?}", e))?;
        c2_coms.push(com);
    }
    
    let mut pi = Vec::new();
    for bytes in pi_bytes_list {
        let com = Com2::<Bls12_381>::deserialize_compressed(bytes.as_slice())
            .map_err(|e| format!("π deser: {:?}", e))?;
        pi.push(com);
    }
    
    let mut theta = Vec::new();
    for bytes in theta_bytes_list {
        let com = Com1::<Bls12_381>::deserialize_compressed(bytes.as_slice())
            .map_err(|e| format!("θ deser: {:?}", e))?;
        theta.push(com);
    }
    
    // Deserialize masked CRS elements
    let mut u_masked = Vec::new();
    for bytes in u_masked_bytes_list {
        let com = Com1::<Bls12_381>::deserialize_compressed(bytes.as_slice())
            .map_err(|e| format!("U^ρ deser: {:?}", e))?;
        u_masked.push(com);
    }
    
    let mut v_masked = Vec::new();
    for bytes in v_masked_bytes_list {
        let com = Com2::<Bls12_381>::deserialize_compressed(bytes.as_slice())
            .map_err(|e| format!("V^ρ deser: {:?}", e))?;
        v_masked.push(com);
    }
    
    // Compute e(U^ρ, π) and e(θ, V^ρ)
    let u_pi_masked = ComT::<Bls12_381>::pairing_sum(&u_masked, &pi);
    let theta_v_masked = ComT::<Bls12_381>::pairing_sum(&theta, &v_masked);
    
    // Compute the commitment product (diagonal gamma)
    // For diagonal gamma: e(C1_i, C2_i) for each i
    let mut gt_product = Fq12::one();
    for i in 0..c1_coms.len().min(c2_coms.len()) {
        let PairingOutput(p0) = Bls12_381::pairing(c1_coms[i].0, c2_coms[i].0);
        let PairingOutput(p1) = Bls12_381::pairing(c1_coms[i].1, c2_coms[i].1);
        gt_product *= p0 * p1;
    }
    
    // Combine: commitment_product * u_pi * theta_v
    // This gives us target^ρ when valid proofs are provided
    let u_pi_mat = u_pi_masked.as_matrix();
    let theta_v_mat = theta_v_masked.as_matrix();
    
    // For KEM, we use the diagonal elements
    let mut result_bytes = Vec::new();
    let final_gt = gt_product * u_pi_mat[0][0].0 * u_pi_mat[1][1].0 
                             * theta_v_mat[0][0].0 * theta_v_mat[1][1].0;
    
    final_gt.serialize_compressed(&mut result_bytes)
        .map_err(|e| format!("Serialize GT: {:?}", e))?;
    
    Ok(result_bytes)
}

/// Serialize GT element
pub fn serialize_gt_pvugc(gt: &Fq12) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    gt.serialize_compressed(&mut bytes)
        .map_err(|e| format!("GT ser: {:?}", e))?;
    Ok(bytes)
}

/// Deserialize GT element
pub fn deserialize_gt_pvugc(bytes: &[u8]) -> Result<Fq12, String> {
    Fq12::deserialize_compressed(bytes)
        .map_err(|e| format!("GT deser: {:?}", e))
}

/// Convert big-endian bytes to Fr
pub fn fr_from_be(bytes: &[u8]) -> Fr {
    use ark_ff::PrimeField;
    Fr::from_be_bytes_mod_order(bytes)
}

/// Helper to serialize attestation components for KEM operations
pub fn serialize_attestation_for_kem(
    attestation: &crate::GSAttestation
) -> (Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>) {
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
    
    let mut pi_bytes = Vec::new();
    for pi in &attestation.pi_elements {
        let mut bytes = Vec::new();
        pi.serialize_compressed(&mut bytes).unwrap();
        pi_bytes.push(bytes);
    }
    
    let mut theta_bytes = Vec::new();
    for theta in &attestation.theta_elements {
        let mut bytes = Vec::new();
        theta.serialize_compressed(&mut bytes).unwrap();
        theta_bytes.push(bytes);
    }
    
    (c1_bytes, c2_bytes, pi_bytes, theta_bytes)
}

/// Helper to serialize CRS elements for KEM operations
pub fn serialize_crs_for_kem(
    crs: &groth_sahai::generator::CRS<Bls12_381>
) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let mut u_bases = Vec::new();
    for u in &crs.u {
        let mut bytes = Vec::new();
        u.serialize_compressed(&mut bytes).unwrap();
        u_bases.push(bytes);
    }
    
    let mut v_bases = Vec::new();
    for v in &crs.v {
        let mut bytes = Vec::new();
        v.serialize_compressed(&mut bytes).unwrap();
        v_bases.push(bytes);
    }
    
    (u_bases, v_bases)
}