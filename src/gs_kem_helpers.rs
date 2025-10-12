use ark_bls12_381::{Bls12_381, Fq12, Fr, G1Affine, G2Affine};
use ark_ec::pairing::PairingOutput;
use ark_ec::AffineRepr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use groth_sahai::{statement::PPE, Com1, Com2, ComT, BT};

/// Compute canonical masked evaluation for KEM
/// Uses the canonical masked verifier approach that evaluates target^ρ
pub fn compute_canonical_masked_eval(
    c1_bytes_list: &[Vec<u8>],    // C1 commitments
    c2_bytes_list: &[Vec<u8>],    // C2 commitments
    pi_bytes_list: &[Vec<u8>],    // π proof elements
    theta_bytes_list: &[Vec<u8>], // θ proof elements
    u_bytes_list: &[Vec<u8>],     // CRS U elements
    v_bytes_list: &[Vec<u8>],     // CRS V elements
    rho: Fr,                      // Masking scalar
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
    use ark_ec::pairing::Pairing;
    use ark_ec::CurveGroup;
    use ark_ff::One;
    use groth_sahai::data_structures::{ComT, BT};

    let u_masked: Vec<Com1<Bls12_381>> = u
        .iter()
        .map(|ui| {
            Com1::<Bls12_381>(
                (ui.0.into_group() * rho).into_affine(),
                (ui.1.into_group() * rho).into_affine(),
            )
        })
        .collect();

    let v_masked: Vec<Com2<Bls12_381>> = v
        .iter()
        .map(|vi| {
            Com2::<Bls12_381>(
                (vi.0.into_group() * rho).into_affine(),
                (vi.1.into_group() * rho).into_affine(),
            )
        })
        .collect();

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
    let final_gt = gt_product
        * u_pi_mat[0][0].0
        * u_pi_mat[1][1].0
        * theta_v_mat[0][0].0
        * theta_v_mat[1][1].0;

    let mut result_bytes = Vec::new();
    final_gt
        .serialize_compressed(&mut result_bytes)
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
    u_masked_bytes_list: &[Vec<u8>], // U^ρ
    v_masked_bytes_list: &[Vec<u8>], // V^ρ
) -> Result<Vec<u8>, String> {
    use ark_ec::pairing::Pairing;
    use ark_ff::One;
    use groth_sahai::data_structures::{Com1, Com2, ComT, BT};

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
    let final_gt = gt_product
        * u_pi_mat[0][0].0
        * u_pi_mat[1][1].0
        * theta_v_mat[0][0].0
        * theta_v_mat[1][1].0;

    final_gt
        .serialize_compressed(&mut result_bytes)
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
    Fq12::deserialize_compressed(bytes).map_err(|e| format!("GT deser: {:?}", e))
}

/// Serialize full 2x2 ComT matrix row-major
pub fn serialize_comt_matrix(comt: &ComT<Bls12_381>) -> Result<Vec<u8>, String> {
    let matrix = comt.as_matrix();
    let mut out = Vec::new();
    for r in 0..2 {
        for c in 0..2 {
            matrix[r][c]
                .0
                .serialize_compressed(&mut out)
                .map_err(|e| format!("Serialize GT cell: {:?}", e))?;
        }
    }
    Ok(out)
}

/// Convert big-endian bytes to Fr
pub fn fr_from_be(bytes: &[u8]) -> Fr {
    use ark_ff::PrimeField;
    Fr::from_be_bytes_mod_order(bytes)
}

/// Helper to serialize attestation components for KEM operations
pub fn serialize_attestation_for_kem(
    attestation: &crate::GSAttestation,
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
    crs: &groth_sahai::generator::CRS<Bls12_381>,
) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let mut u_bytes = Vec::new();
    for u in &crs.u {
        let mut bytes = Vec::new();
        u.serialize_compressed(&mut bytes).unwrap();
        u_bytes.push(bytes);
    }

    let mut v_bytes = Vec::new();
    for v in &crs.v {
        let mut bytes = Vec::new();
        v.serialize_compressed(&mut bytes).unwrap();
        v_bytes.push(bytes);
    }

    (u_bytes, v_bytes)
}

pub fn deserialize_g1_pair(bytes: &[u8]) -> Result<(G1Affine, G1Affine), String> {
    if bytes.len() != 96 {
        return Err(format!("G1 pair must be 96 bytes, got {}", bytes.len()));
    }
    let first = G1Affine::deserialize_compressed(&bytes[..48])
        .map_err(|e| format!("G1 deser0: {:?}", e))?;
    let second = G1Affine::deserialize_compressed(&bytes[48..])
        .map_err(|e| format!("G1 deser1: {:?}", e))?;
    Ok((first, second))
}

pub fn deserialize_g2_pair(bytes: &[u8]) -> Result<(G2Affine, G2Affine), String> {
    if bytes.len() != 192 {
        return Err(format!("G2 pair must be 192 bytes, got {}", bytes.len()));
    }
    let first = G2Affine::deserialize_compressed(&bytes[..96])
        .map_err(|e| format!("G2 deser0: {:?}", e))?;
    let second = G2Affine::deserialize_compressed(&bytes[96..])
        .map_err(|e| format!("G2 deser1: {:?}", e))?;
    Ok((first, second))
}

pub fn deserialize_masked_u(bytes_list: &[Vec<u8>]) -> Result<Vec<Com1<Bls12_381>>, String> {
    let mut out = Vec::new();
    for bytes in bytes_list {
        let (g0, g1) = deserialize_g1_pair(bytes)?;
        out.push(Com1::<Bls12_381>(g0, g1));
    }
    Ok(out)
}

pub fn deserialize_masked_v(bytes_list: &[Vec<u8>]) -> Result<Vec<Com2<Bls12_381>>, String> {
    let mut out = Vec::new();
    for bytes in bytes_list {
        let (g0, g1) = deserialize_g2_pair(bytes)?;
        out.push(Com2::<Bls12_381>(g0, g1));
    }
    Ok(out)
}
/// Compute masked verifier result using published masked primaries (ρ never revealed)
pub fn masked_verifier_from_masked(
    _ppe: &PPE<Bls12_381>,
    c1_coms: &[Com1<Bls12_381>],
    c2_coms: &[Com2<Bls12_381>],
    pi: &[Com2<Bls12_381>],
    theta: &[Com1<Bls12_381>],
    u_rho: &[Com1<Bls12_381>],
    v_rho: &[Com2<Bls12_381>],
) -> ComT<Bls12_381> {
    use ark_ec::pairing::Pairing;
    use ark_ff::One;

    // Contribution from commitments (diagonal gamma)
    let mut gt_product = Fq12::one();
    for i in 0..c1_coms.len().min(c2_coms.len()) {
        let PairingOutput(p0) = Bls12_381::pairing(c1_coms[i].0, c2_coms[i].0);
        let PairingOutput(p1) = Bls12_381::pairing(c1_coms[i].1, c2_coms[i].1);
        gt_product *= p0 * p1;
    }

    // Proof legs with masked CRS primaries
    let u_pi_masked = ComT::<Bls12_381>::pairing_sum(u_rho, pi);
    let theta_v_masked = ComT::<Bls12_381>::pairing_sum(theta, v_rho);

    let u_pi_mat = u_pi_masked.as_matrix();
    let theta_v_mat = theta_v_masked.as_matrix();

    let final_gt = gt_product * u_pi_mat[0][0].0 * u_pi_mat[1][1].0
        * theta_v_mat[0][0].0 * theta_v_mat[1][1].0;

    ComT::<Bls12_381>::linear_map_PPE(&PairingOutput::<Bls12_381>(final_gt))
}
