use ark_bls12_381::{Bls12_381, Fq12, Fr};
use ark_ec::AffineRepr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use ark_ec::CurveGroup;
use groth_sahai::data_structures::{Com1, Com2, ComT, BT};

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
    let pi = deserialize_com2_list(pi_bytes_list, "π")?;
    let theta = deserialize_com1_list(theta_bytes_list, "θ")?;

    let u = deserialize_com1_list(u_bytes_list, "U")?;
    let v = deserialize_com2_list(v_bytes_list, "V")?;
    let u_dual = deserialize_com2_list(u_dual_bytes_list, "U*")?;
    let v_dual = deserialize_com1_list(v_dual_bytes_list, "V*")?;

    let u_rho = scale_com1_list(&u, rho);
    let v_rho = scale_com2_list(&v, rho);
    let u_dual_rho = scale_com2_list(&u_dual, rho);
    let v_dual_rho = scale_com1_list(&v_dual, rho);

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
    let pi = deserialize_com2_list(pi_bytes_list, "π")?;
    let theta = deserialize_com1_list(theta_bytes_list, "θ")?;

    let u_masked = deserialize_com1_list(u_masked_bytes_list, "U^ρ")?;
    let v_masked = deserialize_com2_list(v_masked_bytes_list, "V^ρ")?;
    let u_dual_masked = deserialize_com2_list(u_dual_masked_bytes_list, "U*^ρ")?;
    let v_dual_masked = deserialize_com1_list(v_dual_masked_bytes_list, "V*^ρ")?;

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
    u_dual_rho: &[Com2<Bls12_381>],
    v_dual_rho: &[Com1<Bls12_381>],
) -> Result<ComT<Bls12_381>, String> {
    if c1.len() != c2.len() || c1.len() != u_rho.len() || c2.len() != v_rho.len() {
        return Err("Mismatched commitment and CRS lengths".to_string());
    }

    if pi.len() != u_rho.len() || theta.len() != v_rho.len() {
        return Err("Mismatched proof element lengths".to_string());
    }

    if u_dual_rho.len() != c1.len() || v_dual_rho.len() != c2.len() {
        return Err("Mismatched dual lengths".to_string());
    }

    let b1 = ComT::<Bls12_381>::pairing_sum(c1, u_dual_rho);
    let b2 = ComT::<Bls12_381>::pairing_sum(v_dual_rho, c2);
    let g_cross = ComT::<Bls12_381>::pairing_sum(c1, c2);
    let b3 = ComT::<Bls12_381>::pairing_sum(u_rho, pi);
    let b4 = ComT::<Bls12_381>::pairing_sum(theta, v_rho);

    Ok((b1 + b2 + g_cross) - b3 - b4)
}

fn deserialize_com1_list(
    bytes_list: &[Vec<u8>],
    label: &str,
) -> Result<Vec<Com1<Bls12_381>>, String> {
    let mut result = Vec::new();
    for bytes in bytes_list {
        let com = Com1::<Bls12_381>::deserialize_compressed(bytes.as_slice())
            .map_err(|e| format!("{} deser: {:?}", label, e))?;
        result.push(com);
    }
    Ok(result)
}

fn deserialize_com2_list(
    bytes_list: &[Vec<u8>],
    label: &str,
) -> Result<Vec<Com2<Bls12_381>>, String> {
    let mut result = Vec::new();
    for bytes in bytes_list {
        let com = Com2::<Bls12_381>::deserialize_compressed(bytes.as_slice())
            .map_err(|e| format!("{} deser: {:?}", label, e))?;
        result.push(com);
    }
    Ok(result)
}

fn scale_com1_list(list: &[Com1<Bls12_381>], rho: Fr) -> Vec<Com1<Bls12_381>> {
    list.iter()
        .map(|com| {
            Com1::<Bls12_381>(
                (com.0.into_group() * rho).into_affine(),
                (com.1.into_group() * rho).into_affine(),
            )
        })
        .collect()
}

fn scale_com2_list(list: &[Com2<Bls12_381>], rho: Fr) -> Vec<Com2<Bls12_381>> {
    list.iter()
        .map(|com| {
            Com2::<Bls12_381>(
                (com.0.into_group() * rho).into_affine(),
                (com.1.into_group() * rho).into_affine(),
            )
        })
        .collect()
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

/// Helper to serialize CRS elements (including duals) for KEM operations
pub fn serialize_crs_for_kem(
    crs: &groth_sahai::generator::CRS<Bls12_381>,
    u_duals: &[Com2<Bls12_381>],
    v_duals: &[Com1<Bls12_381>],
) -> (Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>) {
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

    let mut u_dual_bytes = Vec::new();
    for du in u_duals {
        let mut bytes = Vec::new();
        du.serialize_compressed(&mut bytes).unwrap();
        u_dual_bytes.push(bytes);
    }

    let mut v_dual_bytes = Vec::new();
    for dv in v_duals {
        let mut bytes = Vec::new();
        dv.serialize_compressed(&mut bytes).unwrap();
        v_dual_bytes.push(bytes);
    }

    (u_bases, v_bases, u_dual_bytes, v_dual_bytes)
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
