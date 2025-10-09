use ark_bls12_381::{Bls12_381, Fr, Fq12, G1Affine, G2Affine};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_ec::pairing::PairingOutput;

/// Compute KEM product using dual-base evaluator
/// Evaluates: ∏_j e(C1_j, D1_j) · ∏_k e(D2_k, C2_k)
pub fn compute_kem_product(
    c1_bytes_list: &[Vec<u8>],
    c2_bytes_list: &[Vec<u8>],
    d1_masked: &[Vec<u8>],
    d2_masked: &[Vec<u8>],
) -> Result<Vec<u8>, String> {
    use groth_sahai::data_structures::{Com1, Com2};
    use groth_sahai::ppe_eval_with_masked_pairs;
    
    // Deserialize C1 commitments
    let mut c1_coms = Vec::new();
    for bytes in c1_bytes_list {
        let com = Com1::<Bls12_381>::deserialize_compressed(bytes.as_slice())
            .map_err(|e| format!("C1 deser: {:?}", e))?;
        c1_coms.push(com);
    }
    
    // Deserialize C2 commitments
    let mut c2_coms = Vec::new();
    for bytes in c2_bytes_list {
        let com = Com2::<Bls12_381>::deserialize_compressed(bytes.as_slice())
            .map_err(|e| format!("C2 deser: {:?}", e))?;
        c2_coms.push(com);
    }
    
    // Deserialize D1 (u_dual^ρ) pairs
    let mut u_pairs = Vec::new();
    for pair_bytes in d1_masked {
        if pair_bytes.len() != 192 {
            return Err(format!("D1 pair must be 192 bytes, got {}", pair_bytes.len()));
        }
        let u0 = G2Affine::deserialize_compressed(&pair_bytes[..96])
            .map_err(|e| format!("U0: {:?}", e))?;
        let u1 = G2Affine::deserialize_compressed(&pair_bytes[96..])
            .map_err(|e| format!("U1: {:?}", e))?;
        u_pairs.push((u0, u1));
    }
    
    // Deserialize D2 (v_dual^ρ) pairs
    let mut v_pairs = Vec::new();
    for pair_bytes in d2_masked {
        if pair_bytes.len() != 96 {
            return Err(format!("D2 pair must be 96 bytes, got {}", pair_bytes.len()));
        }
        let v0 = G1Affine::deserialize_compressed(&pair_bytes[..48])
            .map_err(|e| format!("V0: {:?}", e))?;
        let v1 = G1Affine::deserialize_compressed(&pair_bytes[48..])
            .map_err(|e| format!("V1: {:?}", e))?;
        v_pairs.push((v0, v1));
    }
    
    // Evaluate: ∏ e(C1, u_dual^ρ) · ∏ e(v_dual^ρ, C2)
    let PairingOutput(result) = ppe_eval_with_masked_pairs::<Bls12_381>(
        &c1_coms,
        &c2_coms,
        &u_pairs,
        &v_pairs,
    );
    
    Ok(serialize_gt_pvugc(&result))
}

/// Deserialize GT from PVUGC canonical format (576 bytes)
pub fn deserialize_gt_pvugc(bytes: &[u8]) -> Result<Fq12, String> {
    use ark_bls12_381::{Fq, Fq2, Fq6};
    
    if bytes.len() != 576 {
        return Err(format!("GT must be 576 bytes, got {}", bytes.len()));
    }
    
    // Deserialize 12 Fq elements (each 48 bytes)
    let mut fq_elements = Vec::new();
    for i in 0..12 {
        let start = i * 48;
        let end = start + 48;
        let fq = Fq::deserialize_compressed(&bytes[start..end])
            .map_err(|e| format!("Failed to deserialize Fq[{}]: {:?}", i, e))?;
        fq_elements.push(fq);
    }
    
    // Group into 6 Fq2 elements
    let mut fq2_elements = Vec::new();
    for i in 0..6 {
        let fq2 = Fq2::new(fq_elements[i * 2], fq_elements[i * 2 + 1]);
        fq2_elements.push(fq2);
    }
    
    // Create two Fq6 elements
    let c0 = Fq6::new(fq2_elements[0], fq2_elements[1], fq2_elements[2]);
    let c1 = Fq6::new(fq2_elements[3], fq2_elements[4], fq2_elements[5]);
    
    // Create Fq12
    let fq12 = Fq12::new(c0, c1);
    
    Ok(fq12)
}

/// Canonical PVUGC GT serializer: 12 limbs × 48 bytes (big-endian) = 576 bytes.
/// Use this in BOTH encap and decap so KDF input matches byte-for-byte.
pub fn serialize_gt_pvugc(gt: &Fq12) -> Vec<u8> {
    let mut out = Vec::with_capacity(576);
    
    // Fq12 structure: c0 and c1 are Fq6; each Fq6 has c0, c1, c2 as Fq2; each Fq2 has c0, c1 as Fq
    // Order: gt.c0.{c0, c1, c2}, gt.c1.{c0, c1, c2} = 6 Fq2s = 12 Fq elements
    let fq2s = [&gt.c0.c0, &gt.c0.c1, &gt.c0.c2, &gt.c1.c0, &gt.c1.c1, &gt.c1.c2];
    
    for fq2 in fq2s {
        for fq in [fq2.c0, fq2.c1] {
            // ark's compressed Fq is already big-endian 48 bytes
            let mut buf = Vec::with_capacity(48);
            fq.serialize_compressed(&mut buf)
                .expect("Fq serialization should not fail");
            out.extend_from_slice(&buf);
        }
    }
    
    assert_eq!(out.len(), 576, "GT serialization must be 576 bytes");
    out
}

// Helper to convert 32-byte big-endian to Fr
pub fn fr_from_be(bytes: &[u8]) -> Fr {
    use ark_ff::PrimeField;
    Fr::from_be_bytes_mod_order(bytes)
}
