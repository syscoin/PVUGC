use ark_bls12_381::Fr;
use ark_ff::PrimeField;
use sha2::{Sha256, Digest};

/// Deterministically derive ρ from deposit parameters
/// This is SAFE and RECOMMENDED per the expert's analysis
/// 
/// The deterministic derivation ensures:
/// 1. Pre-signable masks at deposit time  
/// 2. Reproducibility across different provers
/// 3. No weakening of soundness
pub fn derive_rho_from_deposit(
    deposit_outpoint: &[u8],  // txid || vout
    policy_id: &[u8],
    vk_hash: &[u8],           // Hash of Groth16 VK
    crs_digest: &[u8],        // Hash of GS CRS  
    share_index: u64,
) -> Fr {
    let seed = Sha256::new()
        .chain_update(b"PVUGC/rho/v1")
        .chain_update(deposit_outpoint)
        .chain_update(policy_id)
        .chain_update(vk_hash)
        .chain_update(crs_digest)
        .chain_update(share_index.to_be_bytes())
        .finalize();
    
    Fr::from_le_bytes_mod_order(&seed)
}

/// For testing: derive rho from simpler parameters
pub fn derive_rho_test(
    vk_bytes: &[u8],
    public_input: &[Fr],
    index: u64,
) -> Fr {
    use ark_serialize::CanonicalSerialize;
    
    let mut hasher = Sha256::new();
    hasher.update(b"PVUGC/rho/test/v1");
    hasher.update(vk_bytes);
    
    // Serialize public input
    let mut pi_bytes = Vec::new();
    for x in public_input {
        x.serialize_compressed(&mut pi_bytes).unwrap();
    }
    hasher.update(&pi_bytes);
    hasher.update(index.to_be_bytes());
    
    let seed = hasher.finalize();
    Fr::from_le_bytes_mod_order(&seed)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_deterministic_rho() {
        // Test that same inputs produce same rho
        let outpoint = b"txid123:0";
        let policy = b"policy1";
        let vk_hash = b"vk_hash_abc";
        let crs_digest = b"crs_xyz";
        let index = 42;
        
        let rho1 = derive_rho_from_deposit(outpoint, policy, vk_hash, crs_digest, index);
        let rho2 = derive_rho_from_deposit(outpoint, policy, vk_hash, crs_digest, index);
        
        assert_eq!(rho1, rho2, "Same inputs should produce same rho");
        
        // Test that different inputs produce different rho
        let rho3 = derive_rho_from_deposit(outpoint, policy, vk_hash, crs_digest, index + 1);
        assert_ne!(rho1, rho3, "Different share index should produce different rho");
        
        let rho4 = derive_rho_from_deposit(b"txid456:1", policy, vk_hash, crs_digest, index);
        assert_ne!(rho1, rho4, "Different outpoint should produce different rho");
    }
}
