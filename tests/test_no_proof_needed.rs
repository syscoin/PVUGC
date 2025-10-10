// Test: Can we compute M without having a Groth16 proof?
use ark_bls12_381::{Bls12_381, Fr};
use ark_std::test_rng;
use arkworks_groth16::gs_commitments::{GrothSahaiCommitments, GSAttestation};
use arkworks_groth16::groth16_wrapper::ArkworksGroth16;
use groth_sahai::{Com1, Com2};

#[test]
fn test_m_computable_without_proof() {
    println!("\n=== CRITICAL SECURITY TEST: Computing M without a proof ===\n");
    
    let gs = GrothSahaiCommitments::from_seed(b"SECURITY_TEST");
    
    // Setup Groth16 to get vk (PUBLIC)
    let mut groth16 = ArkworksGroth16::new();
    let vk = groth16.setup().expect("Setup should succeed");
    let x = vec![Fr::from(25u64)]; // public input (PUBLIC)
    
    // STEP 1: Legitimate user with proof
    println!("LEGITIMATE USER:");
    let witness = Fr::from(5u64);
    let real_proof = groth16.prove(witness).expect("Prove should succeed");
    let mut rng = test_rng();
    let real_attestation = gs.commit_proof_deterministic(&real_proof, &vk, &x, &mut rng)
        .expect("Real attestation should succeed");
    
    // Compute M with real attestation
    let rho = Fr::from(12345u64); // Public parameter
    let m_real = gs.evaluate_masked_verifier_comt(&real_attestation, &vk, &x, rho);
    println!("  - Has valid Groth16 proof ✓");
    println!("  - Created valid attestation ✓");
    println!("  - Computed M successfully ✓");
    
    // STEP 2: Attacker WITHOUT proof
    println!("\nATTACKER WITHOUT PROOF:");
    
    // Create a COMPLETELY FAKE attestation with dummy values
    use ark_bls12_381::{G1Affine, G2Affine};
    let fake_attestation = GSAttestation {
        c1_commitments: vec![
            Com1::<Bls12_381>(G1Affine::identity(), G1Affine::identity()),  // Dummy commitment
            Com1::<Bls12_381>(G1Affine::identity(), G1Affine::identity()),  // Dummy commitment
        ],
        c2_commitments: vec![
            Com2::<Bls12_381>(G2Affine::identity(), G2Affine::identity()),  // Dummy commitment
            Com2::<Bls12_381>(G2Affine::identity(), G2Affine::identity()),  // Dummy commitment
        ],
        pi_elements: vec![
            Com2::<Bls12_381>(G2Affine::identity(), G2Affine::identity()),  // Dummy pi
            Com2::<Bls12_381>(G2Affine::identity(), G2Affine::identity()),  // Dummy pi
        ],
        theta_elements: vec![
            Com1::<Bls12_381>(G1Affine::identity(), G1Affine::identity()),  // Dummy theta
            Com1::<Bls12_381>(G1Affine::identity(), G1Affine::identity()),  // Dummy theta
        ],
        proof_data: vec![0u8; 32],         // Random bytes
        randomness_used: vec![Fr::from(0u64); 3],
        ppe_target: Default::default(),    // Dummy value
    };
    
    println!("  - Has NO Groth16 proof ✗");
    println!("  - Created FAKE attestation with dummy values");
    
    // Try to compute M with fake attestation
    let m_fake = gs.evaluate_masked_verifier_comt(&fake_attestation, &vk, &x, rho);
    println!("  - Computed M successfully ✓ (THIS SHOULD NOT WORK!)");
    
    // CRITICAL TEST: Are the M values the same?
    println!("\n=== SECURITY ANALYSIS ===");
    println!("M from real proof  : {:?}", &format!("{:?}", m_real.0)[0..50]);
    println!("M from fake 'proof': {:?}", &format!("{:?}", m_fake.0)[0..50]);
    
    // More detailed comparison
    println!("\nDetailed comparison:");
    println!("  m_real.3 (bottom-right cell): {:?}", &format!("{:?}", m_real.3.0)[0..30]);
    println!("  m_fake.3 (bottom-right cell): {:?}", &format!("{:?}", m_fake.3.0)[0..30]);
    
    if m_real == m_fake {
        println!("\n🚨🚨🚨 CRITICAL SECURITY FAILURE 🚨🚨🚨");
        println!("M values are IDENTICAL!");
        println!("\nThis proves:");
        println!("  1. The attestation parameter is NEVER USED");
        println!("  2. M is computed from (vk, x) alone");
        println!("  3. NO PROOF IS REQUIRED to compute M");
        println!("  4. Signature completion is NOT gated by proof existence");
        println!("\n❌ PVUGC security is completely broken!");
        
        panic!("Security test FAILED: M computable without proof!");
    } else {
        println!("\n✅ M values differ - proof requirement is enforced");
    }
}
