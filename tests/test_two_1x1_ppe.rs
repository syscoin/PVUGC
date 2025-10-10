use ark_bls12_381::{Fr, Fq12, Bls12_381};
use ark_ec::pairing::{Pairing, PairingOutput};
use arkworks_groth16::groth16_wrapper::ArkworksGroth16;
use arkworks_groth16::gs_commitments::GrothSahaiCommitments;

#[test]
fn test_two_1x1_ppe_approach() {
    // Test the two 1×1 PPE approach for proof-agnostic determinism
    println!("\n=== Testing Two 1×1 PPE Approach ===");
    
    let gs = GrothSahaiCommitments::from_seed(b"TWO_1x1_PPE");
    let mut groth16 = ArkworksGroth16::new();
    let vk = groth16.setup().expect("Setup should succeed");
    
    // Create two different proofs for the same witness
    let witness = Fr::from(5u64);
    let proof1 = groth16.prove(witness).expect("Prove should succeed");
    let proof2 = groth16.prove(witness).expect("Prove should succeed");
    
    // Create attestations using two 1×1 PPEs
    let x = [Fr::from(25u64)];  // Public input
    let att1 = gs.commit_arkworks_proof(&proof1, &vk, &x, true)
        .expect("First attestation should succeed");
    let att2 = gs.commit_arkworks_proof(&proof2, &vk, &x, true)
        .expect("Second attestation should succeed");
    
    // Verify attestation structure
    // The GS library uses 2-element vectors even for 1×1 PPEs (internal representation)
    println!("Attestation structure:");
    println!("  eq_ab.pi.len() = {}", att1.eq_ab.pi.len());
    println!("  eq_ab.theta.len() = {}", att1.eq_ab.theta.len());
    println!("  eq_cd.pi.len() = {}", att1.eq_cd.pi.len());
    println!("  eq_cd.theta.len() = {}", att1.eq_cd.theta.len());
    
    println!("✓ Attestations created with two equations");
    
    // Check commitments are different (as expected)
    let c1_ab_same = att1.eq_ab.c1.0 == att2.eq_ab.c1.0 && att1.eq_ab.c1.1 == att2.eq_ab.c1.1;
    let c2_ab_same = att1.eq_ab.c2.0 == att2.eq_ab.c2.0 && att1.eq_ab.c2.1 == att2.eq_ab.c2.1;
    let c1_cd_same = att1.eq_cd.c1.0 == att2.eq_cd.c1.0 && att1.eq_cd.c1.1 == att2.eq_cd.c1.1;
    let c2_cd_same = att1.eq_cd.c2.0 == att2.eq_cd.c2.0 && att1.eq_cd.c2.1 == att2.eq_cd.c2.1;
    
    println!("\nCommitment Analysis:");
    println!("  eq_ab.c1 same: {}", c1_ab_same);
    println!("  eq_ab.c2 same: {}", c2_ab_same);
    println!("  eq_cd.c1 same: {}", c1_cd_same);
    println!("  eq_cd.c2 same: {}", c2_cd_same);
    
    // The key test: evaluate with masking
    let rho = Fr::from(123456u64);
    
    use groth_sahai::kem_eval::eval_two_equations_masked;
    use groth_sahai::kem_eval::pow_gt;
    
    let PairingOutput(m1) = eval_two_equations_masked::<Bls12_381>(
        &att1.eq_ab.c1,
        &att1.eq_ab.c2,
        &att1.eq_ab.pi,
        &att1.eq_ab.theta,
        &att1.eq_cd.c1,
        &att1.eq_cd.c2,
        &att1.eq_cd.pi,
        &att1.eq_cd.theta,
        gs.get_crs(),
        rho,
    );
    
    let PairingOutput(m2) = eval_two_equations_masked::<Bls12_381>(
        &att2.eq_ab.c1,
        &att2.eq_ab.c2,
        &att2.eq_ab.pi,
        &att2.eq_ab.theta,
        &att2.eq_cd.c1,
        &att2.eq_cd.c2,
        &att2.eq_cd.pi,
        &att2.eq_cd.theta,
        gs.get_crs(),
        rho,
    );
    
    // The expected value: target^ρ
    let expected = pow_gt::<Bls12_381>(att1.ppe_target, rho);
    
    println!("\nEvaluation Results:");
    println!("  M1 == expected (target^ρ): {}", m1 == expected);
    println!("  M2 == expected (target^ρ): {}", m2 == expected);
    println!("  M1 == M2 (proof-agnostic): {}", m1 == m2);
    
    // The critical assertions
    assert_eq!(att1.ppe_target, att2.ppe_target, "Targets should be identical for same (vk,x)");
    assert_eq!(m1, expected, "First attestation should evaluate to target^ρ");
    assert_eq!(m2, expected, "Second attestation should evaluate to target^ρ");
    assert_eq!(m1, m2, "Two distinct proofs for same (vk,x) must yield identical M");
    
    println!("\n✅ SUCCESS: Two 1×1 PPE approach achieves proof-agnostic determinism!");
}
