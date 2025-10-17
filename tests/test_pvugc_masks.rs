#![allow(non_snake_case)]
// Tests PoCE-B tag and D-mask decapsulation
use ark_bls12_381::Fr;
use ark_std::test_rng;
use arkworks_groth16::{groth16_wrapper::ArkworksGroth16, GrothSahaiCommitments};
use groth_sahai::generator::CRS;
use sha2::{Digest, Sha256};

#[test]
fn test_pvugc_masks_arm_decap_same_x() {
    let mut rng = test_rng();
    let gs = GrothSahaiCommitments::new();

    // Setup Groth16
    let mut g16 = ArkworksGroth16::new();
    let vk = g16.setup().expect("setup");
    let w1 = Fr::from(3u64);
    let w2 = Fr::from(2u64);
    let proof = g16.prove(w1, w2).expect("prove");
    let x = vec![Fr::from(5u64)];

    // CRS per-slot 3x3
    let crs = CRS::generate_crs_per_slot(&mut rng, 3, 3);

    // Arm: rho, header, ct
    let rho = Fr::from(7u64);
    let ctx_hash = Sha256::digest(b"CTX(vk,x)").to_vec();
    let secret = b"secret-share-32-bytes__________"; // 32 bytes
    let (header, ct) = gs
        .pvugc_arm(&vk, &x, &crs, rho, secret, &ctx_hash, &mut rng)
        .expect("arm");

    // Prover attests (full-GS)
    let att = gs
        .commit_arkworks_proof(&proof, &vk, &x, &crs, &mut rng)
        .expect("att");

    // Decap with masks
    let pt = gs
        .pvugc_decapsulate_with_masks(&att, &vk, &x, &crs, &header, &ct, &ctx_hash)
        .expect("decap");
    assert_eq!(pt, secret);
}

#[test]
fn test_pvugc_masks_proof_agnostic_same_vk_x() {
    let mut rng = test_rng();
    let gs = GrothSahaiCommitments::new();
    let mut g16 = ArkworksGroth16::new();
    let vk = g16.setup().expect("setup");

    // Two different proofs for same x
    let proof1 = g16.prove(Fr::from(3u64), Fr::from(2u64)).expect("p1"); // x=5
    let proof2 = g16.prove(Fr::from(4u64), Fr::from(1u64)).expect("p2"); // x=5
    let x = vec![Fr::from(5u64)];

    let crs = CRS::generate_crs_per_slot(&mut rng, 3, 3);
    let rho = Fr::from(11u64);
    let ctx_hash = Sha256::digest(b"CTX(vk,x)").to_vec();
    let secret = b"________________secret-32-bytes";
    let (header, ct) = gs
        .pvugc_arm(&vk, &x, &crs, rho, secret, &ctx_hash, &mut rng)
        .expect("arm");

    let att1 = gs
        .commit_arkworks_proof(&proof1, &vk, &x, &crs, &mut rng)
        .expect("att1");
    let att2 = gs
        .commit_arkworks_proof(&proof2, &vk, &x, &crs, &mut rng)
        .expect("att2");

    // Both decrypt to same key
    let pt1 = gs
        .pvugc_decapsulate_with_masks(&att1, &vk, &x, &crs, &header, &ct, &ctx_hash)
        .expect("decap1");
    let pt2 = gs
        .pvugc_decapsulate_with_masks(&att2, &vk, &x, &crs, &header, &ct, &ctx_hash)
        .expect("decap2");
    assert_eq!(pt1, secret);
    assert_eq!(pt2, secret);
}

#[test]
fn test_pvugc_masks_wrong_x_fails() {
    let mut rng = test_rng();
    let gs = GrothSahaiCommitments::new();
    let mut g16 = ArkworksGroth16::new();
    let vk = g16.setup().expect("setup");

    // Arm for x=5
    let x1 = vec![Fr::from(5u64)];
    let crs = CRS::generate_crs_per_slot(&mut rng, 3, 3);
    let rho = Fr::from(13u64);
    let ctx1 = Sha256::digest(b"CTX(vk,x=5)").to_vec();
    let secret = b"mask share for x=5 32bytes____";
    let (_h1, ct) = gs
        .pvugc_arm(&vk, &x1, &crs, rho, secret, &ctx1, &mut rng)
        .expect("arm");

    // Prover for x=10
    let proof2 = g16.prove(Fr::from(4u64), Fr::from(6u64)).expect("p2"); // 10
    let x2 = vec![Fr::from(10u64)];
    let att2 = gs
        .commit_arkworks_proof(&proof2, &vk, &x2, &crs, &mut rng)
        .expect("att2");

    // Using different ctx (x2) should fail to decrypt original ct
    let ctx2 = Sha256::digest(b"CTX(vk,x=10)").to_vec();
    let header_wrong = gs
        .pvugc_arm(&vk, &x2, &crs, rho, secret, &ctx2, &mut rng)
        .expect("arm2")
        .0;
    // Decap with attestation for x2 + header for x2 on ciphertext for x1 should fail
    let res = gs.pvugc_decapsulate_with_masks(&att2, &vk, &x2, &crs, &header_wrong, &ct, &ctx2);
    assert!(res.is_err(), "decryption should fail for different x");
}
