#![allow(non_snake_case)]
use ark_bls12_381::Fr;
use ark_std::test_rng;
use arkworks_groth16::{groth16_wrapper::ArkworksGroth16, GrothSahaiCommitments};
use groth_sahai::generator::CRS;
use sha2::{Digest, Sha256};

#[test]
fn test_pvugc_and2_masks_flow() {
    let mut rng = test_rng();
    let gs = GrothSahaiCommitments::new();
    let mut g16 = ArkworksGroth16::new();
    let vk = g16.setup().expect("setup");
    let proof = g16.prove(Fr::from(3u64), Fr::from(2u64)).expect("prove"); // x=5
    let x = vec![Fr::from(5u64)];

    let crs1 = CRS::generate_crs_per_slot(&mut rng, 3, 3);
    let crs2 = CRS::generate_crs_per_slot(&mut rng, 3, 3);

    let rho = Fr::from(19u64);
    let ctx_hash = Sha256::digest(b"CTX_AND2").to_vec();
    let secret = b"and2 secret 32 bytes long________";

    let ((h1, h2), ct) = gs
        .pvugc_arm_and2(&vk, &x, &crs1, &crs2, rho, secret, &ctx_hash, &mut rng)
        .expect("arm and2");

    let att = gs
        .commit_arkworks_proof(&proof, &vk, &x, &crs1, &mut rng)
        .expect("att");

    let pt = gs
        .pvugc_decapsulate_with_masks_and2(&att, &vk, &x, &crs1, &crs2, &h1, &h2, &ct, &ctx_hash)
        .expect("decap and2");
    assert_eq!(pt, secret);
}
