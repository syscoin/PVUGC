use ark_ff::One;

use ark_bls12_381::{Fq12, Fr};
use ark_std::UniformRand;
use arkworks_groth16::kem::ProductKeyKEM;

#[test]
fn product_key_anchor_length_mismatch() {
    let res = arkworks_groth16::gs_kem_helpers::compute_product_key_anchor(
        &vec![vec![0u8; 96]],
        &vec![vec![0u8; 192]],
        &vec![vec![0u8; 192], vec![0u8; 192]],
        &vec![vec![0u8; 96]],
    );
    assert!(res.is_err());
}

#[test]
fn two_phase_flow_rejects_dummy_inputs() {
    let kem = ProductKeyKEM::new();
    let mut rng = ark_std::test_rng();
    let target = Fq12::one();
    let share_scalar = Fr::rand(&mut rng);
    let result = kem.encapsulate(
        &mut rng,
        0,
        &vec![vec![0u8; 192]],
        &vec![vec![0u8; 96]],
        &vec![vec![0u8; 96]],
        &vec![vec![0u8; 192]],
        &target,
        share_scalar,
        b"ctx",
        b"digest",
    );
    assert!(result.is_err());
}
