use ark_bls12_381::Fr;
use ark_ec::{AffineRepr, CurveGroup};
use ark_std::test_rng;

use arkworks_groth16::groth16_wrapper::ArkworksGroth16;
use arkworks_groth16::gs_commitments::GrothSahaiCommitments;

use groth_sahai::masked_verifier_comt_2x2;
use groth_sahai::masked_verifier_matrix_canonical_2x2;
use groth_sahai::rhs_masked_matrix;
use groth_sahai::kdf_from_comt;
use groth_sahai::prover::Provable;
use groth_sahai::verifier::Verifiable;

#[test]
fn gs_verifier_parity_cells() {
    // Prepare Groth16 proofs for the same witness
    let gs = GrothSahaiCommitments::from_seed(b"GS_PARITY_DET");
    let mut groth16 = ArkworksGroth16::new();
    let vk = groth16.setup().expect("vk setup");

    let witness = Fr::from(5u64);
    let proof1 = groth16.prove(witness).expect("proof1");
    let proof2 = groth16.prove(witness).expect("proof2");
    let public_input = [Fr::from(25u64)];

    // Encode Groth16 verifier equation as a 2×2 PPE
    let ppe = gs.groth16_verify_as_ppe_2var(&vk, &public_input);
    let crs = gs.get_crs().clone();

    // Arrange variables in the canonical ordering used by the PPE
    let delta_neg = (-vk.delta_g2.into_group()).into_affine();
    let xvars1 = vec![proof1.pi_a, proof1.pi_c];
    let yvars1 = vec![proof1.pi_b, delta_neg];
    let xvars2 = vec![proof2.pi_a, proof2.pi_c];
    let yvars2 = vec![proof2.pi_b, delta_neg];

    // Commit proofs via Groth-Sahai using fresh randomness
    let mut rng = test_rng();
    let cproof1 = ppe.commit_and_prove(&xvars1, &yvars1, &crs, &mut rng);
    let cproof2 = ppe.commit_and_prove(&xvars2, &yvars2, &crs, &mut rng);

    // Sanity: both commitments verify against the PPE/CRS pair
    assert!(ppe.verify(&cproof1, &crs));
    assert!(ppe.verify(&cproof2, &crs));

    // Evaluate the canonical masked verifier matrix for both proofs
    let rho = Fr::from(777u64);
    let canonical1 = masked_verifier_matrix_canonical_2x2(
        &ppe,
        &crs,
        &cproof1.xcoms.coms,
        &cproof1.ycoms.coms,
        &cproof1.equ_proofs[0].pi,
        &cproof1.equ_proofs[0].theta,
        rho,
    );
    let canonical2 = masked_verifier_matrix_canonical_2x2(
        &ppe,
        &crs,
        &cproof2.xcoms.coms,
        &cproof2.ycoms.coms,
        &cproof2.equ_proofs[0].pi,
        &cproof2.equ_proofs[0].theta,
        rho,
    );

    // Expected RHS matrix is the PPE target raised to ρ
    let rhs = rhs_masked_matrix(&ppe, rho);
    assert_eq!(canonical1, rhs, "Proof1 masked matrix should equal target^ρ");
    assert_eq!(canonical2, rhs, "Proof2 masked matrix should equal target^ρ");

    // Derive KEM keys from the canonical masked ComT and ensure determinism
    let comt1 = masked_verifier_comt_2x2(
        &ppe,
        &crs,
        &cproof1.xcoms.coms,
        &cproof1.ycoms.coms,
        &cproof1.equ_proofs[0].pi,
        &cproof1.equ_proofs[0].theta,
        rho,
    );
    let comt2 = masked_verifier_comt_2x2(
        &ppe,
        &crs,
        &cproof2.xcoms.coms,
        &cproof2.ycoms.coms,
        &cproof2.equ_proofs[0].pi,
        &cproof2.equ_proofs[0].theta,
        rho,
    );

    let key1 = kdf_from_comt(&comt1, b"crs", b"ppe", b"vk", b"x", b"deposit", 1);
    let key2 = kdf_from_comt(&comt2, b"crs", b"ppe", b"vk", b"x", b"deposit", 1);
    assert_eq!(
        key1, key2,
        "Canonical masked verifier KEM keys should match across proofs"
    );
}
