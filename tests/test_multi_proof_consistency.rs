use ark_bls12_381::{Bls12_381, Fq12, Fr};
use ark_ec::{AffineRepr, CurveGroup};
use ark_std::test_rng;

use arkworks_groth16::groth16_wrapper::ArkworksGroth16;
use arkworks_groth16::gs_commitments::GrothSahaiCommitments;

use ark_ec::pairing::PairingOutput;
use arkworks_groth16::{kdf_from_comt, masked_verifier_matrix_canonical, rhs_masked_matrix};
use groth_sahai::data_structures::{ComT, Matrix};
use groth_sahai::prover::Provable;

#[test]
fn test_masked_matrix_consistency_and_uniqueness() {
    // Setup Groth16 instance
    let gs = GrothSahaiCommitments::from_seed(b"CONSISTENCY");
    let mut groth16 = ArkworksGroth16::new();
    let vk = groth16.setup().expect("vk setup");
    let delta_neg = (-vk.delta_g2.into_group()).into_affine();

    // Statement A: public input 25
    let witness_a = Fr::from(5u64);
    let x_a = vec![Fr::from(25u64)];
    let ppe_a = gs.groth16_verify_as_ppe(&vk, &x_a);
    let crs = gs.get_crs().clone();

    let mut rng_a1 = test_rng();
    let mut rng_a2 = test_rng();
    let mut rng_a3 = test_rng();
    let proof_a1 = groth16.prove(witness_a).expect("proof a1");
    let proof_a2 = groth16.prove(witness_a).expect("proof a2");
    let witness_a_alt = -witness_a;
    let proof_a3 = groth16
        .prove(witness_a_alt)
        .expect("proof a3 (alternate witness)");

    let cpr_a1 = ppe_a.commit_and_prove(
        &[proof_a1.pi_a, proof_a1.pi_c],
        &[proof_a1.pi_b, delta_neg],
        &crs,
        &mut rng_a1,
    );
    let cpr_a2 = ppe_a.commit_and_prove(
        &[proof_a2.pi_a, proof_a2.pi_c],
        &[proof_a2.pi_b, delta_neg],
        &crs,
        &mut rng_a2,
    );
    let cpr_a3 = ppe_a.commit_and_prove(
        &[proof_a3.pi_a, proof_a3.pi_c],
        &[proof_a3.pi_b, delta_neg],
        &crs,
        &mut rng_a3,
    );

    let rho = Fr::from(777u64);
    let lhs_a1 = masked_verifier_matrix_canonical(
        &ppe_a,
        &crs,
        &cpr_a1.xcoms.coms,
        &cpr_a1.ycoms.coms,
        &cpr_a1.equ_proofs[0].pi,
        &cpr_a1.equ_proofs[0].theta,
        rho,
    );
    let lhs_a2 = masked_verifier_matrix_canonical(
        &ppe_a,
        &crs,
        &cpr_a2.xcoms.coms,
        &cpr_a2.ycoms.coms,
        &cpr_a2.equ_proofs[0].pi,
        &cpr_a2.equ_proofs[0].theta,
        rho,
    );
    let lhs_a3 = masked_verifier_matrix_canonical(
        &ppe_a,
        &crs,
        &cpr_a3.xcoms.coms,
        &cpr_a3.ycoms.coms,
        &cpr_a3.equ_proofs[0].pi,
        &cpr_a3.equ_proofs[0].theta,
        rho,
    );
    let rhs_a = rhs_masked_matrix(&ppe_a, rho);

    assert_eq!(lhs_a1, rhs_a, "Proof A1 masked matrix must equal target");
    assert_eq!(lhs_a2, rhs_a, "Proof A2 masked matrix must equal target");
    assert_eq!(
        lhs_a3, rhs_a,
        "Proof A3 (alternate witness) masked matrix must equal target"
    );

    let comt_a1 = matrix_to_comt(lhs_a1);
    let comt_a2 = matrix_to_comt(lhs_a2);
    let comt_a3 = matrix_to_comt(lhs_a3);

    let key_a1 = kdf_from_comt(&comt_a1, b"crs", b"ppe", b"vk", b"x", b"deposit", 1);
    let key_a2 = kdf_from_comt(&comt_a2, b"crs", b"ppe", b"vk", b"x", b"deposit", 1);
    assert_eq!(
        key_a1, key_a2,
        "KEM keys must match across valid proofs for the same statement"
    );
    let key_a3 = kdf_from_comt(&comt_a3, b"crs", b"ppe", b"vk", b"x", b"deposit", 1);
    assert_eq!(
        key_a1, key_a3,
        "KEM keys must match even with alternate witnesses for the same statement"
    );

    // Statement B: different public input 36 (witness 6)
    let witness_b = Fr::from(6u64);
    let x_b = vec![Fr::from(36u64)];
    let ppe_b = gs.groth16_verify_as_ppe(&vk, &x_b);
    let proof_b = groth16.prove(witness_b).expect("proof b");
    let mut rng_b = test_rng();
    let cpr_b = ppe_b.commit_and_prove(
        &[proof_b.pi_a, proof_b.pi_c],
        &[proof_b.pi_b, delta_neg],
        &crs,
        &mut rng_b,
    );

    let lhs_b = masked_verifier_matrix_canonical(
        &ppe_b,
        &crs,
        &cpr_b.xcoms.coms,
        &cpr_b.ycoms.coms,
        &cpr_b.equ_proofs[0].pi,
        &cpr_b.equ_proofs[0].theta,
        rho,
    );
    let rhs_b = rhs_masked_matrix(&ppe_b, rho);
    assert_eq!(lhs_b, rhs_b, "Proof B masked matrix must equal target");

    // Ensure distinct statements produce different masked matrices/keys
    assert_ne!(
        lhs_a1, lhs_b,
        "Different statements should not share masked matrices"
    );
    let comt_b = matrix_to_comt(lhs_b);
    let key_b = kdf_from_comt(&comt_b, b"crs", b"ppe", b"vk", b"x", b"deposit", 1);
    assert_ne!(
        key_a1, key_b,
        "Different statements should not derive identical KEM keys"
    );
}

fn matrix_to_comt(matrix: [[Fq12; 2]; 2]) -> ComT<Bls12_381> {
    ComT::<Bls12_381>::from(Matrix::<PairingOutput<Bls12_381>>::from(vec![
        vec![
            PairingOutput::<Bls12_381>(matrix[0][0]),
            PairingOutput::<Bls12_381>(matrix[0][1]),
        ],
        vec![
            PairingOutput::<Bls12_381>(matrix[1][0]),
            PairingOutput::<Bls12_381>(matrix[1][1]),
        ],
    ]))
}
