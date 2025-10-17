#![allow(non_snake_case)]

// Security assumption tests for PVUGC's dual-base KEM
//
// NOTE: These tests are for the rank-decomposition approach and need updating for full-GS.
// The current working tests are in test_pvugc.rs::test_complete_adaptor_signature_flow
// which uses the full-GS approach with real Groth16 proofs.
//
// These tests verify:
// - Deterministic KEM properties
// - Multiple valid attestations for the same statement produce the same M
// - Attestations for different statements produce different M
// - One signature can be unlocked by any valid proof for a specific circuit
// - Proofs for other circuits cannot unlock

use ark_bls12_381::{Bls12_381 as E, Fr};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{UniformRand, Zero};
use ark_std::test_rng;

use groth_sahai::base_construction::RankDecompPpeBases;
use groth_sahai::generator::CRS;
use groth_sahai::pvugc::{pvugc_arm, pvugc_decap};
use groth_sahai::rank_decomp::RankDecomp;
use groth_sahai::statement::PPE;

#[test]
fn test_determinism_different_proofs_same_statement() {
    // Core assumption: different valid proofs for the same statement
    // should extract to the same M value (proof-agnostic property)
    let mut rng = test_rng();

    // Setup simple 2x2 PPE
    let m = 2;
    let n = 2;
    let crs = CRS::<E>::generate_crs_per_slot(&mut rng, m, n);

    let gamma = vec![
        vec![Fr::from(2u64), Fr::from(3u64)],
        vec![Fr::from(5u64), Fr::from(7u64)],
    ];
    let a_consts = vec![<E as Pairing>::G1::zero().into_affine(); n];
    let b_consts = vec![<E as Pairing>::G2::zero().into_affine(); m];

    let x_vars = vec![<E as Pairing>::G1::generator().into_affine(); m];
    let y_vars = vec![<E as Pairing>::G2::generator().into_affine(); n];

    // Compute target
    let mut target = PairingOutput::<E>::zero();
    for i in 0..m {
        for j in 0..n {
            let (_v_rand, v_var) = crs.v_for_slot(j);
            target += <E as Pairing>::pairing(x_vars[i], v_var.1) * gamma[i][j];
        }
    }

    let ppe = PPE {
        gamma: gamma.clone(),
        a_consts,
        b_consts,
        target,
    };

    // Create rank-decomposition bases
    let decomp = RankDecomp::decompose(&ppe.gamma);
    let bases = RankDecompPpeBases::build(&crs, &ppe, &decomp);

    // Arm with rho
    let rho = Fr::rand(&mut rng);
    let armed_bases = pvugc_arm(&bases, &rho);

    // Generate two different attestations for the SAME statement
    let attestation1 = ppe.commit_and_prove_rank_decomp(&x_vars, &y_vars, &crs, &mut rng);
    let attestation2 = ppe.commit_and_prove_rank_decomp(&x_vars, &y_vars, &crs, &mut rng);

    // Verify both attestations
    assert!(
        ppe.verify_rank_decomp(&attestation1, &crs),
        "Attestation 1 should verify"
    );
    assert!(
        ppe.verify_rank_decomp(&attestation2, &crs),
        "Attestation 2 should verify"
    );

    // Extract K from both attestations
    let k1 = pvugc_decap(&attestation1, &armed_bases);
    let k2 = pvugc_decap(&attestation2, &armed_bases);

    // CRITICAL: Both should produce the same K (proof-agnostic property)
    assert_eq!(
        k1, k2,
        "Different proofs for same statement must produce same K"
    );

    // Verify K = target^rho
    let expected = target * rho;
    assert_eq!(k1, expected, "Extracted K should equal target^rho");
}

#[test]
fn test_wrong_public_input_rejection() {
    // Test that attestations for different statements produce different K
    let mut rng = test_rng();

    let m = 2;
    let n = 2;
    let crs = CRS::<E>::generate_crs_per_slot(&mut rng, m, n);

    // Statement 1
    let gamma1 = vec![
        vec![Fr::from(2u64), Fr::from(3u64)],
        vec![Fr::from(5u64), Fr::from(7u64)],
    ];
    let a_consts = vec![<E as Pairing>::G1::zero().into_affine(); n];
    let b_consts = vec![<E as Pairing>::G2::zero().into_affine(); m];

    let x_vars1 = vec![<E as Pairing>::G1::generator().into_affine(); m];
    let y_vars1 = vec![<E as Pairing>::G2::generator().into_affine(); n];

    let mut target1 = PairingOutput::<E>::zero();
    for i in 0..m {
        for j in 0..n {
            let (_v_rand, v_var) = crs.v_for_slot(j);
            target1 += <E as Pairing>::pairing(x_vars1[i], v_var.1) * gamma1[i][j];
        }
    }

    let ppe1 = PPE {
        gamma: gamma1.clone(),
        a_consts: a_consts.clone(),
        b_consts: b_consts.clone(),
        target: target1,
    };

    // Statement 2 (different gamma)
    let gamma2 = vec![
        vec![Fr::from(11u64), Fr::from(13u64)],
        vec![Fr::from(17u64), Fr::from(19u64)],
    ];

    let x_vars2 = x_vars1.clone(); // Same variables
    let y_vars2 = y_vars1.clone();

    let mut target2 = PairingOutput::<E>::zero();
    for i in 0..m {
        for j in 0..n {
            let (_v_rand, v_var) = crs.v_for_slot(j);
            target2 += <E as Pairing>::pairing(x_vars2[i], v_var.1) * gamma2[i][j];
        }
    }

    let ppe2 = PPE {
        gamma: gamma2,
        a_consts,
        b_consts,
        target: target2,
    };

    // Create bases and arm
    let rho = Fr::rand(&mut rng);
    let decomp1 = RankDecomp::decompose(&ppe1.gamma);
    let bases1 = RankDecompPpeBases::build(&crs, &ppe1, &decomp1);
    let armed1 = pvugc_arm(&bases1, &rho);

    let decomp2 = RankDecomp::decompose(&ppe2.gamma);
    let bases2 = RankDecompPpeBases::build(&crs, &ppe2, &decomp2);
    let armed2 = pvugc_arm(&bases2, &rho);

    // Generate attestations
    let attestation1 = ppe1.commit_and_prove_rank_decomp(&x_vars1, &y_vars1, &crs, &mut rng);
    let attestation2 = ppe2.commit_and_prove_rank_decomp(&x_vars2, &y_vars2, &crs, &mut rng);

    // Extract K from both
    let k1 = pvugc_decap(&attestation1, &armed1);
    let k2 = pvugc_decap(&attestation2, &armed2);

    // CRITICAL: Different statements should produce different K
    assert_ne!(k1, k2, "Different statements must produce different K");

    // Verify each K matches its own target^rho
    assert_eq!(k1, target1 * rho, "K1 should equal target1^rho");
    assert_eq!(k2, target2 * rho, "K2 should equal target2^rho");
}

#[test]
fn test_identity_element_protection() {
    // Test that identity elements are properly handled
    let mut rng = test_rng();

    let m = 2;
    let n = 2;
    let crs = CRS::<E>::generate_crs_per_slot(&mut rng, m, n);

    let gamma = vec![
        vec![Fr::from(1u64), Fr::from(0u64)], // Contains zero
        vec![Fr::from(0u64), Fr::from(1u64)],
    ];
    let a_consts = vec![<E as Pairing>::G1::zero().into_affine(); n];
    let b_consts = vec![<E as Pairing>::G2::zero().into_affine(); m];

    let x_vars = vec![<E as Pairing>::G1::generator().into_affine(); m];
    let y_vars = vec![<E as Pairing>::G2::generator().into_affine(); n];

    let mut target = PairingOutput::<E>::zero();
    for i in 0..m {
        for j in 0..n {
            let (_v_rand, v_var) = crs.v_for_slot(j);
            target += <E as Pairing>::pairing(x_vars[i], v_var.1) * gamma[i][j];
        }
    }

    let ppe = PPE {
        gamma,
        a_consts,
        b_consts,
        target,
    };

    let decomp = RankDecomp::decompose(&ppe.gamma);
    let bases = RankDecompPpeBases::build(&crs, &ppe, &decomp);

    let rho = Fr::rand(&mut rng);
    let armed_bases = pvugc_arm(&bases, &rho);

    // Generate valid attestation
    let attestation = ppe.commit_and_prove_rank_decomp(&x_vars, &y_vars, &crs, &mut rng);

    assert!(
        ppe.verify_rank_decomp(&attestation, &crs),
        "Attestation should verify"
    );

    let k = pvugc_decap(&attestation, &armed_bases);
    let expected = target * rho;

    assert_eq!(
        k, expected,
        "K should equal target^rho even with zeros in gamma"
    );
}

// Test to verify commitment binding property
#[test]
fn test_commitment_binding() {
    // This test verifies that commitments are binding - you can't change
    // the committed value after seeing the commitment
    let mut rng = test_rng();

    let m = 1;
    let n = 1;
    let crs = CRS::<E>::generate_crs_per_slot(&mut rng, m, n);

    let gamma = vec![vec![Fr::from(1u64)]];
    let a_consts = vec![<E as Pairing>::G1::zero().into_affine(); n];
    let b_consts = vec![<E as Pairing>::G2::zero().into_affine(); m];

    // Two different values
    let x_var1 = <E as Pairing>::G1::generator().into_affine();
    let x_var2 = (<E as Pairing>::G1::generator() * Fr::from(2u64)).into_affine();
    let y_var = <E as Pairing>::G2::generator().into_affine();

    let mut target1 = PairingOutput::<E>::zero();
    let (_v_rand, v_var) = crs.v_for_slot(0);
    target1 += <E as Pairing>::pairing(x_var1, v_var.1);

    let mut target2 = PairingOutput::<E>::zero();
    target2 += <E as Pairing>::pairing(x_var2, v_var.1);

    let ppe1 = PPE {
        gamma: gamma.clone(),
        a_consts: a_consts.clone(),
        b_consts: b_consts.clone(),
        target: target1,
    };
    let ppe2 = PPE {
        gamma,
        a_consts,
        b_consts,
        target: target2,
    };

    let rho = Fr::rand(&mut rng);

    let decomp1 = RankDecomp::decompose(&ppe1.gamma);
    let bases1 = RankDecompPpeBases::build(&crs, &ppe1, &decomp1);
    let armed1 = pvugc_arm(&bases1, &rho);

    let decomp2 = RankDecomp::decompose(&ppe2.gamma);
    let bases2 = RankDecompPpeBases::build(&crs, &ppe2, &decomp2);
    let armed2 = pvugc_arm(&bases2, &rho);

    // Generate attestations for different values
    let attestation1 =
        ppe1.commit_and_prove_rank_decomp(&vec![x_var1], &vec![y_var], &crs, &mut rng);
    let attestation2 =
        ppe2.commit_and_prove_rank_decomp(&vec![x_var2], &vec![y_var], &crs, &mut rng);

    // Extract K from both
    let k1 = pvugc_decap(&attestation1, &armed1);
    let k2 = pvugc_decap(&attestation2, &armed2);

    // Different committed values should produce different K
    assert_ne!(
        k1, k2,
        "Different committed values must produce different K (binding property)"
    );

    // Verify correctness
    assert_eq!(k1, target1 * rho);
    assert_eq!(k2, target2 * rho);
}

#[test]
fn test_randomness_independence() {
    // Verify that K is independent of the randomizers used in the commitment
    let mut rng = test_rng();

    let m = 2;
    let n = 2;
    let crs = CRS::<E>::generate_crs_per_slot(&mut rng, m, n);

    let gamma = vec![
        vec![Fr::from(1u64), Fr::from(2u64)],
        vec![Fr::from(3u64), Fr::from(4u64)],
    ];
    let a_consts = vec![<E as Pairing>::G1::zero().into_affine(); n];
    let b_consts = vec![<E as Pairing>::G2::zero().into_affine(); m];

    let x_vars = vec![<E as Pairing>::G1::generator().into_affine(); m];
    let y_vars = vec![<E as Pairing>::G2::generator().into_affine(); n];

    let mut target = PairingOutput::<E>::zero();
    for i in 0..m {
        for j in 0..n {
            let (_v_rand, v_var) = crs.v_for_slot(j);
            target += <E as Pairing>::pairing(x_vars[i], v_var.1) * gamma[i][j];
        }
    }

    let ppe = PPE {
        gamma,
        a_consts,
        b_consts,
        target,
    };

    let decomp = RankDecomp::decompose(&ppe.gamma);
    let bases = RankDecompPpeBases::build(&crs, &ppe, &decomp);

    let rho = Fr::rand(&mut rng);
    let armed_bases = pvugc_arm(&bases, &rho);

    // Generate multiple attestations with different randomizers
    let mut ks = Vec::new();
    for _ in 0..5 {
        let attestation = ppe.commit_and_prove_rank_decomp(&x_vars, &y_vars, &crs, &mut rng);
        assert!(
            ppe.verify_rank_decomp(&attestation, &crs),
            "All attestations should verify"
        );

        let k = pvugc_decap(&attestation, &armed_bases);
        ks.push(k);
    }

    // All K values should be identical (randomness independence)
    for k in &ks[1..] {
        assert_eq!(*k, ks[0], "K must be independent of commitment randomizers");
    }

    // Verify correctness
    let expected = target * rho;
    assert_eq!(ks[0], expected);
}
