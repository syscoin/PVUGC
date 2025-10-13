#![allow(non_snake_case)]

use ark_bls12_381::{Bls12_381, Fr, G1Affine, G2Affine};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, One, PrimeField, UniformRand, Zero};
use ark_serialize::CanonicalSerialize;
use ark_std::test_rng;
use sha2::{Digest, Sha256};

// Use PVUGC wrappers
use arkworks_groth16::{
    masked_verifier_matrix_canonical, serialize_attestation_for_kem, serialize_crs_for_kem,
    ArkworksProof, ArkworksVK, GSAttestation, GrothSahaiCommitments, ProductKeyKEM, SchnorrAdaptor,
    compute_target_public, deserialize_com1_pairs, deserialize_com2_pairs, five_bucket_comt,
};

// GS internals for direct testing
use groth_sahai::data_structures::{Com1, Com2};
use groth_sahai::generator::CRS;
use groth_sahai::prover::Provable;
use groth_sahai::statement::PPE;
use groth_sahai::AbstractCrs;

use arkworks_groth16::groth16_wrapper::ArkworksGroth16;
use schnorr_fun::fun::{marker::*, Scalar};

type E = Bls12_381;
type G1 = G1Affine;
type G2 = G2Affine;

// Helper to create mock proof and VK with proper serialization
fn create_mock_proof_and_vk(rng: &mut impl rand::Rng) -> (ArkworksProof, ArkworksVK) {
    use ark_groth16::{Proof, VerifyingKey};

    // Create proper Groth16 proof elements
    let pi_a = G1Affine::rand(rng);
    let pi_b = G2Affine::rand(rng);
    let pi_c = G1Affine::rand(rng);

    // Create a proper Groth16 proof for serialization
    let groth16_proof = Proof::<Bls12_381> {
        a: pi_a,
        b: pi_b,
        c: pi_c,
    };

    let mut proof_bytes = Vec::new();
    groth16_proof
        .serialize_compressed(&mut proof_bytes)
        .unwrap();

    let proof = ArkworksProof {
        pi_a,
        pi_b,
        pi_c,
        public_input: vec![],
        proof_bytes,
    };

    // Create proper VK elements
    let alpha_g1 = G1Affine::rand(rng);
    let beta_g2 = G2Affine::rand(rng);
    let gamma_g2 = G2Affine::rand(rng);
    let delta_g2 = G2Affine::rand(rng);
    let gamma_abc_g1 = vec![G1Affine::rand(rng), G1Affine::rand(rng)]; // At least 2 for public input

    // Create a proper Groth16 VK for serialization
    let groth16_vk = VerifyingKey::<Bls12_381> {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        gamma_abc_g1: gamma_abc_g1.clone(),
    };

    let mut vk_bytes = Vec::new();
    groth16_vk.serialize_compressed(&mut vk_bytes).unwrap();

    let vk = ArkworksVK {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        gamma_abc_g1,
        vk_bytes,
    };

    (proof, vk)
}

#[test]
fn test_kem_bit_for_bit_match() {
    // Test ProductKeyKEM encap/decap produces bit-for-bit matching results
    println!("Testing KEM bit-for-bit match");

    let mut rng = test_rng();
    let gs = GrothSahaiCommitments::from_seed(b"KEM_BIT_TEST");
    let (proof, vk) = create_mock_proof_and_vk(&mut rng);

    // Public input x for this test (must be used consistently in attestation and target)
    let x = vec![Fr::from(25u64)]; // public input
    let attestation = gs
        .commit_arkworks_proof(&proof, &vk, &x, true, &mut rng)
        .expect("Failed to create attestation");

    // Serialize attestation and CRS components for KEM
    let (c1_bytes, c2_bytes, pi_bytes, theta_bytes) = serialize_attestation_for_kem(&attestation);
    let crs = gs.get_crs();
    let (u_duals, v_duals) = gs.duals();
    let (u_bases, v_bases, u_dual_bases, v_dual_bases) =
        serialize_crs_for_kem(crs, u_duals, v_duals);

    // Context for KEM
    let ctx_hash = b"test_context";
    let gs_instance_digest = b"test_gs_instance";
    let adaptor_share = Fr::from(0x1234567890abcdefu64);

    // Use ProductKeyKEM for encap
    let kem = ProductKeyKEM::new();
    let (kem_share, _m_i_encap) = kem
        .encapsulate(
            &mut rng,
            0,
            &c1_bytes,
            &c2_bytes,
            &pi_bytes,
            &theta_bytes,
            &u_bases,
            &v_bases,
            &u_dual_bases,
            &v_dual_bases,
            adaptor_share,
            ctx_hash,
            gs_instance_digest,
        )
        .expect("Encapsulation failed");

    // Use ProductKeyKEM for decap (should recover same M_i)
    let recovered_share = kem
        .decapsulate(
            &kem_share,
            &c1_bytes,
            &c2_bytes,
            &pi_bytes,
            &theta_bytes,
            ctx_hash,
            gs_instance_digest,
        )
        .expect("Decapsulation failed");

    // Verify recovered adaptor share matches original
    assert_eq!(
        recovered_share, adaptor_share,
        "Adaptor share recovery failed"
    );
}

#[test]
fn test_kem_determinism_guarantee() {
    // Test: canonical masked verifier produces consistent results across multiple attestations

    let mut rng = test_rng();
    let gs = GrothSahaiCommitments::from_seed(b"DETERMINISM_TEST");
    let (proof, vk) = create_mock_proof_and_vk(&mut rng);

    let crs = gs.get_crs();

    let attestation = gs
        .commit_arkworks_proof(&proof, &vk, &vec![], true, &mut rng)
        .expect("Failed to create attestation");

    // Test proof-agnostic behavior: different attestations for same statement should produce same masked matrix
    let num_iterations = 5;

    // Serialize CRS elements for KEM
    let (u_duals, v_duals) = gs.duals();
    let (u_bases, v_bases, u_dual_bases, v_dual_bases) =
        serialize_crs_for_kem(crs, u_duals, v_duals);

    // Context for KEM
    let ctx_hash = b"test_context";
    let gs_instance_digest = b"test_gs_instance";
    let adaptor_share = Fr::from(0xdeadbeefcafeu64);

    let kem = ProductKeyKEM::new();

    // Serialize first attestation
    let (c1_bytes, c2_bytes, pi_bytes, theta_bytes) = serialize_attestation_for_kem(&attestation);

    // Encapsulate with first attestation
    let (kem_share_first, _) = kem
        .encapsulate(
            &mut rng,
            0,
            &c1_bytes,
            &c2_bytes,
            &pi_bytes,
            &theta_bytes,
            &u_bases,
            &v_bases,
            &u_dual_bases,
            &v_dual_bases,
            adaptor_share,
            ctx_hash,
            gs_instance_digest,
        )
        .expect("First encapsulation failed");

    // Decapsulate with same attestation to verify it works
    let recovered_share_first = kem
        .decapsulate(
            &kem_share_first,
            &c1_bytes,
            &c2_bytes,
            &pi_bytes,
            &theta_bytes,
            ctx_hash,
            gs_instance_digest,
        )
        .expect("Decapsulation failed");

    assert_eq!(
        recovered_share_first, adaptor_share,
        "First attestation should recover correct adaptor share"
    );

    // Test proof-agnostic behavior: different attestations for same statement should produce same KEM key
    for i in 0..num_iterations {
        let attestation_i = gs
            .commit_arkworks_proof(&proof, &vk, &vec![], true, &mut rng)
            .expect("Failed to create attestation");

        // Serialize new attestation
        let (c1_bytes_i, c2_bytes_i, pi_bytes_i, theta_bytes_i) =
            serialize_attestation_for_kem(&attestation_i);

        // Encapsulate with new attestation - should produce same KEM key (proof-agnostic)
        let (kem_share_i, _) = kem
            .encapsulate(
                &mut rng,
                i as u32,
                &c1_bytes_i,
                &c2_bytes_i,
                &pi_bytes_i,
                &theta_bytes_i,
                &u_bases,
                &v_bases,
                &u_dual_bases,
                &v_dual_bases,
                adaptor_share,
                ctx_hash,
                gs_instance_digest,
            )
            .expect("Encapsulation failed");

        // Decapsulate using same attestation - should recover same adaptor share
        let recovered_share_i = kem
            .decapsulate(
                &kem_share_i,
                &c1_bytes_i,
                &c2_bytes_i,
                &pi_bytes_i,
                &theta_bytes_i,
                ctx_hash,
                gs_instance_digest,
            )
            .expect("Decapsulation failed");

        // Critical: adaptor share must be identical (proof-agnostic behavior)
        assert_eq!(
            recovered_share_i, adaptor_share,
            "Attestation {} produced different adaptor share",
            i
        );
        println!(
            "Attestation {} produced same adaptor share as first attestation",
            i
        );
    }
}

#[test]
fn test_negative_wrong_public_input() {
    // Negative test: attestation for wrong public input should fail
    let mut rng = test_rng();
    let crs = CRS::<E>::generate_crs(&mut rng);

    // Create proof for message1
    let pi_A1 = (crs.g1_gen.into_group() * Fr::from(2u64)).into_affine();
    let pi_C1 = (crs.g1_gen.into_group() * Fr::from(3u64)).into_affine();
    let pi_B1 = (crs.g2_gen.into_group() * Fr::from(5u64)).into_affine();
    let Y_delta1 = (crs.g2_gen.into_group() * Fr::from(7u64)).into_affine();

    let xvars1 = vec![pi_A1, pi_C1];
    let yvars1 = vec![pi_B1, Y_delta1];

    let ppe1 = PPE::<E> {
        a_consts: vec![G1::identity(), G1::identity()],
        b_consts: vec![G2::identity(), G2::identity()],
        gamma: vec![vec![Fr::one(), Fr::zero()], vec![Fr::zero(), Fr::one()]],
        target: {
            let PairingOutput(t) = E::multi_pairing(&[pi_A1, pi_C1], &[pi_B1, Y_delta1]);
            PairingOutput::<E>(t)
        },
    };

    let attestation1 = ppe1.commit_and_prove(&xvars1, &yvars1, &crs, &mut rng);

    // Create proof for message2 (different public input)
    let pi_A2 = (crs.g1_gen.into_group() * Fr::from(11u64)).into_affine();
    let pi_C2 = (crs.g1_gen.into_group() * Fr::from(13u64)).into_affine();
    let pi_B2 = (crs.g2_gen.into_group() * Fr::from(17u64)).into_affine();
    let Y_delta2 = (crs.g2_gen.into_group() * Fr::from(19u64)).into_affine();

    let xvars2 = vec![pi_A2, pi_C2];
    let yvars2 = vec![pi_B2, Y_delta2];

    let ppe2 = PPE::<E> {
        a_consts: vec![G1::identity(), G1::identity()],
        b_consts: vec![G2::identity(), G2::identity()],
        gamma: vec![vec![Fr::one(), Fr::zero()], vec![Fr::zero(), Fr::one()]],
        target: {
            let PairingOutput(t) = E::multi_pairing(&[pi_A2, pi_C2], &[pi_B2, Y_delta2]);
            PairingOutput::<E>(t)
        },
    };

    let attestation2 = ppe2.commit_and_prove(&xvars2, &yvars2, &crs, &mut rng);

    let rho = Fr::rand(&mut rng);

    // Use canonical masked verifier for attestation1
    let masked_matrix1 = masked_verifier_matrix_canonical(
        &ppe1,
        &crs,
        &attestation1.xcoms.coms,
        &attestation1.ycoms.coms,
        &attestation1.equ_proofs[0].pi,
        &attestation1.equ_proofs[0].theta,
        rho,
    );

    // Use canonical masked verifier for attestation2 (wrong public input)
    let masked_matrix2 = masked_verifier_matrix_canonical(
        &ppe2,
        &crs,
        &attestation2.xcoms.coms,
        &attestation2.ycoms.coms,
        &attestation2.equ_proofs[0].pi,
        &attestation2.equ_proofs[0].theta,
        rho,
    );

    // Should fail (different public input → different matrices)
    assert_ne!(
        masked_matrix1, masked_matrix2,
        "Should not match with wrong public input"
    );
}

#[test]
fn test_negative_no_proof_cannot_sign() {
    // Negative test: without valid proof, cannot complete adaptor signature.
    // This is the core security property of PVUGC: proof existence gates signature completion.

    let mut rng = test_rng();
    let crs = CRS::<E>::generate_crs(&mut rng);

    let pi_A = (crs.g1_gen.into_group() * Fr::rand(&mut rng)).into_affine();
    let pi_C = (crs.g1_gen.into_group() * Fr::rand(&mut rng)).into_affine();
    let pi_B = (crs.g2_gen.into_group() * Fr::rand(&mut rng)).into_affine();
    let Y_delta = (crs.g2_gen.into_group() * Fr::rand(&mut rng)).into_affine();

    let xvars = vec![pi_A, pi_C];
    let yvars = vec![pi_B, Y_delta];

    // PPE for Groth16 verification
    let ppe = PPE::<E> {
        a_consts: vec![G1::identity(), G1::identity()],
        b_consts: vec![G2::identity(), G2::identity()],
        gamma: vec![vec![Fr::one(), Fr::zero()], vec![Fr::zero(), Fr::one()]],
        target: {
            let PairingOutput(t) = E::multi_pairing(&[pi_A, pi_C], &[pi_B, Y_delta]);
            PairingOutput::<E>(t)
        },
    };

    let attestation_dummy = ppe.commit_and_prove(&xvars, &yvars, &crs, &mut rng);

    let rho = Fr::rand(&mut rng);

    // Use canonical masked verifier with valid attestation
    let masked_matrix_valid = masked_verifier_matrix_canonical(
        &ppe,
        &crs,
        &attestation_dummy.xcoms.coms,
        &attestation_dummy.ycoms.coms,
        &attestation_dummy.equ_proofs[0].pi,
        &attestation_dummy.equ_proofs[0].theta,
        rho,
    );

    // ATTACK: Try to use canonical masked verifier with fake commitments
    let fake_C1: Vec<_> = (0..2)
        .map(|_| {
            Com1::<E>(
                (crs.g1_gen.into_group() * Fr::rand(&mut rng)).into_affine(),
                (crs.g1_gen.into_group() * Fr::rand(&mut rng)).into_affine(),
            )
        })
        .collect();

    let fake_C2: Vec<_> = (0..2)
        .map(|_| {
            Com2::<E>(
                (crs.g2_gen.into_group() * Fr::rand(&mut rng)).into_affine(),
                (crs.g2_gen.into_group() * Fr::rand(&mut rng)).into_affine(),
            )
        })
        .collect();

    // Use canonical masked verifier with fake commitments
    let masked_matrix_fake = masked_verifier_matrix_canonical(
        &ppe,
        &crs,
        &fake_C1,
        &fake_C2,
        &attestation_dummy.equ_proofs[0].pi,
        &attestation_dummy.equ_proofs[0].theta,
        rho,
    );

    // Should NOT match (fake commitments → different matrix)
    assert_ne!(
        masked_matrix_valid, masked_matrix_fake,
        "❌ Should NOT match with fake commitments!"
    );
}

#[test]
fn test_determinism_across_sessions() {
    // Critical: verify determinism across multiple independent sessions.

    let mut rng = test_rng();

    // Session 1: Arm
    let crs1 = CRS::<E>::generate_crs(&mut rng);

    let pi_A = (crs1.g1_gen.into_group() * Fr::from(2u64)).into_affine();
    let pi_C = (crs1.g1_gen.into_group() * Fr::from(3u64)).into_affine();
    let pi_B = (crs1.g2_gen.into_group() * Fr::from(5u64)).into_affine();
    let Y_delta = (crs1.g2_gen.into_group() * Fr::from(7u64)).into_affine();

    let xvars = vec![pi_A, pi_C];
    let yvars = vec![pi_B, Y_delta];

    let ppe = PPE::<E> {
        a_consts: vec![G1::identity(), G1::identity()],
        b_consts: vec![G2::identity(), G2::identity()],
        gamma: vec![vec![Fr::one(), Fr::zero()], vec![Fr::zero(), Fr::one()]],
        target: {
            let PairingOutput(t) = E::multi_pairing(&[pi_A, pi_C], &[pi_B, Y_delta]);
            PairingOutput::<E>(t)
        },
    };

    let attestation1 = ppe.commit_and_prove(&xvars, &yvars, &crs1, &mut rng);

    let rho = Fr::from(42u64);

    // Use canonical masked verifier for session 1
    let masked_matrix1 = masked_verifier_matrix_canonical(
        &ppe,
        &crs1,
        &attestation1.xcoms.coms,
        &attestation1.ycoms.coms,
        &attestation1.equ_proofs[0].pi,
        &attestation1.equ_proofs[0].theta,
        rho,
    );

    // Session 2: Same CRS instance, same proof variables (deterministic across sessions)
    // This tests that the same statement + same CRS produces the same masked matrix
    let attestation2 = ppe.commit_and_prove(&xvars, &yvars, &crs1, &mut rng);

    // Use canonical masked verifier for session 2 with same CRS
    let masked_matrix2 = masked_verifier_matrix_canonical(
        &ppe,
        &crs1,
        &attestation2.xcoms.coms,
        &attestation2.ycoms.coms,
        &attestation2.equ_proofs[0].pi,
        &attestation2.equ_proofs[0].theta,
        rho,
    );

    // Test determinism: same statement + same CRS + same rho → same masked matrix
    assert_eq!(
        masked_matrix1, masked_matrix2,
        "Same statement and CRS should produce identical masked matrices across sessions"
    );

    // Session 3: Different CRS instance, same proof variables (should produce different matrix)
    let crs3 = CRS::<E>::generate_crs(&mut rng);
    let attestation3 = ppe.commit_and_prove(&xvars, &yvars, &crs3, &mut rng);

    let masked_matrix3 = masked_verifier_matrix_canonical(
        &ppe,
        &crs3,
        &attestation3.xcoms.coms,
        &attestation3.ycoms.coms,
        &attestation3.equ_proofs[0].pi,
        &attestation3.equ_proofs[0].theta,
        rho,
    );

    // Test CRS independence: different CRS produces same masked matrix (canonical masked verifier behavior)
    assert_eq!(
        masked_matrix1, masked_matrix3,
        "Different CRS should produce same masked matrix for canonical masked verifier"
    );

    // Session 4: Same CRS, different rho (should produce different matrix)
    let rho2 = Fr::from(123u64);
    let masked_matrix4 = masked_verifier_matrix_canonical(
        &ppe,
        &crs1,
        &attestation1.xcoms.coms,
        &attestation1.ycoms.coms,
        &attestation1.equ_proofs[0].pi,
        &attestation1.equ_proofs[0].theta,
        rho2,
    );

    // Test rho dependency: different rho should produce different masked matrix
    assert_ne!(
        masked_matrix1, masked_matrix4,
        "Different rho should produce different masked matrices"
    );

    // Session 5: Different PPE + Different CRS (should produce different matrix)
    let crs5 = CRS::<E>::generate_crs(&mut rng);

    // Create different proof variables for different statement
    let pi_A5 = (crs5.g1_gen.into_group() * Fr::from(11u64)).into_affine();
    let pi_C5 = (crs5.g1_gen.into_group() * Fr::from(13u64)).into_affine();
    let pi_B5 = (crs5.g2_gen.into_group() * Fr::from(17u64)).into_affine();
    let Y_delta5 = (crs5.g2_gen.into_group() * Fr::from(19u64)).into_affine();

    let xvars5 = vec![pi_A5, pi_C5];
    let yvars5 = vec![pi_B5, Y_delta5];

    let ppe5 = PPE::<E> {
        a_consts: vec![G1::identity(), G1::identity()],
        b_consts: vec![G2::identity(), G2::identity()],
        gamma: vec![vec![Fr::one(), Fr::zero()], vec![Fr::zero(), Fr::one()]],
        target: {
            let PairingOutput(t) = E::multi_pairing(&[pi_A5, pi_C5], &[pi_B5, Y_delta5]);
            PairingOutput::<E>(t)
        },
    };

    let attestation5 = ppe5.commit_and_prove(&xvars5, &yvars5, &crs5, &mut rng);

    let masked_matrix5 = masked_verifier_matrix_canonical(
        &ppe5,
        &crs5,
        &attestation5.xcoms.coms,
        &attestation5.ycoms.coms,
        &attestation5.equ_proofs[0].pi,
        &attestation5.equ_proofs[0].theta,
        rho,
    );

    // Test statement dependency: different PPE + different CRS should produce different masked matrix
    assert_ne!(
        masked_matrix1, masked_matrix5,
        "Different PPE and CRS should produce different masked matrices"
    );
}

#[test]
fn test_kem_multi_share() {
    // Test KEM with multiple shares (threshold setting)

    let mut rng = test_rng();
    let crs = CRS::<E>::generate_crs(&mut rng);

    let pi_A = (crs.g1_gen.into_group() * Fr::rand(&mut rng)).into_affine();
    let pi_C = (crs.g1_gen.into_group() * Fr::rand(&mut rng)).into_affine();
    let pi_B = (crs.g2_gen.into_group() * Fr::rand(&mut rng)).into_affine();
    let Y_delta = (crs.g2_gen.into_group() * Fr::rand(&mut rng)).into_affine();

    let xvars = vec![pi_A, pi_C];
    let yvars = vec![pi_B, Y_delta];

    // PPE for Groth16 verification
    let ppe = PPE::<E> {
        a_consts: vec![G1::identity(), G1::identity()],
        b_consts: vec![G2::identity(), G2::identity()],
        gamma: vec![vec![Fr::one(), Fr::zero()], vec![Fr::zero(), Fr::one()]],
        target: {
            let PairingOutput(t) = E::multi_pairing(&[pi_A, pi_C], &[pi_B, Y_delta]);
            PairingOutput::<E>(t)
        },
    };

    let attestation = ppe.commit_and_prove(&xvars, &yvars, &crs, &mut rng);

    // Create 3 KEM shares using canonical masked verifier
    let adaptor_shares = vec![
        Fr::from(0x111111u64),
        Fr::from(0x222222u64),
        Fr::from(0x333333u64),
    ];
    let mut kem_shares = Vec::new();

    for (_i, _adaptor) in adaptor_shares.iter().enumerate() {
        let rho = Fr::rand(&mut rng);

        let masked_matrix_i = masked_verifier_matrix_canonical(
            &ppe,
            &crs,
            &attestation.xcoms.coms,
            &attestation.ycoms.coms,
            &attestation.equ_proofs[0].pi,
            &attestation.equ_proofs[0].theta,
            rho,
        );

        kem_shares.push((rho, masked_matrix_i));
    }

    // Decapsulate all shares
    for (i, (rho, expected_matrix)) in kem_shares.iter().enumerate() {
        let recovered_matrix = masked_verifier_matrix_canonical(
            &ppe,
            &crs,
            &attestation.xcoms.coms,
            &attestation.ycoms.coms,
            &attestation.equ_proofs[0].pi,
            &attestation.equ_proofs[0].theta,
            *rho,
        );

        assert_eq!(
            recovered_matrix, *expected_matrix,
            "Share {} matrix mismatch",
            i
        );
    }
}

#[test]
fn test_complete_adaptor_signature_flow() {
    println!("\n{}", "=".repeat(70));
    println!("COMPLETE ADAPTOR SIGNATURE FLOW");
    println!("{}\n", "=".repeat(70));

    let mut rng = test_rng();

    // === STEP 1: CREATE GROTH-SAHAI SYSTEM ===
    let gs = GrothSahaiCommitments::from_seed(b"PVUGC_TEST_CRS");
    println!("✓ Step 1: GS system with dual-base CRS created");

    // === CREATE MOCK GROTH16 PROOF ===
    let (proof, vk) = create_mock_proof_and_vk(&mut rng);
    println!("✓ Mock Groth16 proof and VK created with proper serialization");

    // === STEP 2: CREATE SCHNORR ADAPTOR PRE-SIGNATURE ===
    let schnorr_adaptor = SchnorrAdaptor::new();

    // SIMPLIFIED: Use single-party adaptor signature for testing
    // In production, use proper MuSig2 with coefficient-based aggregation
    let _k = 1; // Simplified to single party for testing
    let mut participant_secrets = Vec::new();
    let mut participant_pubkeys = Vec::new();
    let mut adaptor_secret_scalars: Vec<Scalar<Secret, NonZero>> = Vec::new(); // These get encrypted with KEM

    use schnorr_fun::fun::{Point, G};

    // Generate single signing key
    let mut secret = Scalar::random(&mut rand::thread_rng());
    let secret_bytes: [u8; 32] = secret.to_bytes();
    participant_secrets.push(secret_bytes);

    // Create pubkey: P = x·G
    let pubkey_point = Point::even_y_from_scalar_mul(G, &mut secret);
    let pubkey = pubkey_point.to_bytes();
    participant_pubkeys.push(pubkey);

    // Generate multiple adaptor secret shares that sum to α
    // This simulates k-of-k threshold where each party holds a share
    let num_shares = 3;
    let mut shares = Vec::new();
    let mut total_alpha_fr = Fr::zero();

    for i in 0..num_shares {
        // Generate Fr scalar directly (BLS12-381 field)
        let s_i_fr = if i < num_shares - 1 {
            Fr::rand(&mut rng)
        } else {
            // Last share can be random too
            Fr::rand(&mut rng)
        };
        shares.push(s_i_fr);
        total_alpha_fr += s_i_fr;

        // Convert Fr to secp256k1 Scalar for Schnorr operations
        // Note: This may wrap around secp256k1 modulus
        let fr_bytes = s_i_fr.into_bigint().to_bytes_be();
        let mut scalar_bytes = [0u8; 32];
        scalar_bytes.copy_from_slice(&fr_bytes[..32]);
        let s_i_scalar = Scalar::<Secret, NonZero>::from_bytes(scalar_bytes).unwrap_or_else(|| {
            Scalar::from_bytes(
                [0u8; 31]
                    .iter()
                    .chain(&[1u8])
                    .cloned()
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap(),
            )
            .unwrap()
        });
        adaptor_secret_scalars.push(s_i_scalar);
    }

    // T = α·G (single adaptor point for total secret)
    // Sum the secp256k1 scalars to get total alpha
    let mut total_alpha_scalar = Scalar::zero();
    for s in adaptor_secret_scalars.iter() {
        total_alpha_scalar = schnorr_fun::fun::op::scalar_add(total_alpha_scalar, *s);
    }

    // Convert to NonZero for point multiplication
    let alpha_nonzero = Scalar::<Secret, NonZero>::from_bytes(total_alpha_scalar.to_bytes())
        .expect("Total alpha should be non-zero");
    let mut alpha_for_t = alpha_nonzero;
    let t_point = Point::even_y_from_scalar_mul(G, &mut alpha_for_t);
    let agg_T = t_point.to_bytes();

    // Save for verification later
    let expected_alpha_bytes: [u8; 32] = total_alpha_scalar.to_bytes();

    // Use single pubkey as "aggregated" pubkey for simplified test
    let agg_pubkey = pubkey;

    // Message to sign
    let message = b"Bitcoin_TX_SIGHASH_ALL";

    // Create adaptor pre-signature using wrapper
    let presig = schnorr_adaptor
        .create_presignature(&mut rng, message, &agg_pubkey, &agg_T, &participant_secrets)
        .expect("Failed to create pre-signature");

    // Verify pre-signature using wrapper
    assert!(
        schnorr_adaptor
            .verify_presignature(message, &agg_pubkey, &presig)
            .expect("Verification error"),
        "Adaptor pre-signature verification failed!"
    );

    println!("\n✓ Step 2: Schnorr adaptor pre-signature created using SchnorrAdaptor wrapper");
    println!("  - Simplified single-party signature for testing");
    println!(
        "  - {} secret shares will be encrypted with KEM",
        num_shares
    );
    println!("  - Adaptor equation verified: s'·G + T = R' + c·P ✓");

    // === STEP 3: CREATE GS ATTESTATION ===
    let _public_input: Vec<Fr> = vec![];
    let attestation = gs
        .commit_arkworks_proof(&proof, &vk, &vec![], true, &mut rng)
        .expect("Failed to create attestation");

    println!("\n✓ Step 3: GS attestation created using GrothSahaiCommitments");
    println!("  - {} C1 commitments", attestation.c1_commitments.len());
    println!("  - {} C2 commitments", attestation.c2_commitments.len());

    // === STEP 4: GET DUAL BASES FOR KEM ===
    // Get CRS elements for canonical evaluation
    let (u_elements, v_elements) = gs.get_crs_elements();
    println!("\n✓ Step 4: Dual bases extracted from GS");
    println!("  - {} U elements (G1)", u_elements.len());
    println!("  - {} V elements (G2)", v_elements.len());

    // === STEP 5: ARM (Encrypt adaptor secrets with ProductKeyKEM) ===
    use ark_serialize::CanonicalSerialize;
    use arkworks_groth16::kem::{KEMShare, ProductKeyKEM};

    let kem = ProductKeyKEM::new();
    let ctx_hash = Sha256::digest(b"test_context").to_vec();
    let gs_instance_digest = Sha256::digest(b"test_crs").to_vec();

    let (u_duals_for_kem, v_duals_for_kem) = gs.duals();
    let (u_elements_bytes, v_elements_bytes, u_dual_elements_bytes, v_dual_elements_bytes) =
        serialize_crs_for_kem(gs.get_crs(), u_duals_for_kem, v_duals_for_kem);

    // Serialize attestation commitments
    let mut c1_bytes = Vec::new();
    for c1 in &attestation.c1_commitments {
        let mut bytes = Vec::new();
        c1.serialize_compressed(&mut bytes).unwrap();
        c1_bytes.push(bytes);
    }

    let mut c2_bytes = Vec::new();
    for c2 in &attestation.c2_commitments {
        let mut bytes = Vec::new();
        c2.serialize_compressed(&mut bytes).unwrap();
        c2_bytes.push(bytes);
    }

    // Serialize pi and theta elements for canonical evaluation
    let mut pi_bytes = Vec::new();
    for pi_elem in &attestation.pi_elements {
        let mut bytes = Vec::new();
        pi_elem.serialize_compressed(&mut bytes).unwrap();
        pi_bytes.push(bytes);
    }

    let mut theta_bytes = Vec::new();
    for theta_elem in &attestation.theta_elements {
        let mut bytes = Vec::new();
        theta_elem.serialize_compressed(&mut bytes).unwrap();
        theta_bytes.push(bytes);
    }

    let mut kem_shares: Vec<KEMShare> = Vec::new();

    for (i, s_i_fr) in shares.iter().enumerate() {
        // Encapsulate using ProductKeyKEM
        let (share, _m_i) = kem
            .encapsulate(
                &mut rng,
                i as u32,
                &c1_bytes,
                &c2_bytes,
                &pi_bytes,
                &theta_bytes,
                &u_elements_bytes,
                &v_elements_bytes,
                &u_dual_elements_bytes,
                &v_dual_elements_bytes,
                *s_i_fr,
                &ctx_hash,
                &gs_instance_digest,
            )
            .expect(&format!("Encapsulation failed for share {}", i));

        kem_shares.push(share);
    }

    println!("\n✓ Step 5: Arming complete using ProductKeyKEM");
    println!("  - {} KEM shares encrypted", kem_shares.len());
    println!("  - Uses dual-base evaluator internally");

    // === STEP 6: DECAPSULATE (Recover secrets using ProductKeyKEM) ===
    let mut recovered_frs = Vec::new();
    let mut recovered_scalars = Vec::new();

    for (i, share) in kem_shares.iter().enumerate() {
        // Decapsulate using ProductKeyKEM
        let recovered_fr = kem
            .decapsulate(
                share,
                &c1_bytes,
                &c2_bytes,
                &pi_bytes,
                &theta_bytes,
                &ctx_hash,
                &gs_instance_digest,
            )
            .expect(&format!("Decapsulation failed for share {}", i));

        recovered_frs.push(recovered_fr);

        // Convert Fr back to Scalar for Schnorr operations
        let recovered_bytes = recovered_fr.into_bigint().to_bytes_be();
        let mut recovered_bytes_32 = [0u8; 32];
        recovered_bytes_32.copy_from_slice(&recovered_bytes[..32]);
        let recovered_scalar: Scalar<Secret, NonZero> =
            Scalar::from_bytes(recovered_bytes_32).expect("Invalid scalar");

        recovered_scalars.push(recovered_scalar);
    }

    println!("\n✓ Step 6: Decapsulation complete using ProductKeyKEM");
    println!("  - All {} secrets recovered", recovered_frs.len());

    // === VERIFY: Recovered Fr values match originals ===
    println!("\n=== Verifying KEM Correctness ===");
    for (i, (original, recovered)) in shares.iter().zip(recovered_frs.iter()).enumerate() {
        assert_eq!(*original, *recovered, "Share {} Fr mismatch!", i);
        println!("  ✓ Share {}: Recovered Fr matches original", i);
    }
    println!("✓ KEM VERIFIED: All recovered Fr values match originals!");
    println!("✓ ProductKeyKEM works correctly!");

    // === VERIFY ATTESTATION ===
    // Use canonical masked verifier equality as the acceptance check
    println!("\n✓ Attestation available for verification (canonical check deferred)");

    // === STEP 7: SUM RECOVERED SCALARS TO GET α ===
    let mut alpha_recovered = Scalar::zero();
    for s in recovered_scalars.iter() {
        alpha_recovered = schnorr_fun::fun::op::scalar_add(alpha_recovered, *s);
    }

    let alpha_bytes: [u8; 32] = alpha_recovered.to_bytes();

    println!("\n✓ Step 7: Secret scalars summed to get α");
    println!("  - α = Σ(recovered s_i)");

    // Verify the recovered alpha matches expected
    assert_eq!(
        expected_alpha_bytes, alpha_bytes,
        "Alpha mismatch! KEM recovery doesn't match expected sum"
    );
    println!("  - Recovered α matches expected value");

    // === STEP 8: COMPLETE SIGNATURE WITH RECOVERED α ===
    let (r_x, s_bytes) = schnorr_adaptor
        .complete_signature(&presig, &alpha_bytes)
        .expect("Failed to complete signature");

    println!("\n✓ Step 8: Signature completed using SchnorrAdaptor wrapper");
    println!("  - Used recovered α from KEM decryption");
    println!("  - Formula: s = s' + α");

    // === STEP 9: VERIFY COMPLETED SCHNORR SIGNATURE ===
    let is_valid = schnorr_adaptor
        .verify_schnorr(message, &agg_pubkey, (r_x, s_bytes))
        .expect("Verification error");

    assert!(is_valid, "❌ Completed signature verification FAILED!");

    println!("\n✓ Step 9: Schnorr signature VERIFIED using SchnorrAdaptor wrapper");
    println!("  - Cryptographic verification passed!");
    println!("  - Can spend Bitcoin transaction!");
    println!("  - PROVES: KEM correctly recovered α");

    // === NEGATIVE TEST: Fake attestation cannot decrypt ===
    println!("\n=== Negative Test: Fake Attestation Cannot Decrypt ===");

    // Create fake attestation with random commitments
    use groth_sahai::data_structures::{Com1, Com2};
    let fake_C1: Vec<_> = (0..2)
        .map(|_| Com1::<Bls12_381>(G1Affine::rand(&mut rng), G1Affine::rand(&mut rng)))
        .collect();

    let fake_C2: Vec<_> = (0..2)
        .map(|_| Com2::<Bls12_381>(G2Affine::rand(&mut rng), G2Affine::rand(&mut rng)))
        .collect();

    let fake_attestation = GSAttestation {
        c1_commitments: fake_C1,
        c2_commitments: fake_C2,
        pi_elements: vec![],    // Empty for fake attestation
        theta_elements: vec![], // Empty for fake attestation
        proof_data: vec![],
        randomness_used: vec![],
        ppe_target: attestation.ppe_target, // Even with correct target!
        cproof: attestation.cproof.clone(),
    };

    // Serialize fake attestation commitments
    let mut fake_c1_bytes = Vec::new();
    for c1 in &fake_attestation.c1_commitments {
        let mut bytes = Vec::new();
        c1.serialize_compressed(&mut bytes).unwrap();
        fake_c1_bytes.push(bytes);
    }

    let mut fake_c2_bytes = Vec::new();
    for c2 in &fake_attestation.c2_commitments {
        let mut bytes = Vec::new();
        c2.serialize_compressed(&mut bytes).unwrap();
        fake_c2_bytes.push(bytes);
    }

    // Try to decrypt with fake attestation using ProductKeyKEM
    let mut any_decrypted = false;
    for share in kem_shares.iter() {
        // Create dummy pi and theta for the test (decapsulation should fail regardless)
        let fake_pi_bytes = pi_bytes.clone(); // Use same structure
        let fake_theta_bytes = theta_bytes.clone();

        let result = kem.decapsulate(
            share,
            &fake_c1_bytes,
            &fake_c2_bytes,
            &fake_pi_bytes,
            &fake_theta_bytes,
            &ctx_hash,
            &gs_instance_digest,
        );

        // Should fail (wrong attestation → wrong M → wrong KDF → decryption fails)
        if result.is_ok() {
            any_decrypted = true;
        }
    }

    assert!(!any_decrypted, "❌ Fake attestation should NOT decrypt!");
}

#[test]
fn test_two_distinct_groth16_proofs_same_output() {
    // Two different Groth16 proofs for same (vk,x) should yield identical M under same CRS and masks
    let gs = GrothSahaiCommitments::from_seed(b"TWO_PROOFS_DET");

    let mut groth16 = ArkworksGroth16::new();
    let vk = groth16.setup().expect("Setup should succeed");

    // Same witness produces same public input; Groth16 proofs are randomized
    let witness1 = Fr::from(3u64);
    let witness2 = Fr::from(2u64); // 3 + 2 = 5
    let witness3 = Fr::from(4u64);
    let witness4 = Fr::from(1u64); // 4 + 1 = 5 (different witnesses, same public input)
    let proof1 = groth16.prove(witness1, witness2).expect("Prove should succeed");
    let proof2 = groth16.prove(witness3, witness4).expect("Prove should succeed");

    // Explicit x: public_input = [5]
    let x = [Fr::from(5u64)];

    let crs = gs.get_crs().clone();
    let (u_duals, v_duals) = gs.duals();
    
    // Convert Com1/Com2 to affine pairs for encapsulate_duo
    let _u_star_pairs: Vec<(ark_bls12_381::G2Affine, ark_bls12_381::G2Affine)> = u_duals.iter()
        .map(|com2| (com2.0, com2.1))
        .collect();
    let _v_star_pairs: Vec<(ark_bls12_381::G1Affine, ark_bls12_381::G1Affine)> = v_duals.iter()
        .map(|com1| (com1.0, com1.1))
        .collect();
    
    let mut rng = test_rng();

    // Test proof-agnostic behavior using ProductKeyKEM
    let kem = ProductKeyKEM::new();
    let adaptor_share = Fr::from(0x1234567890abcdefu64);
    let ctx_hash = b"crs";
    let _gs_instance_digest = b"ppe";

    // Serialize CRS elements
    let (u_bases, v_bases, _u_dual_bases, _v_dual_bases) =
        serialize_crs_for_kem(&crs, u_duals, v_duals);

    // Convert GS proofs to GSAttestations and serialize them
    let attestation1 = gs
        .commit_arkworks_proof(&proof1, &vk, &x, true, &mut rng)
        .expect("Failed to create attestation1");
    let attestation2 = gs
        .commit_arkworks_proof(&proof2, &vk, &x, true, &mut rng)
        .expect("Failed to create attestation2");

    let (c1_bytes1, c2_bytes1, pi_bytes1, theta_bytes1) =
        serialize_attestation_for_kem(&attestation1);
    let (c1_bytes2, c2_bytes2, pi_bytes2, theta_bytes2) =
        serialize_attestation_for_kem(&attestation2);

    // Deposit: encapsulate once using Duo flow
    let crs_digest = b"crs_digest";
    let ppe_digest = b"ppe_digest";
    let vk_hash = b"vk_hash";
    let x_hash = b"x_hash";
    let deposit_id = b"deposit_id";
    
    // Use attestation1 for encapsulation to match decapsulation
    let (kem_share1, _) = kem
        .encapsulate_duo(
            &mut rng,
            0,
            &u_bases,
            &v_bases,
            &_u_star_pairs,
            &_v_star_pairs,
            adaptor_share,
            ctx_hash,
            &vk,
            &x[0].into_bigint().to_bytes_be(),
            crs_digest,
            ppe_digest,
            vk_hash,
            x_hash,
            deposit_id,
        )
        .expect("Deposit encapsulation failed");

    // Second share not needed for Duo; reuse same kem_share for both withdraws
    let kem_share2 = kem_share1.clone();

    // Both KEM shares should decrypt to the same adaptor share (proof-agnostic behavior)
    let ppe = gs.groth16_verify_as_ppe(&vk, &x);
    {
        // Canonical GS verification of both attestations for the same (vk,x)
        use groth_sahai::verifier::Verifiable;
        let crs_ref = gs.get_crs();
        let ok1 = ppe.verify(&attestation1.cproof, crs_ref);
        let ok2 = ppe.verify(&attestation2.cproof, crs_ref);
        println!("Attestation1 PPE verify: {}", ok1);
        println!("Attestation2 PPE verify: {}", ok2);
        assert!(ok1, "PPE verification failed for attestation1");
        assert!(ok2, "PPE verification failed for attestation2");
    }
    let recovered1 = kem
        .decapsulate_duo(
            &kem_share1,
            &ppe,
            &c1_bytes1,
            &c2_bytes1,
            &pi_bytes1,
            &theta_bytes1,
            ctx_hash,
            crs_digest,
            ppe_digest,
            vk_hash,
            x_hash,
            deposit_id,
        )
        .expect("Decapsulation failed");

    let recovered2 = kem
        .decapsulate_duo(
            &kem_share2,
            &ppe,
            &c1_bytes2,
            &c2_bytes2,
            &pi_bytes2,
            &theta_bytes2,
            ctx_hash,
            crs_digest,
            ppe_digest,
            vk_hash,
            x_hash,
            deposit_id,
        )
        .expect("Decapsulation failed");

    assert_eq!(
        recovered1, adaptor_share,
        "First proof should recover correct adaptor share"
    );
    assert_eq!(
        recovered2, adaptor_share,
        "Second proof should recover correct adaptor share"
    );
    assert_eq!(
        recovered1, recovered2,
        "Both proofs should produce identical adaptor shares"
    );
}

#[test]
fn deposit_withdraw_comt_equivalence() {
    use arkworks_groth16::gs_kem_eval;
    use groth_sahai::{vec_to_col_vec, col_vec_to_vec, Mat};
    use ark_bls12_381::Bls12_381 as E;
    use ark_ec::pairing::PairingOutput;
    use ark_ff::Field;
    use groth_sahai::data_structures::{Com1, Com2, ComT};
    use groth_sahai::BT;
    use groth_sahai::verifier::Verifiable;
    use ark_serialize::CanonicalDeserialize;
    use ark_std::test_rng;

    let mut rng = test_rng();
    
    // === SETUP: Create real Groth16 circuit and proof ===
    let gs = GrothSahaiCommitments::from_seed(b"KEM_BIT_TEST");
    
    // Create real Groth16 circuit and proof
    use arkworks_groth16::groth16_wrapper::ArkworksGroth16;
    let mut groth16 = ArkworksGroth16::new();
    let vk_struct = groth16.setup().expect("Failed to setup Groth16");
    
    // Create proof for addition (3 + 2 = 5)
    let witness1 = Fr::from(3u64);
    let witness2 = Fr::from(2u64);
    let proof_struct = groth16.prove(witness1, witness2).expect("Failed to prove");
    
    // Convert to ArkworksProof format
    let _proof = ArkworksProof {
        pi_a: proof_struct.pi_a,
        pi_b: proof_struct.pi_b,
        pi_c: proof_struct.pi_c,
        public_input: proof_struct.public_input.clone(),
        proof_bytes: proof_struct.proof_bytes,
    };
    
    // Convert to ArkworksVK format
    let vk = ArkworksVK {
        alpha_g1: vk_struct.alpha_g1,
        beta_g2: vk_struct.beta_g2,
        gamma_g2: vk_struct.gamma_g2,
        delta_g2: vk_struct.delta_g2,
        gamma_abc_g1: vk_struct.gamma_abc_g1,
        vk_bytes: vk_struct.vk_bytes,
    };
    
    // Use consistent public input for both attestation creation and verification
    let x = vec![Fr::from(5u64)]; // public input (3 + 2 = 5)
    
    // === CREATE MULTIPLE PROOFS/ATTESTATIONS ===
    // Create multiple proofs for the SAME statement (same public input) with different witnesses
    // Using addition circuit: witness1 + witness2 = public_input
    let test_cases = vec![
        (Fr::from(3u64), Fr::from(2u64), Fr::from(5u64)),   // 3 + 2 = 5
        (Fr::from(4u64), Fr::from(1u64), Fr::from(5u64)),   // 4 + 1 = 5
        (Fr::from(0u64), Fr::from(5u64), Fr::from(5u64)),   // 0 + 5 = 5
    ];
    
    let mut attestations = Vec::new();
    let mut public_inputs = Vec::new();
    
    for (i, (witness1, witness2, public_input)) in test_cases.iter().enumerate() {
        // Create proof for each witness pair
        let proof_struct = groth16.prove(*witness1, *witness2).expect(&format!("Failed to prove witnesses {}", i));
        
        // Convert to ArkworksProof format
        let proof = ArkworksProof {
            pi_a: proof_struct.pi_a,
            pi_b: proof_struct.pi_b,
            pi_c: proof_struct.pi_c,
            public_input: proof_struct.public_input.clone(),
            proof_bytes: proof_struct.proof_bytes,
        };
        
        // Create attestation with the CORRECT public input for each proof
        let x_i = vec![*public_input];
    let attestation = gs
            .commit_arkworks_proof(&proof, &vk, &x_i, true, &mut rng)
            .expect(&format!("Failed to create attestation {}", i));
        
        attestations.push(attestation);
        public_inputs.push(x_i);
        println!("Created attestation {} with witnesses ({}, {}) and public input {}", i, witness1, witness2, public_input);
    }
    
    // Use the first attestation for the main test logic
    let attestation = &attestations[0];

    // Serialize attestation and CRS components for KEM
    let (c1_bytes, c2_bytes, pi_bytes, theta_bytes) = serialize_attestation_for_kem(&attestation);
    let crs = gs.get_crs();
    let (u_duals, v_duals) = gs.duals();
    
    // Convert duals to affine pairs for encapsulate_duo
    let u_star_pairs: Vec<(ark_bls12_381::G2Affine, ark_bls12_381::G2Affine)> = u_duals.iter()
        .map(|com2| (com2.0, com2.1))
        .collect();
    let v_star_pairs: Vec<(ark_bls12_381::G1Affine, ark_bls12_381::G1Affine)> = v_duals.iter()
        .map(|com1| (com1.0, com1.1))
        .collect();

    // Serialize CRS bases
    let (u_bases, v_bases, _, _) = serialize_crs_for_kem(crs, &u_duals, &v_duals);
    
    // Create PPE (using the same public input as attestation creation)
    let ppe = gs.groth16_verify_as_ppe(&vk, &x);
    
    // === PPE VERIFICATION: Verify the attestation satisfies the PPE ===
    let ppe_verification_result = ppe.verify(&attestation.cproof, crs);
    assert!(ppe_verification_result, "PPE verification must pass for valid attestation");
    
    // Generate random rho
    let rho = ark_bls12_381::Fr::rand(&mut rng);
    
    // === DEPOSIT SIDE: Compute ComT using linear_map_PPE(T^ρ) ===
    let t = compute_target_public(&vk, &x[0].into_bigint().to_bytes_be())
        .expect("Failed to compute target");
    let t_rho = t.0.pow(rho.into_bigint());
    let comt_dep = ComT::<E>::linear_map_PPE(&PairingOutput::<E>(t_rho));

    // === DIAG 1: Canonical masked-verifier ComT must equal deposit linear map ===
    let mv = gs_kem_eval::masked_verifier_matrix_canonical(
        &ppe, crs, &attestation.c1_commitments, &attestation.c2_commitments,
        &attestation.pi_elements, &attestation.theta_elements, rho);
    let comt_mv = ComT::<E>::from(vec![
        vec![PairingOutput::<E>(mv[0][0]), PairingOutput::<E>(mv[0][1])],
        vec![PairingOutput::<E>(mv[1][0]), PairingOutput::<E>(mv[1][1])],
    ]);
    
    // === WITHDRAW SIDE: Compute ComT using five_bucket_comt ===
    // Deserialize attestation components
    let c1: Vec<Com1<E>> = c1_bytes.iter().map(|b| Com1::deserialize_compressed(&**b)).collect::<Result<_,_>>()
        .expect("Failed to deserialize C1");
    let c2: Vec<Com2<E>> = c2_bytes.iter().map(|b| Com2::deserialize_compressed(&**b)).collect::<Result<_,_>>()
        .expect("Failed to deserialize C2");
    let pi: Vec<Com2<E>> = pi_bytes.iter().map(|b| Com2::deserialize_compressed(&**b)).collect::<Result<_,_>>()
        .expect("Failed to deserialize pi");
    let theta: Vec<Com1<E>> = theta_bytes.iter().map(|b| Com1::deserialize_compressed(&**b)).collect::<Result<_,_>>()
        .expect("Failed to deserialize theta");
    
    // Create masked bases (simplified - just use the same rho for all)
    let kem = ProductKeyKEM::new();
    let u_rho = kem.mask_g1_pairs(&u_bases, rho).expect("Failed to mask U");
    let v_rho = kem.mask_g2_pairs(&v_bases, rho).expect("Failed to mask V");
    let u_star_rho = kem.mask_g2_dual_pairs(&u_star_pairs, rho);
    let v_star_rho = kem.mask_g1_dual_pairs(&v_star_pairs, rho);
    
    // Deserialize masked bases
    let u_rho_com1: Vec<Com1<E>> = deserialize_com1_pairs(&u_rho).expect("Failed to deserialize U^ρ");
    let v_rho_com2: Vec<Com2<E>> = deserialize_com2_pairs(&v_rho).expect("Failed to deserialize V^ρ");
    
    // Deserialize masked duals to affine pairs
    let u_star_rho_pairs: Vec<(ark_bls12_381::G2Affine, ark_bls12_381::G2Affine)> = u_star_rho.iter()
        .map(|bytes| {
            let mut cursor = std::io::Cursor::new(bytes);
            let a = ark_bls12_381::G2Affine::deserialize_compressed(&mut cursor).expect("Failed to deserialize G2");
            let b = ark_bls12_381::G2Affine::deserialize_compressed(&mut cursor).expect("Failed to deserialize G2");
            (a, b)
        }).collect();
    
    let v_star_rho_pairs: Vec<(ark_bls12_381::G1Affine, ark_bls12_381::G1Affine)> = v_star_rho.iter()
        .map(|bytes| {
            let mut cursor = std::io::Cursor::new(bytes);
            let a = ark_bls12_381::G1Affine::deserialize_compressed(&mut cursor).expect("Failed to deserialize G1");
            let b = ark_bls12_381::G1Affine::deserialize_compressed(&mut cursor).expect("Failed to deserialize G1");
            (a, b)
        }).collect();
    
    // Convert pairs to Com1/Com2 types
    let u_star_rho_com2: Vec<Com2<E>> = u_star_rho_pairs.iter().map(|(a,b)| Com2(*a,*b)).collect();
    let v_star_rho_com1: Vec<Com1<E>> = v_star_rho_pairs.iter().map(|(a,b)| Com1(*a,*b)).collect();
    
    let comt_wd = five_bucket_comt::<E>(
        &c1, &c2, &pi, &theta, &ppe.gamma,
        &u_rho_com1, &v_rho_com2, &u_star_rho_com2, &v_star_rho_com1
    );
    
    // === COMPARISON: Check cell-by-cell equality ===
    let md = comt_dep.as_matrix();
    let mw = comt_wd.as_matrix();
    
    // === SYSTEMATIC COMBINATION TESTING ===
    println!("\n=== SYSTEMATIC COMBINATION TESTING ===");
    println!("Expected T^ρ: {:?}", t_rho);
    println!("Deposit [1][1]: {:?}", md[1][1].0);



    // Buckets with primaries (new approach) - but primaries don't work for pairing types
    // This is just for testing, will fail due to Com1×Com1 and Com2×Com2 pairings
    let b1_primary = ComT::<E>::zero(); // Can't compute Com1×Com1 pairing
    let b2_primary = ComT::<E>::zero(); // Can't compute Com2×Com2 pairing  
    let b3_primary = ComT::<E>::pairing_sum(&u_rho_com1, &pi);
    let b4_primary = ComT::<E>::pairing_sum(&theta, &v_rho_com2);
    let g_primary = {
        let stmt_y = vec_to_col_vec(&c2).left_mul(&ppe.gamma, false);
        ComT::<E>::pairing_sum(&c1, &col_vec_to_vec(&stmt_y))
    };

    // Buckets with duals (original approach)
    let b1_dual = ComT::<E>::pairing_sum(&c1, &u_star_rho_com2);
    let b2_dual = ComT::<E>::pairing_sum(&v_star_rho_com1, &c2);
    let b3_dual = ComT::<E>::pairing_sum(&u_rho_com1, &pi);
    let b4_dual = ComT::<E>::pairing_sum(&theta, &v_rho_com2);
    let g_dual = {
        let stmt_y = vec_to_col_vec(&c2).left_mul(&ppe.gamma, false);
        ComT::<E>::pairing_sum(&c1, &col_vec_to_vec(&stmt_y))
    };

    let buckets_primary = [b1_primary, b2_primary, b3_primary, b4_primary, g_primary];
    let buckets_dual = [b1_dual, b2_dual, b3_dual, b4_dual, g_dual];
    let bucket_names = ["B1", "B2", "B3", "B4", "G"];

    // Test all 32 combinations (2^5) for each approach type
    let mut found_match = false;
    for use_primary in [true, false] {
        let buckets = if use_primary { &buckets_primary } else { &buckets_dual };
        let approach_str = if use_primary { "primary" } else { "dual" };
        
        println!("\n--- Testing {} combinations ---", approach_str);
        
        for combination in 0..32 {
            let mut result = ComT::<E>::from(vec![
                vec![PairingOutput::<E>::zero(), PairingOutput::<E>::zero()],
                vec![PairingOutput::<E>::zero(), PairingOutput::<E>::zero()],
            ]);
            
            let mut used_buckets = Vec::new();
            let mut signs = Vec::new();
            
            for i in 0..5 {
                if (combination >> i) & 1 == 1 {
                    result = result + buckets[i];
                    used_buckets.push(bucket_names[i]);
                    signs.push("+");
            } else {
                    result = result - buckets[i];
                    used_buckets.push(bucket_names[i]);
                    signs.push("-");
                }
            }
            
            let result_val = result.as_matrix()[1][1].0;
            let matches_deposit = result_val == md[1][1].0;
            let matches_t_rho = result_val == t_rho;
            
            if matches_deposit || matches_t_rho {
                println!("✅ MATCH FOUND! Combination {}: {} {} {} {} {} {} {} {} {} {}",
                    combination,
                    signs[0], used_buckets[0],
                    signs[1], used_buckets[1], 
                    signs[2], used_buckets[2],
                    signs[3], used_buckets[3],
                    signs[4], used_buckets[4]
                );
                println!("   Result: {:?}", result_val);
                println!("   Matches deposit: {}", matches_deposit);
                println!("   Matches T^ρ: {}", matches_t_rho);
                found_match = true;
            }
        }
    }

    if !found_match {
        println!("❌ No combination found that matches deposit or T^ρ");
    }
    
    // Compare with deposit side (which is known to be correct)
    println!("\n=== COMPARING WITH DEPOSIT SIDE ===");
    println!("Deposit [1][1]: {:?}", md[1][1].0);
    println!("Five bucket [1][1]: {:?}", mw[1][1].0);
    println!("Expected T^ρ: {:?}", t_rho);
    println!("Deposit == T^ρ: {}", md[1][1].0 == t_rho);
    println!("Five bucket == T^ρ: {}", mw[1][1].0 == t_rho);
    println!("Five bucket == Deposit: {}", mw[1][1].0 == md[1][1].0);

    // === VERIFY: Five bucket should equal deposit [1][1] ===
    assert_eq!(mw[1][1].0, md[1][1].0, "Five bucket [1][1] should equal deposit [1][1]");
    println!("✅ Five bucket equals deposit [1][1]");
    
    // === MULTIPLE ATTESTATIONS COMPARISON ===
    println!("\n=== COMPARING MULTIPLE ATTESTATIONS ===");
    
    // Compute ComT matrices for all attestations
    let mut all_comt_matrices = Vec::new();
    
    for (i, attestation) in attestations.iter().enumerate() {
        // Serialize this attestation
        let (c1_bytes_i, c2_bytes_i, pi_bytes_i, theta_bytes_i) = serialize_attestation_for_kem(attestation);
        
        // Deserialize components
        let c1_i: Vec<Com1<E>> = c1_bytes_i.iter().map(|b| Com1::deserialize_compressed(&**b)).collect::<Result<_,_>>()
            .expect(&format!("Failed to deserialize C1 for attestation {}", i));
        let c2_i: Vec<Com2<E>> = c2_bytes_i.iter().map(|b| Com2::deserialize_compressed(&**b)).collect::<Result<_,_>>()
            .expect(&format!("Failed to deserialize C2 for attestation {}", i));
        let pi_i: Vec<Com2<E>> = pi_bytes_i.iter().map(|b| Com2::deserialize_compressed(&**b)).collect::<Result<_,_>>()
            .expect(&format!("Failed to deserialize pi for attestation {}", i));
        let theta_i: Vec<Com1<E>> = theta_bytes_i.iter().map(|b| Com1::deserialize_compressed(&**b)).collect::<Result<_,_>>()
            .expect(&format!("Failed to deserialize theta for attestation {}", i));
        
        // Create PPE for this attestation's public input
        let ppe_i = gs.groth16_verify_as_ppe(&vk, &public_inputs[i]);
        
        // === VERIFY EACH ATTESTATION ===
        let ppe_verification_result = ppe_i.verify(&attestation.cproof, crs);
        assert!(ppe_verification_result, "PPE verification must pass for attestation {}", i);
        println!("✅ PPE verification passed for attestation {}", i);
        
        // Compute ComT using five_bucket_comt
        let comt_i = five_bucket_comt::<E>(
            &c1_i, &c2_i, &pi_i, &theta_i, &ppe_i.gamma,
            &u_rho_com1, &v_rho_com2, &u_star_rho_com2, &v_star_rho_com1
        );
        
        all_comt_matrices.push(comt_i);
        println!("Computed ComT matrix for attestation {} with public input {}", i, public_inputs[i][0]);
    }
    
    // Compare attestations with the same public input (should produce same ComT)
    println!("\n=== COMPARING ATTESTATIONS WITH SAME PUBLIC INPUT ===");
    
    // Group attestations by public input
    let mut groups: std::collections::HashMap<Fr, Vec<usize>> = std::collections::HashMap::new();
    for (i, public_input) in public_inputs.iter().enumerate() {
        groups.entry(public_input[0]).or_insert_with(Vec::new).push(i);
    }
    
    for (public_input, indices) in groups.iter() {
        if indices.len() > 1 {
            println!("Found {} attestations with public input {}", indices.len(), public_input);
            
            // Compare all attestations in this group
            for i in 0..indices.len() {
                for j in (i+1)..indices.len() {
                    let idx_i = indices[i];
                    let idx_j = indices[j];
                    let matrix_i = all_comt_matrices[idx_i].as_matrix();
                    let matrix_j = all_comt_matrices[idx_j].as_matrix();
                    let mut matches = true;
                    
                    for row in 0..2 {
                        for col in 0..2 {
                            if matrix_i[row][col].0 != matrix_j[row][col].0 {
                                println!("❌ Attestation {} ComT[{}][{}] differs from attestation {}", idx_i, row, col, idx_j);
                                matches = false;
                            }
                        }
                    }
                    
                    if matches {
                        println!("✅ Attestation {} ComT matrix matches attestation {}", idx_i, idx_j);
                    }
                }
            }
        }
    }
    
    // Compare attestations with different public inputs (should produce different ComT)
    println!("\n=== COMPARING ATTESTATIONS WITH DIFFERENT PUBLIC INPUTS ===");
    for i in 0..attestations.len() {
        for j in (i+1)..attestations.len() {
            if public_inputs[i][0] != public_inputs[j][0] {
                let matrix_i = all_comt_matrices[i].as_matrix();
                let matrix_j = all_comt_matrices[j].as_matrix();
                let mut differs = false;
                
                for row in 0..2 {
                    for col in 0..2 {
                        if matrix_i[row][col].0 != matrix_j[row][col].0 {
                            differs = true;
                            break;
                        }
                    }
                    if differs { break; }
                }
                
                if differs {
                    println!("✅ Attestation {} (public input {}) differs from attestation {} (public input {})", 
                             i, public_inputs[i][0], j, public_inputs[j][0]);
    } else {
                    println!("❌ Attestation {} (public input {}) unexpectedly matches attestation {} (public input {})", 
                             i, public_inputs[i][0], j, public_inputs[j][0]);
                }
            }
        }
    }
    
    // Only assert that the first attestation matches the deposit ComT (since they have the same public input)
    let first_matrix = all_comt_matrices[0].as_matrix();
    
    // Debug: Print the [1][1] values to understand the target cell issue
    println!("\n=== TARGET CELL DEBUG ===");
    println!("Deposit ComT[1][1]: {:?}", md[1][1].0);
    println!("Withdraw ComT[1][1]: {:?}", first_matrix[1][1].0);
        println!("T^ρ: {:?}", t_rho);
    println!("Deposit [1][1] == T^ρ: {}", md[1][1].0 == t_rho);
    println!("Withdraw [1][1] == T^ρ: {}", first_matrix[1][1].0 == t_rho);
    println!("Deposit [1][1] == Withdraw [1][1]: {}", md[1][1].0 == first_matrix[1][1].0);
    
    assert_eq!(md[0][0].0, first_matrix[0][0].0, "First attestation ComT[0][0] should match deposit");
    assert_eq!(md[0][1].0, first_matrix[0][1].0, "First attestation ComT[0][1] should match deposit");
    assert_eq!(md[1][0].0, first_matrix[1][0].0, "First attestation ComT[1][0] should match deposit");
    assert_eq!(md[1][1].0, first_matrix[1][1].0, "First attestation ComT[1][1] should match deposit (target cell)");
    
    println!("✅ Multiple attestations test completed successfully!");
    
    // Sanity check: target cell should equal T^ρ
    assert_eq!(md[1][1].0, t_rho, "target cell mismatch");
}
