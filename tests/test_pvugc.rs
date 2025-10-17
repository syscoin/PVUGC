#![allow(non_snake_case)]

use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::{BigInteger, PrimeField, UniformRand, Zero};
use ark_serialize::CanonicalSerialize;
use ark_std::test_rng;
use sha2::{Digest, Sha256};

use arkworks_groth16::{
    groth16_wrapper::ArkworksGroth16, ArkworksProof, ArkworksVK, GrothSahaiCommitments,
    SchnorrAdaptor,
};

use groth_sahai::base_construction::FullGSPpeBases;
use groth_sahai::rank_decomp::RankDecomp;

use schnorr_fun::fun::{marker::*, Point, Scalar, G};

#[test]
fn test_complete_adaptor_signature_flow() {
    println!("\n{}", "=".repeat(70));
    println!("COMPLETE ADAPTOR SIGNATURE FLOW WITH RANK-DECOMPOSITION PVUGC");
    println!("{}\n", "=".repeat(70));

    let mut rng = test_rng();

    // STEP 1: CREATE GROTH-SAHAI SYSTEM
    let gs = GrothSahaiCommitments::from_seed(b"PVUGC_RANK_DECOMP");
    println!("Step 1: GS system with per-slot CRS created");

    // CREATE REAL GROTH16 PROOF
    let mut groth16 = ArkworksGroth16::new();
    let vk = groth16.setup().expect("Setup failed");

    let witness1 = Fr::from(3u64);
    let witness2 = Fr::from(2u64);
    let proof_struct = groth16.prove(witness1, witness2).expect("Prove failed");

    let proof = ArkworksProof {
        pi_a: proof_struct.pi_a,
        pi_b: proof_struct.pi_b,
        pi_c: proof_struct.pi_c,
        public_input: proof_struct.public_input.clone(),
        proof_bytes: proof_struct.proof_bytes,
    };

    let vk = ArkworksVK {
        alpha_g1: vk.alpha_g1,
        beta_g2: vk.beta_g2,
        gamma_g2: vk.gamma_g2,
        delta_g2: vk.delta_g2,
        gamma_abc_g1: vk.gamma_abc_g1,
        vk_bytes: vk.vk_bytes,
    };

    println!("Step 1b: Real Groth16 proof created (3 + 2 = 5)");

    // STEP 2: CREATE SCHNORR ADAPTOR PRE-SIGNATURE
    let schnorr_adaptor = SchnorrAdaptor::new();

    // Generate single signing key (simplified for testing)
    let mut secret = Scalar::random(&mut rand::thread_rng());
    let secret_bytes: [u8; 32] = secret.to_bytes();
    let participant_secrets = vec![secret_bytes];

    let pubkey_point = Point::even_y_from_scalar_mul(G, &mut secret);
    let agg_pubkey = pubkey_point.to_bytes();

    // Generate adaptor secret shares (simulating threshold)
    let num_shares = 3;
    let mut shares = Vec::new();
    let mut total_alpha_fr = Fr::zero();

    for _i in 0..num_shares {
        let s_i_fr = Fr::rand(&mut rng);
        shares.push(s_i_fr);
        total_alpha_fr += s_i_fr;
    }

    // Compute T = alpha*G
    let mut adaptor_secret_scalars: Vec<Scalar<Secret, NonZero>> = Vec::new();
    let mut total_alpha_scalar = Scalar::zero();

    for s_i_fr in shares.iter() {
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
        total_alpha_scalar = schnorr_fun::fun::op::scalar_add(total_alpha_scalar, s_i_scalar);
    }

    let alpha_nonzero = Scalar::<Secret, NonZero>::from_bytes(total_alpha_scalar.to_bytes())
        .expect("Total alpha should be non-zero");
    let mut alpha_for_t = alpha_nonzero;
    let t_point = Point::even_y_from_scalar_mul(G, &mut alpha_for_t);
    let agg_T = t_point.to_bytes();
    let expected_alpha_bytes: [u8; 32] = total_alpha_scalar.to_bytes();

    let message = b"Bitcoin_TX_SIGHASH_ALL";
    let presig = schnorr_adaptor
        .create_presignature(&mut rng, message, &agg_pubkey, &agg_T, &participant_secrets)
        .expect("Failed to create pre-signature");

    assert!(
        schnorr_adaptor
            .verify_presignature(message, &agg_pubkey, &presig)
            .expect("Verification error"),
        "Adaptor pre-signature verification failed"
    );

    println!("\nStep 2: Schnorr adaptor pre-signature created");
    println!(
        "  - {} secret shares will be encrypted with PVUGC-KEM",
        num_shares
    );

    // STEP 3: SETUP RANK-DECOMPOSITION PVUGC (before any proofs)
    let x = vec![Fr::from(5u64)]; // public input

    // SANITY CHECK: Verify Groth16 proof is valid using standard Arkworks verifier
    use ark_groth16::{Groth16, Proof as ArkProof, VerifyingKey as ArkVK};
    use ark_snark::SNARK;
    let ark_proof = ArkProof {
        a: proof.pi_a,
        b: proof.pi_b,
        c: proof.pi_c,
    };
    let ark_vk = ArkVK {
        alpha_g1: vk.alpha_g1,
        beta_g2: vk.beta_g2,
        gamma_g2: vk.gamma_g2,
        delta_g2: vk.delta_g2,
        gamma_abc_g1: vk.gamma_abc_g1.clone(),
    };
    let is_valid =
        Groth16::<Bls12_381>::verify(&ark_vk, &x, &ark_proof).expect("Verification failed");
    println!("  Groth16 proof valid (standard Arkworks): {}", is_valid);
    assert!(is_valid, "Groth16 proof must be valid!");

    // Generate per-slot CRS for rank-decomposition (3x3 for Groth16)
    // CRS must be 3×3 to match Γ dimensions
    // X witnesses: [A, C] + X constants: [L(x)]
    // Y witnesses: [B] + Y constants: [δ⁻¹, γ⁻¹]
    use groth_sahai::generator::CRS;
    let crs_per_slot = CRS::<Bls12_381>::generate_crs_per_slot(&mut rng, 3, 3);

    // Get the Groth16 PPE using the standard function (needs CRS for target computation)
    let ppe = gs.groth16_verify_as_ppe(&vk, &x, &crs_per_slot);

    // NOTE: Target is now CRS-based, not direct Groth16 e(α,β)
    // This is required for the GS rank-decomposition verifier to work correctly

    let decomp = RankDecomp::decompose(&ppe.gamma);
    let bases = FullGSPpeBases::build(&crs_per_slot, &ppe, &decomp);

    println!("\nStep 3: Full-GS PVUGC setup");
    println!(
        "  - Gamma dimensions: {}×{}",
        ppe.gamma.len(),
        ppe.gamma[0].len()
    );
    println!(
        "  - Gamma rank: {} (should be 3 for 3×3 identity)",
        decomp.rank
    );
    println!(
        "  - U_rand bases: {}, U_var bases: {}",
        bases.U_rand.len(),
        bases.U_var.len()
    );
    println!(
        "  - V_rand bases: {}, V_var bases: {}",
        bases.V_rand.len(),
        bases.V_var.len()
    );
    println!("  - Full-GS block bases computed");

    // STEP 4: ARM (OFFLINE - before any proofs exist)
    println!("\n=== ARMER ROLE: Offline Setup (ONE TIME) ===");
    let ctx_hash = Sha256::digest(b"test_context").to_vec();

    let mut encrypted_shares = Vec::new();

    for (_i, s_i_fr) in shares.iter().enumerate() {
        // ARMER: Generate random rho (kept secret by ARMER - never revealed!)
        let rho_i = Fr::rand(&mut rng);

        // ARMER: Compute K = target^rho (ARMER can do this offline from VK alone)
        // This is what ARMER publishes - DECAPPER will use this without knowing rho
        let target_rho_i = ppe.target * rho_i;

        // Derive encryption key from target^rho
        let mut target_rho_bytes = Vec::new();
        target_rho_i
            .serialize_compressed(&mut target_rho_bytes)
            .unwrap();

        let key_material = Sha256::digest(&[&ctx_hash[..], &target_rho_bytes].concat()).to_vec();
        let key: [u8; 32] = key_material[..32].try_into().unwrap();

        // Encrypt the share
        use chacha20poly1305::{
            aead::{Aead, KeyInit},
            ChaCha20Poly1305, Nonce,
        };
        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        let nonce = Nonce::from_slice(&[0u8; 12]);

        let share_bytes = s_i_fr.into_bigint().to_bytes_be();
        let ciphertext = cipher.encrypt(nonce, share_bytes.as_ref()).unwrap();

        // ARMER publishes: (ciphertext, K=target^rho)
        // ARMER keeps secret: rho (never revealed!)
        encrypted_shares.push((target_rho_i, ciphertext));
    }

    println!("Step 4: ARMER setup complete (OFFLINE)");
    println!("  - {} armed shares published", encrypted_shares.len());
    println!("  - ARMER now goes OFFLINE permanently");

    // STEP 5: PROVER GENERATES ATTESTATION (happens later, online)
    println!("\n=== PROVER ROLE: Create attestation (happens later) ===");

    // Prover creates attestation (proof + commitments)
    let gs_attestation = gs
        .commit_arkworks_proof(&proof, &vk, &x, &crs_per_slot, &mut rng)
        .expect("Failed to create attestation");

    // Verify attestation
    let ppe_for_verify = gs.groth16_verify_as_ppe(&vk, &x, &crs_per_slot);
    let verify_result = gs
        .verify_attestation(&gs_attestation, &ppe_for_verify, &crs_per_slot)
        .expect("Verification error");

    assert!(verify_result, "Attestation verification failed!");

    println!("Step 5: Attestation created and verified");

    // STEP 6: DECAPPER ROLE (happens later when attestation is available)
    println!("\n=== DECAPPER ROLE: Extract and decrypt ===");

    // Build full-GS bases for extraction
    let decomp_decap = RankDecomp::decompose(&ppe_for_verify.gamma);
    let bases_decap = FullGSPpeBases::build(&crs_per_slot, &ppe_for_verify, &decomp_decap);

    // DIAGNOSTIC: Verify attestation and extract M
    let (verifies, m_extracted) =
        ppe_for_verify.verify_full_gs(&gs_attestation.cproof, &crs_per_slot, &bases_decap);
    println!("  DIAGNOSTIC: Attestation verifies? {}", verifies);
    println!(
        "  DIAGNOSTIC: M extracted equals target? {}",
        m_extracted == ppe_for_verify.target
    );

    if !verifies {
        println!("    WARNING: Attestation does not verify! M ≠ target.");
    }

    let mut recovered_frs = Vec::new();
    let mut recovered_scalars = Vec::new();

    for (_i, (target_rho_i, ciphertext)) in encrypted_shares.iter().enumerate() {
        // Use KEM decapsulate with the pre-computed target^rho (DECAPPER never learns rho!)
        let recovered_fr = gs
            .kem_decapsulate(
                &gs_attestation,
                &vk,
                &x,
                &crs_per_slot,
                &ciphertext,
                *target_rho_i,
                &ctx_hash,
            )
            .expect("KEM decapsulation failed");

        recovered_frs.push(recovered_fr);

        // Convert to Scalar for signature completion
        let fr_bytes = recovered_fr.into_bigint().to_bytes_be();
        let mut scalar_bytes = [0u8; 32];
        scalar_bytes.copy_from_slice(&fr_bytes[..32]);
        let recovered_scalar: Scalar<Secret, NonZero> =
            Scalar::from_bytes(scalar_bytes).expect("Invalid scalar");
        recovered_scalars.push(recovered_scalar);
    }

    println!(
        "  All {} shares decrypted successfully",
        recovered_frs.len()
    );

    // Verify recovered values match originals
    for (original, recovered) in shares.iter().zip(recovered_frs.iter()) {
        assert_eq!(*original, *recovered, "Share Fr mismatch");
    }
    println!("  PVUGC verified: All recovered values match originals");

    // STEP 7: SUM RECOVERED SCALARS TO GET ALPHA
    let mut alpha_recovered = Scalar::zero();
    for s in recovered_scalars.iter() {
        alpha_recovered = schnorr_fun::fun::op::scalar_add(alpha_recovered, *s);
    }

    let alpha_bytes: [u8; 32] = alpha_recovered.to_bytes();
    assert_eq!(
        expected_alpha_bytes, alpha_bytes,
        "Alpha mismatch: PVUGC recovery failed"
    );
    println!("\nStep 7: Secret scalars summed to recover alpha");

    // STEP 8: COMPLETE SIGNATURE
    let (r_x, s_bytes) = schnorr_adaptor
        .complete_signature(&presig, &alpha_bytes)
        .expect("Failed to complete signature");

    println!("\nStep 8: Signature completed using recovered alpha");

    // STEP 9: VERIFY SCHNORR SIGNATURE
    let is_valid = schnorr_adaptor
        .verify_schnorr(message, &agg_pubkey, (r_x, s_bytes))
        .expect("Verification error");

    assert!(is_valid, "Completed signature verification FAILED");

    println!("\nStep 9: Schnorr signature VERIFIED");
    println!("  - Can spend Bitcoin transaction");
    println!("  - PROVES: Rank-decomposition PVUGC correctly recovered alpha");

    // POSITIVE TEST: Different attestation with same VK SHOULD decrypt (proof-agnostic)
    println!("\nStep 8: Testing proof-agnostic property");

    // Create a different attestation with DIFFERENT public input but SAME VK
    // This tests that PVUGC is proof-agnostic: M = e(α,β) is the same for all proofs from same circuit
    let x_different = vec![Fr::from(10u64)]; // Different public input: 10 instead of 5
    let witness3 = Fr::from(4u64); // 4 + 6 = 10
    let witness4 = Fr::from(6u64);
    let proof_struct2 = groth16.prove(witness3, witness4).expect("Prove failed");

    let proof2 = ArkworksProof {
        pi_a: proof_struct2.pi_a,
        pi_b: proof_struct2.pi_b,
        pi_c: proof_struct2.pi_c,
        public_input: proof_struct2.public_input,
        proof_bytes: proof_struct2.proof_bytes,
    };

    // Create attestation2 using same VK (thus same e(α,β) target)
    let gs_attestation2 = gs
        .commit_arkworks_proof(&proof2, &vk, &x_different, &crs_per_slot, &mut rng)
        .expect("Failed to create attestation2");

    let attestation2 = &gs_attestation2.cproof;

    // Try to decrypt with different attestation (should work!)
    let (target_rho_test, ciphertext_test) = &encrypted_shares[0];

    // Build PPE for the different public input
    let ppe_different = gs.groth16_verify_as_ppe(&vk, &x_different, &crs_per_slot);
    let decomp_different = RankDecomp::decompose(&ppe_different.gamma);
    let bases_different = FullGSPpeBases::build(&crs_per_slot, &ppe_different, &decomp_different);

    // DECAPPER: Extract using DIFFERENT attestation - should get SAME M because same VK!
    let (verifies_different, m_extracted_different) =
        ppe_different.verify_full_gs(attestation2, &crs_per_slot, &bases_different);

    assert!(verifies_different, "Attestation 2 should verify");
    assert_eq!(
        m_extracted, m_extracted_different,
        "PVUGC should be proof-agnostic: same M for same VK"
    );
    assert_eq!(
        ppe.target, ppe_different.target,
        "Targets should be equal (same VK)"
    );

    // Try to decrypt with the key from attestation 2 using the KEM API
    let decap_result = gs.kem_decapsulate(
        &gs_attestation2,
        &vk,
        &x_different,
        &crs_per_slot,
        ciphertext_test,
        *target_rho_test,
        &ctx_hash,
    );

    // Should decrypt successfully because M is the same and target is proof-agnostic!
    assert!(
        decap_result.is_ok(),
        "Different attestation (same VK) should decrypt"
    );
    let recovered_share = decap_result.unwrap();
    let original_share = shares[0];
    assert_eq!(
        recovered_share, original_share,
        "Decrypted value should match"
    );

    println!("  ✓ Proof-agnostic property verified: Different proof (x=10) decrypted same secret");

    println!("\n{}", "=".repeat(70));
    println!("COMPLETE FLOW: ALL TESTS PASSED");
    println!("{}", "=".repeat(70));
}
