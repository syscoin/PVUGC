use ark_bls12_381::{Bls12_381, Fr};
use ark_ec::{CurveGroup, pairing::{Pairing, PairingOutput}};
use ark_ec::AffineRepr;
use ark_ff::{Field, PrimeField, One, Zero, UniformRand};
use ark_std::Zero as StdZero;
use ark_std::test_rng;
use arkworks_groth16::groth16_wrapper::ArkworksGroth16;
use arkworks_groth16::gs_commitments::GrothSahaiCommitments;
use groth_sahai::generator::CRS;
use groth_sahai::statement::PPE;
use groth_sahai::data_structures::{Com1, Com2};
use groth_sahai::prover::Provable;
use groth_sahai::verifier::Verifiable;
use groth_sahai::{B1, B2};

#[test]
#[ignore]
fn test_gs_unmasked_diag_debug() {
    // Trigger commit_arkworks_proof to print GS DEBUG unmasked diag equality
    let gs = GrothSahaiCommitments::from_seed(b"GS_UNMASKED_DIAG_DBG");
    let mut groth16 = ArkworksGroth16::new();
    let vk = groth16.setup().expect("Setup should succeed");

    let witness = Fr::from(5u64);
    let proof1 = groth16.prove(witness).expect("Prove 1 should succeed");
    let proof2 = groth16.prove(witness).expect("Prove 2 should succeed");

    let x = [Fr::from(25u64)];

    let mut rng = test_rng();
    let _att1 = gs
        .commit_arkworks_proof(&proof1, &vk, &x, true, &mut rng)
        .expect("Att1 should succeed");
    let _att2 = gs
        .commit_arkworks_proof(&proof2, &vk, &x, true, &mut rng)
        .expect("Att2 should succeed");

    // Now reconstruct 2×2 PPE and compute the five buckets explicitly to isolate mismatch
    let ppe = {
        use arkworks_groth16::gs_commitments::compute_ic_from_vk_and_inputs;
        let ic = compute_ic_from_vk_and_inputs(&vk, &x);
        let PairingOutput(t1) = Bls12_381::pairing(vk.alpha_g1, vk.beta_g2);
        let PairingOutput(t2) = Bls12_381::pairing(ic, vk.gamma_g2);
        PPE::<Bls12_381> {
            a_consts: vec![vk.alpha_g1, vk.alpha_g1],
            b_consts: vec![vk.beta_g2, vk.beta_g2],
            gamma: vec![vec![Fr::one(), Fr::zero()], vec![Fr::zero(), Fr::one()]],
            target: PairingOutput::<Bls12_381>(t1 * t2),
        }
    };

    fn align_crs<E: Pairing>(crs: &CRS<E>) -> CRS<E> {
        use ark_ec::CurveGroup;
        let mut out = crs.clone();
        for j in 0..out.u.len() {
            let PairingOutput(p0a) = E::pairing(out.u[j].0, out.u_dual[j].0);
            let PairingOutput(p1a) = E::pairing(out.u[j].1, out.u_dual[j].1);
            if p0a * p1a != E::TargetField::one() {
                let u1n = (-out.u[j].1.into_group()).into_affine();
                let PairingOutput(p0b) = E::pairing(out.u[j].0, out.u_dual[j].0);
                let PairingOutput(p1b) = E::pairing(u1n, out.u_dual[j].1);
                if p0b * p1b == E::TargetField::one() { out.u[j].1 = u1n; continue; }
                let u0n = (-out.u[j].0.into_group()).into_affine();
                let PairingOutput(p0c) = E::pairing(u0n, out.u_dual[j].0);
                let PairingOutput(p1c) = E::pairing(out.u[j].1, out.u_dual[j].1);
                if p0c * p1c == E::TargetField::one() { out.u[j].0 = u0n; continue; }
                out.u[j].0 = u0n; out.u[j].1 = u1n;
            }
        }
        for k in 0..out.v.len() {
            let PairingOutput(p0a) = E::pairing(out.v_dual[k].0, out.v[k].0);
            let PairingOutput(p1a) = E::pairing(out.v_dual[k].1, out.v[k].1);
            if p0a * p1a != E::TargetField::one() {
                let v1n = (-out.v_dual[k].1.into_group()).into_affine();
                let PairingOutput(p0b) = E::pairing(out.v_dual[k].0, out.v[k].0);
                let PairingOutput(p1b) = E::pairing(v1n, out.v[k].1);
                if p0b * p1b == E::TargetField::one() { out.v_dual[k].1 = v1n; continue; }
                let v0n = (-out.v_dual[k].0.into_group()).into_affine();
                let PairingOutput(p0c) = E::pairing(v0n, out.v[k].0);
                let PairingOutput(p1c) = E::pairing(out.v_dual[k].1, out.v[k].1);
                if p0c * p1c == E::TargetField::one() { out.v_dual[k].0 = v0n; continue; }
                out.v_dual[k].0 = v0n; out.v_dual[k].1 = v1n;
            }
        }
        out
    }

    let mut rng = test_rng();
    let crs_aligned = align_crs::<Bls12_381>(gs.get_crs());

    // Binding-mode diagnostics: per-index equals-one and off-diagonal not-equals-one
    fn check_crs_duality<E: Pairing>(crs: &CRS<E>) {
        // u vs u_dual
        for i in 0..crs.u.len() {
            for j in 0..crs.u_dual.len() {
                let PairingOutput(p0) = E::pairing(crs.u[i].0, crs.u_dual[j].0);
                let PairingOutput(p1) = E::pairing(crs.u[i].1, crs.u_dual[j].1);
                let prod = p0 * p1;
                if i == j {
                    assert_eq!(prod, E::TargetField::one(), "u/u* mismatch at {}", i);
                } else {
                    assert_ne!(prod, E::TargetField::one(), "u/u* off-diagonal unexpectedly cancels at ({},{})", i, j);
                }
            }
        }
        // v_dual vs v
        for i in 0..crs.v_dual.len() {
            for j in 0..crs.v.len() {
                let PairingOutput(p0) = E::pairing(crs.v_dual[i].0, crs.v[j].0);
                let PairingOutput(p1) = E::pairing(crs.v_dual[i].1, crs.v[j].1);
                let prod = p0 * p1;
                if i == j {
                    assert_eq!(prod, E::TargetField::one(), "v*/v mismatch at {}", i);
                } else {
                    assert_ne!(prod, E::TargetField::one(), "v*/v off-diagonal unexpectedly cancels at ({},{})", i, j);
                }
            }
        }
        println!("CRS duality invariants OK (per-index) and non-cancel off-diagonals");
    }

    check_crs_duality::<Bls12_381>(&crs_aligned);
    let cproof1 = ppe.commit_and_prove(&[proof1.pi_a, proof1.pi_c], &[proof1.pi_b, vk.delta_g2], &crs_aligned, &mut rng);
    let cproof2 = ppe.commit_and_prove(&[proof2.pi_a, proof2.pi_c], &[proof2.pi_b, vk.delta_g2], &crs_aligned, &mut rng);

    // Compute five buckets explicitly for each proof
    fn five_buckets<E: Pairing>(
        x: &[Com1<E>], y: &[Com2<E>],
        pi: &[Com2<E>], th: &[Com1<E>],
        crs: &CRS<E>, gamma: &Vec<Vec<E::ScalarField>>, rho: E::ScalarField,
    ) -> (E::TargetField, E::TargetField, E::TargetField, E::TargetField, E::TargetField, E::TargetField) {
        use ark_ec::CurveGroup;
        use ark_ff::Zero;
        let mut b1 = E::TargetField::one();
        let mut b2 = E::TargetField::one();
        let mut b3 = E::TargetField::one();
        let mut b4 = E::TargetField::one();
        let mut g  = E::TargetField::one();

        // masked duals
        let u_dual_rho: Vec<_> = crs.u_dual.iter().map(|d| ((d.0.into_group()*rho).into_affine(), (d.1.into_group()*rho).into_affine())).collect();
        let v_dual_rho: Vec<_> = crs.v_dual.iter().map(|d| ((d.0.into_group()*rho).into_affine(), (d.1.into_group()*rho).into_affine())).collect();
        // primaries masked
        let u_rho: Vec<_> = crs.u.iter().map(|u| Com1::<E>((u.0.into_group()*rho).into_affine(), (u.1.into_group()*rho).into_affine())).collect();
        let v_rho: Vec<_> = crs.v.iter().map(|v| Com2::<E>((v.0.into_group()*rho).into_affine(), (v.1.into_group()*rho).into_affine())).collect();

        for j in 0..x.len() {
            let PairingOutput(p0) = E::pairing(x[j].0, u_dual_rho[j].0); let PairingOutput(p1) = E::pairing(x[j].1, u_dual_rho[j].1); b1 *= p0*p1;
        }
        for k in 0..y.len() {
            let PairingOutput(p0) = E::pairing(v_dual_rho[k].0, y[k].0); let PairingOutput(p1) = E::pairing(v_dual_rho[k].1, y[k].1); b2 *= p0*p1;
        }
        for j in 0..pi.len() {
            let PairingOutput(p0) = E::pairing(u_rho[j].0, pi[j].0); let PairingOutput(p1) = E::pairing(u_rho[j].1, pi[j].1); b3 *= p0*p1;
        }
        for k in 0..th.len() {
            let PairingOutput(p0) = E::pairing(th[k].0, v_rho[k].0); let PairingOutput(p1) = E::pairing(th[k].1, v_rho[k].1); b4 *= p0*p1;
        }
        for j in 0..gamma.len() { for k in 0..gamma[j].len() {
            let coeff = gamma[j][k]; if coeff.is_zero() { continue; }
            let PairingOutput(p00)=E::pairing(x[j].0, y[k].0); let PairingOutput(p11)=E::pairing(x[j].1, y[k].1);
            g *= (p00*p11).pow(coeff.into_bigint());
        }}
        let g_rho = g.pow(rho.into_bigint());
        (b1,b2,b3,b4,g,g_rho)
    }

    let rho = Fr::from(7u64);
    let (b1a,b2a,b3a,b4a,ga,ga_rho) = five_buckets::<Bls12_381>(&cproof1.xcoms.coms, &cproof1.ycoms.coms, &cproof1.equ_proofs[0].pi, &cproof1.equ_proofs[0].theta, &crs_aligned, &ppe.gamma, rho);
    let (b1b,b2b,b3b,b4b,gb,gb_rho) = five_buckets::<Bls12_381>(&cproof2.xcoms.coms, &cproof2.ycoms.coms, &cproof2.equ_proofs[0].pi, &cproof2.equ_proofs[0].theta, &crs_aligned, &ppe.gamma, rho);

    // Expected target^ρ
    let PairingOutput(tgt) = ppe.target; let exp = tgt.pow(rho.into_bigint());
    let m_a = b1a * b2a * b3a * b4a * ga_rho;
    let m_b = b1b * b2b * b3b * b4b * gb_rho;
    println!("5-buckets: M1==target^ρ: {} M2==target^ρ: {} M1==M2: {}", m_a==exp, m_b==exp, m_a==m_b);
    println!("Buckets P1 (non-identity?): b1:{} b2:{} b3:{} b4:{}", b1a != <Bls12_381 as Pairing>::TargetField::one(), b2a != <Bls12_381 as Pairing>::TargetField::one(), b3a != <Bls12_381 as Pairing>::TargetField::one(), b4a != <Bls12_381 as Pairing>::TargetField::one());
    println!("Buckets P2 (non-identity?): b1:{} b2:{} b3:{} b4:{}", b1b != <Bls12_381 as Pairing>::TargetField::one(), b2b != <Bls12_381 as Pairing>::TargetField::one(), b3b != <Bls12_381 as Pairing>::TargetField::one(), b4b != <Bls12_381 as Pairing>::TargetField::one());

    // 1) Compare buckets across proofs
    println!("Buckets equal across proofs: b1:{} b2:{} b3:{} b4:{} g^ρ:{}", b1a==b1b, b2a==b2b, b3a==b3b, b4a==b4b, ga_rho==gb_rho);

    // 2) Try minimal orientation swaps for proof1 on b3/b4 (slot swap in pairs)
    fn swapped_M<E: Pairing>(
        x: &[Com1<E>], y: &[Com2<E>], pi: &[Com2<E>], th: &[Com1<E>], crs: &CRS<E>, gamma:&Vec<Vec<E::ScalarField>>, rho:E::ScalarField,
        swap_pi_slots: bool, swap_th_slots: bool, rev_pi: bool, rev_th: bool,
    ) -> E::TargetField {
        use ark_ec::CurveGroup; use ark_ff::{Field, Zero};
        let mut b1 = E::TargetField::one(); let mut b2 = E::TargetField::one(); let mut b3 = E::TargetField::one(); let mut b4 = E::TargetField::one(); let mut g = E::TargetField::one();
        let u_dual_rho: Vec<_> = crs.u_dual.iter().map(|d| ((d.0.into_group()*rho).into_affine(), (d.1.into_group()*rho).into_affine())).collect();
        let v_dual_rho: Vec<_> = crs.v_dual.iter().map(|d| ((d.0.into_group()*rho).into_affine(), (d.1.into_group()*rho).into_affine())).collect();
        let u_rho: Vec<_> = crs.u.iter().map(|u| Com1::<E>((u.0.into_group()*rho).into_affine(), (u.1.into_group()*rho).into_affine())).collect();
        let v_rho: Vec<_> = crs.v.iter().map(|v| Com2::<E>((v.0.into_group()*rho).into_affine(), (v.1.into_group()*rho).into_affine())).collect();
        for j in 0..x.len() { let PairingOutput(p0)=E::pairing(x[j].0,u_dual_rho[j].0); let PairingOutput(p1)=E::pairing(x[j].1,u_dual_rho[j].1); b1*=p0*p1; }
        for k in 0..y.len() { let PairingOutput(p0)=E::pairing(v_dual_rho[k].0,y[k].0); let PairingOutput(p1)=E::pairing(v_dual_rho[k].1,y[k].1); b2*=p0*p1; }
        let mut piv: Vec<Com2<E>> = pi.to_vec(); if rev_pi { piv.reverse(); }
        let mut thv: Vec<Com1<E>> = th.to_vec(); if rev_th { thv.reverse(); }
        for j in 0..piv.len() {
            let PairingOutput(p0) = if swap_pi_slots { E::pairing(u_rho[j].1, piv[j].0) } else { E::pairing(u_rho[j].0, piv[j].0) };
            let PairingOutput(p1) = if swap_pi_slots { E::pairing(u_rho[j].0, piv[j].1) } else { E::pairing(u_rho[j].1, piv[j].1) };
            b3 *= p0*p1;
        }
        for k in 0..thv.len() {
            let PairingOutput(p0) = if swap_th_slots { E::pairing(thv[k].1, v_rho[k].0) } else { E::pairing(thv[k].0, v_rho[k].0) };
            let PairingOutput(p1) = if swap_th_slots { E::pairing(thv[k].0, v_rho[k].1) } else { E::pairing(thv[k].1, v_rho[k].1) };
            b4 *= p0*p1;
        }
        for j in 0..gamma.len() { for k in 0..gamma[j].len() { let coeff=gamma[j][k]; if coeff.is_zero(){continue;} let PairingOutput(p00)=E::pairing(x[j].0,y[k].0); let PairingOutput(p11)=E::pairing(x[j].1,y[k].1); g*=(p00*p11).pow(coeff.into_bigint()); }}
        let gr = g.pow(rho.into_bigint()); b1*b2*b3*b4*gr
    }

    // Deep-dive: print ComT matrices for verifier buckets to see slot mismatches
    use groth_sahai::data_structures::{ComT, BT, Mat, Matrix, col_vec_to_vec, vec_to_col_vec};
    fn print_comt(label:&str, m:&ComT<Bls12_381>) { let mat=m.as_matrix();
        let PairingOutput(a00)=mat[0][0]; let PairingOutput(a01)=mat[0][1];
        let PairingOutput(a10)=mat[1][0]; let PairingOutput(a11)=mat[1][1];
        println!("{}: [00:{:?}] [01:{:?}] [10:{:?}] [11:{:?}]", label, a00, a01, a10, a11);
    }
    // Build verifier buckets (unmasked) for both proofs
    let lin_a1 = ComT::<Bls12_381>::pairing_sum(&Com1::<Bls12_381>::batch_linear_map(&ppe.a_consts), &cproof1.ycoms.coms);
    let lin_b1 = ComT::<Bls12_381>::pairing_sum(&cproof1.xcoms.coms, &Com2::<Bls12_381>::batch_linear_map(&ppe.b_consts));
    let stmt_y1: Matrix<Com2<Bls12_381>> = vec_to_col_vec(&cproof1.ycoms.coms).left_mul(&ppe.gamma, true);
    let cross1 = ComT::<Bls12_381>::pairing_sum(&cproof1.xcoms.coms, &col_vec_to_vec(&stmt_y1));
    let u_pi1 = ComT::<Bls12_381>::pairing_sum(crs_aligned.u.as_slice(), &cproof1.equ_proofs[0].pi);
    let th_v1 = ComT::<Bls12_381>::pairing_sum(&cproof1.equ_proofs[0].theta, crs_aligned.v.as_slice());
    let lhs1: ComT<Bls12_381> = lin_a1 + lin_b1 + cross1;
    let rhs1: ComT<Bls12_381> = ComT::<Bls12_381>::linear_map_PPE(&ppe.target) + u_pi1 + th_v1;
    println!("\nProof1 ComT buckets:");
    print_comt("lin_a·Y", &lin_a1);
    print_comt("X·lin_b", &lin_b1);
    print_comt("X·(Γ·Y)", &cross1);
    print_comt("U·π", &u_pi1);
    print_comt("θ·V", &th_v1);
    print_comt("LHS=", &lhs1);
    print_comt("RHS=", &rhs1);
    let lhs1m = lhs1.as_matrix(); let rhs1m = rhs1.as_matrix();
    println!("P1 cells equal? 00:{} 01:{} 10:{} 11:{}", lhs1m[0][0]==rhs1m[0][0], lhs1m[0][1]==rhs1m[0][1], lhs1m[1][0]==rhs1m[1][0], lhs1m[1][1]==rhs1m[1][1]);

    let lin_a2 = ComT::<Bls12_381>::pairing_sum(&Com1::<Bls12_381>::batch_linear_map(&ppe.a_consts), &cproof2.ycoms.coms);
    let lin_b2 = ComT::<Bls12_381>::pairing_sum(&cproof2.xcoms.coms, &Com2::<Bls12_381>::batch_linear_map(&ppe.b_consts));
    let stmt_y2: Matrix<Com2<Bls12_381>> = vec_to_col_vec(&cproof2.ycoms.coms).left_mul(&ppe.gamma, true);
    let cross2 = ComT::<Bls12_381>::pairing_sum(&cproof2.xcoms.coms, &col_vec_to_vec(&stmt_y2));
    let u_pi2 = ComT::<Bls12_381>::pairing_sum(crs_aligned.u.as_slice(), &cproof2.equ_proofs[0].pi);
    let th_v2 = ComT::<Bls12_381>::pairing_sum(&cproof2.equ_proofs[0].theta, crs_aligned.v.as_slice());
    let lhs2: ComT<Bls12_381> = lin_a2 + lin_b2 + cross2;
    let rhs2: ComT<Bls12_381> = ComT::<Bls12_381>::linear_map_PPE(&ppe.target) + u_pi2 + th_v2;
    println!("\nProof2 ComT buckets:");
    print_comt("lin_a·Y", &lin_a2);
    print_comt("X·lin_b", &lin_b2);
    print_comt("X·(Γ·Y)", &cross2);
    print_comt("U·π", &u_pi2);
    print_comt("θ·V", &th_v2);
    print_comt("LHS=", &lhs2);
    print_comt("RHS=", &rhs2);
    let lhs2m = lhs2.as_matrix(); let rhs2m = rhs2.as_matrix();
    println!("P2 cells equal? 00:{} 01:{} 10:{} 11:{}", lhs2m[0][0]==rhs2m[0][0], lhs2m[0][1]==rhs2m[0][1], lhs2m[1][0]==rhs2m[1][0], lhs2m[1][1]==rhs2m[1][1]);

    let variants = [
        (false,false,false,false,"base"),
        (true,false,false,false,"swap_pi_slots"),
        (false,true,false,false,"swap_th_slots"),
        (true,true,false,false,"swap_both_slots"),
        (false,false,true,false,"rev_pi"),
        (false,false,false,true,"rev_th"),
        (true,false,true,false,"swap_pi_slots+rev_pi"),
        (false,true,false,true,"swap_th_slots+rev_th"),
        (true,true,true,true,"swap_both+rev_both"),
    ];
    for (spi, sth, rpi, rth, label) in variants.iter() {
        let ma = swapped_M::<Bls12_381>(&cproof1.xcoms.coms, &cproof1.ycoms.coms, &cproof1.equ_proofs[0].pi, &cproof1.equ_proofs[0].theta, &crs_aligned, &ppe.gamma, rho, *spi, *sth, *rpi, *rth);
        let mb = swapped_M::<Bls12_381>(&cproof2.xcoms.coms, &cproof2.ycoms.coms, &cproof2.equ_proofs[0].pi, &cproof2.equ_proofs[0].theta, &crs_aligned, &ppe.gamma, rho, *spi, *sth, *rpi, *rth);
        println!("variant {}: M1==target^ρ:{} M2==target^ρ:{} M1==M2:{}", label, ma==exp, mb==exp, ma==mb);
    }
}

#[test]
fn test_gs_verifier_consistency() {
    let gs = GrothSahaiCommitments::from_seed(b"GS_VERIFIER_TEST");
    let mut groth16 = ArkworksGroth16::new();
    let vk = groth16.setup().expect("Setup should succeed");

    let witness = Fr::from(5u64);
    let proof1 = groth16.prove(witness).expect("Prove 1 should succeed");
    let proof2 = groth16.prove(witness).expect("Prove 2 should succeed");

    let x = [Fr::from(25u64)];

    // PPE for Groth16 verification (no const terms)
    let ppe = {
        use arkworks_groth16::gs_commitments::compute_ic_from_vk_and_inputs;
        let ic = compute_ic_from_vk_and_inputs(&vk, &x);
        let PairingOutput(t1) = Bls12_381::pairing(vk.alpha_g1, vk.beta_g2);
        let PairingOutput(t2) = Bls12_381::pairing(ic, vk.gamma_g2);
        PPE::<Bls12_381> {
            a_consts: vec![ark_bls12_381::G1Affine::zero(), ark_bls12_381::G1Affine::zero()],
            b_consts: vec![ark_bls12_381::G2Affine::zero(), ark_bls12_381::G2Affine::zero()],
            gamma: vec![vec![Fr::one(), Fr::zero()], vec![Fr::zero(), Fr::one()]],
            target: PairingOutput::<Bls12_381>(t1 * t2),
        }
    };

    let mut rng = test_rng();
    // Align CRS duals to primaries for exact invariants
    fn align_crs<E: Pairing>(crs: &CRS<E>) -> CRS<E> {
        use ark_ec::CurveGroup;
        let mut out = crs.clone();
        for j in 0..out.u.len() {
            let PairingOutput(p0a) = E::pairing(out.u[j].0, out.u_dual[j].0);
            let PairingOutput(p1a) = E::pairing(out.u[j].1, out.u_dual[j].1);
            if p0a * p1a != E::TargetField::one() {
                let u1n = (-out.u[j].1.into_group()).into_affine();
                let PairingOutput(p0b) = E::pairing(out.u[j].0, out.u_dual[j].0);
                let PairingOutput(p1b) = E::pairing(u1n, out.u_dual[j].1);
                if p0b * p1b == E::TargetField::one() { out.u[j].1 = u1n; continue; }
                let u0n = (-out.u[j].0.into_group()).into_affine();
                let PairingOutput(p0c) = E::pairing(u0n, out.u_dual[j].0);
                let PairingOutput(p1c) = E::pairing(out.u[j].1, out.u_dual[j].1);
                if p0c * p1c == E::TargetField::one() { out.u[j].0 = u0n; continue; }
                out.u[j].0 = u0n; out.u[j].1 = u1n;
            }
        }
        for k in 0..out.v.len() {
            let PairingOutput(p0a) = E::pairing(out.v_dual[k].0, out.v[k].0);
            let PairingOutput(p1a) = E::pairing(out.v_dual[k].1, out.v[k].1);
            if p0a * p1a != E::TargetField::one() {
                let v1n = (-out.v_dual[k].1.into_group()).into_affine();
                let PairingOutput(p0b) = E::pairing(out.v_dual[k].0, out.v[k].0);
                let PairingOutput(p1b) = E::pairing(v1n, out.v[k].1);
                if p0b * p1b == E::TargetField::one() { out.v_dual[k].1 = v1n; continue; }
                let v0n = (-out.v_dual[k].0.into_group()).into_affine();
                let PairingOutput(p0c) = E::pairing(v0n, out.v[k].0);
                let PairingOutput(p1c) = E::pairing(out.v_dual[k].1, out.v[k].1);
                if p0c * p1c == E::TargetField::one() { out.v_dual[k].0 = v0n; continue; }
                out.v_dual[k].0 = v0n; out.v_dual[k].1 = v1n;
            }
        }
        out
    }
    let crs_aligned = align_crs::<Bls12_381>(gs.get_crs());
    let gs_proof1 = ppe.commit_and_prove(&[proof1.pi_a, proof1.pi_c], &[proof1.pi_b, vk.delta_g2], &crs_aligned, &mut rng);
    let gs_proof2 = ppe.commit_and_prove(&[proof2.pi_a, proof2.pi_c], &[proof2.pi_b, vk.delta_g2], &crs_aligned, &mut rng);

    let verifies1 = ppe.verify(&gs_proof1, &crs_aligned);
    let verifies2 = ppe.verify(&gs_proof2, &crs_aligned);
    println!("GS Verifier - Proof 1 valid: {}", verifies1);
    println!("GS Verifier - Proof 2 valid: {}", verifies2);
}

#[test]
fn test_gs_small_ppe_verify_like_bench() {
    let gs = GrothSahaiCommitments::from_seed(b"GS_SMALL_PPE");
    let mut groth16 = ArkworksGroth16::new();
    let vk = groth16.setup().expect("Setup should succeed");

    let witness = Fr::from(5u64);
    let proof = groth16.prove(witness).expect("Prove should succeed");
    let x = [Fr::from(25u64)];

    // Build 2x1 PPE: X=[piA, piC], Y=[piB], gamma=[[1],[0]], a_consts len 1, b_consts len 2
    let ppe = {
        let a_consts = vec![ark_bls12_381::G1Affine::zero()];
        let b_consts = vec![ark_bls12_381::G2Affine::zero(), ark_bls12_381::G2Affine::zero()];
        // target = e(alpha, beta) so equation is piA vs piB
        let PairingOutput(t1) = Bls12_381::pairing(vk.alpha_g1, vk.beta_g2);
        PPE::<Bls12_381> {
            a_consts,
            b_consts,
            gamma: vec![vec![Fr::one()], vec![Fr::zero()]],
            target: PairingOutput::<Bls12_381>(t1),
        }
    };

    let mut rng = test_rng();
    // Align CRS for exact invariants
    fn align_crs<E: Pairing>(crs: &CRS<E>) -> CRS<E> {
        use ark_ec::CurveGroup; let mut out = crs.clone();
        for j in 0..out.u.len() { let PairingOutput(p0a)=E::pairing(out.u[j].0,out.u_dual[j].0); let PairingOutput(p1a)=E::pairing(out.u[j].1,out.u_dual[j].1); if p0a*p1a!=E::TargetField::one(){ let u1n=(-out.u[j].1.into_group()).into_affine(); let PairingOutput(p0b)=E::pairing(out.u[j].0,out.u_dual[j].0); let PairingOutput(p1b)=E::pairing(u1n,out.u_dual[j].1); if p0b*p1b==E::TargetField::one(){out.u[j].1=u1n; continue;} let u0n=(-out.u[j].0.into_group()).into_affine(); let PairingOutput(p0c)=E::pairing(u0n,out.u_dual[j].0); let PairingOutput(p1c)=E::pairing(out.u[j].1,out.u_dual[j].1); if p0c*p1c==E::TargetField::one(){out.u[j].0=u0n; continue;} out.u[j].0=u0n; out.u[j].1=u1n; }}
        for k in 0..out.v.len() { let PairingOutput(p0a)=E::pairing(out.v_dual[k].0,out.v[k].0); let PairingOutput(p1a)=E::pairing(out.v_dual[k].1,out.v[k].1); if p0a*p1a!=E::TargetField::one(){ let v1n=(-out.v_dual[k].1.into_group()).into_affine(); let PairingOutput(p0b)=E::pairing(out.v_dual[k].0,out.v[k].0); let PairingOutput(p1b)=E::pairing(v1n,out.v[k].1); if p0b*p1b==E::TargetField::one(){out.v_dual[k].1=v1n; continue;} let v0n=(-out.v_dual[k].0.into_group()).into_affine(); let PairingOutput(p0c)=E::pairing(v0n,out.v[k].0); let PairingOutput(p1c)=E::pairing(out.v_dual[k].1,out.v[k].1); if p0c*p1c==E::TargetField::one(){out.v_dual[k].0=v0n; continue;} out.v_dual[k].0=v0n; out.v_dual[k].1=v1n; }} out }
    let crs_aligned = align_crs::<Bls12_381>(gs.get_crs());

    let gs_proof = ppe.commit_and_prove(&[proof.pi_a, proof.pi_c], &[proof.pi_b], &crs_aligned, &mut rng);
    let verifies = ppe.verify(&gs_proof, &crs_aligned);
    println!("GS Verifier (2x1 AB) valid: {}", verifies);
}

#[test]
fn test_gs_minimal_ppe_truth_path_and_substitutions() {
    use ark_bls12_381::{G1Affine, G2Affine};
    let mut rng = test_rng();
    let gs = GrothSahaiCommitments::from_seed(b"GS_MIN_PPE");
    let crs = gs.get_crs();

    // Random variables: X=[x0, x1], Y=[y0]; gamma=[[1],[0]] so only x0·y0 active
    let x0: G1Affine = (crs.g1_gen.into_group() * Fr::rand(&mut rng)).into_affine();
    let x1: G1Affine = (crs.g1_gen.into_group() * Fr::rand(&mut rng)).into_affine();
    let y0: G2Affine = (crs.g2_gen.into_group() * Fr::rand(&mut rng)).into_affine();
    let PairingOutput(t_ab) = Bls12_381::pairing(x0, y0);
    let ppe = PPE::<Bls12_381> {
        a_consts: vec![G1Affine::zero()],
        b_consts: vec![G2Affine::zero(), G2Affine::zero()],
        gamma: vec![vec![Fr::one()], vec![Fr::zero()]],
        target: PairingOutput::<Bls12_381>(t_ab),
    };
    let mut rng2 = test_rng();
    let cproof = ppe.commit_and_prove(&[x0, x1], &[y0], crs, &mut rng2);
    let v_ok = ppe.verify(&cproof, crs);
    println!("Minimal PPE (random Vars, true target) verify: {}", v_ok);

    // Now integrate Groth16 elements progressively
    let mut groth16 = ArkworksGroth16::new();
    let vk = groth16.setup().expect("Setup should succeed");
    let witness = Fr::from(5u64);
    let proof = groth16.prove(witness).expect("Prove should succeed");

    // Variant A: Replace x0 with pi_a, adjust target = e(pi_a, y0)
    let PairingOutput(t_a) = Bls12_381::pairing(proof.pi_a, y0);
    let ppe_a = PPE::<Bls12_381> {
        a_consts: vec![G1Affine::zero()],
        b_consts: vec![G2Affine::zero(), G2Affine::zero()],
        gamma: vec![vec![Fr::one()], vec![Fr::zero()]],
        target: PairingOutput::<Bls12_381>(t_a),
    };
    let mut rng3 = test_rng();
    let cproof_a = ppe_a.commit_and_prove(&[proof.pi_a, x1], &[y0], crs, &mut rng3);
    let v_a = ppe_a.verify(&cproof_a, crs);
    println!("Substitution A (x0=pi_a) verify: {}", v_a);

    // Variant B: Replace y0 with pi_b, adjust target = e(x0, pi_b)
    let PairingOutput(t_b) = Bls12_381::pairing(x0, proof.pi_b);
    let ppe_b = PPE::<Bls12_381> {
        a_consts: vec![G1Affine::zero()],
        b_consts: vec![G2Affine::zero(), G2Affine::zero()],
        gamma: vec![vec![Fr::one()], vec![Fr::zero()]],
        target: PairingOutput::<Bls12_381>(t_b),
    };
    let mut rng4 = test_rng();
    let cproof_b = ppe_b.commit_and_prove(&[x0, x1], &[proof.pi_b], crs, &mut rng4);
    let v_b = ppe_b.verify(&cproof_b, crs);
    println!("Substitution B (y0=pi_b) verify: {}", v_b);

    // Variant C: Replace both x0=pi_a, y0=pi_b, adjust target = e(pi_a, pi_b)
    let PairingOutput(t_ab2) = Bls12_381::pairing(proof.pi_a, proof.pi_b);
    let ppe_c = PPE::<Bls12_381> {
        a_consts: vec![G1Affine::zero()],
        b_consts: vec![G2Affine::zero(), G2Affine::zero()],
        gamma: vec![vec![Fr::one()], vec![Fr::zero()]],
        target: PairingOutput::<Bls12_381>(t_ab2),
    };
    let mut rng5 = test_rng();
    let cproof_c = ppe_c.commit_and_prove(&[proof.pi_a, x1], &[proof.pi_b], crs, &mut rng5);
    let v_c = ppe_c.verify(&cproof_c, crs);
    println!("Substitution C (x0=pi_a, y0=pi_b) verify: {}", v_c);
}

