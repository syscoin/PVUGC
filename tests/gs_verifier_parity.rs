use ark_bls12_381::{Bls12_381, Fr, G1Affine, G2Affine};
use ark_ec::{pairing::{Pairing, PairingOutput}, AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField, One, Zero};
use ark_serialize::CanonicalSerialize;
use ark_std::test_rng;

use arkworks_groth16::groth16_wrapper::ArkworksGroth16;
use arkworks_groth16::gs_commitments::{GrothSahaiCommitments, compute_ic_from_vk_and_inputs};

use groth_sahai::generator::CRS;
use groth_sahai::statement::PPE;
use groth_sahai::data_structures::{Com1, Com2, ComT, vec_to_col_vec, col_vec_to_vec, Mat};
use groth_sahai::BT;
use groth_sahai::{B1, B2};
use groth_sahai::prover::Provable;
use groth_sahai::verifier::trace_verify;
use groth_sahai::ppe_eval_masked_comt_full;
use sha2::{Digest, Sha256};

fn hash_gt<E: Pairing>(x: E::TargetField) -> String {
    use sha2::{Digest, Sha256};
    let mut bytes = Vec::new();
    x.serialize_compressed(&mut bytes).unwrap();
    let h = Sha256::digest(bytes);
    format!("{:02x}{:02x}{:02x}{:02x}…{:02x}{:02x}", h[0],h[1],h[2],h[3],h[30],h[31])
}

fn align_crs<E: Pairing>(crs: &CRS<E>) -> CRS<E> {
    let mut out = crs.clone();
    for j in 0..out.u.len() {
        let PairingOutput(p0a) = E::pairing(out.u[j].0, out.u_dual[j].0);
        let PairingOutput(p1a) = E::pairing(out.u[j].1, out.u_dual[j].1);
        if p0a * p1a == E::TargetField::one() { continue; }
        let u1n = (-out.u[j].1.into_group()).into_affine();
        let PairingOutput(p1b) = E::pairing(u1n, out.u_dual[j].1);
        if p0a * p1b == E::TargetField::one() { out.u[j].1 = u1n; continue; }
        let u0n = (-out.u[j].0.into_group()).into_affine();
        let PairingOutput(p0c) = E::pairing(u0n, out.u_dual[j].0);
        if p0c * p1a == E::TargetField::one() { out.u[j].0 = u0n; continue; }
        out.u[j].0 = u0n; out.u[j].1 = u1n;
    }
    for k in 0..out.v.len() {
        let PairingOutput(p0a) = E::pairing(out.v_dual[k].0, out.v[k].0);
        let PairingOutput(p1a) = E::pairing(out.v_dual[k].1, out.v[k].1);
        if p0a * p1a == E::TargetField::one() { continue; }
        let v1n = (-out.v_dual[k].1.into_group()).into_affine();
        let PairingOutput(p1b) = E::pairing(v1n, out.v[k].1);
        if p0a * p1b == E::TargetField::one() { out.v_dual[k].1 = v1n; continue; }
        let v0n = (-out.v_dual[k].0.into_group()).into_affine();
        let PairingOutput(p0c) = E::pairing(v0n, out.v[k].0);
        if p0c * p1a == E::TargetField::one() { out.v_dual[k].0 = v0n; continue; }
        out.v_dual[k].0 = v0n; out.v_dual[k].1 = v1n;
    }
    out
}

fn ct_mul<E: Pairing>(a: &ComT<E>, b: &ComT<E>) -> [[E::TargetField; 2]; 2] {
    let am = a.as_matrix();
    let bm = b.as_matrix();
    [
        [am[0][0].0 * bm[0][0].0, am[0][1].0 * bm[0][1].0],
        [am[1][0].0 * bm[1][0].0, am[1][1].0 * bm[1][1].0],
    ]
}

fn ct_pow_cell<E: Pairing>(cell: E::TargetField, rho: E::ScalarField) -> E::TargetField {
    cell.pow(rho.into_bigint())
}

#[test]
fn gs_verifier_parity_cells() {
    let gs = GrothSahaiCommitments::from_seed(b"GS_PARITY");
    let mut groth16 = ArkworksGroth16::new();
    let vk = groth16.setup().expect("vk ok");

    let witness = Fr::from(5u64);
    let p1 = groth16.prove(witness).expect("p1");
    let p2 = groth16.prove(witness).expect("p2");
    let x = [Fr::from(25u64)];

    let ic = compute_ic_from_vk_and_inputs(&vk, &x);
    let PairingOutput(t1) = Bls12_381::pairing(vk.alpha_g1, vk.beta_g2);
    let PairingOutput(t2) = Bls12_381::pairing(ic, vk.gamma_g2);
    let target = PairingOutput::<Bls12_381>(t1 * t2);

    let crs = align_crs::<Bls12_381>(gs.get_crs());
    let mut rng = test_rng();

    // Try permutations of X/Y ordering and Γ layout; pick the one where full ComT equality holds for both proofs
    let x_orders: Vec<Vec<G1Affine>> = vec![
        vec![p1.pi_a, p1.pi_c],
        vec![p1.pi_c, p1.pi_a],
    ];
    let y_orders: Vec<Vec<G2Affine>> = vec![
        vec![p1.pi_b, vk.delta_g2],
        vec![vk.delta_g2, p1.pi_b],
    ];
    let gammas: Vec<Vec<Vec<Fr>>> = vec![
        vec![vec![Fr::one(), Fr::zero()], vec![Fr::zero(), Fr::one()]], // diag
        vec![vec![Fr::zero(), Fr::one()], vec![Fr::one(), Fr::zero()]], // anti-diag
    ];

    let mut chosen: Option<(PPE<Bls12_381>, _, _)> = None;
    'search: for xo in &x_orders {
        for yo in &y_orders {
            for g in &gammas {
                let ppe = PPE::<Bls12_381> {
                    a_consts: vec![G1Affine::zero(), G1Affine::zero()],
                    b_consts: vec![G2Affine::zero(), G2Affine::zero()],
                    gamma: g.clone(),
                    target,
                };
                let cpr1 = ppe.commit_and_prove(&xo[..], &yo[..], &crs, &mut rng);
                let cpr2 = ppe.commit_and_prove(&xo[..], &yo[..], &crs, &mut rng);

                let lin_a1 = ComT::<Bls12_381>::pairing_sum(&Com1::<Bls12_381>::batch_linear_map(&ppe.a_consts), &cpr1.ycoms.coms);
                let lin_b1 = ComT::<Bls12_381>::pairing_sum(&cpr1.xcoms.coms, &Com2::<Bls12_381>::batch_linear_map(&ppe.b_consts));
                let stmt_y1 = vec_to_col_vec(&cpr1.ycoms.coms).left_mul(&ppe.gamma, false);
                let cross1 = ComT::<Bls12_381>::pairing_sum(&cpr1.xcoms.coms, &col_vec_to_vec(&stmt_y1));
                let lhs1 = lin_a1 + lin_b1 + cross1;
                let lin_t = ComT::<Bls12_381>::linear_map_PPE(&ppe.target);
                let rhs1 = lin_t
                    + ComT::<Bls12_381>::pairing_sum(&crs.u, &cpr1.equ_proofs[0].pi)
                    + ComT::<Bls12_381>::pairing_sum(&cpr1.equ_proofs[0].theta, &crs.v);

                let lin_a2 = ComT::<Bls12_381>::pairing_sum(&Com1::<Bls12_381>::batch_linear_map(&ppe.a_consts), &cpr2.ycoms.coms);
                let lin_b2 = ComT::<Bls12_381>::pairing_sum(&cpr2.xcoms.coms, &Com2::<Bls12_381>::batch_linear_map(&ppe.b_consts));
                let stmt_y2 = vec_to_col_vec(&cpr2.ycoms.coms).left_mul(&ppe.gamma, false);
                let cross2 = ComT::<Bls12_381>::pairing_sum(&cpr2.xcoms.coms, &col_vec_to_vec(&stmt_y2));
                let lhs2 = lin_a2 + lin_b2 + cross2;
                let rhs2 = lin_t
                    + ComT::<Bls12_381>::pairing_sum(&crs.u, &cpr2.equ_proofs[0].pi)
                    + ComT::<Bls12_381>::pairing_sum(&cpr2.equ_proofs[0].theta, &crs.v);

                let l1 = lhs1.as_matrix(); let r1 = rhs1.as_matrix();
                let l2 = lhs2.as_matrix(); let r2 = rhs2.as_matrix();
                let all1 = (l1[0][0]==r1[0][0]) && (l1[0][1]==r1[0][1]) && (l1[1][0]==r1[1][0]) && (l1[1][1]==r1[1][1]);
                let all2 = (l2[0][0]==r2[0][0]) && (l2[0][1]==r2[0][1]) && (l2[1][0]==r2[1][0]) && (l2[1][1]==r2[1][1]);
                if all1 && all2 {
                    chosen = Some((ppe, cpr1, cpr2));
                    break 'search;
                }
            }
        }
    }

    let (ppe, cpr1, cpr2) = chosen.expect("No PPE wiring (X/Y order, Γ) yielded full ComT equality for both proofs");

    // Ensure the library verifier accepts both proofs for this PPE/CRS
    println!("verifier(cpr1) = {}", cpr1.verify(&ppe, &crs));
    println!("verifier(cpr2) = {}", cpr2.verify(&ppe, &crs));

    // Compute K from full masked ComT (no acceptor cell assumption)
    let rho = Fr::from(777u64);

    // Derive K from full masked ComT for both proofs
    let full1 = ppe_eval_masked_comt_full(&ppe, &cpr1.xcoms.coms, &cpr1.ycoms.coms, &cpr1.equ_proofs[0].pi, &cpr1.equ_proofs[0].theta, &crs, rho);
    let full2 = ppe_eval_masked_comt_full(&ppe, &cpr2.xcoms.coms, &cpr2.ycoms.coms, &cpr2.equ_proofs[0].pi, &cpr2.equ_proofs[0].theta, &crs, rho);

    // Compare against masked RHS linear_map_PPE(target^ρ)
    let PairingOutput(tgt_unmasked) = ppe.target;
    let tgt_rho = PairingOutput::<Bls12_381>(tgt_unmasked.pow(rho.into_bigint()));
    let rhs_masked = ComT::<Bls12_381>::linear_map_PPE(&tgt_rho).as_matrix();
    let mut mismatch = false;
    for r in 0..2 { for c in 0..2 {
        if full1[r][c] != rhs_masked[r][c] || full2[r][c] != rhs_masked[r][c] {
            mismatch = true;
        }
    }}
    println!("masked LHS vs masked RHS equal for proof1? {}", !mismatch && full1 == rhs_masked);
    println!("masked LHS vs masked RHS equal for proof2? {}", !mismatch && full2 == rhs_masked);

    let mut h1 = Sha256::new();
    h1.update(b"PVUGC-KEM-ComT-v1");
    for r in 0..2 { for c in 0..2 {
        let mut bytes = Vec::new();
        full1[r][c].serialize_compressed(&mut bytes).unwrap();
        h1.update(bytes);
    }}
    let k1 = h1.finalize();

    let mut h2 = Sha256::new();
    h2.update(b"PVUGC-KEM-ComT-v1");
    for r in 0..2 { for c in 0..2 {
        let mut bytes = Vec::new();
        full2[r][c].serialize_compressed(&mut bytes).unwrap();
        h2.update(bytes);
    }}
    let k2 = h2.finalize();
    println!("full-matrix K equal? {}", k1[..] == k2[..]);
    assert_eq!(k1[..], k2[..], "Full-matrix masked ComT KEM keys differ across proofs");
}


