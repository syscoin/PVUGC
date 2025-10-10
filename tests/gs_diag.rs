use ark_bls12_381::{Bls12_381, Fr, G1Affine, G2Affine, Fq12};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField, One, Zero};
use ark_serialize::CanonicalSerialize;
use ark_std::test_rng;

use arkworks_groth16::groth16_wrapper::ArkworksGroth16;
use arkworks_groth16::gs_commitments::{GrothSahaiCommitments, compute_ic_from_vk_and_inputs};

use groth_sahai::generator::CRS;
use groth_sahai::statement::PPE;
use groth_sahai::data_structures::{Com1, Com2};
use groth_sahai::prover::Provable;

fn hash_gt<E: Pairing>(x: E::TargetField) -> String {
    use sha2::{Digest, Sha256};
    let mut bytes = Vec::new();
    x.serialize_compressed(&mut bytes).unwrap();
    let h = Sha256::digest(bytes);
    format!("{:02x}{:02x}{:02x}{:02x}…{:02x}{:02x}", h[0],h[1],h[2],h[3],h[30],h[31])
}

fn inv<E: Pairing>(x: E::TargetField) -> E::TargetField { x.inverse().expect("nonzero") }

fn align_crs<E: Pairing>(crs: &CRS<E>) -> CRS<E> {
    let mut out = crs.clone();
    for j in 0..out.u.len() {
        let PairingOutput(p0a) = E::pairing(out.u[j].0, out.u_dual[j].0);
        let PairingOutput(p1a) = E::pairing(out.u[j].1, out.u_dual[j].1);
        if p0a * p1a == E::TargetField::one() { continue; }
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
    for k in 0..out.v.len() {
        let PairingOutput(p0a) = E::pairing(out.v_dual[k].0, out.v[k].0);
        let PairingOutput(p1a) = E::pairing(out.v_dual[k].1, out.v[k].1);
        if p0a * p1a == E::TargetField::one() { continue; }
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
    out
}

fn five_buckets<E: Pairing>(
    x: &[Com1<E>], y: &[Com2<E>],
    pi: &[Com2<E>], th: &[Com1<E>],
    crs: &CRS<E>, gamma: &Vec<Vec<E::ScalarField>>,
    rho_opt: Option<E::ScalarField>,
) -> (E::TargetField, E::TargetField, E::TargetField, E::TargetField, E::TargetField, E::TargetField, Vec<Vec<E::TargetField>>) {
    let rho = rho_opt.unwrap_or_else(E::ScalarField::one);
    let u_dual_rho: Vec<_> = crs.u_dual.iter().map(|d| ((d.0.into_group()*rho).into_affine(), (d.1.into_group()*rho).into_affine())).collect();
    let v_dual_rho: Vec<_> = crs.v_dual.iter().map(|d| ((d.0.into_group()*rho).into_affine(), (d.1.into_group()*rho).into_affine())).collect();
    let u_rho: Vec<_> = crs.u.iter().map(|u| Com1::<E>((u.0.into_group()*rho).into_affine(), (u.1.into_group()*rho).into_affine())).collect();
    let v_rho: Vec<_> = crs.v.iter().map(|v| Com2::<E>((v.0.into_group()*rho).into_affine(), (v.1.into_group()*rho).into_affine())).collect();

    let mut b1 = E::TargetField::one(); let mut b2 = E::TargetField::one();
    let mut b3 = E::TargetField::one(); let mut b4 = E::TargetField::one();
    let mut g  = E::TargetField::one();

    for j in 0..x.len() { let PairingOutput(p0)=E::pairing(x[j].0,u_dual_rho[j].0); let PairingOutput(p1)=E::pairing(x[j].1,u_dual_rho[j].1); b1*=p0*p1; }
    for k in 0..y.len() { let PairingOutput(p0)=E::pairing(v_dual_rho[k].0,y[k].0); let PairingOutput(p1)=E::pairing(v_dual_rho[k].1,y[k].1); b2*=p0*p1; }
    for j in 0..pi.len() { let PairingOutput(p0)=E::pairing(u_rho[j].0,pi[j].0); let PairingOutput(p1)=E::pairing(u_rho[j].1,pi[j].1); b3*=p0*p1; }
    for k in 0..th.len() { let PairingOutput(p0)=E::pairing(th[k].0,v_rho[k].0); let PairingOutput(p1)=E::pairing(th[k].1,v_rho[k].1); b4*=p0*p1; }

    let mut cells = vec![vec![E::TargetField::one(); y.len()]; x.len()];
    for j in 0..gamma.len() {
        for k in 0..gamma[j].len() {
            if gamma[j][k].is_zero() { continue; }
            let PairingOutput(p00)=E::pairing(x[j].0,y[k].0); let PairingOutput(p11)=E::pairing(x[j].1,y[k].1);
            let cell=(p00*p11).pow(gamma[j][k].into_bigint()); g*=cell; cells[j][k]=cell;
        }
    }
    let g_rho = g.pow(rho.into_bigint());
    (b1,b2,b3,b4,g,g_rho,cells)
}

#[test]
fn gs_diag_five_buckets() {
    let gs = GrothSahaiCommitments::from_seed(b"GS_DIAG");
    let mut groth16 = ArkworksGroth16::new();
    let vk = groth16.setup().expect("vk ok");
    let witness = Fr::from(5u64);
    let proof1 = groth16.prove(witness).expect("p1");
    let proof2 = groth16.prove(witness).expect("p2");
    let x = [Fr::from(25u64)];

    let ic = compute_ic_from_vk_and_inputs(&vk, &x);
    let PairingOutput(t1) = Bls12_381::pairing(vk.alpha_g1, vk.beta_g2);
    let PairingOutput(t2) = Bls12_381::pairing(ic, vk.gamma_g2);
    let ppe = PPE::<Bls12_381> {
        a_consts: vec![G1Affine::zero(), G1Affine::zero()],
        b_consts: vec![G2Affine::zero(), G2Affine::zero()],
        gamma: vec![vec![Fr::one(), Fr::zero()], vec![Fr::zero(), Fr::one()]],
        target: PairingOutput::<Bls12_381>(t1 * t2),
    };

    let crs_aligned = align_crs::<Bls12_381>(gs.get_crs());
    let mut rng = test_rng();
    let c1 = ppe.commit_and_prove(&[proof1.pi_a, proof1.pi_c], &[proof1.pi_b, vk.delta_g2], &crs_aligned, &mut rng);
    let c2 = ppe.commit_and_prove(&[proof2.pi_a, proof2.pi_c], &[proof2.pi_b, vk.delta_g2], &crs_aligned, &mut rng);

    let rho = Fr::from(777u64);
    let (b1a,b2a,b3a,b4a,ga,ga_rho_a,cells_a) = five_buckets::<Bls12_381>(&c1.xcoms.coms,&c1.ycoms.coms,&c1.equ_proofs[0].pi,&c1.equ_proofs[0].theta,&crs_aligned,&ppe.gamma,None);
    let (b1b,b2b,b3b,b4b,gb,ga_rho_b,cells_b) = five_buckets::<Bls12_381>(&c2.xcoms.coms,&c2.ycoms.coms,&c2.equ_proofs[0].pi,&c2.equ_proofs[0].theta,&crs_aligned,&ppe.gamma,None);
    let (mb1a,mb2a,mb3a,mb4a,_g_unused_a, mg_a, _) = five_buckets::<Bls12_381>(&c1.xcoms.coms,&c1.ycoms.coms,&c1.equ_proofs[0].pi,&c1.equ_proofs[0].theta,&crs_aligned,&ppe.gamma,Some(rho));
    let (mb1b,mb2b,mb3b,mb4b,_g_unused_b, mg_b, _) = five_buckets::<Bls12_381>(&c2.xcoms.coms,&c2.ycoms.coms,&c2.equ_proofs[0].pi,&c2.equ_proofs[0].theta,&crs_aligned,&ppe.gamma,Some(rho));

    let anchor_a = b1a*b2a*b3a*b4a*ga; let anchor_b = b1b*b2b*b3b*b4b*gb;
    let masked_a = mb1a*mb2a*mb3a*mb4a*mg_a; let masked_b = mb1b*mb2b*mb3b*mb4b*mg_b;
    let PairingOutput(tgt) = ppe.target; let expected_masked = tgt.pow(rho.into_bigint());

    println!("\n=== GS DIAG ===");
    println!("target         : {}", hash_gt::<Bls12_381>(tgt));
    println!("anchor_p1      : {}", hash_gt::<Bls12_381>(anchor_a));
    println!("anchor_p2      : {}", hash_gt::<Bls12_381>(anchor_b));
    println!("masked_p1      : {}", hash_gt::<Bls12_381>(masked_a));
    println!("masked_p2      : {}", hash_gt::<Bls12_381>(masked_b));
    println!("expected tgt^ρ : {}", hash_gt::<Bls12_381>(expected_masked));
    println!("sanity masked==anchor^ρ? p1:{} p2:{}", masked_a==anchor_a.pow(rho.into_bigint()), masked_b==anchor_b.pow(rho.into_bigint()));
    println!("unmasked==target? p1:{} p2:{}", anchor_a==tgt, anchor_b==tgt);
    let r1 = b1a*inv::<Bls12_381>(b1b); let r2=b2a*inv::<Bls12_381>(b2b); let r3=b3a*inv::<Bls12_381>(b3b); let r4=b4a*inv::<Bls12_381>(b4b); let rg=ga*inv::<Bls12_381>(gb);
    println!("ratios (unmasked) b1:{} b2:{} b3:{} b4:{} γ:{}", hash_gt::<Bls12_381>(r1), hash_gt::<Bls12_381>(r2), hash_gt::<Bls12_381>(r3), hash_gt::<Bls12_381>(r4), hash_gt::<Bls12_381>(rg));
    println!("γ cells equal? [0][0]:{} [1][1]:{}", cells_a[0][0]==cells_b[0][0], cells_a[1][1]==cells_b[1][1]);
}


