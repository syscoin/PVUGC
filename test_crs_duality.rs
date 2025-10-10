use ark_bls12_381::{Bls12_381, Fr};
use ark_ec::pairing::Pairing;
use groth_sahai::generator::CRS;
use ark_ff::One;

fn main() {
    let seed = b"TWO_PROOFS_DET";
    let crs = CRS::<Bls12_381>::generate_crs(seed);
    
    println!("Testing CRS duality invariants:");
    println!("Number of u pairs: {}", crs.u.len());
    println!("Number of v pairs: {}", crs.v.len());
    
    // Test u/u_dual duality
    for j in 0..crs.u.len() {
        let e00 = Bls12_381::pairing(crs.u[j].0, crs.u_dual[j].0);
        let e11 = Bls12_381::pairing(crs.u[j].1, crs.u_dual[j].1);
        let product = e00.0 * e11.0;
        
        let is_one = product == <Bls12_381 as Pairing>::TargetField::one();
        println!("u[{}] duality check: e(u0,u*0) * e(u1,u*1) = 1? {}", j, is_one);
        if !is_one {
            println!("  ERROR: Product = {:?}", product);
        }
    }
    
    // Test v/v_dual duality
    for k in 0..crs.v.len() {
        let e00 = Bls12_381::pairing(crs.v_dual[k].0, crs.v[k].0);
        let e11 = Bls12_381::pairing(crs.v_dual[k].1, crs.v[k].1);
        let product = e00.0 * e11.0;
        
        let is_one = product == <Bls12_381 as Pairing>::TargetField::one();
        println!("v[{}] duality check: e(v*0,v0) * e(v*1,v1) = 1? {}", k, is_one);
        if !is_one {
            println!("  ERROR: Product = {:?}", product);
        }
    }
}
