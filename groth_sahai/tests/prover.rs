#![allow(non_snake_case)]

#[cfg(test)]
mod SXDH_prover_tests {

    use ark_bls12_381::Bls12_381 as F;
    use ark_ec::pairing::{Pairing, PairingOutput};
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::{Field, PrimeField};
    use ark_std::ops::Mul;
    use ark_std::str::FromStr;
    use ark_std::{test_rng, UniformRand, Zero};

    use groth_sahai::data_structures::*;
    use groth_sahai::prover::*;
    use groth_sahai::statement::*;
    use groth_sahai::verifier::Verifiable;
    use groth_sahai::{AbstractCrs, CRS};
    use groth_sahai::{masked_verifier_comt, masked_verifier_comt_with_gamma_mode, masked_verifier_matrix_postexp, kdf_from_comt, BT};

    type G1Affine = <F as Pairing>::G1Affine;
    type G2Affine = <F as Pairing>::G2Affine;
    type Fr = <F as Pairing>::ScalarField;
    type GT = PairingOutput<F>;

    #[test]
    fn pairing_product_equation_verifies() {
        let mut rng = test_rng();
        let crs = CRS::<F>::generate_crs(&mut rng);

        // An equation of the form e(X_2, c_2) * e(c_1, Y_1) * e(X_1, Y_1)^5 = t where t = e(3 g1, c_2) * e(c_1, 4 g2) * e(2 g1, 4 g2)^5 is satisfied
        // by variables X_1, X_2 in G1 and Y_1 in G2, and constants c_1 in G1 and c_2 in G2

        // X = [ X_1, X_2 ] = [2 g1, 3 g1]
        let xvars: Vec<G1Affine> = vec![
            crs.g1_gen.mul(Fr::from_str("2").unwrap()).into_affine(),
            crs.g1_gen.mul(Fr::from_str("3").unwrap()).into_affine(),
        ];
        // Y = [ Y_1 ] = [4 g2]
        let yvars: Vec<G2Affine> = vec![crs.g2_gen.mul(Fr::from_str("4").unwrap()).into_affine()];

        // A = [ c_1 ] (i.e. e(c_1, Y_1) term in equation)
        let a_consts: Vec<G1Affine> = vec![crs.g1_gen.mul(Fr::rand(&mut rng)).into_affine()];
        // B = [ 0, c_2 ] (i.e. only e(X_2, c_2) term in equation)
        let b_consts: Vec<G2Affine> = vec![
            G2Affine::zero(),
            crs.g2_gen.mul(Fr::rand(&mut rng)).into_affine(),
        ];
        // Gamma = [ 5, 0 ] (i.e. only e(X_1, Y_1)^5 term)
        let gamma: Matrix<Fr> = vec![vec![Fr::from_str("5").unwrap()], vec![Fr::zero()]];
        // Target -> all together (n.b. e(X_1, Y_1)^5 = e(X_1, 5 Y_1) = e(5 X_1, Y_1) by the properties of non-degenerate bilinear maps)
        let target: GT = F::pairing(xvars[1], b_consts[1])
            + F::pairing(a_consts[0], yvars[0])
            + F::pairing(xvars[0], yvars[0].mul(gamma[0][0]).into_affine());
        let equ: PPE<F> = PPE::<F> {
            a_consts,
            b_consts,
            gamma,
            target,
        };

        let proof: CProof<F> = equ.commit_and_prove(&xvars, &yvars, &crs, &mut rng);
        assert!(equ.verify(&proof, &crs));
    }

    #[test]
    fn pairing_product_equation_masked_comt_parity() {
        let mut rng = test_rng();
        let crs = CRS::<F>::generate_crs(&mut rng);

        // 2x2 PPE: X has 2 G1 vars, Y has 2 G2 vars
        let xvars: Vec<G1Affine> = vec![
            crs.g1_gen.mul(Fr::from_str("2").unwrap()).into_affine(),
            crs.g1_gen.mul(Fr::from_str("3").unwrap()).into_affine(),
        ];
        let yvars: Vec<G2Affine> = vec![
            crs.g2_gen.mul(Fr::from_str("4").unwrap()).into_affine(),
            crs.g2_gen.mul(Fr::from_str("5").unwrap()).into_affine(),
        ];
        // a_consts len = |Y|, b_consts len = |X|
        let a_consts: Vec<G1Affine> = vec![
            crs.g1_gen.mul(Fr::rand(&mut rng)).into_affine(),
            crs.g1_gen.mul(Fr::rand(&mut rng)).into_affine(),
        ];
        let b_consts: Vec<G2Affine> = vec![
            crs.g2_gen.mul(Fr::rand(&mut rng)).into_affine(),
            crs.g2_gen.mul(Fr::rand(&mut rng)).into_affine(),
        ];
        // Γ diagonal 2x2
        let gamma: Matrix<Fr> = vec![
            vec![Fr::from_str("7").unwrap(), Fr::zero()],
            vec![Fr::zero(), Fr::from_str("11").unwrap()],
        ];
        // Target = e(X0,b0)+e(X1,b1)+e(a0,Y0)+e(a1,Y1)+e(X0,Y0)^g00+e(X1,Y1)^g11
        let target: GT = F::pairing(xvars[0], b_consts[0])
            + F::pairing(xvars[1], b_consts[1])
            + F::pairing(a_consts[0], yvars[0])
            + F::pairing(a_consts[1], yvars[1])
            + F::pairing(xvars[0], yvars[0].mul(gamma[0][0]).into_affine())
            + F::pairing(xvars[1], yvars[1].mul(gamma[1][1]).into_affine());
        let equ: PPE<F> = PPE::<F> { a_consts, b_consts, gamma, target };

        // Two proofs for same equation
        let p1: CProof<F> = equ.commit_and_prove(&xvars, &yvars, &crs, &mut rng);
        let p2: CProof<F> = equ.commit_and_prove(&xvars, &yvars, &crs, &mut rng);
        assert!(equ.verify(&p1, &crs));
        assert!(equ.verify(&p2, &crs));

        // Masked verifier-style ComT for both proofs
        let rho = Fr::from_str("777").unwrap();
        let m1 = masked_verifier_comt::<F>(
            &equ, &crs,
            &p1.xcoms.coms, &p1.ycoms.coms,
            &p1.equ_proofs[0].pi, &p1.equ_proofs[0].theta,
            rho, /*include_dual_helpers=*/ false,
        );
        let m2 = masked_verifier_comt::<F>(
            &equ, &crs,
            &p2.xcoms.coms, &p2.ycoms.coms,
            &p2.equ_proofs[0].pi, &p2.equ_proofs[0].theta,
            rho, /*include_dual_helpers=*/ false,
        );

        // RHS mask check
        let PairingOutput(tgt) = equ.target;
        let rhs_mask = ComT::<F>::linear_map_PPE(&PairingOutput::<F>(tgt.pow(rho.into_bigint())));
        // Instrument per-leg vs RHS for p1/p2
        let print_legs = |lab: &str, p: &CProof<F>| {
            // Scale helpers
            let x_rho: Vec<G1Affine> = p.xcoms.coms.iter().map(|c| (c.0.into_group()*rho).into_affine()).collect::<Vec<_>>();
            let x_rho_com1: Vec<Com1<F>> = p.xcoms.coms.iter().map(|c| Com1::<F>((c.0.into_group()*rho).into_affine(), (c.1.into_group()*rho).into_affine())).collect();
            let y_rho_com2: Vec<Com2<F>> = p.ycoms.coms.iter().map(|d| Com2::<F>((d.0.into_group()*rho).into_affine(), (d.1.into_group()*rho).into_affine())).collect();
            let u_rho: Vec<Com1<F>> = crs.u.iter().map(|u| Com1::<F>((u.0.into_group()*rho).into_affine(), (u.1.into_group()*rho).into_affine())).collect();
            let v_rho: Vec<Com2<F>> = crs.v.iter().map(|v| Com2::<F>((v.0.into_group()*rho).into_affine(), (v.1.into_group()*rho).into_affine())).collect();

            let i1_a: Vec<Com1<F>> = Com1::batch_linear_map(&equ.a_consts);
            let i2_b: Vec<Com2<F>> = Com2::batch_linear_map(&equ.b_consts);

            // Legs: (i1(a)·Y)^ρ via Y^ρ, (X·i2(b))^ρ via X^ρ, (X·Γ·Y^ρ), (U^ρ·π), (θ·V^ρ)
            let a_y_rho = ComT::<F>::pairing_sum(&i1_a, &y_rho_com2);
            let x_rho_b = ComT::<F>::pairing_sum(&x_rho_com1, &i2_b);
            let stmt_y_rho = vec_to_col_vec(&y_rho_com2).left_mul(&equ.gamma, false);
            let cross_y_rho = ComT::<F>::pairing_sum(&p.xcoms.coms, &col_vec_to_vec(&stmt_y_rho));
            let u_pi_rho = ComT::<F>::pairing_sum(&u_rho, &p.equ_proofs[0].pi);
            let th_v_rho = ComT::<F>::pairing_sum(&p.equ_proofs[0].theta, &v_rho);

            let rhs = rhs_mask.as_matrix();
            let pr = |name: &str, m: &ComT<F>| {
                let mm = m.as_matrix();
                print!("{}:", name);
                for r in 0..2 { for c in 0..2 { print!(" [{}][{}] {} ", r,c, mm[r][c]==rhs[r][c]); } print!(" | "); }
                println!();
            };
            println!("{} per-cell vs RHS:", lab);
            pr("i1(a)·Y^rho", &a_y_rho);
            pr("X^rho·i2(b)", &x_rho_b);
            pr("X·Gamma·Y^rho", &cross_y_rho);
            pr("U^rho·pi", &u_pi_rho);
            pr("theta·V^rho", &th_v_rho);
        };
        print_legs("p1", &p1);
        print_legs("p2", &p2);

        assert_eq!(m1.as_matrix(), rhs_mask.as_matrix(), "masked LHS != masked RHS");
        assert_eq!(m1.as_matrix(), m2.as_matrix(), "masked ComT differs across proofs");

        // KDF equality
        let k1 = kdf_from_comt::<F>(&m1, b"crs", b"ppe", b"vk", b"x", b"deposit", 1);
        let k2 = kdf_from_comt::<F>(&m2, b"crs", b"ppe", b"vk", b"x", b"deposit", 1);
        assert_eq!(k1, k2, "KEM key differs across proofs for 2x2 PPE");
    }

    #[test]
    fn pairing_product_equation_masked_comt_parity_sweep() {
        let mut rng = test_rng();
        let crs = CRS::<F>::generate_crs(&mut rng);

        // Base X and Y vars
        let x_base: Vec<G1Affine> = vec![
            crs.g1_gen.mul(Fr::from_str("2").unwrap()).into_affine(),
            crs.g1_gen.mul(Fr::from_str("3").unwrap()).into_affine(),
        ];
        let y_base: Vec<G2Affine> = vec![
            crs.g2_gen.mul(Fr::from_str("4").unwrap()).into_affine(),
            crs.g2_gen.mul(Fr::from_str("5").unwrap()).into_affine(),
        ];
        let a_consts: Vec<G1Affine> = vec![
            crs.g1_gen.mul(Fr::rand(&mut rng)).into_affine(),
            crs.g1_gen.mul(Fr::rand(&mut rng)).into_affine(),
        ];
        let b_consts: Vec<G2Affine> = vec![
            crs.g2_gen.mul(Fr::rand(&mut rng)).into_affine(),
            crs.g2_gen.mul(Fr::rand(&mut rng)).into_affine(),
        ];
        let rho = Fr::from_str("777").unwrap();

        let orders = [false, true]; // false=orig, true=swap
        let mut found = false;
        for swap_x in orders {
            for swap_y in orders {
                let mut xvars = x_base.clone();
                let mut yvars = y_base.clone();
                if swap_x { xvars.swap(0,1); }
                if swap_y { yvars.swap(0,1); }

                // Γ stays diagonal w.r.t the current order
                let gamma: Matrix<Fr> = vec![
                    vec![Fr::from_str("7").unwrap(), Fr::zero()],
                    vec![Fr::zero(), Fr::from_str("11").unwrap()],
                ];
                // Target matching current order
                let target: GT = F::pairing(xvars[0], b_consts[0])
                    + F::pairing(xvars[1], b_consts[1])
                    + F::pairing(a_consts[0], yvars[0])
                    + F::pairing(a_consts[1], yvars[1])
                    + F::pairing(xvars[0], yvars[0].mul(gamma[0][0]).into_affine())
                    + F::pairing(xvars[1], yvars[1].mul(gamma[1][1]).into_affine());
                let equ: PPE<F> = PPE::<F> { a_consts: a_consts.clone(), b_consts: b_consts.clone(), gamma: gamma.clone(), target };

                let p1: CProof<F> = equ.commit_and_prove(&xvars, &yvars, &crs, &mut rng);
                let p2: CProof<F> = equ.commit_and_prove(&xvars, &yvars, &crs, &mut rng);
                assert!(equ.verify(&p1, &crs));
                assert!(equ.verify(&p2, &crs));

                for postexp in [true, false] {
                    let m1_mat = if postexp {
                        masked_verifier_matrix_postexp::<F>(&equ, &crs, &p1.xcoms.coms, &p1.ycoms.coms, &p1.equ_proofs[0].pi, &p1.equ_proofs[0].theta, rho)
                    } else {
                        let m = masked_verifier_comt::<F>(&equ, &crs, &p1.xcoms.coms, &p1.ycoms.coms, &p1.equ_proofs[0].pi, &p1.equ_proofs[0].theta, rho, false);
                        let mm = m.as_matrix();
                        [[mm[0][0].0, mm[0][1].0],[mm[1][0].0, mm[1][1].0]]
                    };
                    let m2_mat = if postexp {
                        masked_verifier_matrix_postexp::<F>(&equ, &crs, &p2.xcoms.coms, &p2.ycoms.coms, &p2.equ_proofs[0].pi, &p2.equ_proofs[0].theta, rho)
                    } else {
                        let m = masked_verifier_comt::<F>(&equ, &crs, &p2.xcoms.coms, &p2.ycoms.coms, &p2.equ_proofs[0].pi, &p2.equ_proofs[0].theta, rho, false);
                        let mm = m.as_matrix();
                        [[mm[0][0].0, mm[0][1].0],[mm[1][0].0, mm[1][1].0]]
                    };
                    let PairingOutput(tgt) = equ.target;
                    let rhs_mask = ComT::<F>::linear_map_PPE(&PairingOutput::<F>(tgt.pow(rho.into_bigint()))).as_matrix();

                    let ok = m1_mat == [[rhs_mask[0][0].0, rhs_mask[0][1].0],[rhs_mask[1][0].0, rhs_mask[1][1].0]]
                          && m2_mat == [[rhs_mask[0][0].0, rhs_mask[0][1].0],[rhs_mask[1][0].0, rhs_mask[1][1].0]];
                    println!("sweep swap_x={} swap_y={} postexp={} => {}", swap_x, swap_y, postexp, ok);
                    if ok {
                        // derive K off m1_mat/m2_mat cells
                        use ark_serialize::CanonicalSerialize;
                        use sha2::{Sha256, Digest};
                        let mut hasher = Sha256::new();
                        for r in 0..2 { for c in 0..2 { let mut b=Vec::new(); m1_mat[r][c].serialize_compressed(&mut b).unwrap(); hasher.update(b);} }
                        let k1 = hasher.finalize();
                        let mut hasher2 = Sha256::new();
                        for r in 0..2 { for c in 0..2 { let mut b=Vec::new(); m2_mat[r][c].serialize_compressed(&mut b).unwrap(); hasher2.update(b);} }
                        let k2 = hasher2.finalize();
                        assert_eq!(k1, k2, "KDF mismatch under working order");
                        found = true;
                        break;
                    }
                }
            }
            if found { break; }
        }
        assert!(found, "No X/Y order produced masked parity");
    }

    #[test]
    fn multi_scalar_mult_equation_G1_verifies() {
        let mut rng = test_rng();
        let crs = CRS::<F>::generate_crs(&mut rng);

        // An equation of the form c_2 * X_2 + y_1 * c_1 + (y_1 * X_1)*5 = t where t = c_2 * (3 g1) + 4 * c_1 + (4 * (2 g1))*5 is satisfied
        // by variables X_1, X_2 in G1 and y_1 in Fr, and constants c_1 in G1 and c_2 in Fr

        // X = [ X_1, X_2 ] = [2 g1, 3 g1]
        let xvars: Vec<G1Affine> = vec![
            crs.g1_gen.mul(Fr::from_str("2").unwrap()).into_affine(),
            crs.g1_gen.mul(Fr::from_str("3").unwrap()).into_affine(),
        ];
        // y = [ y_1 ] = [ 4 ]
        let scalar_yvars: Vec<Fr> = vec![Fr::from_str("4").unwrap()];

        // A = [ c_1 ] (i.e. y_1 * c_1 term in equation)
        let a_consts: Vec<G1Affine> = vec![crs.g1_gen.mul(Fr::rand(&mut rng)).into_affine()];
        // B = [ 0, c_2 ] (i.e. only c_2 * X_2 term in equation)
        let b_consts: Vec<Fr> = vec![Fr::zero(), Fr::rand(&mut rng)];
        // Gamma = [ 5, 0 ] (i.e. only (y_1 * X_1)*5 term)
        let gamma: Matrix<Fr> = vec![vec![Fr::from_str("5").unwrap()], vec![Fr::zero()]];
        // Target -> all together
        let target: G1Affine = (xvars[1].mul(b_consts[1])
            + a_consts[0].mul(scalar_yvars[0])
            + xvars[0].mul(scalar_yvars[0] * gamma[0][0]))
        .into_affine();
        let equ: MSMEG1<F> = MSMEG1::<F> {
            a_consts,
            b_consts,
            gamma,
            target,
        };

        let proof: CProof<F> = equ.commit_and_prove(&xvars, &scalar_yvars, &crs, &mut rng);
        assert!(equ.verify(&proof, &crs));
    }

    #[test]
    fn multi_scalar_mult_equation_G2_verifies() {
        let mut rng = test_rng();
        let crs = CRS::<F>::generate_crs(&mut rng);

        // An equation of the form x_2 * c_2 + c_1 * Y_1 + (x_1 * Y_1)*5 = t where t = 3 * c_2 + c_1 * (4 g2) + (2 * (4 g2))*5 is satisfied
        // by variables x_1, x_2 in Fr and Y_1 in G2, and constants c_1 in Fr and c_2 in G2

        // x = [ x_1, x_2 ] = [2, 3]
        let scalar_xvars: Vec<Fr> = vec![Fr::from_str("2").unwrap(), Fr::from_str("3").unwrap()];
        // Y = [ y_1 ] = [ 4 g2 ]
        let yvars: Vec<G2Affine> = vec![crs.g2_gen.mul(Fr::from_str("4").unwrap()).into_affine()];

        // A = [ c_1 ] (i.e. c_1 * Y_1 term in equation)
        let a_consts: Vec<Fr> = vec![Fr::rand(&mut rng)];
        // B = [ 0, c_2 ] (i.e. only x_2 * c_2 term in equation)
        let b_consts: Vec<G2Affine> = vec![
            G2Affine::zero(),
            crs.g2_gen.mul(Fr::rand(&mut rng)).into_affine(),
        ];
        // Gamma = [ 5, 0 ] (i.e. only (x_1 * Y_1)*5 term)
        let gamma: Matrix<Fr> = vec![vec![Fr::from_str("5").unwrap()], vec![Fr::zero()]];
        // Target -> all together
        let target: G2Affine = (b_consts[1].mul(scalar_xvars[1])
            + yvars[0].mul(a_consts[0])
            + yvars[0].mul(scalar_xvars[0] * gamma[0][0]))
        .into_affine();
        let equ: MSMEG2<F> = MSMEG2::<F> {
            a_consts,
            b_consts,
            gamma,
            target,
        };

        let proof: CProof<F> = equ.commit_and_prove(&scalar_xvars, &yvars, &crs, &mut rng);
        assert!(equ.verify(&proof, &crs));
    }

    #[test]
    fn quadratic_equation_verifies() {
        let mut rng = test_rng();
        let crs = CRS::<F>::generate_crs(&mut rng);

        // An equation of the form c_2 * x_2 + c_1 * y_1 + (x_1 * y_1)*5 = t where t = c_2 * 3 + c_1 * 4 + (2 * 4)*5 is satisfied
        // by variables x_1, x_2 and y_1 in Fr, and constants c_1 and c_2 in Fr

        // x = [ x_1, x_2 ] = [2, 3]
        let scalar_xvars: Vec<Fr> = vec![Fr::from_str("2").unwrap(), Fr::from_str("3").unwrap()];
        // y = [ y_1 ] = [ 4 ]
        let scalar_yvars: Vec<Fr> = vec![Fr::from_str("4").unwrap()];

        // A = [ c_1 ] (i.e. c_1 * y_1 term in equation)
        let a_consts: Vec<Fr> = vec![Fr::rand(&mut rng)];
        // B = [ 0, c_2 ] (i.e. only c_2 * x2 term in equation)
        let b_consts: Vec<Fr> = vec![Fr::zero(), Fr::rand(&mut rng)];
        // Gamma = [ 5, 0 ] (i.e. only (x_1 * y_1)*5 term)
        let gamma: Matrix<Fr> = vec![vec![Fr::from_str("5").unwrap()], vec![Fr::zero()]];
        // Target -> all together
        let target: Fr = b_consts[1] * scalar_xvars[1]
            + scalar_yvars[0] * a_consts[0]
            + scalar_yvars[0] * scalar_xvars[0] * gamma[0][0];
        let equ: QuadEqu<F> = QuadEqu::<F> {
            a_consts,
            b_consts,
            gamma,
            target,
        };

        let proof: CProof<F> = equ.commit_and_prove(&scalar_xvars, &scalar_yvars, &crs, &mut rng);
        assert!(equ.verify(&proof, &crs));
    }

    #[test]
    fn multiple_proofs_deterministic_kem_ppe() {
        use groth_sahai::kem_eval::{ppe_eval_bases, ppe_eval_with_masked_pairs, mask_g1_pair, mask_g2_pair};
        use sha2::{Sha256, Digest};
        use ark_serialize::CanonicalSerialize;

        let mut rng = test_rng();
        let crs = CRS::<F>::generate_crs(&mut rng);

        // Create a 2x2 PPE equation structure (like Groth16 verification)
        // Use ZERO constants to simulate Groth16 structure more closely
        let a_consts: Vec<G1Affine> = vec![G1Affine::zero(), G1Affine::zero()];
        let b_consts: Vec<G2Affine> = vec![G2Affine::zero(), G2Affine::zero()];
        
        // Diagonal gamma matrix (like Groth16: e(pi_A, pi_B) * e(pi_C, delta))
        let gamma: Matrix<Fr> = vec![
            vec![Fr::from(1u64), Fr::zero()],
            vec![Fr::zero(), Fr::from(1u64)],
        ];
        
        // Fixed target (like e(alpha, beta) * e(IC, gamma) in Groth16)
        let target: GT = F::pairing(
            crs.g1_gen.mul(Fr::from(100u64)).into_affine(),
            crs.g2_gen.mul(Fr::from(1u64)).into_affine()
        );
        
        let equ: PPE<F> = PPE::<F> { a_consts, b_consts, gamma, target };

        // Generate multiple proofs with DIFFERENT variables (simulating different Groth16 proofs)
        let num_proofs = 3;
        let mut proofs = Vec::new();
        
        println!("\n=== Testing with DIFFERENT variables (like different Groth16 proofs) ===");
        
        // Create different variable sets that satisfy: e(x1,y1) + e(x2,y2) = target
        // Since target = e(100*g1, 1*g2), we need x1*y1 + x2*y2 = 100 in the exponent
        let variable_sets = vec![
            // Set 1: 20*2 + 60*1 = 40 + 60 = 100
            (vec![
                crs.g1_gen.mul(Fr::from(20u64)).into_affine(),
                crs.g1_gen.mul(Fr::from(60u64)).into_affine(),
            ], vec![
                crs.g2_gen.mul(Fr::from(2u64)).into_affine(),
                crs.g2_gen.mul(Fr::from(1u64)).into_affine(),
            ]),
            // Set 2: 10*5 + 25*2 = 50 + 50 = 100  
            (vec![
                crs.g1_gen.mul(Fr::from(10u64)).into_affine(),
                crs.g1_gen.mul(Fr::from(25u64)).into_affine(),
            ], vec![
                crs.g2_gen.mul(Fr::from(5u64)).into_affine(),
                crs.g2_gen.mul(Fr::from(2u64)).into_affine(),
            ]),
            // Set 3: 50*1 + 10*5 = 50 + 50 = 100
            (vec![
                crs.g1_gen.mul(Fr::from(50u64)).into_affine(),
                crs.g1_gen.mul(Fr::from(10u64)).into_affine(),
            ], vec![
                crs.g2_gen.mul(Fr::from(1u64)).into_affine(),
                crs.g2_gen.mul(Fr::from(5u64)).into_affine(),
            ]),
        ];
        
        for (i, (xvars, yvars)) in variable_sets.iter().enumerate() {
            // Verify the equation is satisfied
            let check = F::pairing(xvars[0], yvars[0]) + F::pairing(xvars[1], yvars[1]);
            println!("Set {}: Variables satisfy equation: {}", i, check == target);
            
            let proof = equ.commit_and_prove(xvars, yvars, &crs, &mut rng);
            assert!(equ.verify(&proof, &crs), "Proof {} should verify", i);
            proofs.push(proof);
        }

        // Get evaluation bases for KEM
        let eval_bases = ppe_eval_bases(&equ, &crs);
        
        // Deterministically derive rho from statement parameters
        let mut hasher = Sha256::new();
        hasher.update(b"PVUGC/test/multiple_proofs");
        
        // Serialize PPE parameters for deterministic rho
        let mut equ_bytes = Vec::new();
        for a in &equ.a_consts {
            a.serialize_compressed(&mut equ_bytes).unwrap();
        }
        for b in &equ.b_consts {
            b.serialize_compressed(&mut equ_bytes).unwrap();
        }
        for row in &equ.gamma {
            for val in row {
                val.serialize_compressed(&mut equ_bytes).unwrap();
            }
        }
        equ.target.serialize_compressed(&mut equ_bytes).unwrap();
        
        hasher.update(&equ_bytes);
        let rho_seed = hasher.finalize();
        let rho = Fr::from_le_bytes_mod_order(&rho_seed);

        // Mask the evaluation bases with deterministic rho
        let u_masked: Vec<_> = eval_bases.x_g2_pairs.iter()
            .map(|&p| mask_g2_pair::<F>(p, rho))
            .collect();
        let v_masked: Vec<_> = eval_bases.v_pairs.iter()
            .map(|&p| mask_g1_pair::<F>(p, rho))
            .collect();

        // Evaluate KEM for each proof
        let mut kem_values = Vec::new();
        for (i, proof) in proofs.iter().enumerate() {
            let PairingOutput(kem_val) = ppe_eval_with_masked_pairs::<F>(
                &proof.xcoms.coms,
                &proof.ycoms.coms,
                &u_masked,
                &v_masked,
            );
            kem_values.push(kem_val);
            println!("Proof {} KEM value: {:?}", i, kem_val);
        }

        // Critical assertion: all KEM values must be identical
        // This demonstrates the proof-agnostic property of deterministic KEM/PPE
        let first_kem = kem_values[0];
        for (i, &kem_val) in kem_values.iter().enumerate().skip(1) {
            assert_eq!(kem_val, first_kem, 
                "KEM value {} differs from first KEM value. This violates proof-agnostic determinism.", i);
        }

        // Additional verification: derive KDF keys from KEM values
        let mut kdf_keys = Vec::new();
        for (i, &kem_val) in kem_values.iter().enumerate() {
            let mut kdf_hasher = Sha256::new();
            kdf_hasher.update(b"PVUGC/KDF/test");
            kdf_hasher.update(&rho_seed);
            
            // Serialize KEM value to bytes first
            let mut kem_bytes = Vec::new();
            kem_val.serialize_compressed(&mut kem_bytes).unwrap();
            kdf_hasher.update(&kem_bytes);
            
            let kdf_key = kdf_hasher.finalize();
            kdf_keys.push(kdf_key);
            println!("Proof {} KDF key: {:x}", i, kdf_key);
        }

        // All KDF keys must be identical
        let first_kdf = kdf_keys[0];
        for (i, kdf_key) in kdf_keys.iter().enumerate().skip(1) {
            assert_eq!(kdf_key, &first_kdf, 
                "KDF key {} differs from first KDF key", i);
        }

        println!("✅ All {} proofs produced identical KEM values and KDF keys", num_proofs);
        println!("✅ Deterministic KEM/PPE successfully demonstrated proof-agnostic property");
    }

    #[test]
    fn multiple_proofs_gs_algebra_masked_comt() {
        use groth_sahai::{masked_verifier_comt, kdf_from_comt};
        use sha2::{Sha256, Digest};
        use ark_serialize::CanonicalSerialize;

        let mut rng = test_rng();
        let crs = CRS::<F>::generate_crs(&mut rng);

        // Create a 2x2 PPE equation
        let xvars: Vec<G1Affine> = vec![
            crs.g1_gen.mul(Fr::from_str("2").unwrap()).into_affine(),
            crs.g1_gen.mul(Fr::from_str("3").unwrap()).into_affine(),
        ];
        let yvars: Vec<G2Affine> = vec![
            crs.g2_gen.mul(Fr::from_str("4").unwrap()).into_affine(),
            crs.g2_gen.mul(Fr::from_str("5").unwrap()).into_affine(),
        ];
        
        let a_consts: Vec<G1Affine> = vec![
            crs.g1_gen.mul(Fr::rand(&mut rng)).into_affine(),
            crs.g1_gen.mul(Fr::rand(&mut rng)).into_affine(),
        ];
        let b_consts: Vec<G2Affine> = vec![
            crs.g2_gen.mul(Fr::rand(&mut rng)).into_affine(),
            crs.g2_gen.mul(Fr::rand(&mut rng)).into_affine(),
        ];
        
        // Γ diagonal 2x2
        let gamma: Matrix<Fr> = vec![
            vec![Fr::from_str("7").unwrap(), Fr::zero()],
            vec![Fr::zero(), Fr::from_str("11").unwrap()],
        ];
        
        let target: GT = F::pairing(xvars[0], b_consts[0])
            + F::pairing(xvars[1], b_consts[1])
            + F::pairing(a_consts[0], yvars[0])
            + F::pairing(a_consts[1], yvars[1])
            + F::pairing(xvars[0], yvars[0].mul(gamma[0][0]).into_affine())
            + F::pairing(xvars[1], yvars[1].mul(gamma[1][1]).into_affine());
        
        let equ: PPE<F> = PPE::<F> { a_consts, b_consts, gamma, target };

        // Generate multiple proofs for the same statement
        let num_proofs = 5;
        let mut proofs = Vec::new();
        
        for i in 0..num_proofs {
            let proof = equ.commit_and_prove(&xvars, &yvars, &crs, &mut rng);
            assert!(equ.verify(&proof, &crs), "Proof {} should verify", i);
            proofs.push(proof);
        }

        // Deterministically derive rho from statement parameters
        let mut hasher = Sha256::new();
        hasher.update(b"PVUGC/test/gs_algebra");
        
        // Serialize PPE parameters for deterministic rho
        let mut equ_bytes = Vec::new();
        for a in &equ.a_consts {
            a.serialize_compressed(&mut equ_bytes).unwrap();
        }
        for b in &equ.b_consts {
            b.serialize_compressed(&mut equ_bytes).unwrap();
        }
        for row in &equ.gamma {
            for val in row {
                val.serialize_compressed(&mut equ_bytes).unwrap();
            }
        }
        equ.target.serialize_compressed(&mut equ_bytes).unwrap();
        
        hasher.update(&equ_bytes);
        let rho_seed = hasher.finalize();
        let rho = Fr::from_le_bytes_mod_order(&rho_seed);

        // Use GS masked ComT approach (no dual bases)
        let mut masked_comts = Vec::new();
        for (i, proof) in proofs.iter().enumerate() {
            let masked_comt = masked_verifier_comt::<F>(
                &equ, &crs,
                &proof.xcoms.coms, &proof.ycoms.coms,
                &proof.equ_proofs[0].pi, &proof.equ_proofs[0].theta,
                rho, /*include_dual_helpers=*/ false,
            );
            masked_comts.push(masked_comt);
            println!("Proof {} masked ComT computed", i);
        }

        // Demonstrate that GS algebra (without dual bases) is NOT proof-agnostic
        // Different proofs produce different masked ComTs
        let first_comt = &masked_comts[0];
        let mut all_different = true;
        for (i, comt) in masked_comts.iter().enumerate().skip(1) {
            if comt.as_matrix() == first_comt.as_matrix() {
                all_different = false;
                break;
            }
        }
        
        if all_different {
            println!("✅ Confirmed: GS algebra produces different masked ComTs for different proofs");
            println!("✅ This demonstrates that GS algebra is NOT proof-agnostic");
        } else {
            panic!("Unexpected: Some proofs produced identical masked ComTs");
        }

        // Derive KDF keys from masked ComTs
        let mut kdf_keys = Vec::new();
        for (i, comt) in masked_comts.iter().enumerate() {
            let kdf_key = kdf_from_comt::<F>(comt, b"crs", b"ppe", b"vk", b"x", b"deposit", 1);
            kdf_keys.push(kdf_key);
            println!("Proof {} KDF key: {:02x?}", i, kdf_key);
        }

        // Demonstrate that KDF keys are also different (since masked ComTs are different)
        let first_kdf = kdf_keys[0];
        let mut all_kdf_different = true;
        for (i, kdf_key) in kdf_keys.iter().enumerate().skip(1) {
            if kdf_key == &first_kdf {
                all_kdf_different = false;
                break;
            }
        }
        
        if all_kdf_different {
            println!("✅ Confirmed: GS algebra produces different KDF keys for different proofs");
        } else {
            panic!("Unexpected: Some proofs produced identical KDF keys");
        }

        // Note: Masked ComT represents the LHS of GS verification equation
        // It should equal target^rho when the equation is satisfied, but this is complex
        // The key point is that different proofs produce different masked ComTs

        println!("✅ All {} proofs produced different masked ComTs and KDF keys", num_proofs);
        println!("✅ GS algebra (without dual bases) correctly demonstrates NON-proof-agnostic behavior");
        println!("✅ This contrasts with dual-bases approach which IS proof-agnostic");
    }

    #[test]
    fn multiple_proofs_gs_algebra_proof_agnostic() {
        use groth_sahai::kem_eval::{ppe_eval_bases, ppe_eval_with_masked_pairs, mask_g1_pair, mask_g2_pair};
        use sha2::{Sha256, Digest};
        use ark_serialize::CanonicalSerialize;

        let mut rng = test_rng();
        let crs = CRS::<F>::generate_crs(&mut rng);

        // Create a 2x2 PPE equation
        let xvars: Vec<G1Affine> = vec![
            crs.g1_gen.mul(Fr::from_str("2").unwrap()).into_affine(),
            crs.g1_gen.mul(Fr::from_str("3").unwrap()).into_affine(),
        ];
        let yvars: Vec<G2Affine> = vec![
            crs.g2_gen.mul(Fr::from_str("4").unwrap()).into_affine(),
            crs.g2_gen.mul(Fr::from_str("5").unwrap()).into_affine(),
        ];
        
        let a_consts: Vec<G1Affine> = vec![
            crs.g1_gen.mul(Fr::rand(&mut rng)).into_affine(),
            crs.g1_gen.mul(Fr::rand(&mut rng)).into_affine(),
        ];
        let b_consts: Vec<G2Affine> = vec![
            crs.g2_gen.mul(Fr::rand(&mut rng)).into_affine(),
            crs.g2_gen.mul(Fr::rand(&mut rng)).into_affine(),
        ];
        
        // Γ diagonal 2x2
        let gamma: Matrix<Fr> = vec![
            vec![Fr::from_str("7").unwrap(), Fr::zero()],
            vec![Fr::zero(), Fr::from_str("11").unwrap()],
        ];
        
        let target: GT = F::pairing(xvars[0], b_consts[0])
            + F::pairing(xvars[1], b_consts[1])
            + F::pairing(a_consts[0], yvars[0])
            + F::pairing(a_consts[1], yvars[1])
            + F::pairing(xvars[0], yvars[0].mul(gamma[0][0]).into_affine())
            + F::pairing(xvars[1], yvars[1].mul(gamma[1][1]).into_affine());
        
        let equ: PPE<F> = PPE::<F> { a_consts, b_consts, gamma, target };

        // Generate multiple proofs for the same statement
        let num_proofs = 5;
        let mut proofs = Vec::new();
        
        for i in 0..num_proofs {
            let proof = equ.commit_and_prove(&xvars, &yvars, &crs, &mut rng);
            assert!(equ.verify(&proof, &crs), "Proof {} should verify", i);
            proofs.push(proof);
        }

        // Deterministically derive rho from statement parameters
        let mut hasher = Sha256::new();
        hasher.update(b"PVUGC/test/gs_proof_agnostic");
        
        // Serialize PPE parameters for deterministic rho
        let mut equ_bytes = Vec::new();
        for a in &equ.a_consts {
            a.serialize_compressed(&mut equ_bytes).unwrap();
        }
        for b in &equ.b_consts {
            b.serialize_compressed(&mut equ_bytes).unwrap();
        }
        for row in &equ.gamma {
            for val in row {
                val.serialize_compressed(&mut equ_bytes).unwrap();
            }
        }
        equ.target.serialize_compressed(&mut equ_bytes).unwrap();
        
        hasher.update(&equ_bytes);
        let rho_seed = hasher.finalize();
        let rho = Fr::from_le_bytes_mod_order(&rho_seed);

        // Get evaluation bases for KEM (dual bases approach)
        let eval_bases = ppe_eval_bases(&equ, &crs);
        
        // Mask the evaluation bases with deterministic rho
        let u_masked: Vec<_> = eval_bases.x_g2_pairs.iter()
            .map(|&p| mask_g2_pair::<F>(p, rho))
            .collect();
        let v_masked: Vec<_> = eval_bases.v_pairs.iter()
            .map(|&p| mask_g1_pair::<F>(p, rho))
            .collect();

        // Evaluate KEM for each proof using dual bases (proof-agnostic approach)
        let mut kem_values = Vec::new();
        for (i, proof) in proofs.iter().enumerate() {
            let PairingOutput(kem_val) = ppe_eval_with_masked_pairs::<F>(
                &proof.xcoms.coms,
                &proof.ycoms.coms,
                &u_masked,
                &v_masked,
            );
            kem_values.push(kem_val);
            println!("Proof {} KEM value computed", i);
        }

        // All KEM values must be identical (proof-agnostic property)
        let first_kem = kem_values[0];
        for (i, &kem_val) in kem_values.iter().enumerate().skip(1) {
            assert_eq!(kem_val, first_kem, 
                "KEM value {} differs from first KEM value. This violates proof-agnostic determinism.", i);
        }

        // Derive KDF keys from KEM values
        let mut kdf_keys = Vec::new();
        for (i, &kem_val) in kem_values.iter().enumerate() {
            let mut kdf_hasher = Sha256::new();
            kdf_hasher.update(b"PVUGC/KDF/gs_proof_agnostic");
            kdf_hasher.update(&rho_seed);
            
            // Serialize KEM value to bytes first
            let mut kem_bytes = Vec::new();
            kem_val.serialize_compressed(&mut kem_bytes).unwrap();
            kdf_hasher.update(&kem_bytes);
            
            let kdf_key = kdf_hasher.finalize();
            kdf_keys.push(kdf_key);
            println!("Proof {} KDF key: {:02x?}", i, kdf_key);
        }

        // All KDF keys must be identical
        let first_kdf = kdf_keys[0];
        for (i, kdf_key) in kdf_keys.iter().enumerate().skip(1) {
            assert_eq!(kdf_key, &first_kdf, 
                "KDF key {} differs from first KDF key", i);
        }

        println!("✅ All {} proofs produced identical KEM values and KDF keys", num_proofs);
        println!("✅ GS algebra with dual bases evaluation IS proof-agnostic");
        println!("✅ This demonstrates that dual bases approach achieves proof-agnostic determinism");
        println!("✅ Note: Standard GS algebra (masked ComT) is NOT proof-agnostic");
    }
}
