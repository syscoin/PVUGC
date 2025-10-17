//! Contains the functionality for proving about the satisfiability of Groth-Sahai equations over bilinear groups.
//!
//! Abstractly, a proof for an equation for the SXDH instantiation of Groth-Sahai consists of the following values,
//! with respect to a pre-defined bilinear group `(A1, A2, AT)`:
//!
//! - `π`: 1-2 elements in [`B2`](crate::data_structures::Com2) (equiv. 2-4 elements in [`G2`](ark_ec::Pairing::G2Affine))
//!     which prove about the satisfiability of `A2` variables in the equation, and
//! - `θ`: 1-2 elements in [`B1`](crate::data_structures::Com1) (equiv. 2-4 elements in [`G1`](ark_ec::Pairing::G1Affine))
//!     which prove about the satisfiability of `A1` variables in the equation
//!
//! Computing these proofs primarily involves matrix multiplication in the [scalar field](ark_ec::Pairing::Fr) and in `B1` and `B2`.
//!
//! See the [`statement`](crate::statement) module for more details about the structure of the equations being proven about.

use ark_ec::pairing::Pairing;
use ark_ec::pairing::PairingOutput;
use ark_ec::AffineRepr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::Rng, UniformRand};

use super::commit::{
    batch_commit_G1, batch_commit_G2, batch_commit_scalar_to_B1, batch_commit_scalar_to_B2,
    Commit1, Commit2,
};
use crate::data_structures::{col_vec_to_vec, vec_to_col_vec, Com1, Com2, Mat, Matrix, B1, B2};
use crate::generator::CRS;
use crate::statement::{EquType, QuadEqu, MSMEG1, MSMEG2, PPE};

/// A collection  of attributes containing prover functionality for an [`Equation`](crate::statement::Equation).
pub trait Provable<E: Pairing, A1, A2, AT> {
    /// Commits to the witness variables and then produces a Groth-Sahai proof for this equation.
    fn commit_and_prove<CR>(
        &self,
        xvars: &[A1],
        yvars: &[A2],
        crs: &CRS<E>,
        rng: &mut CR,
    ) -> CProof<E>
    where
        CR: Rng;
    /// Produces a proof `(π, θ)` for this equation that the already-committed `x` and `y` variables will satisfy a single Groth-Sahai equation.
    fn prove<CR>(
        &self,
        xvars: &[A1],
        yvars: &[A2],
        xcoms: &Commit1<E>,
        ycoms: &Commit2<E>,
        crs: &CRS<E>,
        rng: &mut CR,
    ) -> EquProof<E>
    where
        CR: Rng;
}

/// A witness-indistinguishable proof for a single [`Equation`](crate::statement::Equation).
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct EquProof<E: Pairing> {
    pub pi: Vec<Com2<E>>,
    pub theta: Vec<Com1<E>>,
    pub equ_type: EquType,
    rand: Matrix<E::ScalarField>,
    /// Auxiliary X randomizer legs for full-GS block verifier: A_i = r_i * u_{i,0}
    pub aux_x: Vec<E::G1Affine>,
    /// Auxiliary Y randomizer legs for full-GS block verifier: B_j = s_j * v_{j,0}
    pub aux_y: Vec<E::G2Affine>,
}

impl<E: Pairing> EquProof<E> {
    /// Public constructor for creating an `EquProof` (used by external crates).
    pub fn new(
        theta: Vec<Com1<E>>,
        pi: Vec<Com2<E>>,
        equ_type: EquType,
        aux_x: Vec<E::G1Affine>,
        aux_y: Vec<E::G2Affine>,
    ) -> Self {
        Self {
            theta,
            pi,
            equ_type,
            rand: vec![],
            aux_x,
            aux_y,
        }
    }
}

/// A collection of committed variables and proofs for Groth-Sahai compatible bilinear equations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CProof<E: Pairing> {
    pub xcoms: Commit1<E>,
    pub ycoms: Commit2<E>,
    pub equ_proofs: Vec<EquProof<E>>,
}

impl<E: Pairing> Provable<E, E::G1Affine, E::G2Affine, PairingOutput<E>> for PPE<E> {
    fn commit_and_prove<CR>(
        &self,
        xvars: &[E::G1Affine],
        yvars: &[E::G2Affine],
        crs: &CRS<E>,
        rng: &mut CR,
    ) -> CProof<E>
    where
        CR: Rng,
    {
        let xcoms: Commit1<E> = batch_commit_G1(xvars, crs, rng);
        let ycoms: Commit2<E> = batch_commit_G2(yvars, crs, rng);

        CProof::<E> {
            xcoms: xcoms.clone(),
            ycoms: ycoms.clone(),
            equ_proofs: vec![self.prove(xvars, yvars, &xcoms, &ycoms, crs, rng)],
        }
    }

    fn prove<CR>(
        &self,
        xvars: &[E::G1Affine],
        yvars: &[E::G2Affine],
        xcoms: &Commit1<E>,
        ycoms: &Commit2<E>,
        crs: &CRS<E>,
        rng: &mut CR,
    ) -> EquProof<E>
    where
        CR: Rng,
    {
        // Gamma is an (m x n) matrix with m x variables and n y variables
        // x's commit randomness (i.e. R) is a (m x 2) matrix
        assert_eq!(xvars.len(), xcoms.rand.len());
        assert_eq!(self.gamma.len(), xcoms.rand.len());
        assert_eq!(xcoms.rand[0].len(), 2);
        let _m = xvars.len();
        // y's commit randomness (i.e. S) is a (n x 2) matrix
        assert_eq!(yvars.len(), ycoms.rand.len());
        assert_eq!(self.gamma[0].len(), ycoms.rand.len());
        assert_eq!(ycoms.rand[0].len(), 2);
        let _n = yvars.len();

        let is_parallel = true;

        // (2 x m) field matrix R^T, in GS parlance
        let x_rand_trans = xcoms.rand.transpose();
        // (2 x n) field matrix S^T, in GS parlance
        let y_rand_trans = ycoms.rand.transpose();
        // (2 x 2) field matrix T, in GS parlance
        let pf_rand: Matrix<E::ScalarField> = vec![
            vec![E::ScalarField::rand(rng), E::ScalarField::rand(rng)],
            vec![E::ScalarField::rand(rng), E::ScalarField::rand(rng)],
        ];

        // (2 x 1) Com2 matrix
        let x_rand_lin_b = vec_to_col_vec(&Com2::<E>::batch_linear_map(&self.b_consts))
            .left_mul(&x_rand_trans, is_parallel);

        // (2 x n) field matrix
        let x_rand_stmt = x_rand_trans.right_mul(&self.gamma, is_parallel);
        // (2 x 1) Com2 matrix
        let x_rand_stmt_lin_y =
            vec_to_col_vec(&Com2::<E>::batch_linear_map(yvars)).left_mul(&x_rand_stmt, is_parallel);

        // (2 x 2) field matrix
        let pf_rand_stmt = x_rand_trans
            .right_mul(&self.gamma, is_parallel)
            .right_mul(&ycoms.rand, is_parallel)
            .add(&pf_rand.transpose().neg());
        // (2 x 1) Com2 matrix
        let pf_rand_stmt_com2 = vec_to_col_vec(&crs.v).left_mul(&pf_rand_stmt, is_parallel);

        let pi = col_vec_to_vec(&x_rand_lin_b.add(&x_rand_stmt_lin_y).add(&pf_rand_stmt_com2));
        assert_eq!(pi.len(), 2);

        // (2 x 1) Com1 matrix
        let y_rand_lin_a = vec_to_col_vec(&Com1::<E>::batch_linear_map(&self.a_consts))
            .left_mul(&y_rand_trans, is_parallel);

        // (2 x m) field matrix
        let y_rand_stmt = y_rand_trans.right_mul(&self.gamma.transpose(), is_parallel);
        // (2 x 1) Com1 matrix
        let y_rand_stmt_lin_x =
            vec_to_col_vec(&Com1::<E>::batch_linear_map(xvars)).left_mul(&y_rand_stmt, is_parallel);

        // (2 x 1) Com1 matrix
        let pf_rand_com1 = vec_to_col_vec(&crs.u).left_mul(&pf_rand, is_parallel);

        let theta = col_vec_to_vec(&y_rand_lin_a.add(&y_rand_stmt_lin_x).add(&pf_rand_com1));
        assert_eq!(theta.len(), 2);

        EquProof::<E> {
            pi,
            theta,
            equ_type: EquType::PairingProduct,
            rand: pf_rand,
            aux_x: vec![],
            aux_y: vec![],
        }
    }
}

impl<E: Pairing> Provable<E, E::G1Affine, E::ScalarField, E::G1Affine> for MSMEG1<E> {
    fn commit_and_prove<CR>(
        &self,
        xvars: &[E::G1Affine],
        scalar_yvars: &[E::ScalarField],
        crs: &CRS<E>,
        rng: &mut CR,
    ) -> CProof<E>
    where
        CR: Rng,
    {
        let xcoms: Commit1<E> = batch_commit_G1(xvars, crs, rng);
        let scalar_ycoms: Commit2<E> = batch_commit_scalar_to_B2(scalar_yvars, crs, rng);

        CProof::<E> {
            xcoms: xcoms.clone(),
            ycoms: scalar_ycoms.clone(),
            equ_proofs: vec![self.prove(xvars, scalar_yvars, &xcoms, &scalar_ycoms, crs, rng)],
        }
    }

    fn prove<CR>(
        &self,
        xvars: &[E::G1Affine],
        scalar_yvars: &[E::ScalarField],
        xcoms: &Commit1<E>,
        scalar_ycoms: &Commit2<E>,
        crs: &CRS<E>,
        rng: &mut CR,
    ) -> EquProof<E>
    where
        CR: Rng,
    {
        // Gamma is an (m x n') matrix with m x variables and n' scalar y variables
        // x's commit randomness (i.e. R) is a (m x 2) matrix
        assert_eq!(xvars.len(), xcoms.rand.len());
        assert_eq!(self.gamma.len(), xcoms.rand.len());
        assert_eq!(xcoms.rand[0].len(), 2);
        let _m = xvars.len();
        // scalar y's commit randomness (i.e. s) is a (n' x 1) matrix (i.e. column vector)
        assert_eq!(scalar_yvars.len(), scalar_ycoms.rand.len());
        assert_eq!(self.gamma[0].len(), scalar_ycoms.rand.len());
        assert_eq!(scalar_ycoms.rand[0].len(), 1);
        let _n_prime = scalar_yvars.len();

        let is_parallel = true;

        // (2 x m) field matrix R^T, in GS parlance
        let x_rand_trans = xcoms.rand.transpose();
        // (1 x n') field matrix s^T, in GS parlance
        let y_rand_trans = scalar_ycoms.rand.transpose();
        // (1 x 2) field matrix T, in GS parlance
        let pf_rand: Matrix<E::ScalarField> =
            vec![vec![E::ScalarField::rand(rng), E::ScalarField::rand(rng)]];

        // (2 x 1) Com2 matrix
        let x_rand_lin_b = vec_to_col_vec(&Com2::<E>::batch_scalar_linear_map(&self.b_consts, crs))
            .left_mul(&x_rand_trans, is_parallel);

        // (2 x n) field matrix
        let x_rand_stmt = x_rand_trans.right_mul(&self.gamma, is_parallel);
        // (2 x 1) Com2 matrix
        let x_rand_stmt_lin_y =
            vec_to_col_vec(&Com2::<E>::batch_scalar_linear_map(scalar_yvars, crs))
                .left_mul(&x_rand_stmt, is_parallel);

        // (2 x 1) field matrix
        let pf_rand_stmt = x_rand_trans
            .right_mul(&self.gamma, is_parallel)
            .right_mul(&scalar_ycoms.rand, is_parallel)
            .add(&pf_rand.transpose().neg());
        // (2 x 1) Com2 matrix
        let v1: Matrix<Com2<E>> = vec![vec![crs.v[0]]];
        let pf_rand_stmt_com2 = v1.left_mul(&pf_rand_stmt, is_parallel);

        let pi = col_vec_to_vec(&x_rand_lin_b.add(&x_rand_stmt_lin_y).add(&pf_rand_stmt_com2));
        assert_eq!(pi.len(), 2);

        // (1 x 1) Com1 matrix
        let y_rand_lin_a = vec_to_col_vec(&Com1::<E>::batch_linear_map(&self.a_consts))
            .left_mul(&y_rand_trans, is_parallel);

        // (1 x m) field matrix
        let y_rand_stmt = y_rand_trans.right_mul(&self.gamma.transpose(), is_parallel);
        // (1 x 1) Com1 matrix
        let y_rand_stmt_lin_x =
            vec_to_col_vec(&Com1::<E>::batch_linear_map(xvars)).left_mul(&y_rand_stmt, is_parallel);

        // (1 x 1) Com1 matrix
        let pf_rand_com1 = vec_to_col_vec(&crs.u).left_mul(&pf_rand, is_parallel);

        let theta = col_vec_to_vec(&y_rand_lin_a.add(&y_rand_stmt_lin_x).add(&pf_rand_com1));
        assert_eq!(theta.len(), 1);

        EquProof::<E> {
            pi,
            theta,
            equ_type: EquType::MultiScalarG1,
            rand: pf_rand,
            aux_x: vec![],
            aux_y: vec![],
        }
    }
}

impl<E: Pairing> Provable<E, E::ScalarField, E::G2Affine, E::G2Affine> for MSMEG2<E> {
    fn commit_and_prove<CR>(
        &self,
        scalar_xvars: &[E::ScalarField],
        yvars: &[E::G2Affine],
        crs: &CRS<E>,
        rng: &mut CR,
    ) -> CProof<E>
    where
        CR: Rng,
    {
        let scalar_xcoms: Commit1<E> = batch_commit_scalar_to_B1(scalar_xvars, crs, rng);
        let ycoms: Commit2<E> = batch_commit_G2(yvars, crs, rng);

        CProof::<E> {
            xcoms: scalar_xcoms.clone(),
            ycoms: ycoms.clone(),
            equ_proofs: vec![self.prove(scalar_xvars, yvars, &scalar_xcoms, &ycoms, crs, rng)],
        }
    }

    fn prove<CR>(
        &self,
        scalar_xvars: &[E::ScalarField],
        yvars: &[E::G2Affine],
        scalar_xcoms: &Commit1<E>,
        ycoms: &Commit2<E>,
        crs: &CRS<E>,
        rng: &mut CR,
    ) -> EquProof<E>
    where
        CR: Rng,
    {
        // Gamma is an (m' x n) matrix with m' x variables and n y variables
        // x's commit randomness (i.e. r) is a (m' x 1) matrix (i.e. column vector)
        assert_eq!(scalar_xvars.len(), scalar_xcoms.rand.len());
        assert_eq!(self.gamma.len(), scalar_xcoms.rand.len());
        assert_eq!(scalar_xcoms.rand[0].len(), 1);
        let _m_prime = scalar_xvars.len();
        // y's commit randomness (i.e. S) is a (n x 2) matrix
        assert_eq!(yvars.len(), ycoms.rand.len());
        assert_eq!(self.gamma[0].len(), ycoms.rand.len());
        assert_eq!(ycoms.rand[0].len(), 2);
        let _n = yvars.len();

        let is_parallel = true;

        // (1 x m') field matrix r^T, in GS parlance
        let x_rand_trans = scalar_xcoms.rand.transpose();
        // (2 x n) field matrix S^T, in GS parlance
        let y_rand_trans = ycoms.rand.transpose();
        // (2 x 1) field matrix T, in GS parlance
        let pf_rand: Matrix<E::ScalarField> = vec![
            vec![E::ScalarField::rand(rng)],
            vec![E::ScalarField::rand(rng)],
        ];

        // (1 x 1) Com2 matrix
        let x_rand_lin_b = vec_to_col_vec(&Com2::<E>::batch_linear_map(&self.b_consts))
            .left_mul(&x_rand_trans, is_parallel);

        // (1 x n) field matrix
        let x_rand_stmt = x_rand_trans.right_mul(&self.gamma, is_parallel);
        // (1 x 1) Com2 matrix
        let x_rand_stmt_lin_y =
            vec_to_col_vec(&Com2::<E>::batch_linear_map(yvars)).left_mul(&x_rand_stmt, is_parallel);

        // (1 x 2) field matrix
        let pf_rand_stmt = x_rand_trans
            .right_mul(&self.gamma, is_parallel)
            .right_mul(&ycoms.rand, is_parallel)
            .add(&pf_rand.transpose().neg());
        // (1 x 1) Com2 matrix
        let pf_rand_stmt_com2 = vec_to_col_vec(&crs.v).left_mul(&pf_rand_stmt, is_parallel);

        let pi = col_vec_to_vec(&x_rand_lin_b.add(&x_rand_stmt_lin_y).add(&pf_rand_stmt_com2));
        assert_eq!(pi.len(), 1);

        // (2 x 1) Com1 matrix
        let y_rand_lin_a = vec_to_col_vec(&Com1::<E>::batch_scalar_linear_map(&self.a_consts, crs))
            .left_mul(&y_rand_trans, is_parallel);

        // (2 x m') field matrix
        let y_rand_stmt = y_rand_trans.right_mul(&self.gamma.transpose(), is_parallel);
        // (2 x 1) Com1 matrix
        let y_rand_stmt_lin_x =
            vec_to_col_vec(&Com1::<E>::batch_scalar_linear_map(scalar_xvars, crs))
                .left_mul(&y_rand_stmt, is_parallel);

        // (2 x 1) Com1 matrix
        let u1: Matrix<Com1<E>> = vec![vec![crs.u[0]]];
        let pf_rand_com1 = u1.left_mul(&pf_rand, is_parallel);

        let theta = col_vec_to_vec(&y_rand_lin_a.add(&y_rand_stmt_lin_x).add(&pf_rand_com1));
        assert_eq!(theta.len(), 2);

        EquProof::<E> {
            pi,
            theta,
            equ_type: EquType::MultiScalarG2,
            rand: pf_rand,
            aux_x: vec![],
            aux_y: vec![],
        }
    }
}

impl<E: Pairing> Provable<E, E::ScalarField, E::ScalarField, E::ScalarField> for QuadEqu<E> {
    fn commit_and_prove<CR>(
        &self,
        scalar_xvars: &[E::ScalarField],
        scalar_yvars: &[E::ScalarField],
        crs: &CRS<E>,
        rng: &mut CR,
    ) -> CProof<E>
    where
        CR: Rng,
    {
        let scalar_xcoms: Commit1<E> = batch_commit_scalar_to_B1(scalar_xvars, crs, rng);
        let scalar_ycoms: Commit2<E> = batch_commit_scalar_to_B2(scalar_yvars, crs, rng);

        CProof::<E> {
            xcoms: scalar_xcoms.clone(),
            ycoms: scalar_ycoms.clone(),
            equ_proofs: vec![self.prove(
                scalar_xvars,
                scalar_yvars,
                &scalar_xcoms,
                &scalar_ycoms,
                crs,
                rng,
            )],
        }
    }
    fn prove<CR>(
        &self,
        scalar_xvars: &[E::ScalarField],
        scalar_yvars: &[E::ScalarField],
        scalar_xcoms: &Commit1<E>,
        scalar_ycoms: &Commit2<E>,
        crs: &CRS<E>,
        rng: &mut CR,
    ) -> EquProof<E>
    where
        CR: Rng,
    {
        // Gamma is an (m' x n') matrix with m' x variables and n' y variables
        // x's commit randomness (i.e. r) is a (m' x 1) matrix (i.e. column vector)
        assert_eq!(scalar_xvars.len(), scalar_xcoms.rand.len());
        assert_eq!(self.gamma.len(), scalar_xcoms.rand.len());
        assert_eq!(scalar_xcoms.rand[0].len(), 1);
        let _m_prime = scalar_xvars.len();
        // y's commit randomness (i.e. s) is a (n' x 1) matrix (i.e. column vector)
        assert_eq!(scalar_yvars.len(), scalar_ycoms.rand.len());
        assert_eq!(self.gamma[0].len(), scalar_ycoms.rand.len());
        assert_eq!(scalar_ycoms.rand[0].len(), 1);
        let _n_prime = scalar_yvars.len();

        let is_parallel = true;

        // (1 x m') field matrix r^T, in GS parlance
        let x_rand_trans = scalar_xcoms.rand.transpose();
        // (1 x n') field matrix s^T, in GS parlance
        let y_rand_trans = scalar_ycoms.rand.transpose();
        // field element T, in GS parlance
        let pf_rand: Matrix<E::ScalarField> = vec![vec![E::ScalarField::rand(rng)]];

        let x_rand_lin_b = vec_to_col_vec(&Com2::<E>::batch_scalar_linear_map(&self.b_consts, crs))
            .left_mul(&x_rand_trans, is_parallel);

        // (1 x n') field matrix
        let x_rand_stmt = x_rand_trans.right_mul(&self.gamma, is_parallel);
        // (1 x 1) Com2 matrix
        let x_rand_stmt_lin_y =
            vec_to_col_vec(&Com2::<E>::batch_scalar_linear_map(scalar_yvars, crs))
                .left_mul(&x_rand_stmt, is_parallel);

        // (1 x 2) field matrix
        let pf_rand_stmt = x_rand_trans
            .right_mul(&self.gamma, is_parallel)
            .right_mul(&scalar_ycoms.rand, is_parallel)
            .add(&pf_rand.transpose().neg());
        let v1: Matrix<Com2<E>> = vec![vec![crs.v[0]]];
        // (1 x 1) Com2 matrix
        let pf_rand_stmt_com2 = v1.left_mul(&pf_rand_stmt, is_parallel);

        let pi = col_vec_to_vec(&x_rand_lin_b.add(&x_rand_stmt_lin_y).add(&pf_rand_stmt_com2));
        assert_eq!(pi.len(), 1);

        // (1 x 1) Com1 matrix
        let y_rand_lin_a = vec_to_col_vec(&Com1::<E>::batch_scalar_linear_map(&self.a_consts, crs))
            .left_mul(&y_rand_trans, is_parallel);

        // (1 x m') field matrix
        let y_rand_stmt = y_rand_trans.right_mul(&self.gamma.transpose(), is_parallel);
        // (1 x 1) Com1 matrix
        let y_rand_stmt_lin_x =
            vec_to_col_vec(&Com1::<E>::batch_scalar_linear_map(scalar_xvars, crs))
                .left_mul(&y_rand_stmt, is_parallel);

        // (1 x 1) Com1 matrix
        let u1: Matrix<Com1<E>> = vec![vec![crs.u[0]]];
        let pf_rand_com1 = u1.left_mul(&pf_rand, is_parallel);

        let theta = col_vec_to_vec(&y_rand_lin_a.add(&y_rand_stmt_lin_x).add(&pf_rand_com1));
        assert_eq!(theta.len(), 1);

        EquProof::<E> {
            pi,
            theta,
            equ_type: EquType::Quadratic,
            rand: pf_rand,
            aux_x: vec![],
            aux_y: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(non_snake_case)]

    use ark_bls12_381::Bls12_381 as F;
    use ark_ec::CurveGroup;
    use ark_ff::{One, UniformRand, Zero};
    use ark_std::ops::Mul;
    use ark_std::test_rng;

    use crate::AbstractCrs;

    use super::*;

    type G1Affine = <F as Pairing>::G1Affine;
    type G2Affine = <F as Pairing>::G2Affine;
    type Fr = <F as Pairing>::ScalarField;
    type GT = PairingOutput<F>;

    #[test]
    fn test_PPE_proof_type() {
        let mut rng = test_rng();
        let crs = CRS::<F>::generate_crs(&mut rng);

        let xvars: Vec<G1Affine> = vec![
            crs.g1_gen.mul(Fr::rand(&mut rng)).into_affine(),
            crs.g1_gen.mul(Fr::rand(&mut rng)).into_affine(),
        ];
        let yvars: Vec<G2Affine> = vec![crs.g2_gen.mul(Fr::rand(&mut rng)).into_affine()];
        let xcoms: Commit1<F> = batch_commit_G1(&xvars, &crs, &mut rng);
        let ycoms: Commit2<F> = batch_commit_G2(&yvars, &crs, &mut rng);

        let equ: PPE<F> = PPE::<F> {
            a_consts: vec![crs.g1_gen.mul(Fr::rand(&mut rng)).into_affine()],
            b_consts: vec![
                crs.g2_gen.mul(Fr::rand(&mut rng)).into_affine(),
                crs.g2_gen.mul(Fr::rand(&mut rng)).into_affine(),
            ],
            gamma: vec![vec![Fr::one()], vec![Fr::zero()]],
            target: GT::rand(&mut rng),
        };
        let proof: EquProof<F> = equ.prove(&xvars, &yvars, &xcoms, &ycoms, &crs, &mut rng);

        assert_eq!(proof.equ_type, EquType::PairingProduct);
    }

    #[test]
    fn test_PPE_cproof_is_commit_and_prove() {
        std::env::set_var("DETERMINISTIC_TEST_RNG", "1");
        let mut rng = test_rng();
        let mut rng2 = test_rng();
        let crs = CRS::<F>::generate_crs(&mut rng);

        let xvars: Vec<G1Affine> = vec![
            crs.g1_gen.mul(Fr::rand(&mut rng)).into_affine(),
            crs.g1_gen.mul(Fr::rand(&mut rng)).into_affine(),
        ];
        let yvars: Vec<G2Affine> = vec![crs.g2_gen.mul(Fr::rand(&mut rng)).into_affine()];
        let equ: PPE<F> = PPE::<F> {
            a_consts: vec![crs.g1_gen.mul(Fr::rand(&mut rng)).into_affine()],
            b_consts: vec![
                crs.g2_gen.mul(Fr::rand(&mut rng)).into_affine(),
                crs.g2_gen.mul(Fr::rand(&mut rng)).into_affine(),
            ],
            gamma: vec![vec![Fr::one()], vec![Fr::zero()]],
            target: GT::rand(&mut rng),
        };

        // Individually commit then prove
        let xcoms: Commit1<F> = batch_commit_G1(&xvars, &crs, &mut rng);
        let ycoms: Commit2<F> = batch_commit_G2(&yvars, &crs, &mut rng);
        let proof: EquProof<F> = equ.prove(&xvars, &yvars, &xcoms, &ycoms, &crs, &mut rng);
        let cproof = CProof::<F> {
            xcoms,
            ycoms,
            equ_proofs: vec![proof],
        };

        // Mock calls to CRS to get them in sync
        let _ = CRS::<F>::generate_crs(&mut rng2);
        for _ in 0..xvars.len() {
            let _ = Fr::rand(&mut rng2);
        }
        for _ in 0..yvars.len() {
            let _ = Fr::rand(&mut rng2);
        }
        for _ in 0..equ.a_consts.len() {
            let _ = Fr::rand(&mut rng2);
        }
        for _ in 0..equ.b_consts.len() {
            let _ = Fr::rand(&mut rng2);
        }
        let _ = GT::rand(&mut rng2);

        // Use the helper function to commit-and-prove in one step
        let cproof2 = equ.commit_and_prove(&xvars, &yvars, &crs, &mut rng2);

        assert_eq!(cproof, cproof2);
    }

    #[test]
    fn test_PPE_cproof_serde() {
        let mut rng = test_rng();
        let crs = CRS::<F>::generate_crs(&mut rng);

        let xvars: Vec<G1Affine> = vec![
            crs.g1_gen.mul(Fr::rand(&mut rng)).into_affine(),
            crs.g1_gen.mul(Fr::rand(&mut rng)).into_affine(),
        ];
        let yvars: Vec<G2Affine> = vec![crs.g2_gen.mul(Fr::rand(&mut rng)).into_affine()];
        let xcoms: Commit1<F> = batch_commit_G1(&xvars, &crs, &mut rng);
        let ycoms: Commit2<F> = batch_commit_G2(&yvars, &crs, &mut rng);

        let equ: PPE<F> = PPE::<F> {
            a_consts: vec![crs.g1_gen.mul(Fr::rand(&mut rng)).into_affine()],
            b_consts: vec![
                crs.g2_gen.mul(Fr::rand(&mut rng)).into_affine(),
                crs.g2_gen.mul(Fr::rand(&mut rng)).into_affine(),
            ],
            gamma: vec![vec![Fr::one()], vec![Fr::zero()]],
            target: GT::rand(&mut rng),
        };
        let proof: EquProof<F> = equ.prove(&xvars, &yvars, &xcoms, &ycoms, &crs, &mut rng);

        // Serialize and deserialize the proof
        let mut c_bytes = Vec::new();
        proof.serialize_compressed(&mut c_bytes).unwrap();
        let proof_de = EquProof::<F>::deserialize_compressed(&c_bytes[..]).unwrap();
        assert_eq!(proof, proof_de);

        let mut u_bytes = Vec::new();
        proof.serialize_uncompressed(&mut u_bytes).unwrap();
        let proof_de = EquProof::<F>::deserialize_uncompressed(&u_bytes[..]).unwrap();
        assert_eq!(proof, proof_de);
    }

    #[test]
    fn test_MSMEG1_proof_type() {
        let mut rng = test_rng();
        let crs = CRS::<F>::generate_crs(&mut rng);

        let xvars: Vec<G1Affine> = vec![
            crs.g1_gen.mul(Fr::rand(&mut rng)).into_affine(),
            crs.g1_gen.mul(Fr::rand(&mut rng)).into_affine(),
        ];
        let scalar_yvars: Vec<Fr> = vec![Fr::rand(&mut rng)];
        let xcoms: Commit1<F> = batch_commit_G1(&xvars, &crs, &mut rng);
        let scalar_ycoms: Commit2<F> = batch_commit_scalar_to_B2(&scalar_yvars, &crs, &mut rng);

        let equ: MSMEG1<F> = MSMEG1::<F> {
            a_consts: vec![crs.g1_gen.mul(Fr::rand(&mut rng)).into_affine()],
            b_consts: vec![Fr::rand(&mut rng), Fr::rand(&mut rng)],
            gamma: vec![vec![Fr::one()], vec![Fr::zero()]],
            target: crs.g1_gen.mul(Fr::rand(&mut rng)).into_affine(),
        };
        let proof: EquProof<F> =
            equ.prove(&xvars, &scalar_yvars, &xcoms, &scalar_ycoms, &crs, &mut rng);

        assert_eq!(proof.equ_type, EquType::MultiScalarG1);
    }

    #[test]
    fn test_MSMEG1_cproof_is_commit_and_prove() {
        std::env::set_var("DETERMINISTIC_TEST_RNG", "1");
        let mut rng = test_rng();
        let mut rng2 = test_rng();
        let crs = CRS::<F>::generate_crs(&mut rng);

        let xvars: Vec<G1Affine> = vec![
            crs.g1_gen.mul(Fr::rand(&mut rng)).into_affine(),
            crs.g1_gen.mul(Fr::rand(&mut rng)).into_affine(),
        ];
        let scalar_yvars: Vec<Fr> = vec![Fr::rand(&mut rng)];
        let equ: MSMEG1<F> = MSMEG1::<F> {
            a_consts: vec![crs.g1_gen.mul(Fr::rand(&mut rng)).into_affine()],
            b_consts: vec![Fr::rand(&mut rng), Fr::rand(&mut rng)],
            gamma: vec![vec![Fr::one()], vec![Fr::zero()]],
            target: crs.g1_gen.mul(Fr::rand(&mut rng)).into_affine(),
        };

        // Individually commit then prove
        let xcoms: Commit1<F> = batch_commit_G1(&xvars, &crs, &mut rng);
        let scalar_ycoms: Commit2<F> = batch_commit_scalar_to_B2(&scalar_yvars, &crs, &mut rng);
        let proof: EquProof<F> =
            equ.prove(&xvars, &scalar_yvars, &xcoms, &scalar_ycoms, &crs, &mut rng);
        let cproof = CProof::<F> {
            xcoms,
            ycoms: scalar_ycoms,
            equ_proofs: vec![proof],
        };

        // Mock calls to CRS to get them in sync
        let _ = CRS::<F>::generate_crs(&mut rng2);
        for _ in 0..xvars.len() {
            let _ = Fr::rand(&mut rng2);
        }
        for _ in 0..scalar_yvars.len() {
            let _ = Fr::rand(&mut rng2);
        }
        for _ in 0..equ.a_consts.len() {
            let _ = Fr::rand(&mut rng2);
        }
        for _ in 0..equ.b_consts.len() {
            let _ = Fr::rand(&mut rng2);
        }
        let _ = Fr::rand(&mut rng2);

        // Use the helper function to commit-and-prove in one step
        let cproof2 = equ.commit_and_prove(&xvars, &scalar_yvars, &crs, &mut rng2);

        assert_eq!(cproof, cproof2);
    }

    #[test]
    fn test_MSGMEG1_cproof_serde() {
        let mut rng = test_rng();
        let crs = CRS::<F>::generate_crs(&mut rng);

        let xvars: Vec<G1Affine> = vec![
            crs.g1_gen.mul(Fr::rand(&mut rng)).into_affine(),
            crs.g1_gen.mul(Fr::rand(&mut rng)).into_affine(),
        ];
        let scalar_yvars: Vec<Fr> = vec![Fr::rand(&mut rng)];
        let xcoms: Commit1<F> = batch_commit_G1(&xvars, &crs, &mut rng);
        let scalar_ycoms: Commit2<F> = batch_commit_scalar_to_B2(&scalar_yvars, &crs, &mut rng);

        let equ: MSMEG1<F> = MSMEG1::<F> {
            a_consts: vec![crs.g1_gen.mul(Fr::rand(&mut rng)).into_affine()],
            b_consts: vec![Fr::rand(&mut rng), Fr::rand(&mut rng)],
            gamma: vec![vec![Fr::one()], vec![Fr::zero()]],
            target: crs.g1_gen.mul(Fr::rand(&mut rng)).into_affine(),
        };
        let proof: EquProof<F> =
            equ.prove(&xvars, &scalar_yvars, &xcoms, &scalar_ycoms, &crs, &mut rng);

        // Serialize and deserialize the proof
        let mut c_bytes = Vec::new();
        proof.serialize_compressed(&mut c_bytes).unwrap();
        let proof_de = EquProof::<F>::deserialize_compressed(&c_bytes[..]).unwrap();
        assert_eq!(proof, proof_de);

        let mut u_bytes = Vec::new();
        proof.serialize_uncompressed(&mut u_bytes).unwrap();
        let proof_de = EquProof::<F>::deserialize_uncompressed(&u_bytes[..]).unwrap();
        assert_eq!(proof, proof_de);
    }

    #[test]
    fn test_MSMEG2_proof_type() {
        let mut rng = test_rng();
        let crs = CRS::<F>::generate_crs(&mut rng);

        let scalar_xvars: Vec<Fr> = vec![Fr::rand(&mut rng), Fr::rand(&mut rng)];
        let yvars: Vec<G2Affine> = vec![crs.g2_gen.mul(Fr::rand(&mut rng)).into_affine()];
        let scalar_xcoms: Commit1<F> = batch_commit_scalar_to_B1(&scalar_xvars, &crs, &mut rng);
        let ycoms: Commit2<F> = batch_commit_G2(&yvars, &crs, &mut rng);

        let equ: MSMEG2<F> = MSMEG2::<F> {
            a_consts: vec![Fr::rand(&mut rng)],
            b_consts: vec![
                crs.g2_gen.mul(Fr::rand(&mut rng)).into_affine(),
                crs.g2_gen.mul(Fr::rand(&mut rng)).into_affine(),
            ],
            gamma: vec![vec![Fr::one()], vec![Fr::zero()]],
            target: crs.g2_gen.mul(Fr::rand(&mut rng)).into_affine(),
        };
        let proof: EquProof<F> =
            equ.prove(&scalar_xvars, &yvars, &scalar_xcoms, &ycoms, &crs, &mut rng);

        assert_eq!(proof.equ_type, EquType::MultiScalarG2);
    }

    #[test]
    fn test_MSMEG2_cproof_is_commit_and_prove() {
        let mut rng = test_rng();
        let mut rng2 = test_rng();
        let crs = CRS::<F>::generate_crs(&mut rng);

        let scalar_xvars: Vec<Fr> = vec![Fr::rand(&mut rng), Fr::rand(&mut rng)];
        let yvars: Vec<G2Affine> = vec![crs.g2_gen.mul(Fr::rand(&mut rng)).into_affine()];

        let equ: MSMEG2<F> = MSMEG2::<F> {
            a_consts: vec![Fr::rand(&mut rng)],
            b_consts: vec![
                crs.g2_gen.mul(Fr::rand(&mut rng)).into_affine(),
                crs.g2_gen.mul(Fr::rand(&mut rng)).into_affine(),
            ],
            gamma: vec![vec![Fr::one()], vec![Fr::zero()]],
            target: crs.g2_gen.mul(Fr::rand(&mut rng)).into_affine(),
        };

        // Individually commit then prove
        let scalar_xcoms: Commit1<F> = batch_commit_scalar_to_B1(&scalar_xvars, &crs, &mut rng);
        let ycoms: Commit2<F> = batch_commit_G2(&yvars, &crs, &mut rng);
        let proof: EquProof<F> =
            equ.prove(&scalar_xvars, &yvars, &scalar_xcoms, &ycoms, &crs, &mut rng);
        let cproof = CProof::<F> {
            xcoms: scalar_xcoms,
            ycoms,
            equ_proofs: vec![proof],
        };

        // Mock calls to CRS to get them in sync
        let _ = CRS::<F>::generate_crs(&mut rng2);
        for _ in 0..scalar_xvars.len() {
            let _ = Fr::rand(&mut rng2);
        }
        for _ in 0..yvars.len() {
            let _ = Fr::rand(&mut rng2);
        }
        for _ in 0..equ.a_consts.len() {
            let _ = Fr::rand(&mut rng2);
        }
        for _ in 0..equ.b_consts.len() {
            let _ = Fr::rand(&mut rng2);
        }
        let _ = Fr::rand(&mut rng2);

        // Use the helper function to commit-and-prove in one step
        let cproof2 = equ.commit_and_prove(&scalar_xvars, &yvars, &crs, &mut rng2);

        assert_eq!(cproof, cproof2);
    }

    #[test]
    fn test_MSMEG2_proof_serde() {
        let mut rng = test_rng();
        let crs = CRS::<F>::generate_crs(&mut rng);

        let scalar_xvars: Vec<Fr> = vec![Fr::rand(&mut rng), Fr::rand(&mut rng)];
        let yvars: Vec<G2Affine> = vec![crs.g2_gen.mul(Fr::rand(&mut rng)).into_affine()];
        let scalar_xcoms: Commit1<F> = batch_commit_scalar_to_B1(&scalar_xvars, &crs, &mut rng);
        let ycoms: Commit2<F> = batch_commit_G2(&yvars, &crs, &mut rng);

        let equ: MSMEG2<F> = MSMEG2::<F> {
            a_consts: vec![Fr::rand(&mut rng)],
            b_consts: vec![
                crs.g2_gen.mul(Fr::rand(&mut rng)).into_affine(),
                crs.g2_gen.mul(Fr::rand(&mut rng)).into_affine(),
            ],
            gamma: vec![vec![Fr::one()], vec![Fr::zero()]],
            target: crs.g2_gen.mul(Fr::rand(&mut rng)).into_affine(),
        };
        let proof: EquProof<F> =
            equ.prove(&scalar_xvars, &yvars, &scalar_xcoms, &ycoms, &crs, &mut rng);

        // Serialize and deserialize the proof
        let mut c_bytes = Vec::new();
        proof.serialize_compressed(&mut c_bytes).unwrap();
        let proof_de = EquProof::<F>::deserialize_compressed(&c_bytes[..]).unwrap();
        assert_eq!(proof, proof_de);

        let mut u_bytes = Vec::new();
        proof.serialize_uncompressed(&mut u_bytes).unwrap();
        let proof_de = EquProof::<F>::deserialize_uncompressed(&u_bytes[..]).unwrap();
        assert_eq!(proof, proof_de);
    }

    #[test]
    fn test_quadratic_proof_type() {
        let mut rng = test_rng();
        let crs = CRS::<F>::generate_crs(&mut rng);

        let scalar_xvars: Vec<Fr> = vec![Fr::rand(&mut rng), Fr::rand(&mut rng)];
        let scalar_yvars: Vec<Fr> = vec![Fr::rand(&mut rng)];

        let equ: QuadEqu<F> = QuadEqu::<F> {
            a_consts: vec![Fr::rand(&mut rng)],
            b_consts: vec![Fr::rand(&mut rng), Fr::rand(&mut rng)],
            gamma: vec![vec![Fr::one()], vec![Fr::zero()]],
            target: Fr::rand(&mut rng),
        };

        // Individually commit then prove
        let scalar_xcoms: Commit1<F> = batch_commit_scalar_to_B1(&scalar_xvars, &crs, &mut rng);
        let scalar_ycoms: Commit2<F> = batch_commit_scalar_to_B2(&scalar_yvars, &crs, &mut rng);
        let proof: EquProof<F> = equ.prove(
            &scalar_xvars,
            &scalar_yvars,
            &scalar_xcoms,
            &scalar_ycoms,
            &crs,
            &mut rng,
        );

        assert_eq!(proof.equ_type, EquType::Quadratic);
    }

    #[test]
    fn test_quadratic_cproof_is_commit_and_prove() {
        let mut rng = test_rng();
        let mut rng2 = test_rng();
        let crs = CRS::<F>::generate_crs(&mut rng);

        let scalar_xvars: Vec<Fr> = vec![Fr::rand(&mut rng), Fr::rand(&mut rng)];
        let scalar_yvars: Vec<Fr> = vec![Fr::rand(&mut rng)];

        let equ: QuadEqu<F> = QuadEqu::<F> {
            a_consts: vec![Fr::rand(&mut rng)],
            b_consts: vec![Fr::rand(&mut rng), Fr::rand(&mut rng)],
            gamma: vec![vec![Fr::one()], vec![Fr::zero()]],
            target: Fr::rand(&mut rng),
        };

        // Individually commit then prove
        let scalar_xcoms: Commit1<F> = batch_commit_scalar_to_B1(&scalar_xvars, &crs, &mut rng);
        let scalar_ycoms: Commit2<F> = batch_commit_scalar_to_B2(&scalar_yvars, &crs, &mut rng);
        let proof: EquProof<F> = equ.prove(
            &scalar_xvars,
            &scalar_yvars,
            &scalar_xcoms,
            &scalar_ycoms,
            &crs,
            &mut rng,
        );
        let cproof = CProof::<F> {
            xcoms: scalar_xcoms,
            ycoms: scalar_ycoms,
            equ_proofs: vec![proof],
        };

        // Mock calls to CRS to get them in sync
        let _ = CRS::<F>::generate_crs(&mut rng2);
        for _ in 0..scalar_xvars.len() {
            let _ = Fr::rand(&mut rng2);
        }
        for _ in 0..scalar_yvars.len() {
            let _ = Fr::rand(&mut rng2);
        }
        for _ in 0..equ.a_consts.len() {
            let _ = Fr::rand(&mut rng2);
        }
        for _ in 0..equ.b_consts.len() {
            let _ = Fr::rand(&mut rng2);
        }
        let _ = Fr::rand(&mut rng2);

        // Use the helper function to commit-and-prove in one step
        let cproof2 = equ.commit_and_prove(&scalar_xvars, &scalar_yvars, &crs, &mut rng2);

        assert_eq!(cproof, cproof2);
    }

    #[test]
    fn test_quadratic_proof_serde() {
        let mut rng = test_rng();
        let crs = CRS::<F>::generate_crs(&mut rng);

        let scalar_xvars: Vec<Fr> = vec![Fr::rand(&mut rng), Fr::rand(&mut rng)];
        let scalar_yvars: Vec<Fr> = vec![Fr::rand(&mut rng)];

        let equ: QuadEqu<F> = QuadEqu::<F> {
            a_consts: vec![Fr::rand(&mut rng)],
            b_consts: vec![Fr::rand(&mut rng), Fr::rand(&mut rng)],
            gamma: vec![vec![Fr::one()], vec![Fr::zero()]],
            target: Fr::rand(&mut rng),
        };

        // Individually commit then prove
        let scalar_xcoms: Commit1<F> = batch_commit_scalar_to_B1(&scalar_xvars, &crs, &mut rng);
        let scalar_ycoms: Commit2<F> = batch_commit_scalar_to_B2(&scalar_yvars, &crs, &mut rng);
        let proof: EquProof<F> = equ.prove(
            &scalar_xvars,
            &scalar_yvars,
            &scalar_xcoms,
            &scalar_ycoms,
            &crs,
            &mut rng,
        );

        // Serialize and deserialize the proof
        let mut c_bytes = Vec::new();
        proof.serialize_compressed(&mut c_bytes).unwrap();
        let proof_de = EquProof::<F>::deserialize_compressed(&c_bytes[..]).unwrap();
        assert_eq!(proof, proof_de);

        let mut u_bytes = Vec::new();
        proof.serialize_uncompressed(&mut u_bytes).unwrap();
        let proof_de = EquProof::<F>::deserialize_uncompressed(&u_bytes[..]).unwrap();
        assert_eq!(proof, proof_de);
    }
}

/// Binding-aware prover for PPE with rank-1 binding CRS and kernel-constrained randomness
/// Uses T = λ·k_U·k_V^T (rank-1 structure) for correct extraction
pub fn prove_ppe_binding_1d<E: Pairing, CR: Rng>(
    ppe: &PPE<E>,
    xvars: &[E::G1Affine],
    yvars: &[E::G2Affine],
    xcoms: &Commit1<E>,
    ycoms: &Commit2<E>,
    crs: &CRS<E>,
    kernel_u: &[E::ScalarField; 2],
    kernel_v: &[E::ScalarField; 2],
    rng: &mut CR,
) -> EquProof<E> {
    let m = xvars.len();
    let n = yvars.len();
    let is_parallel = true;

    assert_eq!(ppe.gamma.len(), m);
    assert_eq!(ppe.gamma[0].len(), n);
    assert_eq!(xcoms.rand.len(), m);
    assert_eq!(ycoms.rand.len(), n);

    // Randomness is already kernel-constrained (R^T: 2×m, S^T: 2×n)
    let x_rand_trans = xcoms.rand.transpose();
    let y_rand_trans = ycoms.rand.transpose();

    // Structured T (rank-1): T = λ·k_U·k_V^T
    let lambda = E::ScalarField::rand(rng);
    let pf_rand: Matrix<E::ScalarField> = vec![
        vec![
            kernel_u[0] * kernel_v[0] * lambda,
            kernel_u[0] * kernel_v[1] * lambda,
        ],
        vec![
            kernel_u[1] * kernel_v[0] * lambda,
            kernel_u[1] * kernel_v[1] * lambda,
        ],
    ];

    // Build π (same structure as standard prover, but with kernel-constrained randomness)
    let x_rand_lin_b = vec_to_col_vec(&Com2::<E>::batch_linear_map(&ppe.b_consts))
        .left_mul(&x_rand_trans, is_parallel);

    let x_rand_stmt = x_rand_trans.right_mul(&ppe.gamma, is_parallel);
    let x_rand_stmt_lin_y =
        vec_to_col_vec(&Com2::<E>::batch_linear_map(yvars)).left_mul(&x_rand_stmt, is_parallel);

    let pf_rand_stmt = x_rand_trans
        .right_mul(&ppe.gamma, is_parallel)
        .right_mul(&ycoms.rand, is_parallel)
        .add(&pf_rand.transpose().neg());
    let pf_rand_stmt_com2 = vec_to_col_vec(&crs.v).left_mul(&pf_rand_stmt, is_parallel);

    let pi = col_vec_to_vec(&x_rand_lin_b.add(&x_rand_stmt_lin_y).add(&pf_rand_stmt_com2));
    assert_eq!(pi.len(), 2);

    // Build θ
    let y_rand_lin_a = vec_to_col_vec(&Com1::<E>::batch_linear_map(&ppe.a_consts))
        .left_mul(&y_rand_trans, is_parallel);

    let y_rand_stmt = y_rand_trans.right_mul(&ppe.gamma.transpose(), is_parallel);
    let y_rand_stmt_lin_x =
        vec_to_col_vec(&Com1::<E>::batch_linear_map(xvars)).left_mul(&y_rand_stmt, is_parallel);

    let pf_rand_com1 = vec_to_col_vec(&crs.u).left_mul(&pf_rand, is_parallel);

    let theta = col_vec_to_vec(&y_rand_lin_a.add(&y_rand_stmt_lin_x).add(&pf_rand_com1));
    assert_eq!(theta.len(), 2);

    EquProof::<E> {
        pi,
        theta,
        equ_type: EquType::PairingProduct,
        rand: pf_rand,
        aux_x: vec![],
        aux_y: vec![],
    }
}

/*
 * NOTE:
 *
 * Proof verification tests are considered integration tests for the Groth-Sahai proof system.
 *
 * See tests/prover.rs for more details.
 */

#[cfg(test)]
mod binding_prover_tests {}

// Rank-decomposition PPE prover (for offline PVUGC ARMER)
impl<E: Pairing> PPE<E> {
    /// Commit and prove using rank-decomposition PPE structure.
    ///
    /// This prover generates θ/π that are compatible with the four-bucket verifier,
    /// enabling offline PVUGC ARMER. The proof elements are:
    ///
    /// - θ_a = Σ_i u^(a)_i · r_i · u_{i,0} (G1, rank elements)
    /// - π_j = s_j · v_{j,0} (G2, n elements)
    ///
    /// These work with the statement-only bases (U, V, W, Z) to achieve randomizer cancellation.
    ///
    /// # Arguments
    /// * `xvars` - Witness X variables (G1, length m)
    /// * `yvars` - Witness Y variables (G2, length n)
    /// * `crs` - Per-slot CRS (must have m X-slots and n Y-slots)
    /// * `rng` - Random number generator
    ///
    /// # Returns
    /// `CProof` with commitments and rank-decomp proof elements
    pub fn commit_and_prove_rank_decomp<R: Rng>(
        &self,
        xvars: &[E::G1Affine],
        yvars: &[E::G2Affine],
        crs: &CRS<E>,
        rng: &mut R,
    ) -> CProof<E> {
        use super::commit::{batch_commit_G1_per_slot, batch_commit_G2_per_slot};
        use crate::base_construction::{build_P_slots, build_Q_slots};
        use crate::rank_decomp::RankDecomp;

        let m = xvars.len();
        let n = yvars.len();

        // Verify dimensions
        assert_eq!(self.gamma.len(), m, "Γ rows must match X variables");
        assert_eq!(self.gamma[0].len(), n, "Γ cols must match Y variables");
        assert_eq!(crs.num_x_slots(), m, "CRS must have m X-slots");
        assert_eq!(crs.num_y_slots(), n, "CRS must have n Y-slots");

        // 1. Commit using per-slot CRS
        let (xcoms, r_randomizers) = batch_commit_G1_per_slot(xvars, crs, rng);
        let (ycoms, s_randomizers) = batch_commit_G2_per_slot(yvars, crs, rng);

        // 2. Compute rank decomposition
        let decomp = RankDecomp::decompose(&self.gamma);

        // 3. Generate rank-decomp proof elements
        // θ = P slots (rank elements in G1)
        let theta = build_P_slots(crs, &decomp, &r_randomizers);

        // π = Q slots (n elements in G2)
        let pi = build_Q_slots(crs, &s_randomizers);

        // 4. Return proof
        CProof {
            xcoms,
            ycoms,
            equ_proofs: vec![EquProof {
                theta,
                pi,
                equ_type: EquType::PairingProduct,
                rand: vec![],  // Not used in rank-decomp verification
                aux_x: vec![], // Not used in rank-decomp path
                aux_y: vec![], // Not used in rank-decomp path
            }],
        }
    }

    /// Commit and prove for full-GS block verifier (Phase 7, Groth16 integration).
    ///
    /// This method creates commitments using VAR-row bases and explicit randomizers,
    /// compatible with the block-based full-GS verifier. No θ/π proof elements are
    /// generated since B3/B4 are disabled in the block verifier.
    ///
    /// # Arguments
    /// * `xvars` - G1 variables
    /// * `yvars` - G2 variables
    /// * `r` - Explicit randomizers for X (use 0 for constants)
    /// * `s` - Explicit randomizers for Y (use 0 for constants)
    /// * `crs` - Per-slot CRS
    ///
    /// # Returns
    /// Proof with commitments, empty θ/π
    pub fn commit_and_prove_full_gs<R: Rng>(
        &self,
        xvars: &[E::G1Affine],
        yvars: &[E::G2Affine],
        r: &[E::ScalarField],
        s: &[E::ScalarField],
        crs: &CRS<E>,
        _rng: &mut R,
    ) -> CProof<E> {
        use super::commit::{commit_g1_full_gs, commit_g2_full_gs};
        use ark_ec::CurveGroup;

        let m = xvars.len();
        let n = yvars.len();

        let (xcoms, _) = commit_g1_full_gs(xvars, crs, r);
        let (ycoms, _) = commit_g2_full_gs(yvars, crs, s);

        // Compute auxiliary randomizer legs for proper telescoping cancellation
        let mut aux_x = Vec::with_capacity(m);
        for i in 0..m {
            let (_, u_var) = crs.u_for_slot(i);
            aux_x.push((u_var.0.into_group() * r[i]).into_affine()); // r_i * u_{i,0}
        }

        let mut aux_y = Vec::with_capacity(n);
        for j in 0..n {
            let (_, v_var) = crs.v_for_slot(j);
            aux_y.push((v_var.0.into_group() * s[j]).into_affine()); // s_j * v_{j,0}
        }

        // For full-GS block verifier, θ and π are not needed (B3/B4 disabled)
        // but aux_x and aux_y are required for complete telescoping
        CProof {
            xcoms,
            ycoms,
            equ_proofs: vec![EquProof {
                theta: vec![],
                pi: vec![],
                equ_type: EquType::PairingProduct,
                rand: vec![],
                aux_x,
                aux_y,
            }],
        }
    }
}
