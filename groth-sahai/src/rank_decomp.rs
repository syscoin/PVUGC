//! Rank decomposition for Γ matrices in rank-decomposition PPE.
//!
//! For offline PVUGC ARMER, we need to decompose the Γ matrix (m×n) into a sum
//! of rank-1 matrices:
//!
//! ```text
//! Γ = Σ_{a=1}^{rank} u^(a) · v^(a)^T
//! ```
//!
//! where u^(a) ∈ F^m and v^(a) ∈ F^n are column vectors.
//!
//! This allows us to encode Γ into statement-only bases:
//! - U_i = Σ_j Γ_ij · v_{j,1} (using all v^(a) components)
//! - W_a = Σ_j v^(a)_j · v_{j,1} (one base per rank component)
//!
//! And the prover generates proof slots that cancel randomizers:
//! - P_a = Σ_i u^(a)_i · r_i · u_{i,0}

use ark_ff::Field;
use crate::data_structures::Matrix;

/// Rank decomposition of a matrix Γ
///
/// Stores the factorization Γ = Σ_a u^(a) · v^(a)^T
#[derive(Clone, Debug)]
pub struct RankDecomp<F: Field> {
    /// Rank of the matrix
    pub rank: usize,
    
    /// Column vectors u^(a) ∈ F^m (one per rank component)
    /// Each u_vecs[a] is a vector of length m
    pub u_vecs: Vec<Vec<F>>,
    
    /// Column vectors v^(a) ∈ F^n (one per rank component)
    /// Each v_vecs[a] is a vector of length n
    pub v_vecs: Vec<Vec<F>>,
    
    /// Original matrix dimensions
    pub m: usize,  // rows
    pub n: usize,  // cols
}

impl<F: Field> RankDecomp<F> {
    /// Compute the rank decomposition of Γ using Gaussian elimination.
    ///
    /// This implements a simple column-space rank factorization:
    /// 1. Find pivot columns (linearly independent columns)
    /// 2. Express each column as a linear combination of pivot columns
    /// 3. Extract u^(a) and v^(a) from the factorization
    ///
    /// # Arguments
    /// * `gamma` - The m×n matrix to decompose
    ///
    /// # Returns
    /// A `RankDecomp` struct with vectors u^(a), v^(a) such that Γ = Σ_a u^(a)·v^(a)^T
    ///
    /// # Example
    /// ```ignore
    /// let gamma = vec![
    ///     vec![Fr::from(1u64), Fr::from(2u64)],
    ///     vec![Fr::from(3u64), Fr::from(4u64)],
    /// ];
    /// let decomp = RankDecomp::decompose(&gamma);
    /// assert!(decomp.rank <= 2);
    /// 
    /// // Verify reconstruction
    /// let reconstructed = decomp.reconstruct();
    /// assert_eq!(reconstructed, gamma);
    /// ```
    pub fn decompose(gamma: &Matrix<F>) -> Self {
        let m = gamma.len();
        let n = if m > 0 { gamma[0].len() } else { 0 };
        
        if m == 0 || n == 0 {
            return Self {
                rank: 0,
                u_vecs: vec![],
                v_vecs: vec![],
                m,
                n,
            };
        }
        
        // Transpose Γ to work with columns as vectors
        let gamma_t = transpose(gamma);
        
        // Find linearly independent columns using Gaussian elimination
        let (pivot_cols, coefficients) = find_pivot_columns(&gamma_t);
        let rank = pivot_cols.len();
        
        if rank == 0 {
            return Self {
                rank: 0,
                u_vecs: vec![],
                v_vecs: vec![],
                m,
                n,
            };
        }
        
        // Extract u^(a) and v^(a) from the pivot structure
        // For each pivot column j:
        //   u^(a) = column j of Γ
        //   v^(a) = canonical basis vector e_j extended with coefficients for other columns
        
        let mut u_vecs = Vec::with_capacity(rank);
        let mut v_vecs = Vec::with_capacity(rank);
        
        for (a, &pivot_j) in pivot_cols.iter().enumerate() {
            // u^(a) = Γ[:, pivot_j] (column pivot_j of Γ)
            let u_a: Vec<F> = (0..m).map(|i| gamma[i][pivot_j]).collect();
            u_vecs.push(u_a);
            
            // v^(a) has coefficient 1 at pivot_j, and coefficients for dependent columns
            let mut v_a = vec![F::zero(); n];
            v_a[pivot_j] = F::one();
            
            // For each non-pivot column k, add the coefficient from k's expression
            for (k, coeff_vec) in coefficients.iter().enumerate() {
                if !pivot_cols.contains(&k) && !coeff_vec.is_empty() {
                    // Column k = Σ_a coeff_vec[a] · (pivot column a)
                    v_a[k] = coeff_vec[a];
                }
            }
            
            v_vecs.push(v_a);
        }
        
        Self {
            rank,
            u_vecs,
            v_vecs,
            m,
            n,
        }
    }
    
    /// Reconstruct the original matrix from the decomposition.
    ///
    /// Computes Γ = Σ_a u^(a) · v^(a)^T
    ///
    /// # Returns
    /// The reconstructed m×n matrix
    pub fn reconstruct(&self) -> Matrix<F> {
        let mut gamma = vec![vec![F::zero(); self.n]; self.m];
        
        for a in 0..self.rank {
            let u_a = &self.u_vecs[a];
            let v_a = &self.v_vecs[a];
            
            for i in 0..self.m {
                for j in 0..self.n {
                    gamma[i][j] += u_a[i] * v_a[j];
                }
            }
        }
        
        gamma
    }
    
    /// Verify that the decomposition correctly reconstructs Γ.
    ///
    /// # Arguments
    /// * `gamma` - The original matrix to check against
    ///
    /// # Returns
    /// `true` if reconstruction equals the original matrix
    pub fn verify(&self, gamma: &Matrix<F>) -> bool {
        let reconstructed = self.reconstruct();
        matrices_equal(&reconstructed, gamma)
    }
}

/// Transpose a matrix
fn transpose<F: Field>(matrix: &Matrix<F>) -> Matrix<F> {
    let m = matrix.len();
    if m == 0 {
        return vec![];
    }
    let n = matrix[0].len();
    
    let mut result = vec![vec![F::zero(); m]; n];
    for i in 0..m {
        for j in 0..n {
            result[j][i] = matrix[i][j];
        }
    }
    result
}

/// Find pivot columns using Gaussian elimination
///
/// Returns (pivot_indices, coefficients) where:
/// - pivot_indices: indices of linearly independent columns
/// - coefficients[j]: expresses column j as linear combo of pivot columns
fn find_pivot_columns<F: Field>(
    columns: &Matrix<F>,
) -> (Vec<usize>, Vec<Vec<F>>) {
    let n = columns.len();  // number of columns
    if n == 0 {
        return (vec![], vec![]);
    }
    let _m = columns[0].len();  // dimension of each column vector
    
    let mut pivot_cols = Vec::new();
    let mut coefficients = vec![vec![]; n];
    
    // Try each column as a potential pivot
    for j in 0..n {
        let col_j = &columns[j];
        
        // Try to express col_j as a linear combination of existing pivots
        if let Some(coeff) = express_as_linear_combination(col_j, &columns, &pivot_cols) {
            // col_j is dependent - store coefficients
            coefficients[j] = coeff;
        } else {
            // col_j is independent - add as new pivot
            pivot_cols.push(j);
            coefficients[j] = vec![];  // No coefficients for pivots
        }
    }
    
    (pivot_cols, coefficients)
}

/// Try to express a vector as a linear combination of given basis vectors
///
/// Returns Some(coefficients) if successful, None if the vector is independent
fn express_as_linear_combination<F: Field>(
    vec: &[F],
    all_vecs: &Matrix<F>,
    basis_indices: &[usize],
) -> Option<Vec<F>> {
    if basis_indices.is_empty() {
        // Check if vec is zero
        if vec.iter().all(|x| x.is_zero()) {
            return Some(vec![]);
        } else {
            return None;
        }
    }
    
    let dim = vec.len();
    let basis_size = basis_indices.len();
    
    // Build linear system: basis^T · c = vec
    // We'll use a simple Gaussian elimination approach
    
    // Create augmented matrix [basis | vec]
    let mut aug = vec![vec![F::zero(); basis_size + 1]; dim];
    for i in 0..dim {
        for (b_idx, &basis_j) in basis_indices.iter().enumerate() {
            aug[i][b_idx] = all_vecs[basis_j][i];
        }
        aug[i][basis_size] = vec[i];
    }
    
    // Gaussian elimination
    for col in 0..basis_size.min(dim) {
        // Find pivot
        let pivot_row = (col..dim)
            .find(|&row| !aug[row][col].is_zero())?;
        
        if pivot_row != col {
            aug.swap(pivot_row, col);
        }
        
        let pivot = aug[col][col];
        let pivot_inv = pivot.inverse()?;
        
        // Eliminate column
        for row in 0..dim {
            if row != col {
                let factor = aug[row][col] * pivot_inv;
                // Store pivot row values to avoid borrow checker issues
                let pivot_row_vals: Vec<F> = aug[col].clone();
                for k in 0..=basis_size {
                    aug[row][k] -= factor * pivot_row_vals[k];
                }
            }
        }
    }
    
    // Extract solution
    let mut coeffs = vec![F::zero(); basis_size];
    for col in 0..basis_size.min(dim) {
        if !aug[col][col].is_zero() {
            coeffs[col] = aug[col][basis_size] * aug[col][col].inverse()?;
        }
    }
    
    // Verify solution
    let mut reconstructed = vec![F::zero(); dim];
    for (b_idx, &basis_j) in basis_indices.iter().enumerate() {
        for i in 0..dim {
            reconstructed[i] += coeffs[b_idx] * all_vecs[basis_j][i];
        }
    }
    
    for i in 0..dim {
        if reconstructed[i] != vec[i] {
            return None;  // Not in span
        }
    }
    
    Some(coeffs)
}

/// Check if two matrices are equal
fn matrices_equal<F: Field>(a: &Matrix<F>, b: &Matrix<F>) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for i in 0..a.len() {
        if a[i].len() != b[i].len() {
            return false;
        }
        for j in 0..a[i].len() {
            if a[i][j] != b[i][j] {
                return false;
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_ff::{One, Zero};

    #[test]
    fn test_rank_decomp_diagonal() {
        // Diagonal matrix: rank = number of non-zero diagonals
        let gamma = vec![
            vec![Fr::from(2u64), Fr::zero()],
            vec![Fr::zero(), Fr::from(4u64)],
        ];
        
        let decomp = RankDecomp::decompose(&gamma);
        
        println!("Diagonal Γ:");
        println!("  Original rank: 2");
        println!("  Computed rank: {}", decomp.rank);
        assert!(decomp.rank <= 2);
        
        let reconstructed = decomp.reconstruct();
        assert!(decomp.verify(&gamma), "Reconstruction failed");
        assert_eq!(reconstructed, gamma);
        
        println!("  PASS: Reconstruction verified");
    }

    #[test]
    fn test_rank_decomp_full_rank() {
        // Full rank 2×2 matrix
        let gamma = vec![
            vec![Fr::from(1u64), Fr::from(2u64)],
            vec![Fr::from(3u64), Fr::from(4u64)],
        ];
        
        let decomp = RankDecomp::decompose(&gamma);
        
        println!("Full-rank Γ:");
        println!("  Computed rank: {}", decomp.rank);
        assert_eq!(decomp.rank, 2, "Should be full rank");
        
        assert!(decomp.verify(&gamma), "Reconstruction failed");
        
        println!("  PASS: Full rank decomposition verified");
    }

    #[test]
    fn test_rank_decomp_rank_one() {
        // Rank-1 matrix: all rows are multiples of first row
        let gamma = vec![
            vec![Fr::from(1u64), Fr::from(2u64)],
            vec![Fr::from(2u64), Fr::from(4u64)],  // 2× first row
        ];
        
        let decomp = RankDecomp::decompose(&gamma);
        
        println!("Rank-1 Γ:");
        println!("  Computed rank: {}", decomp.rank);
        assert_eq!(decomp.rank, 1, "Should be rank 1");
        
        assert!(decomp.verify(&gamma), "Reconstruction failed");
        
        println!("  PASS: Rank-1 decomposition verified");
    }

    #[test]
    fn test_rank_decomp_zero_matrix() {
        let gamma = vec![
            vec![Fr::zero(), Fr::zero()],
            vec![Fr::zero(), Fr::zero()],
        ];
        
        let decomp = RankDecomp::decompose(&gamma);
        
        println!("Zero Γ:");
        println!("  Computed rank: {}", decomp.rank);
        assert_eq!(decomp.rank, 0, "Zero matrix should have rank 0");
        
        let reconstructed = decomp.reconstruct();
        assert_eq!(reconstructed, gamma);
        
        println!("  PASS: Zero matrix handled correctly");
    }

    #[test]
    fn test_rank_decomp_identity() {
        // Identity matrix
        let gamma = vec![
            vec![Fr::one(), Fr::zero(), Fr::zero()],
            vec![Fr::zero(), Fr::one(), Fr::zero()],
            vec![Fr::zero(), Fr::zero(), Fr::one()],
        ];
        
        let decomp = RankDecomp::decompose(&gamma);
        
        println!("Identity 3×3:");
        println!("  Computed rank: {}", decomp.rank);
        assert_eq!(decomp.rank, 3, "Identity should have full rank");
        
        assert!(decomp.verify(&gamma), "Reconstruction failed");
        
        println!("  PASS: Identity decomposition verified");
    }

    #[test]
    fn test_transpose() {
        let matrix = vec![
            vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)],
            vec![Fr::from(4u64), Fr::from(5u64), Fr::from(6u64)],
        ];
        
        let transposed = transpose(&matrix);
        
        assert_eq!(transposed.len(), 3);
        assert_eq!(transposed[0].len(), 2);
        assert_eq!(transposed[0][0], Fr::from(1u64));
        assert_eq!(transposed[0][1], Fr::from(4u64));
        assert_eq!(transposed[2][1], Fr::from(6u64));
        
        println!("PASS: Transpose works correctly");
    }
}

