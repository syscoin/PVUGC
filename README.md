# PVUGC - Proof-Agnostic Verifiable Unique Group Commitments

**EXPERIMENTAL RESEARCH CODE**

This repository contains experimental cryptographic research code implementing PVUGC: a protocol for extracting Key Encapsulation Mechanism (KEM) secrets from Groth-Sahai attestations in a proof-agnostic manner.

## Overview

PVUGC enables conditional cryptographic operations where a shared secret can be extracted from any valid proof of a given statement, without requiring the extractor to know the secret masking scalar. The protocol uses Groth-Sahai commitments to create attestations of proof validity, which can then be used to extract KEM keys.

**Key Properties:**
- Proof-Agnostic: Different proofs for the same statement yield the same key
- Offline Setup: One-time generation of armed bases, then offline forever
- Randomized Commitments: Full witness-indistinguishability via GS proof system
- General PPE Support: Works with any pairing product equation
- Groth16 Integration: Specialized support for SNARK proofs

## Protocol Architecture

PVUGC uses a three-role architecture:

### 1. ARMER (Offline, One-Time)
- Generates secret scalar ρ
- Publishes "armed bases" = bases^ρ
- Goes offline permanently
- ρ never leaves the ARMER

### 2. PROVER (Runtime, Repeatable)
- Generates proof π (Groth16, R1CS, or other)
- Creates Groth-Sahai attestation
- Does NOT know ρ

### 3. DECAPPER (Runtime, Repeatable)
- Receives attestation from PROVER
- Extracts K = target^ρ using armed bases
- Does NOT know ρ (GT-XPDH security)
- Proof-agnostic: same K from all proofs of same statement

## Technical Foundation

The protocol builds on Groth-Sahai proofs for Pairing Product Equations (PPE):

```
Σ_{i,j} Γ_{i,j} · e(X_i, Y_j) = target
```

Where verification uses four pairing buckets that cancel randomness:
```
M = Σ e(C¹[i], U[i]) + Σ e(V[i], C²[i]) + 
    Σ e(θ[a], W[a]) + Σ e(Z[j], π[j])
```

PVUGC arms these bases with ρ:
- Publish: U^ρ, V^ρ, W^ρ, Z^ρ
- Extract: K = M^ρ = target^ρ

## Documentation

### Protocol Specification

**See [`specs/PVUGC.md`](specs/PVUGC.md) for the complete protocol specification**, including Bitcoin integration, security model, and cryptographic assumptions.

### Implementation Guide

**See [`groth-sahai/PVUGC_PROTOCOL.md`](groth-sahai/PVUGC_PROTOCOL.md) for the implementation details**, including:

- Phase 1: Per-slot CRS with binding structure
- Phase 2: Rank decomposition for Γ matrices
- Phase 3: Four-bucket verifier with randomness cancellation
- Phase 4: PVUGC arming (ρ-powered bases)
- Phase 5: PVUGC decapping (key extraction)
- Phase 6: Soundness validation
- Phase 7: Groth16 integration with 4-term auxiliary recomposition


## Building

Requires Rust 1.70+

```bash
cd arkworks_groth16
cargo build --release
cargo test
```

## Usage Examples

### Example 1: General PPE (Rank-Decomposition)

```rust
use groth_sahai::generator::CRS;
use groth_sahai::statement::PPE;
use groth_sahai::rank_decomp::RankDecomp;
use groth_sahai::base_construction::RankDecompPpeBases;
use groth_sahai::pvugc::{pvugc_arm, pvugc_decap};

// ARMER: One-time setup
let crs = CRS::<Bls12_381>::generate_crs_per_slot(&mut rng, m, n);
let ppe = PPE { gamma, a_consts, b_consts, target };
let decomp = RankDecomp::decompose(&ppe.gamma);
let bases = RankDecompPpeBases::build(&crs, &ppe, &decomp);

let rho = Fr::rand(&mut rng);
let armed_bases = pvugc_arm(&bases, &rho);
// Publish: (crs, armed_bases, target)
// Secret: rho

// PROVER: Generate attestation
let proof = ppe.commit_and_prove_rank_decomp(&x_vars, &y_vars, &crs, &mut rng);

// DECAPPER: Extract key
let k = pvugc_decap(&proof, &armed_bases);
assert_eq!(k, target * rho);  // K = target^ρ
```

### Example 2: Groth16 Integration (Full-GS)

```rust
// PROVER: Groth16 proof → GS attestation
let x_vars = vec![A, C, L_x];
let y_vars = vec![B, delta_inv, gamma_inv];
let r = vec![random, random, zero];  // Randomize witnesses only
let s = vec![random, zero, zero];

let proof = ppe.commit_and_prove_full_gs(&x_vars, &y_vars, &r, &s, &crs, &mut rng);

// DECAPPER: Verify and extract
let (verifies, M) = ppe.verify_full_gs(&proof, &crs, &bases);
let k = M * rho;  // K = e(α,β)^ρ
```

See `groth-sahai/src/pvugc.rs::tests` for complete working examples.

## Security

Based on standard assumptions:
- SXDH assumption in pairing groups (for Groth-Sahai)  
- Discrete log hardness
- Groth16 knowledge soundness

This implementation uses established cryptographic primitives and assumptions.

## Current limitations

- Simplified MuSig2 implementation (single party for testing)
- Mock Groth16 proofs in tests (real proofs work but need circuits)
- BLS12-381 only (other curves need porting)

## Protocol spec

Full specification in `specs/pvugc.md`. This implementation follows the spec closely, with some simplifications for testing.

## Testing

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Specific test
cargo test test_complete_adaptor_signature_flow
```

## Credits

Built on:
- arkworks for elliptic curves and pairings
- schnorr_fun for adaptor signatures  
- Groth-Sahai implementation (vendored and modified)

## License

MIT
