# PVUGC - Proof Verification Under Groth-Sahai Commitments

⚠️ **EXPERIMENTAL AND WORK IN PROGRESS** ⚠️

This repository contains experimental cryptographic research code. It is not production-ready and should not be used in any security-critical applications. The implementation is still under active development and may contain bugs, incomplete features, or security vulnerabilities.

Bitcoin adaptor signatures that only complete when you have a valid zero-knowledge proof. No trusted setup beyond what's already in Groth16.

## What is this?

PVUGC implements witness encryption for Groth16 proofs using Groth-Sahai commitments as an attestation layer. The basic idea: you can create a Bitcoin transaction that can only be spent if someone provides a valid zk-SNARK proof for some statement.

Think of it as conditional payments based on computational proofs. You deposit Bitcoin that gets released when someone proves they know the preimage of a hash, solved a sudoku puzzle, or executed a smart contract correctly.

## How it works

The protocol has three main phases:

**Setup**: Create a Schnorr adaptor signature for a Bitcoin transaction, but instead of sharing the adaptor secret directly, we encrypt it using a special KEM (Key Encapsulation Mechanism) that's tied to a Groth16 verification equation.

**Arming**: Generate masked "dual bases" from the Groth-Sahai CRS. These masks hide the adaptor secret fragments in a way that can only be recovered by evaluating pairings with valid GS commitments.

**Disarming**: Provide a Groth16 proof, create a GS attestation of its validity, use that attestation to decrypt the adaptor fragments, sum them to get α, complete the signature with s = s' + α.

The magic is that any valid proof for the same statement decrypts to the same adaptor secret (deterministic KEM), but without a proof you can't recover anything useful.

## Technical details

The core insight is using the Groth-Sahai proof system's structure where verification reduces to:
```
∏ e(C¹ⱼ, Uⱼ) · ∏ e(Vₖ, C²ₖ) = G_target
```

The commitments C depend on your proof, but the bases U,V only depend on the CRS and public input. We mask these bases with randomness ρ to create the KEM:
- Publish: D₁ⱼ = Uⱼ^ρ, D₂ₖ = Vₖ^ρ  
- Secret: M = G_target^ρ

Anyone with valid commitments can compute M and decrypt. No proof? Can't compute M without solving discrete log.

## Building

Requires Rust 1.70+

```bash
cd arkworks_groth16
cargo build --release
cargo test
```

## Usage

Check out `tests/test_pvugc.rs` for the complete flow. Here's the gist:

```rust
// Create GS system
let gs = GrothSahaiCommitments::from_seed(b"my_context");

// Create Groth16 proof (or mock one for testing)
let (proof, vk) = create_groth16_proof();

// Create GS attestation
let attestation = gs.commit_arkworks_proof(&proof, &vk, &public_input, true)?;

// Setup KEM and encrypt adaptor shares
let kem = ProductKeyKEM::new();
let ppe = gs.groth16_verify_as_ppe(&vk, &public_inputs);
    let (kem_share, masked_target_bytes) = kem.encapsulate_deposit(
        &mut rng,
        share_index,
        &c1_bytes,
        &c2_bytes,
        &pi_bytes,
        &theta_bytes,
        &u_bytes,
        &v_bytes,
        adaptor_share,
        ctx_hash,
        instance_digest,
)?;

// Later: decrypt with any valid attestation
let recovered_secret = kem.decapsulate(&kem_share, &ppe, &c1_bytes, &c2_bytes, &pi_bytes, &theta_bytes, ctx_hash, instance_digest)?;
```

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
