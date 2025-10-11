# PVUGC Hardening Plan

To move from “tests pass” to “Bitcoin-grade” assurance, follow this action plan:

## 1. Freeze the Spec and Implementation Map
- Treat `PVUGC_breakthrough.md` as the canonical specification.
- Maintain a living document that maps each equation and claim in the spec to concrete modules, functions, and tests in the repo.
- Ensure future reviewers can trace every behaviour directly to the spec.

## 2. Expand Deterministic Test Coverage
- Generate fixed test vectors (CRS seeds, sample Groth16 proofs, masked matrices, derived KEM keys) and store them in fixtures for reproducibility.
- Add property-based tests (e.g. 100 random trials) asserting that distinct valid proofs for identical statements produce equal masked outputs and KEM keys.

## 3. Deep Code Review
- Conduct an internal review focusing on masked algebra, commitment randomness, KEM pipeline, and CRS handling.
- Document all assumptions about ordering, masking, and determinism; remove “hand tuned” paths.

## 4. Static Analysis and Sanitizers
- Run `cargo fmt`, `cargo clippy`, and produce code-coverage reports (`cargo tarpaulin` or equivalent).
- Build and test with sanitizers (ASan, UBSan) to catch undefined behaviour in cryptographic routines.

## 5. Protocol Validation Harnesses
- Simulate complete adaptor flows under adversarial scenarios (bad proofs, wrong public inputs, tampered CRS) to confirm deterministic failure behaviour.
- Add fault injection tests that deliberately break each acceptance check to validate error handling.

## 6. Fuzzing and Negative Testing
- Integrate fuzzers (AFL/libFuzzer) for serialization, CRS handling, masked matrices, and KEM decapsulation inputs.
- Maintain targeted corpora exploring random permutations and malformed inputs to uncover algebraic edge cases.

## 7. Independent Re-implementation
- Build a minimal second implementation (possibly in another language) to cross-validate masked outputs and derived keys.
- Highlight any discrepancies to surface hidden assumptions in the primary codebase.

## 8. External Cryptanalysis
- Present the construction (math plus code) to external cryptographers for review.
- Request analysis on CRS dual-basis assumptions, randomness cancellation, multi-proof determinism, and Groth16 integration.
- Incorporate findings into the spec and code changes.

## 9. Formal Verification Targets
- Identify algebraic kernels suitable for formal proofs (e.g. masked verifier equality, KEM determinism).
- Use formal methods (Coq/Isabelle or machine-checkable proofs) to prove invariants.

## 10. Red-Team Exercise and Bug Bounty
- Run an internal red-team engagement (CRS swaps, mask tampering, KEM forging attempts).
- After internal sign-off, open a scoped bug bounty to invite external attempts to break the masking or KEM logic.

## 11. Deployment Readiness
- Produce end-to-end demos that log all invariants.
- Provide reproducible build instructions and container images for independent verification.
- Prepare a release checklist covering tests, coverage thresholds, audit notes, and spec version hashes.

