# Pivot–Schur full-extension rank certificate (construction continuation)

Builds **directly** on the live pivot-twisted SL₂–Frobenius local gate at `79a55d32db8d0b60d46195a180c72ac0da59e892`. Same R1CS→sampled QAP→E-valued public coefficient matrices and same capability for every valid ORIGINAL witness. No extra masks, witnesses, public matrices, release oracle or cryptographic assumption.

**New exact results:** The existing independent base-field shears certify rank ≥**5,200** for *every E-typed nonconstant public slice combination with a nonzero ORIGINAL-variable coefficient*, including arbitrary adaptive E-valued quotient mixing; quotient-only nonzero combinations have rank ≥**752**. A separate exact all-E **wrong-scalar** theorem rules out every public rank-accepted `(y,λ)` with `λ≠zK`. The only Setup change is outer padding `h:117→165`, leaving `L=16,374`, `r=375`, `T=234` unchanged. A sharper rectangular product-rank convolution (minimizer 48, exponent 24,921) preserves the predecessor's supplied-F-original-witness extraction despite `T<2h`.

**Exact, conservative integer certificate:** combined honest-setup SOURCE/rank semantic error `<2^-169`; this is **not** QPT key-security. Public matrix storage **increases** 0.292317%, from 0.93321 PB to **0.93594 PB** (still infeasible). No claim that a bare K or native forgery yields a witness, and no false-instance secrecy, setup security, multiple-capsule or deployed Bitcoin proof.

Read [`FULL_EXTENSION_RANK.md`](FULL_EXTENSION_RANK.md) for Setup/Encode/Recover, every public output, all algebraic proofs, failure games, exact dependency and next missing equation. Execute `python full_extension_certificate.py > output.json && cmp output.json validation.json` (Python 3.10+ stdlib). The executable checks the exact pivot/SL₂/extension gate, includes full-public matrices and runs 1,454,799 assertions over two seeds plus exhaustive E-projective original source classes in the synthetic GF(16)⊂GF(256) fixtures. [`PROVENANCE.json`](PROVENANCE.json) records hashes and execution scope.

**Not a complete or practical PQ witness-KEM.** Keep PR #1 open/draft/unmerged; do not change production or disable the research task.
