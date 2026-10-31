# Run 457 — Public native verification keys preclude full signing-key IND

Date: 2026-10-12 UTC. syscoin/PVUGC#1 research only, starting live head `1fb447f9796e98f2dd9a9b5eded75558f3baf2f7`, draft branch `research/pq-wkem-validation-20260918`. Production unchanged.

## Exact false-instance distinguishing theorem

For an honest classical PPT native signature scheme, let `(vk,sk)` and `(vk',sk')` be *independent* outputs of NativeKeyGen. Fix a branch-bound native message `m` before key generation. An adversary given public `(vk,C_x,aux_x,T)` computes `D=NativeVerify(vk,m,NativeSign(T,m))` and ignores the allegedly opaque release capsule `C_x`. If `T=sk`, D accepts with probability at least `1-eps_correct`. If `T=sk'`, acceptance is a native EUF-CMA forgery under independently generated target `vk`: a straight-line reduction generates `(vk',sk')`, signs m, and submits `(m,sigma)` without making any target-key signing query. Therefore

`Adv_distinguish >= 1-eps_correct-Adv_EUF-CMA`.

Thus even ideal local mixing cannot make the actual signing secret indistinguishable from an *independent valid native signing secret* when the challenger reveals a candidate alongside its real public verification key. This is a **security-game correction**, not a break of native signatures. It also applies to a publicly testable signing-sufficient capability with an appropriately bounded false-positive candidate-authorization probability. The required goal is QPT key **unrecoverability** and unauthorized-native-signing prevention, including full public checking-key correlations, not this impossible full-key-IND hybrid. Run 447's conditional iO-to-forgery theorem need not use this hybrid.

## Classical-only minimality consequence

Let a generic-NP scheme have classical PPT Build(x)->(Y_x,K_x) with `Y_x=(capsule,vk,all public aux)`, full-source-witness correctness `Decap(Y_x,w)=K_x` for **every** valid ORIGINAL w, and classical PPT *target-key one-wayness* given Y_x for false x. Write the serializable common K_x as n bits. Publish `(Y_x,r,b XOR <r,K_x>_2)` with uniform n-bit r. A witness decapsulates K_x and decrypts. For false x, any re-runnable classical PPT distinguisher of the mask from uniform yields a predictor of `<r,K_x>` from `(Y_x,r)`; classical Goldreich-Levin list decoding with fixed Y_x and repeated chosen-r queries recovers K_x with nonnegligible probability, contradicting target-key one-wayness. This is classical *bit witness encryption* under the exact fixed/adaptive statement and joint-aux-input one-way game stated, not a new primitive. Therefore general-NP classical common-capability release is not automatically substantially weaker than WE merely because one requests one-way hiding rather than full-key IND.

**QPT limitation:** arbitrary quantum advice, potentially correlated quantum auxiliaries and single-copy advice are NOT covered by this classical list-decoding argument. No QPT WE reduction is claimed. The signing-key distinguisher itself is classical PPT and hence also an arbitrary-QPT attack on the **invalid IND game**. None of this constructs protected local mixing, false-instance QPT unrecoverability, or accepted-native-signature -> ORIGINAL witness extraction.

## Executed checker and scope

The committed standard-library Node checker deterministically constructs 12 Ed25519 keypairs, tests 12 matching-credential authentications, 132 independent-key cross-checks, 12 context substitutions, and two-valid-witness/same-capability syntactic fixtures. Exact output: **312 assertions**, 12 real accepts, 0 independent accepts, 0 wrong-context accepts, two byte-identical executions. Ed25519 is NON-PQ and these finite diagnostics are not a cryptographic security proof or a GL implementation.

Attack taxonomy: (8) native public checking key decisive; (5) public candidate signing/verification; (6) honest setup suffices; (7) exact branch/UTXO context makes the test specific; (4) multiple capsules demand joint one-wayness but cannot rescue independent-key IND; (9) no coherent quantum step needed. (1) seams, (2) gauge, (3) fingerprints not tested. No CCMR/RIO/CLZ break alleged.

Run 259 remains strictly `accepted COMPLETE residual representation -> ORIGINAL witness` (statistical global folding or conditional QPT-SIS), with exact blob `c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2`; this run does not produce an accepted representation from an arbitrary native signature. Mandatory unproved obligations: actual local mixing, all-witness correctness under malicious N-of-N setup/erasure, full-public false-instance QPT key hiding, unauthorized true-instance recovery or native forgery -> ORIGINAL witness/independent QPT break, arbitrary aux/multi-capsule composition, practical 128-bit resources, and conditional undeployed P2MR/native-SLH endpoint. No on-chain NP or BitVM computation proposed.

Sources: Goldreich-Levin STOC 1989 https://doi.org/10.1145/73007.73010 (classical theorem; no fresh full quantum proof audit); FIPS 205 https://csrc.nist.gov/pubs/fips/205/final (native signature specification, not Bitcoin activation); CCMR https://eprint.iacr.org/2024/006 (architectural background). The full extended derivation is local-only. **No complete practical PQ WKEM.**
