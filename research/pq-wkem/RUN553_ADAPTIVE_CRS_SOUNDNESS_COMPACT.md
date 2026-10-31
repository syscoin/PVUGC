# Run 553 — per-fixed-statement statistical soundness does not survive adaptive claim selection

Starting verified draft PR head: `7869c277685d50438830322abf83ecfe23871b56` (branch `research/pq-wkem-validation-20260918`). The ordinary PR comment count is 265; latest ID `6067040320`. Read exact Run 551 note at the branch, unpublished Run 552 note at unreferenced commit `74ef7bb655e18824926bbb6002d89f1de18aebe2` (NOT on the PR branch), live Run 259 source-binding note, and the CLZ applicability note. This new checkpoint is deliberately narrower than a complete WKEM.

## Counterexample (no computational assumption)

Let `R0(z,w)` be any NP relation. Set `R((b,z),w)=[b=0 AND R0(z,w)]`, so every `x=(1,z)` is an ORIGINAL-false statement. Honest classical-PPT setup publishes uniform `sigma in {0,1}^n`. The public verifier is

`V_sigma((b,z),pi) = R((b,z),pi) OR [b=1 AND z=sigma AND pi=0^n]`.

Completeness for original valid witnesses is immediate. This is a purposefully flawed proof verifier used to test the *selective* quantifier; it is NOT a proof system asserted to have adaptive statistical soundness.

**Theorem 1 (fixed false x before sigma):** For each fixed false statement x independently selected before the uniform CRS, even an unbounded prover that sees sigma before choosing pi succeeds with probability <= `2^-n`. For a false x with b=0, acceptance is impossible. For fixed x=(1,z), some accepting pi exists iff sigma=z, occurring with probability exactly `2^-n`.

**Theorem 2 (false x chosen after sigma):** Given the public sigma, a classical PPT adversary sets `x_sigma=(1,sigma)`, `pi=0^n`; x_sigma has NO ORIGINAL witness but V accepts with probability **1**. In fact
`Pr_sigma[exists false x,pi:V_sigma(x,pi)=1]=1`. The union bound over the `2^n` false strings is tight: `2^n * 2^-n=1`.

For q distinct precommitted false statements and one uniform shared CRS, the probability of some acceptance is exactly `q/2^n` (q<=2^n); if the adversary chooses each false statement after reading sigma, one is enough. The difference is *quantifier order*, not a novel hash/period/gauge construction.

## Consequence at the minimal release frontier

A hypothetical proof-compressed public release `F_(sigma,x)(K,pi)=K if V_sigma(x,pi) else bottom` therefore gives K on an ORIGINAL-false chosen x_sigma. This is a plaintext/functionality-level attack, independent of how one might attempt to protect the program. It is **not** an attack on an actual correctly adaptively sound SNARG or FE system.

The precise potential repairs are (a) an adaptive statistical/global soundness theorem covering false x chosen after all relevant public parameters (and their auxiliary correlations), or (b) independently sampled unbiased CRS **after the entire x is irreversibly bound**, a per-fixed-x statistical guarantee, and a rigorous bad-setup accounting. Neither constructs secure local mixing. A maliciously selected sigma can break selective soundness even for previously fixed x. Honest N-of-N setup coin generation, abort handling and multiple capsules remain separate, unproved requirements.

For a release functionality that checks a small proof instead of the ORIGINAL relation, Run 259 cannot extract an ORIGINAL witness from this public false proof: it extracts only from a **complete accepted source representation** satisfying its residual-map hypotheses. A signature or an accepted short proof alone is outside that theorem. Run 552's general-NP two-input FE interface is already at least witness-encryption-strength, independently of this quantifier fix.

## QPT, attack surface, and limits

Honest algorithms are classical PPT; the attacker is classical PPT and thus a valid arbitrary-QPT attacker even with quantum advice or coherent public evaluation. No QROM, rewinding or oracle programming is used. Attack categories: (1) acceptance seam; (4) shared/multiple claims; (5) adaptive chosen statement; (6) public CRS/malicious seed selection; (7) branch and UTXO binding order; (8) public checking key cannot repair false source admission. Gauge/fingerprint and distinct coherent-only quantum attacks are not implicated. No positive QPT security or 128-bit resource estimate is inferred from the tests.

## Exact checker and handoff

The committed `run553_adaptive_crs_compact_check.js` was executed in V8 using its exact source before this write. `run553_adaptive_crs_compact_validation.json` is its unmodified deterministic output. The local independent Python enumerator also ran with **44,749** assertions, repeated byte-for-byte, over n=1..7; this is not claimed as a committed checker. Both are semantic tests, not cryptographic validation.

**Handoff:** do not replace a computationally sound proof with per-fixed-x statistical soundness and silently allow x to depend on its CRS. Exact next obligation is a provably adaptive source-authenticating proof frontier under the full view, followed by an independently justified QPT-secure release mechanism (not WE/iO/FE renamed). All-original-witness same-capability correctness for an actual compiler, arbitrary-QPT false-instance recovery resistance, native-forgery-to-ORIGINAL extraction or standard break, malicious setup/erasure, multi-capsule security, practical parameters, and the conditional Bitcoin PQ graph remain UNPROVED. No completion; PR stays draft/unmerged.
