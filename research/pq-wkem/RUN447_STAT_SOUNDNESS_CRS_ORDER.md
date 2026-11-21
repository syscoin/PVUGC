# Run 447 — fixed-instance statistical soundness and adaptive CRS selection

Verified starting draft PR head: `3f006f610f69c1837df1bfd913c56e9f69d83483`, `research/pq-wkem-validation-20260918`. Latest ordinary substantive PR comment: `6067040320`. This is a NEW bounded theorem/checkpoint after Run 446, not a retry of denied artifacts.

## A conditional *false-instance-only* construction

Fix the *complete* ORIGINAL NP statement `x=(relation, claim/UTXO, branch, anchors/window, context)` **before** the independent classical-PPT proof setup samples public reference data `rho`. A deterministic public proof verifier is `V(rho,x,pi)`, with classical-PPT prover `P(x,w)` for valid ORIGINAL witnesses. A native signing keypair `(K,vk)` is generated separately, and secret-dependent release code is `G(rho,x,K)(pi) := K` when `V(rho,x,pi)=1` and `bottom` otherwise. Its obfuscation and `vk` are public. All valid ORIGINAL witnesses may make distinct proofs but receive the *same* K; Bitcoin only verifies an ordinary native branch signature (conditional P2MR/SLH endpoint, not implemented).

For a false ORIGINAL x define the **existential** bad-setup probability

`delta_x := Pr_rho[ exists any pi: V(rho,x,pi)=1 ]`.

This is **not** ordinary QPT computational soundness. Run 446's planted OWF-preimage proof yields computational soundness while `delta_x=1`.

**Conditional lemma:** Assume nonuniform **pointwise worst-case auxiliary-input QPT iO** for every pair of equal-size *extensionally equivalent* classical circuits, even with the public native `vk` correlated with the embedded secret; assume QPT native-signature unforgeability with the actual branch-message freshness game, and simulatable public auxiliary inputs without secret K. The signing key must not be exposed by an authorized *other* capsule. Then

`Pr[false-instance accepted fresh native signature] <= delta_x + eps_QPT_iO + eps_QPT_Sig`.

**Proof:** Outside the `delta_x` event, `G(rho,x,K)` is *identically* equal on every input to a same-size padded constant-bottom circuit `Z`. Pointwise worst-case QPT iO replaces `O(G)` with `O(Z)` in the correlated-public-key view. The bad event contributes at most `delta_x`. In the zero hybrid, a fresh signature under `vk` is a QPT native-signature forgery. All reductions are straight-line; no QROM rewinding/programming. The pointwise nonuniform premise is necessary to avoid silently conditioning the circuit-pair generator on an inefficiently testable good-CRS event. Arbitrary secret-correlated quantum advice containing K is not covered (nor can it be).

**Run 259 exact interface:** The live source-binding note Git blob `c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2` proves that for a fixed false ORIGINAL x, complete candidate representation z and global residual rho_x(z), random linear folding `S rho_x(z)=0` has
`delta_x <= |B_x| q^(-t)`, where `B_x` is the invalid COMPLETE-representation set. No zero-residual z can exist for a false ORIGINAL x. Thus **the statistical Run-259 route can supply this false-instance all-input equivalence premise on a good setup**. Its SIS-compressed route only rules out QPT finding a bad z, not mathematical existence, so cannot supply the iO-equivalence premise. The complete residual/source verification still has to be protected, and Run 259 does not prove `accepted native signature -> accepted z`.

## Exact adaptive-CRS counterexample

Add a designated ORIGINAL-false statement domain `x=(0,z)`, `z in {0,1}^lambda`, to any otherwise nontrivial NP language. Draw public `rho <- {0,1}^lambda`. Define `V(rho,(0,z),pi) = [z=rho and pi=0^lambda]`, with standard honest verification on the disjoint true domain.

For **each fixed false** `(0,z)` chosen before rho, `Pr_rho[exists pi V=1]=2^-lambda`. But after seeing rho, an adversary chooses the false claim `x=(0,rho)`, supplies `pi=0^lambda`, and obtains acceptance with **probability one**. Thus pointwise statistical soundness does not imply soundness for claims chosen *after* a shared public CRS. Fix and bind the entire relation/UTXO/branch statement before independently generated CRS, or prove adaptive existential statistical soundness for the actual setup distribution. Adversarial abort/seed grinding and malignant N-of-N setup remain unproved.

The exact finite checker independently exhausts lambda=1..10, and a separate Run-259-style model with invalid `rho(z)=(1,z)` over F_q for q=2,3,5 and t=1,2,3; it confirms full-space bad setup counts and the `|B|q^-t` union bound. Numerical checks are **not** cryptographic proof.

## Scope, QPT, and handoff

This conditionally restores a false-instance iO hybrid that Run 446 correctly rejected under only computational proof soundness. **It still uses full iO, not a weaker local mixer**; it does not construct a compact statistically all-input-sound proof gate or any practical 128-bit signing release. For true x the release circuit differs from Z on valid inputs, so the lemma provides **no** unauthorized-true-instance signature-to-ORIGINAL extractor. No malicious N-of-N ceremony, full quantum auxiliary-input simulation, multi-capsule same-key exposure protection, practical performance, or real Bitcoin endpoint follows.

Attack taxonomy: (4) reused CRS/multi-capsule, (5) chosen-input/adaptive claim, (6) seed/grinding/malicious setup, (7) branch/UTXO context replay, (8) correlated native vk. The counterexample is classical, hence also available to QPT. No seam, synchronization, fingerprint or quantum-only attack is asserted.

Research context: Canetti–Chamon–Mucciolo–Ruckenstein, ePrint 2024/006 (architectural only); Canetti–Luo–Zhang, CRYPTO 2026 DOI 10.1007/978-3-032-35367-2_18; neither supplies an independently justified practical QPT release primitive here. Distinguish **statistical soundness** from **statistical zero knowledge** (privacy). No complete paper proof audit claimed.

Stopping condition UNMET. Draft/unmerged; no production modifications.
