# Run 496 — a correct setup ZK proof does not imply true-instance ORIGINAL extraction

**Scope:** Live draft `syscoin/PVUGC#1`, starting head `ffd22e0e1d6ca3aa0da649783764c1f0c5f6a8df`. Bounded mathematical negative control, NOT a WKEM, a PQ security proof, or an attack on a correctly source-gated release primitive.

## Accepted repair and minimal architecture

A pre-funding, publicly verified **quantum-sound / QPT-zero-knowledge setup proof** may certify that the exact approved Build program generated the intended native verification key, ciphertext, claim/UTXO/branch/window context and all preauthorized graph edges. One honest N-of-N participant may refuse its setup signature until this certificate and required data verify. Later watchers can verify the same proof offline. This is useful and is NOT ruled out by Run 495.

Witness privacy is optional: the watcher may supply the ORIGINAL witness `w` in plaintext to a local public source computation. No fresh witness encryption or watcher-chosen encryption coins are needed. That eliminates the *specific* exceptional-coin attack of Run 495 from the later-input interface. A public check of `R(x,w)` is not itself cryptographic key-release enforcement: a malicious signer need not run the honest caller's check. FHE public evaluation cannot by itself decrypt a protected signing secret.

## Conditional true-instance counterexample

Assume an efficiently evaluable **QPT one-way permutation** `f:{0,1}^n -> {0,1}^n`. This is solely a hypothesis for a game-separation proof, NOT a claimed LWE construction. Define
`R((b,y,context),(z,t)) = [b=1 AND f(z)=y AND t in {0,1}^2]`.

Every `b=1` statement is true and has four different ORIGINAL witnesses, whereas every `b=0` statement is false. On random `y=f(z*)`, producing any ORIGINAL witness remains QPT-hard by the stipulated permutation hardness.

Let honest classical setup generate a native `(sk,vk)` whose signing key is QPT-hard to recover from `vk` (e.g. under applicable QPT EUF-CMA). Define a deliberately insecure but fully specified APPROVED Build:

* publish `vk,x` and a source-independent correct-setup proof;
* for `b=0`, omit the signing key entirely;
* for `b=1`, put `sk` directly in a public release field.

A perfect zero-knowledge proof of faithful execution of this approved Build can verify, since the setup outputs really are generated that way. For all four valid witnesses, the honest public opener first checks `R` and then returns the same `sk`, so all-witness SAME-key correctness holds. For every false `b=0` statement, the public output contains only `vk` and a simulatable proof; under native QPT key-recovery hardness and proof QPT-ZK, **false-instance signing-key nonrecovery** holds. (This is NOT full witness-encryption IND or pseudorandomness conditioned on the public checking key.)

Yet on every true `b=1` statement an attacker reads `sk` from the public capsule and signs immediately without `z` or `t`. If a straight-line / output-only black-box extractor recovered `z` from this attacker plus public setup, with only efficiently simulatable auxiliary inputs, it would invert random `f(z*)`: the reduction creates the independent native signing key, public package, and signature without knowing `z*`, then outputs the extractor's `z`. This contradicts the assumed QPT one-wayness. No quantum rewinding or QROM programming is needed. Arbitrarily correlated unsimulatable advice carrying `z*` is not covered by this reduction.

**Conclusion:** fully valid approved setup + all-witness correctness + false-instance key *nonrecovery* do not logically imply unauthorized true-instance early signing -> ORIGINAL witness. This is an intentionally insecure example that a diligent protocol designer should reject. It does NOT refute an actual secure protected mixer, nor does it claim full false-instance IND security. Its purpose is to prevent mistakenly attributing a release-security theorem to a setup-validity ZK proof.

## Precisely surviving technical requirement

Bind the source relation and approved package at setup, then prove **separately** that the actual publicly exposed release object cannot yield the native credential on arbitrary QPT attacks except via an accepted COMPLETE source representation or an independently stated QPT break. Public `Verify(w)` before honest signing alone is insufficient. Run 259, exact blob `c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2`, only proves accepted COMPLETE representation -> ORIGINAL witness or specified SIS break under its residual and extractor conditions, not native signature -> that representation.

Attack-taxonomy scope: (1) precheck-vs-key exposure seam, (5) adaptive public package inspection, (6) honest proof of faithfully generated **but unsafe** compiler, (7) fresh signatures defeat replay-only protection, (8) public checking key confirms the attack. Multiple independent capsules each fail; no need for (2) gauge or (3) fingerprints. (9) conditional QPT one-wayness is used for the extraction nonimplication; no separate coherent attack is claimed.

## Reproduction and handoff

The exact executed `run496_compact_check.js` enumerates a bijective finite mapping and source statements with four valid witness variants, checks compliant package generation and same-key returns, and demonstrates public early key exposure for true statements. The extended independent local Python diagnostic uses 4,096-element Feistel toy mapping and real **classical** Ed25519 signatures with 5,927 assertions. Neither the toy permutation nor Ed25519 is quantum secure. No real ZK, FHE or release obfuscator was implemented. No new full-paper literature proof audit was made.

**Next:** retain the setup-ZK wrapper and public plaintext ORIGINAL witness computation. Specify and attack a *minimal non-bypassable protected key-release gate*, including chosen inputs, native checking-key correlations, malicious setup, related statements, coherent public evaluation and arbitrary-QPT signature-only extraction. The baseline N-of-N honest-erasure ceremony remains separate from the stronger optional keyless-builder game. The practical WKEM stopping condition is NOT met; production and Bitcoin logic remain unchanged.
