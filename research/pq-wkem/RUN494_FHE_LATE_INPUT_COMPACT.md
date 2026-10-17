# Run 494 — Public FHE admits late witnesses; bit-only release is forgeable

Live connected PVUGC PR #1 starting SHA 87ad2011f64f9e957c3b78d3de634b49b0f80f1b; draft/open branch research/pq-wkem-validation-20260918, 2026-10-13 (Vancouver). This is a bounded local-release research checkpoint, not a completed WKEM.

## Constructive partial result, with strict boundary

Fix the ORIGINAL polynomial-time relation R(x,w), claim/UTXO/branch/window-bound x, native secret K_x and verification key vk_x, and a conventional public-key leveled FHE system (pk,sk,evk). Honest classical setup can publish c_K=Enc_pk(K_x) with pk, evk and vk_x; it may know K_x under the existing honest-erasure N-of-N baseline. A watcher discovering a NEW w after setup can publicly encrypt it to c_w and evaluate F_x(k,w)=(R(x,w),R(x,w)*k). Correct FHE decryption of the result equals (1,K_x) for EVERY valid ORIGINAL w, and (0,0) for invalid w. Ciphertexts and intermediate states may differ across valid witnesses; only the semantic capability agrees. This is ordinary public FHE functionality, not witness encryption, and it gives the watcher NO decryption key. General FHE's public late-input ability does not follow from the more restricted fixed-unary homomorphism advertised in Canetti-Luo-Zhang.

## Exact negative lemma: acceptance-bit override

Suppose an ideal protected public Release oracle simply decrypts ANY supplied FHE ciphertext and outputs its payload if its decrypted acceptance bit is 1; it does not authenticate the ciphertext's source computation or lineage. The unrestricted public FHE evaluator permits the simple unary circuit Force(k)=(1,k). Anyone constructs c_force=Eval_evk(Force,c_K). FHE correctness gives Dec_sk(c_force)=(1,K_x), so Release(c_force)=K_x. This works even when R(x,w)=0 for EVERY w. It is a classical PPT, one-public-Eval attack and therefore also a QPT attack. An ideal secret-hiding Release oracle cannot stop it; an actual public program hiding sk is an ADDITIONAL unsolved problem. Native vk_x checks a fresh unauthorized branch signature; context-binding only rejects replay to different claims.

Scope: this falsifies unrestricted-FHE plus a bit-only conditional decryption frontier. A release interface restricted to source-certified evaluation ciphertexts is outside the lemma. Likewise the result does NOT attack CLZ's controlled fixed-unary g, actual local reversible-circuit obfuscation, FHE IND-CPA or a native signature scheme.

## Precise surviving obligation

The smallest plausible frontier must authenticate a COMPLETE context-bound source evaluation lineage, possibly with a succinct source-knowledge certificate, before a secret-bearing decryptor releases K_x. Run 259 gives accepted COMPLETE representation -> ORIGINAL witness or its specified SIS break, but does not force arbitrary native authorization to yield that representation. Merely assuming a public conditional decryptor secure against arbitrary QPT attacks restates the missing WE-like object. Full-public false-instance QPT hiding, unauthorized true-instance extraction/forgery-to-source, malicious setup/abort/erasure, related capsules, and practical 128-bit size/cost remain UNPROVED. No new hardness assumption is asserted.

Attack taxonomy: (1) acceptance-bit/lineage seam decisive; (5) chosen public Eval decisive; (4) independent capsules each fail; (6) honest setup suffices; (7) new signing defeats replay isolation; (8) public checking key validates attack; (9) a classical attack lies inside arbitrary QPT. No separate (2) gauge, (3) fingerprint or quantum-coherent result is claimed. Full auxiliary public outputs, native keys, other capsules and quantum-capable adversaries remain in the stated game; no QROM programming or rewinding occurs.

## Checks and literature

Exact executed compact checker: node run494_compact_frontier_check.js -> 643 assertions over 64 contexts (32 false ORIGINAL), 64 valid-witness SAME-key semantic releases, and 64 forced-acceptance releases; two byte-identical runs. Independent extended Python checker: 963 assertions, 64 contexts, 64 valid releases and 64 fresh Ed25519 signatures using forced key recovery, with 64 cross-context signature rejections. Those are symbolic ciphertext semantics, not actual FHE, QPT security, PQ signatures or an on-chain implementation.

Brakerski-Vaikuntanathan, Efficient Fully Homomorphic Encryption from (Standard) LWE, SIAM J. Computing 2014, DOI 10.1137/120868669, establishes standard public evaluated computation as the relevant FHE abstraction. Canetti-Luo-Zhang, How to Encrypt with Random Reversible Circuits (CRYPTO 2026), separately advertises controlled fixed-unary homomorphisms under stronger assumptions; the exact proof/assumption applicability is not established here. Neither paper is refuted by this lemma.

Handoff: public *late-input computation* is achievable, but a *public source-certified secret release* remains missing. The challenge is NOT finding a common witness preimage or forcing identical intermediate state. The required off-chain outcome is still every valid ORIGINAL witness -> SAME native key -> simple intended Bitcoin path signature, plus arbitrary-QPT hiding/extraction and the unchanged conditional P2MR/SLH endpoint. Production unchanged; PR draft/unmerged; stopping condition unmet.
