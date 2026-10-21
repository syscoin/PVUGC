# Run 671: Correlated-tape public-cut theorem (research-only)

Starting live PR: syscoin/PVUGC#1, draft branch research/pq-wkem-validation-20260918 at e9fee613f7f3b9ea418b8d8a68e8ca8443d44d9e. Exact dependencies: Run 259 blob c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2; Run 593 blob 29b9168bfff6043810284cd1960400579f224e31. Not a WKEM construction or QPT hiding proof.

## Conditional theorem

Fix an honestly generated public package P and public native verification key pk for x=(relation, claim/UTXO, branch, anchors, window, context). Let a **publicly callable** classical release suffix receive c bits of cut state s and a rho-bit evaluator random tape r. The public prefix may use THE SAME tape and, on a valid ORIGINAL witness w, produce a state s_w(r). All incoming variable provenance and authentication wires MUST count toward c; setup secrets are not available to the adversary.

Define B(s,r)=1 iff the public suffix releases a credential accepted by the native checker for the intended branch. Define T_r={s_w(r):R(x,w)=1 and B(s_w(r),r)=1}, with duplicates removed, and mu=E_r |T_r|. Then the freely enumerable accepted set A={(s,r):B(s,r)=1} obeys

Pr_{s,r uniform}[B(s,r)=1] >= mu/2^c.

If one fixed valid witness succeeds on at least 1-eps fraction of uniformly sampled tapes, then mu>=1-eps. Consequently a classical public attacker finds an accepted credential in expected at most 2^c/mu tests; a QPT attacker uses a reversible implementation of the publicly available classical suffix and checker to obtain O(sqrt(2^c/mu)) coherent search queries. This is a conditional ATTACK UPPER BOUND, not a hardness proof. No remote coherent oracle, random oracle, rewinding, or honest quantum evaluator is required.

**Critical scope correction to Run 670:** when prefix and suffix share correlated tapes, one must count distinct valid states FOR EACH FIXED TAPE. The global union M_global of cut states reached at different tapes need not give M_global marked states for a single tape. Run 670's independent-suffix-coin theorem remains correct under its explicit stronger fixed-state correctness assumption.

Tight semantic example: rho=c, one valid witness, s_w(r)=r, B(s,r)=[s=r]. Then M_global=2^c but mu=1, so success probability is 2^-c rather than 1. This fixture is NOT cryptographically confidential; it checks the scope of the counting theorem. Any tape-dependent public reversible bijection pi_r of the cut state preserves every |T_r| and the corrected attack bound, though it may change M_global.

## Hard-true source-knowledge corollary

Let f be a QPT-secure one-way permutation, and R_f(y,w)=[f(w)=y] for y=f(w) sampled from random w. Setup is classical PPT and knows y but NOT its preimage. On a good setup, if the publicly callable complete internal separator has c=O(log n) bits and honest evaluation succeeds with high probability, an attacker samples a tape r and ENUMERATES all 2^c states. On the honest-good fraction of tapes some state necessarily passes native checking. This classical-PPT attack obtains a bearer credential without knowing w.

Therefore a universally applicable compiler with such an independently callable short cut cannot also satisfy the project's proposed *accepted credential -> ORIGINAL w or independently justified QPT break* guarantee under the corresponding QPT hardness assumptions. This hard-true knowledge barrier is distinct from false-instance hiding and does not require assuming NP != BPP.

## Limits

Run 259 only proves supplied complete accepted SOURCE z -> ORIGINAL w; a cut state and signing credential are not z. The result does not imply all-witness release security, false-instance QPT hiding, malicious/abort-secure N-of-N, multi-capsule soundness, or practical 128-bit security. Native P2MR/SLH signature endpoint remains conditional. No production change, no merge, no new WE-equivalent assumption.

Finite checker and full provenance are preserved locally; its 10,651 assertions over correlated tapes, tape-dependent reversible gauge maps, and classical Grover-amplitude simulation validate counting identities only. Literature: Canetti–Chamon–Mucciolo–Ruckenstein ePrint 2024/006 (the attempted full PDF returned 403); quantum local-mixing extension arXiv 2609.40289 relies on additional assumptions. No full literature proof audit or concrete PQ claim.
