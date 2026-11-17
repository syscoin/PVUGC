# R341 — hash-only hidden source-tap capsule: serialized release, failed ORIGINAL coverage (NONQUALIFYING)

## Provenance and objective

Offline continuation of R340's missing issuerless \`Deliver_C(R)\`, from open draft syscoin/PVUGC PR #1 branch \`research/pq-wkem-validation-20260918\`, head \`fd9bb271ccdc2c4f88f19ab7434794822112cfba\`, R340 note blob \`7281ee8e92b1292bca2feb91ec80a4db2c392c56\`. Read-only Core #609 metadata last observed at \`c91539de3c34937e57d7f5fda47c7b0502ff33f6\`. Issue comments since 2026-11-16: none. No external literature/web, actual source admission, PQ signing, quantum testing or agents.

**Change from R340:** remove the unimplemented private affine evaluator by publishing an actual serialized hash-only capsule. Secret preselected SHA input addresses must later occur inside complete original source evidence. This avoids an arbitrary-public-\`t\` affine evaluator, but it fails every-witness ORIGINAL completeness. It is not an arbitrary-PoW puzzle substitute, a source credential, or a release breakthrough.

## Restricted Build / Open (complete algorithms, insufficient ORIGINAL relation)

Let x bind exact chain/protocol IDs, claim/UTXO, withdrawal/burn/amount/recipient, frozen source baseline and anchors, h_rel and LC depth, windows/deadline/reset, capsule ID and the safe native cancel message/VK. Fix a preauthorized native cancellation signature sigma. Model domain-separated \`H_id,H_pad,H_key\` by independent random oracles ONLY for the restricted ideal analysis; implementation could call SHAKE256, without claiming SHA inherits the QROM argument.

Builder samples independent \`K,A_1,...,A_m <- {0,1}^lambda\`, with m=poly(lambda) and distinct A_i, and publishes

    Y_i = H_id("R341" || x || i || A_i; lambda)
    Z_i = K XOR H_pad("R341" || x || i || A_i; lambda)
    D   = sigma XOR H_key("R341" || x || K; len(sigma))
    C   = (x, [(Y_i,Z_i)]_{i=1..m}, D)

with K and A_i protected/erased after valid setup. Let T(x,w) be a polynomial list of **actual typed 32-byte authenticated source fields**, e.g. Bitcoin or Syscoin block hashes in complete original evidence. These bytes are NOT newly invented secrets and the real PoW digest distribution is conditioned by targets; no uniform entropy is presumed. The public \`Open(C,w)\` first verifies the ORIGINAL certificate, enumerates t in T(x,w) and indices i, and for an exact \`H_id("R341"||x||i||t)=Y_i\` computes \`K'=Z_i XOR H_pad("R341"||x||i||t)\` and \`sigma'=D XOR H_key("R341"||x||K';len(sigma))\`. It accepts only a signature verifying for the frozen safe cancellation message. The public verifier is NOT cryptographic access control: someone learning t=A_i can compute K and sigma directly from C, ignoring VerifyOriginal.

For any valid original w whose T(x,w) contains an A_i, the same K and SAME frozen sigma are recovered independently of which i or which witness. But this covers only the subset of original w with that preselected collision, not EVERY ORIGINAL witness, and gives no release for independently sufficient greater-BTC-work or specific-burn-fault grounds. A signed-witness substitute, secret source coin or online notary is prohibited and was not added.

## Restricted joint-public simulator and its limits

In an ideal random-function transcript that excludes all queries to unknown A_i in the id/pad domains and K in the key domain, the H_pad(A_i) are independent uniform pads, making all Z_i jointly uniform conditioned on K; H_key(K) uniformly masks D even when the native sigma and public VK are correlated. The Y_i are independent random labels. A simulator preserving x/message/VK and sampling independent labels, Z_i and D therefore gives an exact *unqueried-point classical ideal transcript*. This does NOT constitute a full-public QPT simulator: coherent quantum queries can discover or correlate hidden points; no quantum hybrid, malicious auxiliary dependence, sibling selective opening, retained source coins or concrete SHAKE reduction is proved. Independent fresh K/A_i per capsule is required; public capsule validity under malicious N-of-N setup remains unproved.

## Exact coverage-versus-secrecy obligation (hash-tap-only, not a general WE no-go)

For each genuine qualifying ORIGINAL witness w define T(w) to be the secret-eligible source tap addresses its authenticated bytes actually contain. This specific construction requires

    for every qualifying w: {A_1,...,A_m} intersect T(w) != empty.

Thus m must be at least the hitting number of the set family {T(w)}. If L qualifying witnesses have pairwise-disjoint T(w), then m >= L. This is an unconditional combinatorial lemma for hash-tap capsules, not a statement that the actual Bitcoin/Syscoin source necessarily has an exponential disjoint family. If instead some address is common to every certificate and publicly known from the baseline, anyone evaluates its pad before any challenge. If the A_i are uniformly hidden and independently chosen before future miners produce source values with conditional min-entropy h, and each witness supplies q addresses with collision probability <=2^-h against each A_i, then for even one independent valid future witness

    Pr[covered] <= m*q*2^-h.

This is a failure of honest *completeness*, not a security proof. The bound does NOT hold without that independence assumption, e.g. if miners adapt their work to public C; such adaptation, if useful, would still need to yield EXACT admitted original certificates and cover every already-qualifying witness, not an extra invented hash puzzle. Distinct valid Bitcoin parent certificates of the same Syscoin child are not a fork; canonical activated tags/chain IDs and exact actual ancestor comparison remain required. R316's tag-reference delay is not a strict-LC failure.

Attempted repair: publish hash-only GGM/prefix-constrained seeds covering many unknown future source addresses. A publicly published subtree seed gives outsiders the pad on INVENTED addresses in that subtree, bypassing certificate validity. A private seed restores the missing publicly evaluable source-delivery interface. Changing salt, tree size, tap count or SHA output length does not repair this. Source ChainLock/signer-held label release would be a new online/retained secret trust assumption and is not the approved original PoW challenge.

## Bounded executed checker and provenance

Python 3 standard library locally checked seven disjoint source-address families of three addresses each (minimum hitting set 7) versus a public common address (cover 1, unauthorized pad availability), and the exact finite independent-hit probability at 8 bits, m=3, q=4. The independent probability was 0.046324976841, below union bound 0.046875. Checker SHA256 \`142e8db07d308025a1263932477398dbd099c434a8795fea253190faa753b8eb\`; captured JSON SHA256 \`2e2035a28aaeb6ed95b48ae1e4d0fb9ab4cd443bde3d4f55d74dbbf4f4917d7b\`. Executed bytes at local-only \`/mnt/data/pq_r341/check.py\` and \`result.json\`, not claimed to be GitHub-published or cross-run persistent. These are synthetic arithmetic regressions, not ORIGINAL evidence or QPT tests.

## Decision / handoff

**NONQUALIFYING.** There is now a fully specified *restricted* serialized hash-release syntax, but its hidden-address coverage cannot be guaranteed for arbitrary future qualified ORIGINAL source evidence and it is not a complete three-OR Build_inc/Open_inc or a complete independent QPT theorem. Neither source authentication as an honest if-check after raw pad recovery nor public target prefixes count as gating. The missing advance remains: derive a true source-dependent, issuerless public evaluator with global original-certificate consistency, not private-source generated labels or a verifier wrapped around independently recoverable pads; prove complete-public FALSE/hard-TRUE QPT recovery/native-forgery security and multi-capsule/malicious-setup composition. Do not spend subsequent runs increasing this candidate's tap count or synthetic fixture size. R225 native activation-portability remains an independent endpoint issue.

No PR comment, production/Core code edit, deployment, transfer, release, or automation modification in this research iteration.
