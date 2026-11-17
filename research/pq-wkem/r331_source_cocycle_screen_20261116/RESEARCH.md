# R331 — source-history cycle-coboundary release screen (NONQUALIFYING)

## Provenance and distinction from past failures

Opened from syscoin/PVUGC#1 draft research/pq-wkem-validation-20260918 at actual head `d41f2178d312bc5c212d885938664507b239d2c4` (R330 note blob `17e8378dcf7de5ebefb1861b2641496c99a92ee1`). Issue comments after 2026-11-14: zero returned. No Core tests or network authentication were run. The source model preserves strict modern contextual AuxPoW chain ID, canonical exact parent SYS tag, actual ancestor at h_rel (not merely lagging h_ref), correctly qualified LC depth, anchor, windows, and complete claim/native binding; R316 is NOT a claimed strict-LC failure. The candidate changes the algebra, not the hash function or the size of a known-failing mask. Prior R289 label splice, R327 low-degree public evaluator recovery, R329 prefix labels and R330 static garbling remain regression exclusions.

**Hypothesis:** Rather than pick a new hash-derived key for every future witness, encode the one fixed safe cancellation secret in the *cycle space* of an authenticated source-history graph, so each relevant fork exposes the same secret. Construct release and public simulation jointly, and explicitly test whether future edge labels can actually be supplied offline.

## Exact finite-graph construction (ideal edge issuance, NOT a Build/Open)

Work over `F=(GF(2))^lambda`. Each vertex identifies a semantic authenticated child-state prefix, not a parent wrapper. Let `r` be the fixed anchored prefix and `T` a claim-scoped terminal, attached only after complete LC-depth source qualification. Let the baseline path `P0:r -> T` cross the claim-relevant baseline edge `e*=(b[h_rel-1],b[h_rel])`. The authorized competing path `P:r -> T` is a *separately authenticated*, relevant child history. Parent-certificate substitutions for the same child do not create forks. A fork strictly after h_rel cannot veto a claim-prefix assertion.

Sample independent vertex potentials `phi(v) <- F` and freeze `S`, either the exact safe native cancellation signature of matching length or a fixed secret key protecting it. For each issued directed authenticated edge `e=(u,v)` define

`d(e)=1 if e=e* else 0;`
`l(e)=phi(u) XOR phi(v) XOR d(e)*S.`

For a path P, telescoping gives `L(P)=XOR_{e in P} l(e)=phi(r) XOR phi(T) XOR (sum_{e in P}d(e) mod 2)*S`.
Thus `L(P0) XOR L(P)= S` exactly whenever P omits the marked baseline edge, and zero if P includes it. Correctly qualified prefix forks diverging at/before h_rel omit it (assuming collision-resistant, non-reconverging hash ancestry); postclaim forks share it and do not release S. Different qualifying future paths can have completely different bytes and still return the SAME frozen S.

This is ONLY branch-3 claim-prefix inconsistency geometry. Original greater-BTC-work, specific burn-fault, and exact claimed-wrapper tag-fault grounds remain independent OR branches and are not handled by this construction.

## Exact restricted joint-public FALSE simulator

For the *classical list* of edge labels on any observed finite graph, put `Y = B phi XOR d S`, where B is its edge-vertex incidence matrix over GF(2) and d is the edge indicator of e*. If every observed cycle has even d parity, then d is in the image of B: choose g with Bg=d. For any alternative S', set `phi' = phi XOR g*(S XOR S')`. Then `B phi' XOR d S' = Y` for the ENTIRE observed public vector. On a baseline-only forest, B has full row rank, so Y is exactly uniform and independent of S even conditional on external VK/context data when phi is independent. Conversely any authenticated observed cycle with odd d parity gives `XOR_{e in cycle}l(e)=S`.

This is a finite, static, classical ideal-label argument. It is NOT a QPT theorem for a serialized public capsule or a complete public native-signature simulator: there is no concrete label issuer, no coherent quantum query interface, no adaptive/malicious source game, and no multi-capsule security argument. Public native VK may constrain S independently; the lemma says only that these ideal edge labels leak nothing extra before a cut-crossing cycle.

## Why the public offline source operation remains UNCONSTRUCTED

Honest Build can publish labels for the already-known baseline edges. The missing function is a classical-PPT *serialized, public and offline* `Label(C,e,authenticated_context)` that generates compatible labels for arbitrary unknown FUTURE source-history vertices and releases none for forged, incomplete, irrelevant or context-spliced paths, without an online trusted key issuer or hidden evaluated program. Simply labeling individually plausible AuxPoW headers is not enough: cross-history splices must not form a fake cycle.

- With globally PUBLIC `phi(v)=SHA256(v)`, the published marked baseline label immediately gives `S=l(e*) XOR phi(u) XOR phi(v)`. No witness.
- With SECRET `phi(v)=SHA256(kappa||v)`, the baseline is hidden, but no public source algorithm can compute labels at future vertices. Publishing kappa recreates the previous leak.
- With an arbitrary-input label function even a fake, unauthenticated bypass of e* yields S. A capsule/Merkle root authenticates some bytes but does not supply the necessary secret potentials for new authenticated history.
- A proposed public evaluator that produces `Q(P)=phi(r) XOR phi(T)` only for genuine alternate histories while keeping the corresponding baseline value offset by S is already the unresolved common-value source-gated WE interface, not an independently instantiated ingredient. Do not rename it a source oracle, obfuscator or a PRF and count it as progress.

This distinguishes the *algebraic same-key topology* from its indispensable absent implementation and security.

## Actually executed local countercheck and provenance

A Python3 standard-library deterministic checker constructed a synthetic baseline 100..108, claim cut at 102->103, early fork at 102, late fork at 106, a common synthetic terminal, and an unauthenticated fake bypass. It verified `L(P0) XOR L(early)=S`, `L(P0) XOR L(late)=0`, and the unauthorized fake bypass also returns S if arbitrary-edge labels are published. It explicitly reconstructed alternate vertex potentials for another S' giving byte-for-byte identical baseline public labels. Two runs were byte identical. **NOT** Bitcoin/Syscoin source validation, PQ native signature, QPT experiment or a functioning Build/Open.

Source checker SHA256: `44fea97d54149437a71911bf17d36cf376e6650cb96b76d2e556666ce49c9b8f`.
Both captured JSON output SHA256: `9193527eddb4667a89fae483ad763b37de8f521483f9ec17572a7f8c3974475a`.
Complete derivation, checker and both outputs saved LOCAL-only in `/mnt/data/R331_source_cocycle_screen_20261116.tar.gz`, archive SHA256 `a91b8d44541bb73f1c65506352dbd56f412fd737e323f79497350e541245b434`. No sandbox persistence across runs is assumed; checker and outputs are NOT claimed GitHub-published.

## Verdict and precise next equation

**NONQUALIFYING: no original-source foundation advance; no user progress comment.** The cycle-coboundary trick gives exact ideal all-fork common-secret algebra and an ideal forest simulator, but does not generate labels for future original certificates. Its missing source-conditioned label issuance is itself the release problem, with no instantiated QPT reduction. Reject public/secret vertex-hash variants without repeating synthetic loops. Next work must produce actual classical-PPT serialized source-controlled Build_inc/Open_inc under arbitrary future ORIGINAL certificates, with full-public FALSE and hard-TRUE QPT recovery/native-forgery -> actual ORIGINAL witness or independent hash/native break; preserve malformed-tag typing, all three OR grounds, malicious setup, sibling capsules and frozen cancellation-portability restrictions. No Core/production changes, deployment, automation disable or PR comment.
