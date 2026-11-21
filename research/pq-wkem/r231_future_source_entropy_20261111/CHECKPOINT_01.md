# R231 — Future-source entropy versus frozen hash-only release

**Status:** intermediate hypothesis only; no instantiated key-release or security claim.

## Continuity
syscoin/PVUGC PR #1, open/draft/unmerged, branch research/pq-wkem-validation-20260918, initial head 69b059fed9488a1e55bccba79f185d95c94989f1. Exact relevant R230 research blob 0985353843e042e776f69e1ea22531408e9f5e19; read R229 source-finder research. No external web/literature, production edit, independent subagent, or QPT tool.

## Named attempt: future-source entropy versus frozen pad

Fix x = withdrawal claim, precise source window, authenticated baseline, source anchors, all 3 actual challenge predicates, and claim-scoped native cancellation authorization. N-of-N preauthorization samples secret K before the notary chooses or sources reveal a future authenticated witness W.

Investigate public C = K XOR Z and public Open(C,W) = C XOR SourcePad(W), where Build does not know future W. If W is independent of (C,K) conditional on public x, then **I(K;C,W | x) = I(K;C | x)**. This is purely an information-theoretic independence identity and is NOT an impossibility theorem for computational WE, where C can computationally encode a witness-dependent release relation.

Test four concrete candidate carriers:
1. **Future proof hash.** Z(W)=H("src",W); different qualifying W ordinarily yield different pads, and Build does not know future W.
2. **PoW target prefix.** Hash-work target may constrain digest bits, but a common fixed prefix is publicly known from the target and leaks the pad immediately. A random, privately mined parent satisfying an easy target is not qualified ORIGINAL evidence.
3. **Merkle-root normalization.** Every valid path normalizes to one fixed public root; using H(root) for the pad allows unqualified opening.
4. **Setup-keyed source hash.** H(s,W) with private s cannot be computed publicly from a future W. Publishing s (or a public constrained key that evaluates on arbitrary digest values) exposes raw opening before original source qualification. A commitment H(s) does not provide the missing PublicDerive.

The missing equation is an actual classical-PPT Build_hash(x,K) and public Open_hash(C,W) with the SAME frozen capability for every ORIGINAL valid witness, while arbitrary QPT unauthorized recovery/forgery yields an ORIGINAL certificate or a justified independent PQ hash/native break, accounting for full public metadata, related capsules, retained source secrets and malicious setup.

Planned bounded experiment: enumerate exact finite independent-distribution cases, implement SHA256-domain-separated candidate pads and counterfeit digest checks, diagnose and attempt repair. The record is a checkpoint, not proof or progress notification.