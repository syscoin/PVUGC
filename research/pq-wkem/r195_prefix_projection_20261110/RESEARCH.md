# R195: exact claim-prefix projection for authenticated AuxPoW inconsistency

**Research-only, not a key-release construction or a QPT security theorem.** This is a correction of the R194 source-atomic semantic normalization and a narrow proved reduction of the ORIGINAL claim-prefix fork predicate. No native PQ endpoint, Bitcoin/Syscoin source verifier, or public secret-to-source label gate is instantiated here.

## Provenance
Repository: syscoin/PVUGC draft PR #1, existing branch research/pq-wkem-validation-20260918. Initial observed head e16a499e1f11299ee2ba2a6770092b083827c1d8. Reviewed exact R194 CHECKPOINT_02 and R193 RESEARCH at that head. Ordinary PR comments since 2026-11-10T08:30Z: none. An intermediate hypothesis checkpoint was published and verified in branch commit 42cc55b39591e0161c82495991b06f5fb977dc94 (blob 9a79204b47b8e96a5b7b6bf38f5b395839023507) before local tests.

## A concrete mismatch in the rounded-tag identifier
Let h_rel be the last source height relevant to the withdrawal. Let r=10*ceil(h_rel/10). Pinned Core at syscoin/syscoin@1180dad2 checks the branch-local parent-coinbase tag against its ancestor at h_ref(n)=10*floor((n-6)/10). In children n=r+6,...,r+15 the expected ancestor is r, and the correct tag can repeat across different child heights.

If h_rel is not a multiple of 10, r>h_rel. Two qualified histories may be identical through h_rel but first diverge at d with h_rel<d<=r. Their tags at r differ even though **no claim-relevant prefix fork exists**. Counterexample: h_rel=101, r=110, d=105, tag-producing child n=116. Both histories have identical child hash at 101, but different correctly encoded tags of ancestor 110. Comparing the rounded reference alone would incorrectly cancel a withdrawal that only depends on history through 101. If the protocol *intentionally* cancels on later forks, it is a different challenge predicate.

## Constructive source-semantic repair
For every independently and fully qualified source observation P, compute

    U_claim(P) := PureChildHash(Ancestor(P,h_rel)).

Require actual authenticated anchors, pure-child links, exact heights, parent AuxPoW/coinbase/Merkle and tagged-ancestor checks, relevant interval tags, observation windows, proof of source relevance and k_LC descendant depth. Q_x(P) names that concrete yet unimplemented complete verifier, NOT an oracle or adversary-controlled Boolean. Different parent work certificates for one pure Syscoin child must produce the same U_claim.

Define the claim-prefix R3 witness relation:

    R3(x;P0,P1) := Q_x(P0) AND Q_x(P1)
                  AND U_claim(P0) != U_claim(P1).

If a qualified baseline P0 is authenticated and fixed in the withdrawal statement, a challenger need only produce qualified P1. This relation does NOT require deciding the winning Syscoin branch or greater Syscoin work.

**Lemma, precise scope:** For two valid hash-linked pure-child histories from the same authenticated starting anchor, of height >=h_rel, with collision-resistant child-header hashing, the following are equivalent except via a pure-child hash collision:
(a) U_claim(P0)!=U_claim(P1);
(b) their first divergent *pure child* is at height d<=h_rel.
Proof: if histories differ at h_rel, walking authenticated parent links to the common anchor yields a first differing height at or before h_rel. If they first differ at d<=h_rel but later regain equal pure-child identifiers, distinct pure headers or distinct parent commitments must collide. Mutable Bitcoin AuxPoW wrappers are excluded from the pure-child identity. Thus explicit disclosure/extraction of the *first divergence index* is unnecessary if BOTH U_claim memberships are already fully authenticated. The proof is classical and its quantum applicability is only via an independent QPT collision-resistance premise.

This reduces source-semantic comparison to *two qualified exact-height ancestor identities*. It does NOT reduce the entire source verifier to hash inequality. The parent tag tuple can be identical over consecutive child heights; it does not authenticate the child's actual n by itself.

## Executed bounded synthetic experiment
Offline local checker run twice with byte-identical output:
- checker SHA-256: 25eab3d2a527b7a3ddeb4ea5fffe106a032fa723a3fcc721760926512b1a0166;
- captured stdout SHA-256: 64abf4186c6742fb9098331293dfc6717ffe581f7075e1133281e61b6a3fdc95;
- 28,479 functional assertions on 2,907 synthetic chain pairs, with h_rel 21..43, LC depth 2,5,13, forks before/after claim; detected 342 false-positive rounded-reference comparisons.
- included h_rel=101,r=110,d=105,n=116; tested repeated tag tuples within one 10-child window; incorrect tag hash/height rejection and parent work-wrapper distinction.
The checker uses SHA256 over made-up child records. **No actual mining, full Bitcoin/Syscoin validation, native signature, secret opening, or quantum cryptanalysis was performed.** Complete full-size local checker and output are saved separately; a shorter independent reproduction may be published here if its exact bytes are verified.

## Remaining key-release gap
Even with canonical U_claim, fabricated 256-bit hash strings are easy. Public labels L_b=H(public_seed,h_rel,b) are freely computable and give a FALSE-instance shortcut; secret-seeded labels cannot be derived from unknown future evidence by a public Open without another real source-to-label mechanism. Checking Q_x(P) *in ordinary visible software* before returning a signature does not hide that signature from arbitrary attackers. This family-specific observation is not a theorem excluding nonblackbox SHA constructions.

The still-missing pair is Build_hash(R_original,x_W,sigma_cancel) -> public capsule C and PublicOpen_hash(C,w) -> SAME frozen native cancel capability for EVERY ORIGINAL valid fork/burn/work witness. Security is full-public arbitrary QPT recovery/accepted native forgery -> actual ORIGINAL qualifying certificate or independently justified PQ hash break, against malicious setup, source retention, auxiliary inputs, sibling capsules and coherent access. Neither R194 nor this result constructs that pair. Bitcoin must never run the original verifier; no online issuer or independent hash puzzle is substituted.

**Next actual experiment:** build a source-to-hidden-label gate for *fully qualified* U_claim(P) together with its joint public QPT simulator/extractor, or replace the label carrier entirely. Do not spend cycles merely compressing the prefix evidence.