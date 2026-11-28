# R318 — Two-graph AuxPoW certification and release dependency

**NONQUALIFYING source-admission component.** No ORIGINAL hash-only Build/Open construction, frozen native cancellation signature release, QPT security theorem, or deployment. This bounded offline pass carries forward R317's exact unfinished source-qualified common-key problem.

## Start and scope

Read open draft syscoin/PVUGC PR #1 at e940d5e3042ebd98cd69f8a7116a29e324e906b6 on research/pq-wkem-validation-20260918. The R317 note was read (blob ff26d166afbc3c52a1838c2ecfae966e7053fc03); R315's OTS source note (blob 385f653c0579dca00ba812b08558d78a9381d2cb), R314's source-surrogacy note (blob 0adde81241cdb9c300d2e1936e97a037cc8fff5c), and R316's archived executable checker (SHA256 921ea00fbd951c0385f60e3660b9622b1e0152b2de567b8dc6769f2f8d8c31ab) were inspected. Separately, R225 ordinary comment 6796383617 remains the native-activation scope issue. Read-only Core PR #609 metadata remained c91539de3c34937e57d7f5fda47c7b0502ff33f6, draft and release-disabled; no Core source or C++ test rerun in R318.

The ORIGINAL challenge remains R_BTC_greater OR R_burn_fault OR R_SYS_inconsistency/tag_fault, with one notary initiating and any qualified observer challenging. The independently usable branch 3 requires no greater Syscoin work and no fork-winner selection. Bind x_W to exact claim/UTXO, amount/recipient/burn, applicable modern contextual chain ID, exact canonical 41-byte parent SYS tag and separate child AuxPoW Merkle commitment, all source ancestor paths, h_rel, source anchors/windows, required LC depth, deadlines/resets and the exact native cancellation message/VK and capsule. A defective asserted wrapper has an independently authenticated outer Bitcoin carrier and separate maturity rule; it is not itself an admitted Syscoin history. Distinct Bitcoin parent certificates for one child are not two Syscoin forks.

## Constructive verifier invariant: two graphs, not one certificate multiset

With authenticated fixed BTC and child anchors A_B,A_S, a source witness induces two graphs:

BTC graph: parent-header edges Prev(B_i)=SHA256d(B_{i-1}), and parent-chain work W(B_1,...,B_n)=sum_i GetBlockProof(B_i) over a *contiguous distinct linked path*, with actual contextual targets and relevant source anchors/windows. An unordered set of independently valid parent headers is not a history. A branch-1 alternative must actually diverge from the bound baseline (not merely extend it), be source-relevant, and have strictly greater exact cumulative work.

SYS graph: child-header edges Prev(S_j)=SHA256d(S_{j-1}), with unique child identities/heights and contextual AuxPoW/tag/interval validation. LC maturity counts actual linked child blocks (n_tip-h+1 when counting the challenged block as depth one, or n_tip-h for post-block confirmation convention). Source policy must fix this convention. Compare actual authenticated ancestor hashes at h_rel, not simply rounded SYS tag heights. Do not infer post-claim conflicts under a claim-prefix policy.

The AuxPoW relation phi(parent certificate)=child is a *partial function*, not an injection: the activated one-child-per-authenticated-parent rule does not prohibit multiple distinct parents for exactly the same child. Therefore count unique **child links** for Syscoin LC maturity and unique **linked parent headers** along one BTC chain for exact parent work. Never count presented AuxPoW wrappers as either quantity.

Under collision resistance and properly authenticated contextual anchors and paths, an arbitrary number of additional valid parent wrappers for one child cannot deepen Syscoin child history, and an unordered sibling bag cannot accumulate work as one Bitcoin branch. This finite-certificate lemma does not establish best-chain/network membership, bridge liveness, censorship resistance or security of a secret-release compiler.

## Executed bounded checks

A standalone Python3 checker imports exactly the archived R316 SHA256d, coinbase, canonical SYS tag and depth-five Merkle/AuxPoW subchecks. Synthetic constant target 0x207fffff; all generated parents satisfy the modeled byte-level checks, NOT full Bitcoin or Core consensus.

- Baseline: 4 linked parent headers, exact modeled work 8. Divergent alternate: 6 linked parent headers, work 12. Each certifies one identical Syscoin child, so the modeled BTC work comparison succeeds while Syscoin child-fork evidence remains FALSE.
- Extension: baseline followed by 3 more parent headers, work 14. It has greater work but is *not a competing history* relative to the baseline.
- Bag: 24 distinct individually mined parent siblings with exactly the same previous-parent hash and exactly the same Syscoin child/tag. Naively summing work reports 48 > 8, but no linked parent history exists.
- Every wrapper in all groups certifies a SINGLE unique child hash at height 111. An erroneous parent-occurrence maturity computation would report 23 descendant links for the sibling bag; the correctly counted distinct child descendant depth is zero.

The checker was independently invoked twice with byte-identical JSON: 128 assertions each. Checker SHA256 4eb9924dede91d8057b8d8f9ae91df9fd327e0da42276a99afb38ab33f6cf76c; each output SHA256 8a99e4865f0078020a5cab6f70ab8b9a5e182494fa6f5a5b26167b9af749c673. Full derivation, checker, R316 dependency and paired outputs remain in local archive R318_two_graph_qualification_20261116.tar.gz, SHA256 4c4249761f5617cc7af2330179a0b65fd5ee5acbdf83c3f9e12d4e9b263b0080. No real source membership, full targets/retarget, native PQ signatures, malformed burn, or QPT experiment was executed.

## Attempted common-key repair and failure

Let V(w)=(min(Work(BTCPath(w)),W_star),min(ChildDepth(SYSPath(w)),k_star)). One attempted pad is p(w)=SHA256("R318|work-depth"||x_W||V(w)), with C=sigma_cancel XOR p(w_0).

This requires Build to know some future witness w_0 and violates every-witness completeness when valid work levels, child depths or branch types change. If V is normalized to a publicly known constant so Build can encrypt without the future witness, everyone computes p and extracts the native authorization with no source evidence. Adding public VerifyOrig(w) *after* extracting the pad does not cryptographically protect the key. This is only a rejection of the specified scalar-summary pad; it is not a general source-specific WE impossibility.

The exact open equation is a classical-PPT Build_inc(x_W,sigma_cancel;rho)->C and public Open_inc(C,w)=sigma_cancel for EVERY qualifying ORIGINAL authenticated witness, including many-to-one parent wrappers and genuine relevant child forks. Authentication and two-graph consistency must be *inside the secret-release path*, not only a post-unmask validator. Independent full-public FALSE/hard-TRUE recovery or accepted native forgery must imply an ACTUAL qualifying ORIGINAL certificate or a post-quantum hash/native break, accounting for coherent QPT access, correlated VK/aux/siblings, malicious retained source coins, multi-capsule selective opening, malicious setup, useful completeness and honest erasure. No such proof, algorithm or source-dependent hidden preimage exists here.

The separate R225 activation-vs-slot native signature portability issue remains explicit: slot-global veto policy or genuinely activation-bound outpoint/message must be chosen. No repository production files, PR progress comment, deployment or automation disable. This is not a completion report.
