# R308 — Public hash frontier cannot issue ORIGINAL source-conditioned labels (NONQUALIFYING)

## Continuity / inspected source

One bounded offline continuation of R307's unfinished dynamic `Extend` equation. Starting PVUGC PR #1 head `b4f2237a7e4e9cebb5c8593812e7070a02ea56ca`, branch `research/pq-wkem-validation-20260918`, R307 note blob `82973b1a11326bd82e93b8ac2221a46338013f77`. Read R306 blob `fa93fa672652603a820c8bd10e7c2d5f0bca329a` and last ordinary PR comment R225 `6796383617`. Current Core #609 PR metadata head `c91539de3c34937e57d7f5fda47c7b0502ff33f6`; contextual rules carried forward from previously inspected R304, no new Core tests or deployment claim.

The ORIGINAL relation stays the three OR grounds: qualified strictly greater *same-anchor* BTC cumulative work; finite authenticated refutation of the particular withdrawal/burn assertion; or qualified actual Syscoin semantic ancestor inconsistency / independently authenticated asserted-wrapper tag fault. All claim/UTXO/burn/amount/recipient/baseline, BTC anchors and windows, actual ancestor at h_rel, contextual modern AuxPoW chain ID, exact canonical active tag, independent fault-carrier authentication, LC maturity, deadline/reset/capsule ID and frozen native message/VK remain binding. A malformed wrapper cannot borrow LC depth from another valid wrapper; two parent certificates for one child are not a Syscoin fork. R225 native activation portability requires a distinct explicit endpoint policy. One notary initiates; anyone with ORIGINAL evidence challenges; N-of-N is only preauthorization.

## Attempted Build / Open: implicit hash-prefix tree

To repair R307's public finite-graph BFS exposure, replace the graph with a succinct SHA256-derived binary prefix tree over the *complete encoded source witness*. For a fixed public instance x, set an acceptance predicate A_x(w). In the **toy** experiment only, A_toy(w) means an 80-byte synthetic SHA256d header is below a 5-zero-bit target, **not** an authenticated Bitcoin/Syscoin certificate.

Classical Build takes frozen signature surrogate S and samples z_empty uniformly in {0,1}^lambda. Define

    z_(p||b) = H("R308-node" || x || b || z_p).                    (1)

Let F(A_x) be the unique set of maximal accepted-prefix cylinders: for every prefix p in F, all strings extending p are accepted, and the disjoint cylinders cover all accepted full witnesses. Try to publish

    c_p = S XOR H("R308-pad" || x || z_p), p in F(A_x),            (2)
    C = (x, z_empty, { (p,c_p) : p in F(A_x) }, VK, context).

Proposed Open(x,w) verifies R(x,w), identifies p in F that prefixes w, computes z_p along p using (1), and returns the same frozen S using (2). This is an explicit classical opening formula for an *already enumerated* static acceptance set. It is NOT a polynomial builder for unknown future ORIGINAL source histories.

### Exact complete-public leakage

For ANY nonempty published F, a classical attacker simply selects any public (p,c_p), derives z_p from public z_empty, and obtains S = c_p XOR H(pad||z_p). Neither finding an ORIGINAL certificate nor satisfying A_x is needed. A later `Verify_R` check inside Open cannot revoke the already recoverable bytes. The attack runs with the native VK, arbitrary auxiliary material and sibling capsules present and is also a valid QPT attack.

Withhold z_empty and the future honest opener cannot compute z_p from source certificate bytes. Substitute independently sampled hidden vertex labels with publicly registered directed edge rows `P_(u,v)=z_v XOR H(edge||z_u)` from R307: a public start label traverses every registered path, including unqualified ones; omit future edges and every-witness opening fails. Replace z_empty by a public actual SHA midstate or parent digest: anyone computes it. Hashing source credentials or a capsule root authenticates input bytes but does not issue a hidden label. Thus none of these repairs instantiates an actual source-conditioned `Extend`.

## Random-function frontier lemma, restricted model

Under an independent ideal random target predicate on 2^n strings, with each full string accepted independently with probability p=2^-d, an accepted aligned prefix-cylinder of >=8 leaves contains an all-accepted aligned 8-leaf cylinder. There are exactly 2^(n-3) aligned 8-leaf cylinders, each accepted in full with probability p^8. Hence

    Pr[exists all-accepted prefix cylinder of >=8 leaves]
      <= 2^(n-3) * p^8 = 2^(n-3-8d).                              (3)

Outside that event each maximal accepted prefix covers at most 4 leaves and |F(A_x)| >= |A_x|/4. Combining with the separate usual concentration of |A_x| near 2^(n-d), this *specific static prefix registration* has exponential size when n-d grows linearly and n < 8d. This is NOT a lower bound on arbitrary hash-only WE, concrete SHA circuits, general obfuscation, real Bitcoin membership, or QPT extraction. For mathematical illustration only n=640,d=128 gives bound 2^-387, but actual real-world headers do not give 640 freely independent bits of source admission and d=128 is NOT a 128-bit post-quantum security claim.

If Build registers m specific accepted leaves instead, future independently uniform accepted leaf identity among N possibilities opens with probability m/N, not every-witness completeness; an adaptive miner/source producer is not covered by that probability. If row identifiers and z_empty are public, any registered row still releases S without authenticated source evidence. Authenticity in the checker is intentionally *not* modeled.

## Executed concrete SHA256d control

Python 3 stdlib `checker.py` ran twice on four synthetic 80-byte headers whose final 16-bit nonce varies. Accept iff SHA256d output has five leading zero bits. Per fixture, enumerate all 65,536 candidates, compute the unique maximal accepting-prefix antichain, register 32 accepted leaf rows using actual SHA256 tree labels, verify registered openings, recover S from public rows without any ORIGINAL certificate, and exhibit accepted unregistered leaves.

Both runs returned identical output, 262,556 assertions each. Per fixture: accepted 2029/2025/2054/2061; accepted prefix-frontier size 1997/1989/2014/2034. Largest accepted subtree in each fixture was 2 leaves. With only 32 registered rows the uniform accepted-leaf coverage was around 1.55–1.58%. These finite fixtures do NOT prove (3). SHA256 checker `6b9fbd7ae8559fddd4eba2677c3c5187f2351e89fafe5711ccb3dca81c9ac78b`; paired output SHA256 `de9bda921645db39b5c088922b85b06b501977299fc8765bdc041f736f131184`.

Full local derivation, checker, both captured JSON files and provenance are preserved in conversation artifact `R308_source_frontier_20261115.tar.gz`, SHA256 `b9b407e62be174cfff65516d29a093b99a028806a1647ef597f70f62a9b0e6de`. The local full derivation SHA256 is `fb815a9a93a88f16cdb97e500dc42caa42a7f29c139d23ddc20611077c03e4b4`. This GitHub note is a condensed account, NOT a claim that the checker/archive is committed. No Core/source consensus run, native SLH signature, quantum experiment, external literature or production change.

## Exact unfinished source-release equation

Construct an actual classical-PPT hidden source projection with a public noninteractive

    Extend(C, authenticated ORIGINAL transition, hidden_parent_label)
       -> hidden_child_label                                          (4)

for *every unknown future qualifying* source history, with no input path allowing public unqualified extraction, and no issuer holding private labels online. The labels and final capability must depend cryptographically on **whole source authenticity and relevance**, not a Boolean after-check. Prove full-public FALSE security and unauthorized hard-TRUE QPT recovery/native forgery -> ACTUAL qualifying ORIGINAL certificate or independent PQ hash/native break, with malicious setup, native VK, auxiliary information and sibling capsules. (4) is NOT constructed or assumed secure here.

**NONQUALIFYING**: no ORIGINAL hash-only WE progress, working bridge or independent QPT theorem. Routine negative result; no PR progress comment, notification, production change or automation stop warranted.
