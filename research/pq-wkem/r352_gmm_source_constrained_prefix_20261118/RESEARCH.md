# R352 — SHA-preimage constrained GGM frontier; source-release test (NONQUALIFYING)

## Exact starting point / change being screened

Started on open draft syscoin/PVUGC PR #1, branch `research/pq-wkem-validation-20260918`, head `18c6cec29fd37dd13265e2c7b2ff55da932dcf9d`. Read exact R351 note blob `48fc1a17abf0e6455434168aff4be521730a48ba` and R350 blob `bd1de20269249d79bb48481446b5932591fcdd2b`; recent top-level issue comments since 2026-11-16 returned no entries. No new claim about Core #609. This run screened a different proposed fix of R351's unbuilt implicit edge mechanism, *not* another low-degree / polynomial-mask variant: use a hash-only GGM constrained-key prefix cover of the accepted SHA-preimage language to supply local frontier secrets without enumerating all random-state graph edges. The test checks both the actual public release algorithm and its joint-public failure; neither proof of source validity nor a prefix target is treated as the release primitive by fiat.

## Concrete restricted candidate

For a fixed bounded n-bit trial domain D and a d-bit SHA256d proof-of-work target define `A={m in D : int(SHA256d(domain||m)) < 2^(256-d)}`. This is **only a toy hash-target language**; original bridge evidence additionally needs contextual modern child IDs, exact tags, authenticated BTC/Syscoin histories, relevance, anchors and LC depth.

Let a GGM tree seeded by uniform secret k assign a pseudorandom leaf key `L_k(m)` to every n-bit m. Hash-only GGM uses independent left/right domain-separated SHA-expansions of each parent node seed; a prefix secret allows derivation of every leaf beneath that prefix. A builder who can enumerate A constructs its maximal disjoint fully accepted prefix cover `P(A)`, publishes all `(prefix,seed_prefix)`, and for each `m in A` publishes the ciphertext row `D_m = S XOR H_out(x,m,L_k(m))` for one **frozen** S. Public Open takes m, checks it is in the listed prefix and possesses the row, derives `L_k(m)`, and returns `D_m XOR H_out(...)`. All accepted m yield exactly S. Neither the expansion SHA security nor the native signature properties are needed for the following failure.

This design is meaningfully different from R327's low-degree additive pads: it uses discrete GGM subtree-key delegation and arbitrary SHA preimage membership instead of a publicly evaluatable polynomial. It was screened at the *foundation* before any packaging optimization.

## Exact full-public adversary and failed repair

If A is nonempty, the published prefix keys and even one row `(m,D_m)` permit **immediate classical recovery** of S: pick the m named by the row, descend from its exposed prefix key, compute the pad and XOR. No source or Bitcoin-history certificate is required. For an ORIGINAL FALSE claim x_W, raw SHA-target inputs may exist despite no qualified anchor-relevant conflict, greater-BTC-work proof or finite burn fault. Therefore the public ORIGINAL-FALSE capsule leaks the exact native cancellation capability. Attaching `VerifyOriginal(x_W,m)` as an honest-code check **after** the computation is not a repair. Joint public simulation fails even classically, in the presence of public native VK and fixed message.

Repair A (keep prefix seeds secret) stops both the adversary and all genuine Open algorithms: a SHA hash preimage does not intrinsically reveal the independently sampled builder seed. Repair B (enumerate only ORIGINAL-valid and relevant source histories) requires Build to know every future certificate before it exists; an explicitly listed valid record itself gives the source witness and destroys hard-TRUE evidence search. It does not cover unknown future distinct witnesses in polynomial size. Repair C (publish only a hash commitment to each seed) leaves the same missing public inversion/conditional-delegation operation. Neither Merkle authentication nor an additional certificate check changes the secret-release algebra.

Thus this specific hash-only GGM constrained-prefix compiler is rejected *before* parameter optimization. The result does **not** rule out all compact implicit source graphs, non-prefix constrained functions, concrete SHA hardness or general WE. In particular, the random-oracle analysis below is a model-specific *representation cost* observation, not the primary security failure.

## Exact expected prefix-cover census (secondary build feasibility screen)

For a uniform random truth table on n-bit inputs with each input independently accepted with probability `p=2^(-d)`, a maximal prefix cover of A has count `N_cover = |A| - SUM_{k=1}^n N_full(k)`; `N_full(k)` is the number of aligned all-accepted subtrees of size `2^k`. This follows by starting with one leaf per accepted input and replacing both child covers by one parent key whenever an internal node is fully accepted. Consequently, EXACTLY in the independent random-function idealization,

`E N_cover = 2^n p - SUM_{k=1}^n 2^(n-k)*p^(2^k)`.

For small p, most accepted inputs are isolated, so exact GGM subtree delegation cannot describe their complete set with polynomially many prefixes when `2^n p` is exponential. This is not a lower bound on other representations or concrete SHA. More importantly, even a tiny cover has the unconditional early-release defect above.

The executed checker enumerated SHA256d on synthetic bounded inputs with n/d=12/3,14/4,16/4,16/6 and computed exact maximal full-prefix counts: (valid,keys) = (498,469), (980,949), (4183,4051), (1001,986). The 16/4 run had 131 all-valid two-leaf subtrees and one four-leaf subtree; hence 4183-132=4051. Two complete executions were byte-identical. No actual AuxPoW, contextual retargeting, source membership, native signing or quantum experiment was run.

Execution correction: a preliminary checker assertion `keys >= valid - adjacent_valid_pairs` was invalid when larger all-valid subtrees produce additional mergers; this failed. It was replaced by the exact identity `keys = valid - sum_k N_full(k)`, after which both reported runs completed. That failed preliminary attempt is not counted as passed.

## Reproducibility and boundaries

`check.py` is the executed standard-library checker, SHA256 `0b3e3fd3d13f01cfed13b5913c45d91d76707f2565a451dc45c3ffe37863cd8e`; outputs `result_a.json` and `result_b.json` both SHA256 `d396aa3da2c399153086f951802dd6605b5619ceba853ff55b9c5f1da6d070f7`. The two executed inputs and outputs are included under this directory. These numbers are only small-domain constructibility regressions, **not a source-dependent opening or a security proof**. An SHA256d predicate on synthetic n-bit strings is not actual Bitcoin PoW inclusion. A nonce/header string sampled locally does not establish best-chain membership, proper AuxPoW, contextual difficulty, tag applicability or claim relevance.

## Unfinished equation / next constructive move

R351's exact unresolved interface remains: a single polynomial-size **publicly serializable** implicit transition mechanism

`E_C(q,a) = K(T(q,a)) XOR H_edge(x,q,a,K(q))`

for arbitrary future authenticated ORIGINAL source transitions, without a builder-time table of future header preimages, without exposing the frontier keys and with globally consistent paths. Any repair must prove its full public quantum distribution (source, native VK/message, malformed/retained source coins, auxiliary and sibling disclosures), with every qualifying ORIGINAL witness opening the same frozen native safe cancellation capability, and unauthorized recovery implying an actual qualifying original certificate or independent QPT hash/native break. A new constrained-prefix delegation is not adequate: it discloses a valid local label even with no authenticated qualifying history.

The source relation remains the three independent OR grounds, including exact post-PQ contextual AuxPoW, claim-specific finite burn fault and qualified actual Syscoin history inconsistency/tag fault. No claim of working WE, hard-TRUE security, malicious setup handling, solved native activation binding, or real deployment. **NONQUALIFYING: no requested missing advance; do not issue an ordinary PR progress comment or user notification.**
