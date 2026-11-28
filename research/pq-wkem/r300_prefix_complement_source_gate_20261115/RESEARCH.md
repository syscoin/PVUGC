# R300 — claim-ancestor prefix-complement GGM delegation (NONQUALIFYING)

## Continuity and exact source scope

Continues R299 `research/pq-wkem/r299_source_fiber_mask_20261115/RESEARCH.md`, blob `e841f1e8401ad63d3e9cc5f2000996f6dd74c040`. Initial PVUGC PR #1 head `633522d93753011755c901c2966b63f7caa34d07` on `research/pq-wkem-validation-20260918` (open/draft). Core PR #609 read-only metadata `c91539de3c34937e57d7f5fda47c7b0502ff33f6`; no network-activation claim, Core rerun or real source verification. R225 ordinary issue comment `6796383617` still describes the independent activation-binding issue. This iteration only implements an exact 256-bit semantic-ancestor inequality partition and an intentionally insecure public release experiment, not source-authenticated WKEM.

The ORIGINAL three-branch OR relation stays unchanged: qualifying competing BTC history with strictly more exact cumulative work, a finite authenticated specific burn-authorization defect, or qualifying claim-relative SYS inconsistency/exact-parent tag fault (asymmetrically authenticate an invalid-tag outer carrier). A source challenge binds chain IDs, exact claim/UTXO and assertion/amount/recipient/burn, baseline and actual semantic ancestor at h_rel, BTC anchor/window, claimed parent and modern contextual AuxPoW checks (modern chain ID, exact 41-byte SYS tag in valid wrappers, child-tree commitment), required LC/source depth, deadlines/reset, capsule and frozen native safe cancellation message/VK. Distinct authenticated parent carriers for the SAME immutable SYS child alone are not a fork. Do not mistake the 6–15-link h_ref lag for LC depth or compare only rounded tag heights. One notary initiates; any watcher challenges; N-of-N only preauthorizes. R176/R177 future-fork qualification and R225 slot-global-veto/actual activation-bound native spend remain mandatory.

## Candidate and exact lemma

For the fixed authenticated baseline ancestor `a∈{0,1}^256` at h_rel, form 256 sibling prefix cylinders:

```
P_i(a) = {b: b[0:i]=a[0:i] and b[i]=1-a[i]},  i=0..255.
```

These are pairwise disjoint and their union is EXACTLY `{b:b≠a}`. Proof: any non-equal b has a unique first mismatching index i; that b lies only in P_i. Thus the *public inequality policy* (not SHA/AuxPoW source validity) has a 256-element prefix representation instead of an exponential list of b.

Take a SHA256-based GGM root seed r. For each sibling prefix p_i derive `k_i=GGM(r,p_i)`. Attempt to freeze the same 256-bit capability surrogate S with the following public object:

```
C_i=(p_i, k_i, E_i),  E_i = S XOR SHA256("R300-STATIC-PAD"||k_i)
Open_static(C,b)=E_i XOR SHA256("R300-STATIC-PAD"||k_i)
where i is the unique first mismatch of b versus a.
```

Setup has O(256) terms and public Open returns EXACTLY S for every `b≠a`. Importantly, this is not source-authenticated release. Every b, including a fabricated 256-bit string with no parent header or canonical source history, can use the same public subtree key. In fact `E_i,k_i` independently disclose S immediately, without supplying b at all. This is full-public classical FALSE recovery and therefore QPT recovery as well; no SHA inversion, label mixing, quantum rewinding or VKey tester is necessary. A downstream `VerifySource` call cannot retract S.

## Repairs attempted / exact issuer gap

1. Withhold `k_i` and publish only `SHA256(k_i)`: the immediate public extraction is blocked but future honest watchers holding an independently authenticated actual source certificate do not possess the **setup-created** GGM key; their Bitcoin parent/header/coinbase SHA states are unrelated. No public Open exists for arbitrary future w.
2. Tie the key to `SHA256d(parent_header(w))`: all real future parent carriers generally have differing hashes, and Build cannot compute the frozen `E_i` for each unseen parent. An unkeyed public version also grants arbitrary header strings the same capability as contextual admissions. It cannot silently use a later source-check as cryptographic authorization.
3. Upgrade the bucket index to a digest of the FULL original certificate: this resolves R299's particular child-only source-fiber collision, but future full witness digests remain unknown to setup and cannot derive the hidden GGM seeds. It also does not force authentication, semantic ancestor consistency or relevant claim binding.

The exact still-missing operation is a classical-PPT public `SourceEarnedKey(C,x_W,w)` integrated *inside* release, not merely a source check after secret recovery. For **every** ORIGINAL fully authenticated future witness w it must issue the same frozen native-safe cancellation capability without knowing/provisioning all future parent transcripts or introducing a secret source signer, generic assumed WE/iO, source-retained secret coins, on-Bitcoin NP verifier, or QROM programming. Full-public FALSE and unauthorized hard-TRUE QPT recovery/forgery must lead to an ACTUAL qualifying ORIGINAL certificate or independent PQ/native break, with auxiliary/sibling/malicious-setup security. These equations are NOT satisfied by GGM prefix delegation.

## Actual bounded computation

Python 3 standard-library `checker.py` used SHA256 for GGM derivation, exhaustively verified unique prefix-cylinder membership for all bit widths 1..12, then 512 synthetic 256-bit alternatives. It explicitly recovered S for a fabricated `b=a XOR 1` without ANY authenticated source certificate, and also directly from one published `(k_i,E_i)`. Hiding the seed removed the public opening inputs. Two final checker runs were byte-identical with 8,706 assertions each. This fixture did NOT exercise Core admission, actual Bitcoin best-chain membership, AuxPoW Merkle paths, LC depth, native SLH signing, coherent QPT or malicious N-of-N setup.

LOCAL-only reproducible archive `R300_prefix_source_gate_20261115.tar.gz` SHA256 `45bd6d78ab2c09ba2359a07c5021aa149005c35b24983ad81b44764a76b015d8`; checker SHA256 `8dd3078ac97febc45f7fa5cee888f8eb1e0a6a3ef1500c3bb38c74a519763e6c`; identical run output hashes `937e692529032a94a89a4bf08a2d668abb5a3c7ff9c2feb9984a6e239cc2f556`. The archive contains the derivation, checker, output and checksums; it is not committed as an executable Git object.

Disposition: **REJECTED as public WKEM; no ORIGINAL foundation advance**. The compact sibling cover is only a policy fact, not a proof that arbitrary source SHA/AuxPoW history supplies hidden release labels. The next research equation must implement an honest classical-PPT source-earned issue mechanism with same-key convergence and independently justified full-public QPT security for the complete original relation, not optimize this partition. No PR comment, notification, deployment or automation-stop is warranted.
