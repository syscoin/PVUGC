# R314 — Source-view surrogacy and the R313 double-opening adapter (NONQUALIFYING)

## Provenance / continuity

Start: open draft syscoin/PVUGC PR #1 on `research/pq-wkem-validation-20260918` at `df4258134b0baa6a182d9625d1863a30eca098ef` (R313 blob `b9f1cd93eb50c4619ca557e2ccb9ef1add4ee803`; preceding R312 blob `234a8f291f880ba58892d8ba7ef25f8dbd90a5ed`). Top-level comments since 2026-11-15 returned []; last relevant substantive ordinary comment remains R225 #6796383617. Core #609 *metadata only* shows `c91539de3c34937e57d7f5fda47c7b0502ff33f6`; no Core tests and no new Core-code read. No production edits.

The R313 double-opening Lamport KEM opens a single frozen key if TWO precommitted source-dependent secret labels become public. It is not ORIGINAL: qualified future Bitcoin/Syscoin histories do not carry these secret labels, and retaining their seed makes release immediate. This pass tried replacing the missing labels with a digest of actual source PoW, an R312-style work normalizer, or a nonlinear digest decoder, and proves a precise restriction that such repairs must avoid.

## Proved, scoped source-view surrogacy lemma

Let `P=(x_W,C,VK,m,aux)` include the complete public capsule, claim, native verification key/message, siblings, and any public auxiliary data. For a hard-TRUE distribution, let `w` be an independently generated qualified ORIGINAL source certificate. Suppose public `Open` factors through a witness-derived view `Y=View(P,w)`, so its candidate native authorization is `D(P,Y)`. Suppose classical PPT `Samp(P)` outputs a *synthetic view* `Y*` WITHOUT a qualifying original source certificate, and the JOINT distributions obey

    Delta( (P,View(P,w)), (P,Samp(P)) ) <= epsilon.               (1)

If the honest public decoder has native-authorization correctness

    Pr[ NativeVerify(VK,m,D(P,View(P,w))) = 1 ] >= 1-delta,      (2)

then the direct classical algorithm `A(P)=D(P,Samp(P))` outputs an accepted authorization **without that source certificate** with probability at least `1-delta-epsilon`.

Proof: native verification composed with the public decoder is a public Boolean function of `(P,Y)`; statistical distance bounds its acceptance-probability difference. Include decoder random coins identically in both experiments. This proof needs no adversarial internal state, source-query log, quantum rewinding, native secret extraction, or oracle programming. Being classical, the attack is available to QPT adversaries. The bound applies to arbitrary nonlinear SHA-based **digest-only** decoders under (1). It is not a general WE impossibility result, a FALSE-instance proof, or a security proof for actual source authentication. Importantly, **conditioning on P and aux** is necessary; marginal matching of Y alone is insufficient if siblings or setup secrets correlate with it.

### Concrete exact-target consequence, with explicit assumptions

In a fresh-independent random-oracle model of SHA256d, conditioned solely on a work-hash integer `0<=y<=T` for a public Bitcoin compact target T, the accepted hash is uniform on `{0,...,T}`. Sampling an INTEGER from that interval costs expected O(1) 256-bit draws by choosing `bit_length(T)` random bits and rejecting values >T. It does not require finding any Bitcoin header with that digest, a Bitcoin best-chain certificate, a valid coinbase, an AuxPoW commitment, or an actual claim-relevant Syscoin conflict.

Thus if `Open` consumes only the admitted *work hash*, and the honest accepted source view has this target-conditioned law jointly with public P, a synthetic hash obtained with no PoW or authentic ORIGINAL witness opens with exactly the honest correctness probability. A secret coefficient, a nonlinear decoder, a SHA rehash, or a finite-field work-prefix annihilator does not repair a lost certificate binding if the final public decoder sees **only** this cheaply sampleable view.

Real source-qualified histories are NOT assumed uniform after conditioning on all their ancestry, work, source windows, baseline/claim, miner selection, best-history admission and sibling metadata. A miner may bias accepted block hashes. The lemma applies only when (1) is justified. It does not grant the attacker an actual source certificate or declare the ORIGINAL bridge broken.

## Attempted constructive repair and exact unfinished boundary

A necessary repair is to retain the COMPLETE authenticated original certificate through source-conditioned release rather than reduce it to a freely sampleable digest first. The relation must remain the OR of (1) qualified same-anchor strictly higher exact cumulative BTC work, (2) finite authenticated refutation/nonmembership/complete bounded execution for the PARTICULAR claimed burn, and (3) actual `h_rel` ancestor inconsistency at required LC depth or separately authenticated exact claimed-wrapper tag fault under its adopted maturity rule. This preserves post-activation modern contextual AuxPoW chain ID, exact applicable 41-byte SYS parent-coinbase tag, separate child Merkle commitment, independent outer-carrier authentication before faulty-tag testing, all relevant interval tags, proper ancestor paths, exact claim/outpoint/burn/amount/recipient/anchor/window/depth/reset/native message/VK/capsule binding, and the distinction between a true child fork and two parent work certificates for one child. Do not require more SYS work, a global fork winner, or a proof of future fork nonexistence. R225's native signature portability between activations remains unresolved.

The putative compiler must actually implement classical-PPT `Build_orig(x_W,sigma_cancel)->C` and public `Open_orig(C,w)=sigma_cancel` for EVERY qualified ORIGINAL witness, while protecting full-public FALSE and unauthorized hard-TRUE recovery and native-forgery under QPT, even with malicious source/setup, retained coins, VK/signature correlations, siblings and selective openings. A capsule-root hash authenticates bytes but creates no secret-bearing openings. External source verification AFTER key release cannot retract it. Transparent frozen secret/correction coefficients leak; public garbled fragments splice (R287/R289), fixed witness-tag rows fail universal future-witness completeness (R288), and digest-only normalization falls under the lemma here.

The R313 adaptation `Lamport a[i,b] := H(authenticated parent/certificate)` is invalid: authentic future certificates do not expose BOTH precommitted OTS preimages under ONE key, while publicly derived low-work hash values are synthetic-surrogateable. Hashing an entire certificate merely changes the public view; unless the protected computation genuinely cryptographically couples the entire source verifier to release, it provides no SOURCE-conditioned key. No nonspliceable polynomial implementation or QPT simulator/reduction is supplied. Do NOT report a viable ORIGINAL witness-KEM or optimize these unsuccessful digest normalizers.

## Executed bounded evidence (arithmetic, NOT security tests)

A deterministic Python3 standard-library checker exhaustively compared every Boolean decoder table on 4-bit source-view outputs (65,536 functions), 16 independent setup-oracle outcomes, and seven acceptance thresholds: 7,340,032 table tests. Separate conditional-uniform checks covered all setup outcomes. Bitcoin compact target arithmetic was checked for `0x207fffff`, `0x1d00ffff`, `0x1b0404cb`, `0x1703abcd`. SHA256d was evaluated on 8,192 unrelated synthetic 80-byte headers; 4,119 happened to pass the artificial `0x207fffff` threshold, 4,073 failed. Independently drew 4,096 uniformly bounded synthetic target-valid digest integers with NO headers or authenticated source. The two final checker invocations produced byte-identical JSON; each recorded 7,352,740 arithmetic assertions. Large assertion counts are not evidence of source security.

Local checker SHA256: `d75445d740409558edefd0434333537ba6c89dde2a74bdca700f78500c9558cb`.
Both final output SHA256: `69dfb979513aaaab1e641f4450d9f8cfc6ba91b956a5dc2c7217751d03b0664f`.
Detailed local derivation README SHA256: `8e0b618c909a89d32f3cdb7317c18fcf985ff73b75e38b90850339864b10325a`.
Local-only full archive `R314_source_view_surrogacy_20261116.tar.gz`, SHA256 `74b9022afd24b477e2df1c35aba479dccd41b26de36830a6059f7384fc317ca3`; archive is NOT committed in GitHub. No actual Bitcoin/Syscoin source authentication, Core test, native SLH signing, quantum experiment, on-chain action, or malicious N-of-N ceremony was executed.

## Verdict

**NONQUALIFYING.** This is a restricted, complete-public source-view surrogacy regression and a necessary design criterion, NOT an ORIGINAL release mechanism or a complete cryptographic security proof. The exact still-missing object is a polynomial-size, source-credential-bearing, nonspliceable public release compiler over EVERY qualifying ORIGINAL future witness, with independently justified full-public QPT reduction and native activation binding. No PR progress comment, production change, notification or automation stop is warranted.
