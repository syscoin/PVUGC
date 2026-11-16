# R322 — public hash-garbled SHA gate consistency test (NONQUALIFYING)

**Outcome:** no ORIGINAL-source hash-only WKEM advance. This bounded continuation of R321 tests a different nonlinear public Boolean-garbling candidate, not scalar SHA normalizers. It identifies a concrete classical FALSE-instance secret recovery by mixing copyable public wire labels across fanout. It does **not** rule out proper witness encryption, nonpublic/source-earned label delivery, concrete SHA, or nonlinear cryptography generally.

## Read-only continuity

At start PVUGC PR #1 was open on `research/pq-wkem-validation-20260918`, head `511d05b507e5d31a20d7473b05908db9fde23a28`. Latest R321 note blob `53f6fdbc94c7be9ec8163e78b75dae935d3fac3c` was read. R320 `a15cefa391669c224a077f8530214ffd33347a82`, R319 `6e6d4310657c2c65733daf72f2b517a218155277` were read. Core PR #609 **metadata** was read-only at `c91539de3c34937e57d7f5fda47c7b0502ff33f6`, release-disabled, with no Core tests rerun. R225 native activation portability issue (PR comment `6796383617`) remains open. No web or literature access.

Original relation remains the OR of (1) exact same-anchor greater cumulative Bitcoin work, (2) finite authenticated missing/invalid *specific* burn authorization, and (3) actual relevant Syscoin ancestor conflict at LC depth, or independently outer-authenticated relevant tag fault with explicit maturity. Activated contextual modern chain ID, exact canonical 41-byte tag, separate correctly indexed child Merkle commitment, actual h_rel ancestors/interval, relevance/window, exact claim/outpoint/amount/recipient/native cancellation message/VK/capsule remain required. Different parent wrappers of one child are not forks. **No checker fixture below implements this ORIGINAL source relation.**

## Nonlinear candidate

For each Boolean circuit wire u, Build chooses independent λ-bit labels `L_u^0,L_u^1`. For each bounded-fan-in gate g of degree d, publish the 2^d rows

`T_{g,a} = L_v^{g(a)} XOR SHA256("gate"||g||L_{u1}^{a1}||...||L_{ud}^{ad})`.

Publish unordered commitments `Q_v={SHA256("commit"||v||L_v^0), SHA256("commit"||v||L_v^1)}` so that the ordinary public evaluator can recognize valid gate decryptions. Publish a commitment naming the TRUE terminal label and `D = S XOR SHA256("output"||L_root^1)`, where S is one frozen synthetic cancellation capability. Build/Open require classical polynomial time for bounded fan-in **if** the appropriate input labels can be securely delivered for an original valid witness. This last premise is the missing source problem, not a proven or implemented interface.

The attempted all-witness public repair exposes **both** input labels at every source bit. A straight-line public extractor then takes `Known(input_i)={L_i^0,L_i^1}`; at each gate enumerate all combinations of known predecessor labels and all published rows; accept a decrypted candidate exactly when its SHA commitment lies in public Q_v. For every surjective local Boolean gate whose input wires both have both labels, this produces **both output labels**. For fan-in at most 3, closure is O(gates * 4^3) SHA calls. It requires no private label table, quantum measurement, extracted representation, SHA break, source witness, or verification oracle.

For FALSE circuit `V(x)=x AND NOT(x)`, the extractor feeds x=1 at the left AND occurrence and x=0 at NOT, producing both true wires and the terminal TRUE label although no globally consistent assignment exists. A second FALSE circuit uses the *actual SHA256 Ch Boolean function* `c=(x&y) XOR ((1 XOR x)&z)`, followed by `V=c AND NOT(c)`. In all 8 consistent input assignments V=0; public closure still recovers the terminal TRUE label and S. A post-unmasking V verification cannot undo the released S. Classical recovery also invalidates QPT security in the full public transcript; with a real native cancellation signature substituted for synthetic S it would expose exactly that signature, though no native signing was tested.

## Constructive repair attempted and precise unfinished equations

Publish only one label for each **globally consistent** original source witness and keep complementary labels unavailable. A hypothetical noninteractive delivery needs

`Build_inc(x,S;ρ)->(D,T,Q,E)`, before any unknown qualifying source evidence,

`forall w: R_ORIGINAL(x,w)=1 => Deliver(E,x,w)=(L_1^{w1},...,L_m^{wm})` **in one globally nonspliceable state**,

and complete-public unauthorized QPT recovery/accepted native forgery must reduce to an **actual** qualifying authenticated ORIGINAL certificate or independently justified PQ hash/native break. The certificate cannot merely be checked after raw S recovery.

Using a public bit key `H(x||i||b)` to unlock a label reveals both alternatives and reopens closure. Using `H(full_future_parent_certificate)` instead cannot be programmed by classical preauthorization Build for every unknown rerandomizable future parent certificate and fails single-common-label convergence across distinct certificates. Public canonical child/SYS-tag normalization produces a directly computable key. Making a classical public label "one-time consumable" through a Merkle commitment alone is impossible: copied bytes are still usable at inconsistent fanout occurrences. A meaningful replacement must cryptographically **enforce source authentication and global consistency inside label release**, without an online signer, retained source secret, arbitrary PoW puzzle, or external transcript representation. That missing primitive has **not** been constructed or proven weaker than ORIGINAL witness encryption.

## Executed bounded reproducibility

The local Python3 stdlib checker implemented public SHA256 gate pads, public per-wire label digests and TRUE-output label commitment, plus a public closure that does not use hidden labels when choosing candidates. It executed the two FALSE circuits above, enumerated 2+8 honest assignments, and recovered both terminal labels plus the same frozen synthetic 256-bit S without any satisfying assignment. Two independent invocations each completed 68 assertions and produced identical JSON. Checker SHA256 `5950110cd0073ac3ae9174993eabf890c85e15374dfb974853cc01172f8403ff`, both captured output files SHA256 `d91394bd99609037d007ef834a5738287e14e525b30563947f3becb7d2ca48b2`. Complete derivation, verbatim executable checker and paired JSON are in LOCAL-ONLY `R322_garbled_source_gates_20261116.tar.gz`, SHA256 `5a9813ab70eb3dcaa413b561008c6dd54e7ced23b67b245dc96a2edb001f0af7`. No real SHA256d mining/auxpow admission, BTC best chain, QPT experiment, native PQ signature, or adversarial distributed setup was executed.

**Verdict:** nonqualifying, no ORIGINAL Build/Open or independent full-public QPT security. No PR progress comment, production change, release, deployment, or automation disable. Next indispensable step is genuine cryptographically source-earned, nonspliceable label delivery or another **actual** classical-PPT source-dependent secret release algorithm for every ORIGINAL OR witness.