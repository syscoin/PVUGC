# R362 — High-degree public arithmetic transport has a visible invariant projector (NONQUALIFYING)

## Continuation and novelty preflight
Started from actual open/draft PVUGC PR #1 branch `research/pq-wkem-validation-20260918`, head `b6131acca3f464e2a1e35d25caffc9e5f44eadaa` (R361). Read R361 blob `184dac1daa7e063660ecbe6f68334fed27943775`, plus R360 and R359. Last relevant ordinary top-level PR comment remained R225. No web/Core read; no production modification.

The unfinished operation is still classical-PPT source-dependent public Build/Open for all future ORIGINAL witnesses with independent QPT security. R361 defeated low-rank public COPY tensors via fractional clause covers. This attempt tried a different complete-public representation: a **high-degree** polynomial-length arithmetic branching program (ABP), with layerwise independent full-rank basis changes to hide factors. The algebra below is a preflight against that particular encoding family, not another small-degree interpolation bound. The tested FALSE specialization has constant invalidity f_x=1; the intended general form is F_x(z)=S+f_x(z) R_x(z), with f_x(w)=0 for every globally valid original trace w. The general f_x SHA/AuxPoW compiler is not supplied or claimed secure.

## Concrete serialized family
Over finite field F, choose a fixed S and an arbitrary high-degree mask represented by width-d matrices:
  R(z)=u^T B_1^(z_1) ... B_n^(z_n) v.
Publish a directly evaluable width-(d+1) randomized program. Define M_i^b=diag(1,B_i^b), ell=(S,u^T), r=(1,v)^T. Sample independent full-rank T_0,...,T_n. Publish
  L=ell T_0,
  A_i^b=T_(i-1)^(-1) M_i^b T_i,
  R_end=T_n^(-1)r.
Public Open(C,z)=L A_1^(z_1)...A_n^(z_n) R_end=S+R(z). The public encoding is polynomial-size and public evaluation is classical PPT. Honest same-output correctness would hold for valid w only after adding an actual source-failure factor f_x; this FALSE preflight does not implement original challenge authorization.

## Entirely public classical recovery
When det(B_1^0-B_1^1) is nonzero and both B_1^b invertible, form
  X=A_1^0 (A_1^1)^(-1)
   =T_0^(-1) diag(1,B_1^0 (B_1^1)^(-1)) T_0.
The eigenvalue 1 has a 1-dimensional eigenspace. From public X calculate Q=X-I, a right nullvector v0 and left nullvector u0, and set
  P0=v0 u0^T/(u0^T v0).
Under the stated nondegeneracy this is *exactly* T_0^(-1) diag(1,0,...,0) T_0, the hidden constant-channel projector. No private gauge is reconstructed or needed. An attacker obtains
  S=L P0 A_1^0 ... A_n^0 R_end
by public polynomial-time arithmetic, without a witness, a valid original source certificate, any oracle, or representations supplied by the victim. The attack holds for arbitrary high polynomial degree in R. Hence hiding polynomial coefficients with independent invertible gauges while retaining an explicit 1D constant-output summand is not a hash-only WE implementation; neither FALSE nor hard-TRUE security follows. This is not a theorem against indecomposable nonlinear programs, all high-degree masks, or computational SHA-specific release.

## Executed local checker
Actually ran `checker.py` twice with CPython 3 standard library; both results identical. It sampled 160 gauged public width-3 ABPs over GF(257) with 12–15 layers, each with invertible 2x2 nonconstant blocks and det(B_i^0-B_i^1) nonzero. The extractor used only L,A,R_end, recovered every S, verified projector idempotence and sampled public evaluator values against the unblinded definition. This is a synthetic representation check, NOT Core/SHA/AuxPoW/native-signature/QPT testing. Local files, derivation and two JSON output captures are in `/mnt/data/R362_abp_projector_20261118/`; checker SHA256 `a541189c9d71de8c09e43876aaa23d228d95997d55cf587a7a820e4db0d7fbde`, each stdout SHA256 `ac25b4742ec22d2c43e35af364e3160b3246442bcb5e280249d682563914e5d5`. Local archive `R362_abp_projector_20261118.tar.gz`, SHA256 `66c9a2b6f2d8d9d1b7f9c633c5bfe89b51908985bbf4bec2e4e5a2fbd9085e93`. These executable artifacts are LOCAL ONLY; do not assume future session persistence.

## Repaired objective / exact unfinished equation
To avoid this projector, a subsequent candidate must specify an **indecomposable public serialized classical-PPT program** that genuinely embeds the source-authenticated relation in its cryptographic release, not just a validity check applied after a recoverable S. It needs every qualifying ORIGINAL future witness to return the same frozen safe capability, with no per-witness precommitment, independent source labels, private keyed evaluator, public separable invariant S channel, local occurrence splicing or source-gate weakening. It also needs a complete-public QPT FALSE/hard-TRUE release/accepted-native-forgery -> ACTUAL ORIGINAL certificate or independent PQ hash/native break, including malicious source coin retention and correlated sibling capsules. Mere matrix density, large degree, gauge randomness, or an unproved white-box assumption is not a security argument.

All three independent OR challenge grounds remain in force: qualified same-anchor BTC strictly greater work; finite authenticated specific burn fault; LC-depth-qualified actual relevant Syscoin inconsistency or correctly typed tag fault. The claimed source/cancel/amount/recipient/UTXO, anchored contextual modern canonical AuxPoW, true ancestors and all tag/height windows/reset and native VK/message/capsule binding remain mandatory. R316's stale-tag illustration is NOT a strict light-client detection failure. R225 native signature portability remains unresolved. No new source-dependent public Build/Open, original QPT security or practical bridge solution was established; NONQUALIFYING. No PR comment, deployment, Core or production change or task stop.
