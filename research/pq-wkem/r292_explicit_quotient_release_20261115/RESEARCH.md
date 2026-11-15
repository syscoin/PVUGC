# R292 — Public Boolean-quotient coefficient correction: TRUE-instance linear extraction (NONQUALIFYING)

## Continuity / exact experiment
Existing PVUGC PR #1, branch `research/pq-wkem-validation-20260918`, starting SHA `5a8f55cc08521826b8b649e612426edeeba04a6f`. Continues R291's missing polynomial public correction RowEval (blob `ad884954a4e33b1e941bbe3813be9b11c6847440`), after R290's repeated-bit-state problem and R289's multi-evaluation cut splicing. R225 ordinary issue comment 6796383617 remains the separate native signature / activation portability issue. Core #609 observed metadata head `c91539de3c34937e57d7f5fda47c7b0502ff33f6`; no new Core source inspection, Core test, deployment or activation is claimed. Only connected GitHub and bounded local Python were used, no web or literature.

Original requirement unchanged: one notary initiates; anyone with a qualified ORIGINAL higher-work BTC history, finite authenticated particular-burn defect, OR relevant qualified Syscoin inconsistency/tag fault at LC depth should noninteractively open the SAME frozen safe cancellation capability. Modern contextual AuxPoW and exact 41-byte parent SYS tag, actual ancestor comparison at h_rel, parent-wrapper provenance, source/claim/UTXO/amount/recipient/anchors/windows/depth, native VK/message, and N-of-N honest-erasure setup are not replaced by the toy experiment below. No generic WE or release security is claimed.

## Explicit candidate Build/Open
Take `B_n=F_2[z_0,...,z_(n-1)]/(z_i^2-z_i)`. Define full source predicate `F_x(w)=1` exactly for ORIGINAL qualified witnesses, and `Q_x=1+F_x` (mod 2). This predicate must contain all authentication and relevance requirements, not merely a post-decryption verification.

Choose a public monomial support `M` (the experiment chooses degree <=2), let `V=span{z^m:m in M}`. For a fixed frozen payload bit `k`, draw secret mask coefficients `r_m`, set `R=sum r_m*z^m`, and publish ONLY the fully reduced multilinear COEFFICIENT VECTOR of:

`P(z)=k+Q_x(z)*R(z)` in `B_n`.

For a 256-bit payload use independently sampled `R_b`, with one public `P_b` per bit. Honest public Open evaluates `P_b(w)` on one full witness. If `F_x(w)=1`, then `Q_x(w)=0` and EVERY satisfying witness returns exactly the same frozen `k`. This is explicit same-value correctness in this algebraic model, not a polynomial-time ORIGINAL construction.

**Restricted complete-public FALSE theorem.** If the instance is FALSE, `F_x=0` throughout the Boolean cube, hence `Q_x=1` in this quotient. Thus `P=k+R`. If coefficients of `R` are uniform independent and the constant monomial belongs to `V`, shifting its constant coefficient by `k` leaves the ENTIRE public distribution unchanged. This is statistical hiding against even QPT processing of the already drawn classical coefficient vector, in the explicit model only; it says nothing about a practical SHA generator, hard-TRUE secrecy, malicious setup or siblings.

## Hard-TRUE public-only extractor: decisive uninstantiated-repair limit
Suppose the public coefficient-vector ambient dimension is polynomial, the monomials in `M` are known, and multiplying the public `Q_x` by each `z^m` gives explicit public coefficient vectors efficiently. Let

`W = span_{F_2}{Q_x*z^m : m in M}`.

On EVERY TRUE instance, evaluation at any satisfying Boolean witness `w` annihilates every element of `W` but sends constant `1` to `1`. Consequently `1 not in W`. Without finding or providing `w`, an attacker runs ordinary GF(2) elimination on the PUBLIC columns and constructs a functional `phi` with

`phi(Q_x*z^m)=0` for every `m`, and `phi(1)=1`.

Then `phi(P)=phi(k*1+Q_x*R)=k`. Repeat for every payload bit, independently. This is a straight-line CLASSICAL complete-public secret-recovery algorithm on TRUE instances, therefore also an admissible QPT adversary, with no query log, internal-state request or supplied witness. The argument does not care whether the secret mask coefficients came from SHA256, a nonlinear PRG or uniform samples; they all lie in the same publicly annihilable space.

The conclusion is restricted to a publicly computable **polynomial-size explicit coefficient representation / mask-span interface**. The ordinary complete multilinear representation has `2^n` coefficients, and making that large is not a polynomial-time solution. Replacing explicit vectors by a short opaque arithmetic program does not supply the required public non-spliceable source-conditioned evaluator; exposing the decomposed mask reveals the secret, and ordinary reused garbling inherits R289/R290 risks. Neither is an instantiated repair. This is not a black-box impossibility result for SHA-only WE or non-linear opaque encodings.

## Actual bounded executed control
The local checker varied eight bits of a synthetic 80-byte header nonce and calculated actual SHA256d with Python hashlib; the toy acceptance test was high digest nibble zero in an assumed matching context. An unrelated source-context mismatch sets the toy predicate identically zero. Neither variant authenticates a real Bitcoin parent or canonical SYS tag, checks Compact targets, baseline, LC depth or original claim, so NONE is an ORIGINAL certificate.

For 256 toy nonces: 11 qualify in the toy TRUE context; its full ANF has 70 nonzero coefficients; the degree-2 mask subspace has 37 monomials. A public `phi` of coefficient-vector Hamming weight 15 recovers a fixed 256-bit payload surrogate from 256 fully public polynomial vectors with no witness. Open at all 11 qualifying toy nonces returns that SAME secret. An additional 200 independent scalar SHA-masked cases all recovered via the same public annihilator. With toy FALSE `Q=1`, exhaustive enumeration of 512 degree-1 mask vectors showed identical full-ciphertext distributions for payload bits 0 and 1. The two final standard-library Python runs were byte-identical.

An earlier checker attempt was killed by using a bitset rather than a bit index inside `1<<(m|k)`; this was corrected and the killed attempt is NOT counted as a successful run. No Core/BTC/Syscoin admission, native PQ signatures, adversarial QPT, or malicious-ceremony computation was run.

Local archive `R292_explicit_quotient_release_20261115.tar.gz` (complete derivation, checker.py, both outputs and provenance): SHA256 `fd7c079b01bc5b0f137daac975e808c67e6bdc13bfe29d40c576f20c595adfab`. This archive is **local-only** and is NOT claimed committed to the repository. Checker SHA256 `edeebe1b7ccb04df9425c9e309c2e8332e43a595ae4aa62c2db9dc0e7ce91d6e`; run1/run2 each SHA256 `501030d4280e285c6714e4868e0f3b1ed78d3706e5d96fbf7003c5f82176bf0e`. Full local derivation SHA256 `c93fdeacca81d77c71dd1feb74840141c95d1d3aad5b0076f17a85084274e85e`.

## Exact unfinished obligation
Build a CLASSICAL-PPT *source-authenticated* common-key evaluator for every future distinct qualifying ORIGINAL BTC/SYS challenge that is not (i) algebraically extractable from an explicit public linear mask span, (ii) spliceable across public garbled cuts, (iii) vulnerable to inconsistent repeated source-bit reads, (iv) openable by forged source history or sibling-capsule selective opening. A full-public QPT reduction must take unauthorized hard-TRUE recovery / accepted native forgery straight-line to an ACTUAL qualified ORIGINAL certificate or independent native/hash break, including claim-scoped endpoint/activation policies. Neither a public root, a secret future-row issuer, a PRG applied to publicly annihilable coefficients, nor a post-recovery source if-check instantiates this.

Outcome: NONQUALIFYING. No ORIGINAL-source WKEM, security advance, generic WE, bridge deployment recommendation or completion claim. No ordinary PR comment and no notification warranted; automation stays enabled.
