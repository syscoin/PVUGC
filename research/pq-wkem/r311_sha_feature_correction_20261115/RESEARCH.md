# R311 — Public SHA-feature correction and nonlinear repair boundary (NONQUALIFYING)

## Continuity and unchanged ORIGINAL scope

Read current draft PVUGC PR #1 head `c355fc44a14f00283507e935289ec525aaa0484b` on `research/pq-wkem-validation-20260918`; R310 note blob `8559500d028dc8618b3202be0881e23f8fe8b455`, R309 blob `5bd8e9baccad2fa6c572d22a9a81a4ab33a71d7f`. Latest substantive ordinary PR comment remains R225 #6796383617. Core #609 read-only metadata head `c91539de3c34937e57d7f5fda47c7b0502ff33f6`. No Core tests, live admission, external web, quantum experiment, independent agent, production work or deployment in this run.

The target stays the ORIGINAL three OR grounds: strictly higher cumulative BTC work from the same source anchor; finite authenticated burn authorization refutation/nonmembership or bounded complete execution for the PARTICULAR withdrawal; qualified semantic-ancestor Syscoin conflict at actual h_rel with required LC depth, or an independently authenticated claim-pinned exact parent tag fault subject to the explicitly adopted maturity rule. All actual source proof checks must bind protocol/chain IDs, exact claim/UTXO/burn/amount/recipient, baseline, anchors/window, source height, predecessor paths, lag/depth/deadline/reset, exact cancellation message/VK and capsule. Apply Core #609 activated CONTEXTUAL modern child chain ID and exact 41-byte SYS parent tag, plus the separate AuxPoW child-tree commitment. A malformed wrapper cannot borrow LC depth from a different wrapper of the same child; distinct valid parents for one child are not themselves forks. One notary initiates; ANY qualifying witness holder challenges; N-of-N is a setup boundary only. R225 fixed-outpoint native-signature portability remains unresolved.

**This candidate is a compiler experiment on synthetic predicates, NOT a real authenticated ORIGINAL verifier or a bridge release.**

## Candidate 1: SOURCE-gated public SHA features, private additive coefficients

Represent a deterministic authenticated source certificate+trace by z and public Boolean violations C_i(z), accepting iff every C_i(z)=0. In an attempted source-conditioned Build, sample the ONE frozen 256-bit safe capability surrogate S, independent secret 256-bit a_ij, and public SHA feature functions

    f_ij(z) = bit_0 SHA256("feature" || x_W || i || j || z)
    g_ij(z) = C_i(z) * f_ij(z)
    P(z) = S XOR XOR_{i,j:g_ij(z)=1} a_ij.                 (1)

A hypothetical polynomial public Build must encode P for public evaluation *without* exposing S or the individual a_ij. Algebraic all-original-witness correctness is immediate: on every qualified z, all C_i(z)=0, so P(z)=S. No canonical witness is required. Unlike an if-check after decryption, the source-violation functions multiply the release masks directly. This does not establish public concealment, and no independently secure PublicEncode is instantiated.

### Full-public linear feature theorem, independently of SHA algebraic degree

For ANY known efficiently computable features g_j and publicly evaluable P(z)=S XOR sum_j a_j*g_j(z), define v(z)=(1,g_1(z),...,g_M(z)) over F2. If some polynomially sampled (possibly all INVALID) inputs z_k have v-row span containing e0=(1,0,...,0), public Gaussian elimination yields alpha_k with

    XOR_k alpha_k = 1,
    XOR_k alpha_k*g_j(z_k) = 0 for every j.

Consequently

    XOR_{k:alpha_k=1} P(z_k) = S                       (2)

exactly, for every choice of private a_j, without an ORIGINAL certificate, SHA inversion, representation extraction, query logs, or secret coins. This is a straight-line classical attack, hence also QPT. The span condition is required: it is not guaranteed for arbitrary functions/queries. On a TRUE source, e0 is globally spanned by a valid z, but an extractor must FIND a polynomial set of invalid probes; our fixtures do. On FALSE, e0 may or may not be spanned. The scope is the *linear-in-private-coefficients* public feature family, not all nonlinear public release programs.

This removes R310's specific low-degree / positive-high-degree-monomial restriction: even arbitrary-degree SHA feature gates fail if the fixed secret correction coefficients enter publicly evaluable P additively and the public feature vectors have the described span.

## Candidate 2: nonlinear joint hash repair and its exact unsolved endpoint

Try

    q(z)=XOR_{k:g_k(z)=1} a_k,
    P*(z)=S XOR SHA256("R311-nonlinear-pad-v1" || q(z)).  (3)

The linear XOR extractor (2) no longer cancels output pads. But with ONLY SHA-gated g_ij=C_i*f_ij, an invalid source z can have *all* its SHA feature bits zero, hence q(z)=0, opening exactly like a valid witness. The checker locates six such invalid TRUE-fixture inputs and one such invalid FALSE-fixture input. Add one DIRECT violation coordinate g_i0(z)=C_i(z) per i. Then g(z)=0 **iff** all violations are zero, a precise source-path correctness condition; exhaustive synthetic checks confirm it.

For valid z, P*(z) XOR SHA256(domain||0^256)=S for ALL valid z. But (3) is only a **private** function in the executed checker: a publicly readable implementation that exposes a_k (or S) lets any attacker remove the SHA pad from one INVALID public evaluation and recover S. Suppressing those keys requires a genuinely nonspliceable hidden-key public evaluator for arbitrary ORIGINAL future witnesses. Ordinary reusable garbling, witness-tag conversion, an ideal source oracle, or an online signer does not supply this. No secure classical-PPT PublicEncode exists here; no FALSE/hard-TRUE QPT reduction or malicious/sibling-capsule/native-forgery theorem is claimed.

The exact unfinished obligation remains a concrete classical-PPT PublicEncode(x_W,S,a) returning C and public Open(C,w_original)=the SAME frozen safe native capability for EVERY qualifying ORIGINAL source witness, while unauthorized full-public QPT recovery or native acceptance straight-line implies an ACTUAL ORIGINAL qualifying certificate or an independent PQ hash/native break. In particular, secret a must remain protected under full public-code access, source trace correlations, selective opening, sibling capsules and malicious setup—not just in a private evaluation callback.

## Executed checker and reproducibility

Two Python 3.13 standard-library checkers use n=14 synthetic source bits, three constraints, K=10 SHA256 features per violation (M=30), and 256-bit private coefficients. `checker.py` gives the extractor ONLY the public evaluation callback and g(z), never S or private a. It independently verifies every selected probe is invalid, the feature XOR cancels, odd parity holds, and the recovered result equals privately held S. TRUE fixture has 105 accepted inputs; 29 invalid public queries with 17 selected recover S, feature rank 29. FALSE fixture has zero accepted inputs; 32 invalid public queries with 9 selected recover S, feature rank 30. `nonlinear_repair.py` exhausts 2^14 inputs per fixture for the zero-feature issue and the direct-coordinate repair, and confirms immediate exposure when private keys are published. Private callbacks are NOT a public Build construction.

Two executions of each checker produced byte-identical outputs. SHA256:
- checker.py `3b2d81ac7e5fbad70ee29ef2e3c9fc318c1eb71dfb961a08194bc761c8b95bcd`
- linear output (both runs) `db4e6be785416e7dd660e5fa40d8fa5b00276e123434e80ed5af45cd065608ad`
- nonlinear_repair.py `1d5a3c65e096e5df39281ce0df2f450d28dc413f3d6d97b7461ec0b74f645029`
- nonlinear output (both runs) `31b72ef8271b8d367db16584d0b47a18b2e10b5efaf0d11cd02c779dd4da1d30`

The full local derivation, two source checkers, four captured JSON outputs and provenance are archived as `R311_sha_feature_correction_20261115.tar.gz`, SHA256 `824eb00e1e7456d4f0f98c50ee546af3b052f0c7bab2b33b0523ef10bdc08c00`. This local archive is NOT part of the GitHub commit. No authentic Bitcoin/Syscoin source admission, native PQ signature, real cancellation or QPT experiment was performed.

**Verdict: NONQUALIFYING.** No ORIGINAL source-dependent hash-only Build/Open foundation advance, independent QPT source-witness extraction or native bridge solution. No progress comment/notification, workflow or production change. Keep existing research automation enabled.
