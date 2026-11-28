# R363 — Finite-width public release transport: exact support search and virtual word (NONQUALIFYING)

## Scope / provenance
Inspected actual open/draft syscoin/PVUGC PR #1 on `research/pq-wkem-validation-20260918`, starting head `c52e4138a6765a46e17d668e2e35227fd2d19e75` (R362). Read R362's exact note, and R361 blob `184dac1daa7e063660ecbe6f68334fed27943775`; latest relevant ordinary PR comment remains R225. No web or Core source read. Prior R362 recovered the secret by a hidden constant-channel projector. Here the attempted repair removes that explicit constant channel, exposing only a globally source-gated, purportedly indecomposable finite-width arithmetic program. The objective remains the ORIGINAL source-dependent public Build/Open and independent QPT security, not an arithmetic branching program per se.

## Explicit public exact-support candidate
Over finite field F, publish row L, d x d matrices A_i^b for i=1..n and b=0,1, and column R, with d=poly(lambda). Public evaluation on a complete n-bit trace z is

    F(z) = L A_1^(z_1) ... A_n^(z_n) R.

The desired exact-support semantic gate would have F(z)=S for every qualifying globally consistent ORIGINAL witness and F(z)=0 for all invalid traces. This would avoid R362's visibly separable one-dimensional constant-output summand. It is NOT constructed for actual SHA/AuxPoW certificates.

**Causal-span theorem, with a constructive public witness search.** Define V_n=span{R}; recursively V_(i-1)=span({A_i^0 v, A_i^1 v : v in V_i}). Compute these spaces from the PUBLIC matrices by Gaussian elimination, maintaining at most d basis columns at each layer. There exists a bitstring z with F(z)!=0 iff some v in V_0 has L v !=0. If so, set row r=L; at each i choose a bit b for which r A_i^b is not orthogonal to V_i, then update r<-r A_i^b. The recurrence guarantees a choice and a final r R !=0. This is classical polynomial time in n,d (and field operation complexity), independent of any secret basis/gauge.

Thus an exact-zero-invalid / nonzero-valid explicit width-poly transport DOES permit recovery of a genuine accepted input, without asking an arbitrary attacker to volunteer its representation. For a hard-TRUE ORIGINAL instance, an efficiently generated public transport would itself enable an efficient ORIGINAL certificate solver. This is a structural extraction condition, not an independently instantiated source verifier, and it does not prove any universal impossibility for SHA/hash-only witness encryption. Nonzero pseudorandom outputs on invalid inputs or a succinct exponentially-dimensional state may escape this theorem, but then require a genuinely constructed and QPT-analyzed public encoding.

## FALSE full-public challenge: algebraic virtual words
An identically zero legal-input function need not hide a secret in its *serialized representation*. Fix n>=1, a prime p>n+1, dimension d=n+2, N the nilpotent matrix with ones immediately above the diagonal, U=I+N, any nonzero S, and independent random invertible gauges T_0,...,T_n. Define

    A_i^0 = T_(i-1)^(-1) T_i
    A_i^1 = T_(i-1)^(-1) U T_i
    L = e_0^T T_0
    R = T_n^(-1) (S e_(n+1)).

For every LEGAL length-n word z, F(z)=S*binomial(popcount(z),n+1)=0, so the whole evaluation oracle is exactly zero for every secret S. Nevertheless, from the public matrices alone form

    X = A_1^1 (A_1^0)^(-1) = T_0^(-1) U T_0,
    Z = A_1^0 A_2^0 ... A_n^0 = T_0^(-1) T_n.

Then the direct polynomial-time classical calculation

    L X^(n+1) Z R = e_0^T U^(n+1) (S e_(n+1)) = S

recovers the exact secret. The expression is a *virtual word*: its n+1 increments are not a legal length-n witness. But the adversary can multiply exposed matrices in arbitrary ways; no oracle, internal trace or victim-supplied representation is needed. Thus full-public FALSE distributions for distinct secrets are distinguishable (indeed exactly recoverable) in this family. This is not R362's visible constant-summand projector: the canonical legal function is zero everywhere, and the attack composes otherwise legal PUBLIC transition matrices out of order/number.

For a matching TRUE fixture set d=n+1 and R=T_n^(-1)(S e_n). The legal function is nonzero precisely at the all-ones word z=1^n, where it equals S. The causal-span algorithm finds this legal witness and S using only the published, fully gauged matrices. This synthetic witness relation is easy by design; no SHA, PoW or ORIGINAL source semantics are claimed.

## Attempted repair and precise remaining equation
Replacing invertible transitions with noninvertible ones can prevent the displayed X inversion, **but not** the causal-span extraction algorithm (which does not invert anything). Random dense full-rank layer gauges and arbitrary high polynomial input degree do not stop either result in their respective stated models. A nonzero/pseudorandom invalid-output channel, hidden transition representation or succinct exponentially-dimensional state requires a concrete public classical-PPT hash-only encoder plus complete-public QPT simulator, not an ideal source-gated oracle or an unpublished private coefficient vector. This candidate does not supply those primitives. No blanket impossibility of computational, source-specific hash-only release is inferred.

**Unfinished requirement:** Actual polynomial-time serialized Build_inc(x_W,S)->C and public Open_inc(C,w)=S for every distinct qualifying future ORIGINAL certificate, with source validity cryptographically inseparable from release; FALSE and unauthorized hard-TRUE QPT recovery/accepted native forgery reducing to an ACTUAL admissible ORIGINAL certificate or independently justified PQ hash/native break, including native VK/context, malicious setup, retained source mining coins, sibling capsules and selective openings. No such Build/Open or security proof was established.

## Executed local checks and preservation boundary
One standard-library CPython3 script was EXECUTED twice with byte-identical outputs. Across 50 TRUE and 50 FALSE randomly gauged GF(257) programs, n=3..7, it checked the span witness extractor; exhaustively checked EVERY legal FALSE word; recovered the FALSE secret using only public virtual-word matrices; and recorded 2,780 assertions per run. Checker SHA256 `afc9150a90f0dd6232b963e121269fc22162d02f8c53273087d8816c69851a44`; each JSON output SHA256 `0fa4c17b26efdfcd0c6ee48b5f3db36832a157e266d02b03b3e14b2019242a21`. Executable, complete longer derivation, two captured outputs and provenance in LOCAL archive `/mnt/data/R363_explicit_linear_transport_20261118.tar.gz` SHA256 `489412d3a150fe77727e3f13503229c4521390f7730a5f881bd737e73f4c514c`. These local artifacts are NOT claimed published to GitHub or durable across executions. No authentic BTC/SYS/AuxPoW, Core, native SLH or quantum experiment was run.

## Boundaries
The original three independently sufficient challenge grounds remain separate: relevant strictly greater exact BTC work; finite authenticated claim-specific invalid/missing burn authorization; LC-qualified relevant Syscoin history inconsistency or typed tag fault. Maintain current strict contextual modern AuxPoW chain-ID and canonical one-output 41-byte tag; authenticated actual ancestors (R316's stale tag equality does not defeat correct LC), exact claim/outpoint/burn/recipient/amount/anchors/height/depth/window/reset/deadline/native message/VK/capsule binding, and independent proof of malformed carrier evidence. R225's native fixed-outpoint activation-portability problem persists. N-of-N preauthorization is not the anyone-challenge quorum. All large source proofs stay off chain. No progress PR comment, production edit, deployment, or task stop.

**NONQUALIFYING ORIGINAL WKEM.** The analysis rejects a specific finite-width public transport repair, rather than producing the missing original-source hash-only release foundation.