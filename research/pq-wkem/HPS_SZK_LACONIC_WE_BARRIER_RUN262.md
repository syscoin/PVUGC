# Run 262 — ordinary HPS/SZK barrier and laconic-SHVZK = WE boundary

## Checkpoint

This bounded pass began by reading the live `syscoin/PVUGC#1` state through the connected GitHub integration.

- branch: `research/pq-wkem-validation-20260918`
- starting SHA: `808f12c90397c3d25a7bd48606096f640773e8dd`
- PR state: open, draft, unmerged
- exact live Run-259 note: `research/pq-wkem/GLOBAL_FINGERPRINT_SOURCE_BINDING_RUN259.md`, blob `c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2`
- exact live Run-259 checker: blob `9d85bf844695de69d6b86e19cf4cc2dcaabad1ca`
- exact Run-123 dual-mode extraction note: `STAT_DUAL_MODE_SOURCE_HASH_QPT_EXTRACTION_RUN123.md`, blob `2eefa25de7f5a9b9c65abf15a20bb4ae6564702e`
- exact Run-126 resampling barrier: `DUAL_MODE_HASH_SECRET_RESAMPLING_BARRIER_RUN126.md`, blob `94d1a6246da77f561ecacd84ce78917d6121dc33`
- literature assessment: blob `8a1bc1db08156c9ff6410f59963c1af3a0d5a924`
- latest substantive ordinary PR comment at start: `5945825660`

Two initially guessed Run-123/126 filenames returned ordinary GitHub `404 NOT_FOUND`; a read-only recursive tree lookup resolved the exact paths above. No request/correlation IDs were supplied for those 404s.

Run 259 isolated the missing first arrow

`capability recovery -> accepted witness-dependent representation`

and Run 261 ruled out treating ordinary compact/unique witness maps as the needed source extractor.

This run asks a narrower question:

> Can the missing representation be supplied by a generic smooth projective hash / hash-proof system, or by a generic laconic proof transcript, while remaining a genuinely simpler standard-LWE subprimitive rather than rebuilding witness encryption itself?

The answer is a useful boundary:

1. **Ordinary statistically smooth HPS/SPHF is too restrictive for generic NP.** A statistically secure WE induced from it places the language in SZK. For an NP-complete language this yields the standard polynomial-hierarchy-collapse consequence.
2. **Laconic SHVZK is expressive enough, but it is already WE-equivalent.** Liu–Mazor–Pass prove that, for every `L in NP`, WE for `L` exists iff an efficient-prover `O(log n)`-laconic SHVZK argument for `L` exists.
3. **The recent LWE pr-QA-HPS route does not give the fixed-instance interface.** Its syntax is a *gap-language distribution*: setup supplies a trapdoored language parameter, `SampleL(rho)` samples a YES instance together with a witness, and security is a subset-membership game against samples from that distribution. This is useful for PKE/signatures, but it is not a compiler for an externally fixed arbitrary NP statement `x`.

Therefore another pass trying to "find a generic LWE HPS for the Syscoin relation" or "hash a generic laconic proof transcript" is not a lower-level escape. Either it hits the statistical-SZK barrier, or it constructs a primitive already equivalent to WE, or it only handles a sampled special gap language.

This does **not** prove WE from standard LWE impossible. It identifies which apparently simpler proof/hash routes are not actually simpler.

No production path is changed.

---

## 1. Quantitative statistical-WE -> SZK reduction

The original GGSW witness-encryption paper gives the qualitative theorem:

> if an NP language has statistically sound witness encryption, then the language is in SZK.

The proof is short enough to restate quantitatively.

Let `Enc_b(x)` be the ciphertext distribution encrypting bit `b` under statement `x`. For a true `x`, fix any valid witness `w` and let `D_w` be the deterministic bit output by decryption.

Assume correctness

\[
\Pr_{c\leftarrow Enc_0(x)}[D_w(c)=0]\ge 1-\epsilon
\]

and

\[
\Pr_{c\leftarrow Enc_1(x)}[D_w(c)=1]\ge 1-\epsilon.
\]

Let

\[
S_w=\{c:D_w(c)=0\}.
\]

Then

\[
\Pr[Enc_0(x)\in S_w]\ge1-\epsilon
\]

while

\[
\Pr[Enc_1(x)\in S_w]\le\epsilon.
\]

By the variational characterization of total variation distance,

\[
\boxed{
\Delta(Enc_0(x),Enc_1(x))\ge1-2\epsilon.
}
\tag{1}
\]

For a false statement, statistical hiding gives

\[
\Delta(Enc_0(x),Enc_1(x))\le\delta.
\tag{2}
\]

Thus `x` maps to a Statistical-Difference instance consisting of the two efficient encryption samplers. With the standard SZK-complete promise thresholds, any parameters satisfying

\[
1-2\epsilon>\frac23,
\qquad
\delta<\frac13
\tag{3}
\]

already give a reduction to Statistical Difference. Negligible correctness and hiding errors satisfy this by a huge margin.

This is an information-theoretic reduction. It does not depend on whether the adversary is classical or quantum.

The exact checker exhaustively verifies inequality (1) over 25,028 finite distribution/decoder cases; equality is achieved in 942 of them, so the bound is not merely loose bookkeeping.

---

## 2. Consequence for ordinary smooth projective hashing

A standard smooth projective hash function / hash proof system has exactly the functional shape that looked attractive in Runs 255–259:

- secret hash key computes `H`;
- projection key plus **any valid witness** computes the same `H`;
- for a false word, `H` is statistically smooth given the projection key.

As summarized by Liu–Mazor–Pass, every language with such an HPS unconditionally has a witness-encryption scheme, and the HPS/statistical-WE approach only covers languages in SZK. They explicitly note that extending this route to NP-complete languages would imply the standard polynomial-hierarchy-collapse consequence.

For this project that yields a clean rejection rule:

> **Do not target an ordinary statistically smooth generic-NP HPS as the missing public release compiler.**

If it genuinely worked for an NP-complete source relation with the usual statistical smoothness, it would already cross the SZK/PH boundary.

This is stronger than "we have not found the right lattice HPS." It is a complexity-theoretic obstruction to that exact primitive class.

### Scope

This does **not** rule out:

- computational rather than statistical false-instance hiding;
- witness encryption itself;
- non-HPS encodings;
- promise/gap languages;
- a special application relation that independently lies in SZK;
- a construction whose proof relies on a stronger correlated/evasive assumption.

The Syscoin target is intended as a generic NP/source-proof interface, so the generic-NP consequence is the relevant one.

---

## 3. Relaxing to laconic SHVZK does not make the problem easier

One natural reaction is to replace unconditional HPS smoothness/soundness by a computational proof/argument.

The 2024 Liu–Mazor–Pass theorem gives the exact boundary:

For every NP language `L`,

\[
\boxed{
WE(L)
\iff
\text{efficient-prover }O(\log n)\text{-laconic SHVZK argument for }L.
}
\tag{4}
\]

Their statistical version similarly relates statistically secure WE to laconic SHVZK proofs.

This matters because a witness-dependent proof token with a very short prover response is almost exactly the representation family we were considering:

- verifier randomness/public first message fixes the public context;
- a witness produces the short response;
- a simulator supplies the false-instance security hybrid;
- a deterministic/predictable response would naturally serve as a common key-bearing token.

Equation (4) says that a generic construction of that object is already a construction of WE. It is not a lower-level standard-LWE gadget that can be assumed available and then wrapped into WE.

The paper further explains that predictable arguments / deterministic-prover SHVZK sit on the same side of this boundary. Thus making the transcript unique or deterministically recoverable from verifier randomness does not evade the core problem; it moves directly toward the known WE-equivalent regime.

### QPT qualification

The cited equivalence is formulated in the source paper for polynomial-time classical security notions. This run does **not** promote it to an arbitrary-QPT equivalence theorem.

The conclusion used here is weaker and safe:

> even classically, a generic laconic-SHVZK construction is already WE-level power.

A PQ endpoint would need the corresponding arguments, simulators and reductions audited against QPT adversaries.

---

## 4. Why current LWE pr-QA-HPS does not supply the fixed source interface

Han–Liu–Wang–Gu construct probabilistic quasi-adaptive HPS from LWE, but the source syntax is materially different from the fixed-statement WKEM requirement.

Their `Gap Language Distribution` samples `(rho,td_rho)` and supplies:

- `SampleL(rho)`, which outputs an instance from the YES language **together with a witness**;
- `SampleX`, which samples from the ambient universe;
- `CheckLe(rho,td_rho,x)`, which recognizes membership in an extended gap language.

The hardness problem distinguishes random samples from those distributions. Their concrete LWE instantiation is a short/noisy linear-relation gap language.

This does not provide

\[
\text{given arbitrary externally fixed }x,
\quad
P_x\leftarrow Build(x)
\]

with no source witness and with all valid ORIGINAL witnesses projecting to the same protected capability.

### Fixed-instance sampling lemma

Suppose a security reduction only knows how to obtain `(x,w)` by drawing from `SampleL`. If a target fixed `x*` occurs with probability `p_{x*}`, rejection sampling needs expected

\[
\boxed{1/p_{x*}}
\tag{5}
\]

samples to hit it.

If the YES sampler has `h` bits of effective min-entropy and `p_{x*}\le2^{-h}`, this is at least `2^h`.

For `h` polynomial in the security parameter, sampling a random YES pair is therefore not a generic method for programming one externally fixed source-hard instance.

The checker records this arithmetic through `h=256`; after only `h^4` sampler calls, the elementary union bound on hitting one fixed target is at most `h^4 2^{-h}`.

This is not an attack on pr-QA-HPS. Its intended PKE/signature use generates its own sampled language elements. It is an interface mismatch with this project.

---

## 5. Route trichotomy

The current proof/hash approaches now separate cleanly.

### Route A — ordinary statistically smooth HPS

Desired convenience:

- every witness computes one projective hash;
- false words have statistical smoothness.

Barrier:

\[
\boxed{L\in SZK.}
\]

Generic NP-complete use therefore has the standard PH-collapse consequence.

### Route B — laconic SHVZK / predictable proof token

Desired convenience:

- compact witness-dependent prover response;
- simulator supplies hiding;
- deterministic/predictable form can canonicalize the response.

Boundary:

\[
\boxed{\text{laconic SHVZK for }L \iff WE(L)}
\]

in the cited classical theorem.

This is a valid *way to construct WE*, but not a simpler primitive whose existence follows from standard LWE by currently known generic techniques.

### Route C — sampleable LWE gap-language HPS

Desired convenience:

- concrete standard-LWE algebra;
- strong projective-hash machinery;
- efficient trapdoors and probabilistic evaluation.

Mismatch:

- setup/security samples its own YES instance+witness;
- relation is a special noisy linear gap language;
- no arbitrary fixed `x -> public release encoding` compiler or ORIGINAL-source extraction is provided.

---

## 6. Interaction with Runs 123, 126 and 259

Run 123 identified a sufficient true-instance extraction interface:

\[
\text{FINAL-key recovery}
\Longrightarrow
\text{correct hidden canonical value in Ext mode}
\Longrightarrow
w_{\rm ORIGINAL}
\]

provided the hash and extraction modes have statistically close complete public views and the canonical target is mode-independent.

Run 126 then proved the extraction target must be **evasive from the Ext secret itself**; if Ext mode can conditionally resample a compatible hash secret/target, setup can solve the source relation.

Run 259 supplies the final source-binding arrow:

\[
\text{accepted global representation}
\Longrightarrow
w_{\rm ORIGINAL}
\]

information-theoretically with sufficient global folding or under an exact QPT-SIS assumption via an Ajtai residual hash.

Run 262 says ordinary HPS/proof-system technology does not cheaply fill the missing middle:

- statistical HPS is too weak expressively for generic NP;
- laconic SHVZK is already WE-equivalent;
- current LWE QA-HPS is for a sampled special gap language.

So the remaining useful research object is still a **nonstandard, extractable, mutually incompatible dual-mode release representation** or a direct WE construction with a full QPT reduction. Calling it "HPS" or "laconic proof" does not remove that obligation.

---

## 7. Reproducible checker

`hps_szk_laconic_we_barrier_run262_check.py` is deterministic and standard-library only.

Final validation:

- `/usr/bin/python3 -m py_compile` passed;
- two complete executions were byte-identical;
- 25,049 explicit assertions;
- 25,028 exhaustive finite distribution/decoder cases for
  `TV(Enc0,Enc1) >= 1 - 2*correctness_error`;
- 942 exact-tightness cases;
- standard `2/3` versus `1/3` Statistical-Difference threshold arithmetic;
- fixed-instance rejection-sampling arithmetic through 256 bits of sampler min-entropy;
- route-classification sanity checks.

The checker validates only exact finite probability/combinatorics. It does not prove the cited literature theorems, a complexity-class separation, LWE/SIS hardness, or arbitrary-QPT security.

---

## 8. QPT/security ledger

| Component | Model | Assumption | Exact conclusion |
|---|---|---|---|
| quantitative true-ciphertext TV bound | information-theoretic | none | correctness error `epsilon` gives `TV >= 1-2 epsilon` |
| false statistical hiding | information-theoretic | scheme premise | false instance gives `TV <= delta` |
| statistical-WE -> SZK | classical complexity / statistical distributions | cited GGSW theorem; rederived parameter gap | statistically secure WE for `L` places `L` in SZK |
| standard HPS generic-NP route | information-theoretic smoothness | HPS premise | inherits statistical-WE/SZK barrier |
| laconic SHVZK <-> WE | source theorem uses classical polynomial-time notions | Liu–Mazor–Pass 2024 | generic laconic SHVZK is already WE-level; QPT lift not claimed |
| LWE pr-QA-HPS | source theorem uses its stated classical/PPT security model | standard LWE in source | concrete sampled gap-language HPS; no fixed arbitrary-NP interface established |
| fixed-instance sampler mismatch | information-theoretic | none | hitting a target of probability `p` by rejection sampling costs expected `1/p` |
| required PQ WKEM | arbitrary QPT | still missing | **UNPROVED** |

No PPT-only theorem is relabeled as QPT security.

---

## 9. Core handoff

Do **not** spend another pass searching for a conventional statistically smooth generic-NP HPS. That exact route has an SZK barrier.

Do **not** treat a generic `O(log n)`-laconic SHVZK/predictable proof system as a lower-level replacement for WE. The cited theorem says it is already WE-equivalent classically.

Do **not** treat a sampleable LWE gap-language HPS as a fixed-instance compiler unless an exact reduction explains how to bind an externally supplied source-hard `x` without already knowing its witness.

The next bounded constructive pass should instead target one of two things:

1. a direct **computational** dual-mode release encoding whose true canonical target is mutually exclusive with the extraction trapdoor and whose complete false-instance view reduces straight-line to standard QPT-LWE/SIS; or
2. a direct WE-style construction where capability recovery yields a representation that Run 259 can source-bind, accepting explicitly that this is the central WE problem rather than an HPS wrapper problem.

The practical generic-NP public/offline PQ witness-KEM stopping condition remains **unmet**.

## Sources

- Live repository dependencies listed in the checkpoint above.
- Garg, Gentry, Sahai, Waters, *Witness Encryption and its Applications*, ePrint 2013/258, especially Section 6.1 / Lemma 6.1: https://eprint.iacr.org/2013/258.pdf
- Yanyi Liu, Noam Mazor, Rafael Pass, *On Witness Encryption and Laconic Zero-Knowledge Arguments*, ePrint 2024/1932, especially Theorem 1.1: https://eprint.iacr.org/2024/1932.pdf
- Shuai Han, Shengli Liu, Zhedong Wang, Dawu Gu, *Almost Tight Multi-User Security under Adaptive Corruptions from LWE in the Standard Model*, ePrint 2023/1230, especially Definition 1 and Section 6: https://eprint.iacr.org/2023/1230.pdf
