# Run 114 — linear HPS/WPRF restricted-witness dichotomy

## Status and handoff

Verified PR head at the start of this run:

`a0803edfa691f184e33ca92620471a81c17c611c`

on branch `research/pq-wkem-validation-20260918`; PR #1 was open, draft, and unmerged.

This run follows Run 113's WPRF handoff. It corrects one omission in that handoff: there is already a substantial literature on **Hash Proof Systems / Smooth Projective Hash Functions (HPS/SPHF)** whose syntax is essentially a restricted-language witness PRF:

- a secret hashing key `hk`;
- a public projection key `hp`;
- a secret hash `Hash(hk,W)`;
- a witness algorithm `ProjHash(hp,W,w)`.

For exact correctness, every valid membership witness computes the same hash value. Smoothness on false words is the analogue of WPRF pseudorandomness. Lattice- and code-based post-quantum *candidate* HPS constructions therefore deserve to be treated as existing restricted-language WPRF candidates, not rediscovered from scratch.

The main new result here is a complete unconditional characterization of the simplest public linear projective-hash form. It shows exactly why adding a nonlinear/short/Boolean source-witness restriction on top of a public linear projection recreates the project's established pseudowitness/public-quotient failure.

No production path is changed.

---

## 1. Literature correction: HPS already has the WPRF-shaped interface

Bettaieb--Bidoux--Blazy--Connan--Gaborit, ePrint 2021/026, Definition 19 defines an HPS using `Setup`, `HashKG`, `ProjKG`, `Hash`, and `ProjHash`; the projected hash takes the public projection key, word, and a membership witness. Their hard-subset-membership definition also explicitly includes efficient sampling of language words **together with witnesses**.

Benhamouda--Blazy--Ducas--Quach, ePrint 2017/997, builds lattice SPHFs for standard LWE-ciphertext languages. Their relaxed witness-encryption application is explicitly for restricted ciphertext-derived languages rather than NP-complete languages; for the false words covered by their smoothness language, they state statistical soundness.

So Run 113's phrase “search for a PQ restricted-language WPRF” was too broad. Such WPRF-shaped objects already exist under lattice/code assumptions. What remains missing is the **generic-NP source-preserving witness compiler plus arbitrary-QPT process extraction**.

The distinction is crucial because the concrete HPS languages are normally ciphertext/local-opening languages, not arbitrary source NP relations.

---

## 2. Exact linear projective hash

Work over a finite field `F_q`. Let

`A in F_q^(m x n)`

be public. Let the hashing key be uniform

`a <- F_q^m`.

Publish the projection key

`p = A^T a in F_q^n`.

For a public word `x in F_q^m`, define the secret hash

`H = a^T x`.

If a witness `w` satisfies

`A w = x`,

then the public projected evaluation is

`p^T w`.

Correctness is exact:

`p^T w = a^T A w = a^T x = H`.

This already has the desired all-witness common-value property: if `w1,w2` are two different representations of the same `x`, both output the same `H`.

### Theorem 1 — complete conditional law

Condition on a fixed public projection key `p=A^T a`.

1. If `x in im(A)`, then `H=a^T x` is completely determined by `(A,p,x)`.
2. If `x notin im(A)`, then `H` is exactly uniform in `F_q`, even conditioned on `(A,p,x)`.

#### Proof

If `x=A u`, then

`H=a^T A u = p^T u`.

Any public linear-system solution `u` therefore recovers the hash.

Now let `x notin im(A)`. The fiber of hashing keys with the same projection key is an affine coset of

`ker(A^T)=im(A)^perp`.

Because `x notin im(A)=(ker A^T)^perp`, there exists `z in ker(A^T)` with `z^T x != 0`.

For every key `a` in the fiber and every `t in F_q`,

`A^T(a+t z)=p`

while

`(a+t z)^T x = a^T x + t(z^T x)`.

As `t` ranges over `F_q`, this sweeps every hash value exactly once. Hence the conditional hash is uniform. QED.

This theorem is information-theoretic. Its adversary model is unbounded; it is therefore automatically valid against QPT adversaries.

---

## 3. Restricted-witness dichotomy

Now try to turn the easy linear membership relation into a hard source relation by allowing only a structured set of witnesses

`S subset F_q^n`

—for example Boolean, low-Hamming-weight, short, sparse, low-rank encoded, or another source-derived subset.

Define the intended language

`L_S = { A w : w in S }`.

### Theorem 2 — restricted-witness dichotomy

For the public linear projective hash above:

- if `L_S` is a strict subset of `im(A)`, then there exists an **intended false word** whose hash is publicly recoverable;
- the hash is hidden on every intended false word only if

`L_S = im(A)`.

#### Proof

Always `L_S subseteq im(A)`.

If the inclusion is strict, choose

`x in im(A) \ L_S`.

By definition, `x` has **no valid structured witness**, so it is false for the intended source language.

But because `x in im(A)`, public linear algebra returns some unrestricted `u` with

`A u=x`.

Then Theorem 1 gives

`H=p^T u`.

Thus the secret hash is exactly public on an intended false statement.

Conversely, if every intended false word lies outside `im(A)`, no point of `im(A)` can be outside `L_S`. Since `L_S subseteq im(A)`, this forces equality. QED.

### Consequence

A nontrivial structured-witness restriction cannot simply be grafted onto the public linear HPS relation.

Either:

1. the restriction is genuine, so false source statements remain in the public linear image and admit unrestricted **pseudowitnesses** that recover the key; or
2. there are no such pseudowitnesses because the intended language equals the whole public image, in which case the restriction no longer defines a hard source language.

This is the HPS/WPRF version of the public-quotient and pseudorepresentation failures already retained in the research record.

It is **not** a general impossibility theorem for all HPS/SPHF constructions. It rules out the plain public-linear projection strategy for enforcing a strict source-witness predicate.

---

## 4. Why this matters for Hair–Sahai / rank-gated approaches

The same structural issue appears when the public object admits a large linear span but only low-rank/Boolean-factor representations are meant to count as valid source witnesses.

If the projected hash depends only on a public unrestricted representation in that span, then a high-rank or otherwise invalid representation can still evaluate the hash. The semantic theorem

`supplied low-rank representation -> ORIGINAL witness`

does not stop an adversary from using an unrestricted public representation unless the hash evaluation itself is witness-restricted.

Therefore Hair–Sahai's supplied-low-rank extractor remains useful, but the release layer must cryptographically enforce the low-rank/source restriction; a plain linear HPS over the ambient span does not do it.

---

## 5. What the lattice/code HPS literature genuinely contributes

### Lattice SPHF, ePrint 2017/997

The paper constructs SPHFs for standard LWE ciphertext languages. Its high-level linear relation is close to the theorem above but includes small error and rounding. It explicitly describes approximate correctness and then amplifies/decodes it for applications.

The important positive is that HPS gives exactly the desired **secret-hash / witness-projected-hash** decomposition.

The important limitation is that its witness-encryption application is only for restricted ciphertext-derived languages, not generic NP. The paper's generic-any-NP use is instead a **three-round honest-verifier zero-knowledge protocol**: the prover first commits/encrypts every circuit wire, the verifier then computes projection keys for those commitments, and only then can the prover answer using the wire witnesses.

That dependency order is doing real work. It is not an offline setup in which the statement is known but the future witness is absent.

### RQC HPS, ePrint 2021/026

The paper again exposes the exact HPS syntax and constructs witness encryption for the RQC ciphertext-membership language. Its hard-subset language is explicitly efficiently samplable together with a witness.

Its computational KV-smoothness theorem is under `2-IRSD` and decisional `FIRSD`. The displayed proof is a straight-line game sequence, but the paper's smoothness definition maximizes over polynomial-time adversaries and the FIRSD assumption is an additional code-specific assumption. This run does **not** upgrade that theorem to arbitrary-QPT security or treat FIRSD as independently justified QPT hardness.

The later HQC Hamming-metric HPS literature advertises a gapless post-quantum HPS and standard-model witness encryption, but no full theorem-level QPT audit is imported here.

---

## 6. Public samplability and source extraction

HPS hard-subset languages are often deliberately `L`-samplable: an efficient sampler outputs `(W,w)` with `w` a valid HPS membership witness.

That is useful for cryptographic protocols, but it sharpens Run 113's source barrier.

Suppose a generic-NP compiler mapped a source statement `x_src` to an ordinary HPS word `W` and had the property that **every ordinary HPS witness** for `W` mapped efficiently to an ORIGINAL witness for `x_src`.

If the compiler or a public language sampler can already produce an ordinary HPS witness for that `W`, then composition immediately solves the original witness-search problem.

Therefore the desired compiler cannot merely reuse an ordinary publicly samplable ciphertext-opening relation and assert that its openings are source witnesses. It needs a strict witness-derived subclass or a different process-extraction interface.

The linear theorem above then shows why the most obvious “strict subclass of public linear openings” repair fails: unrestricted openings become pseudowitnesses that reveal the projected hash.

---

## 7. Approximate correctness is not automatically a WPRF

Several post-quantum HPS constructions are approximate:

`Hash(hk,W)` and `ProjHash(hp,W,w)`

are close rather than exactly equal.

That is enough for applications that apply an error-correcting decoder, but our WKEM target requires every valid witness to recover the same final key with overwhelming probability.

A decoder/canonicalizer therefore becomes part of the public output and must itself be audited.

This is not a merely cosmetic step. Run 110 already showed that for a powers-of-two gadget, ordinary small-noise public projection lies inside a public secret-recovery radius whenever the worst-case noise is small enough for standard decoding correctness.

Thus “use an approximate lattice HPS and decode” is a candidate interface, not an automatic solution.

---

## 8. QPT/security ledger

### New linear theorem

- Honest algorithms: classical polynomial-time linear algebra.
- Adversary: unbounded.
- Hardness assumption: none.
- Reduction model: direct algebra, no oracle, no rewinding, no extraction.
- Conclusion: exact correctness plus complete statistical characterization; classical public attack on restricted false words.

Because the attack is classical polynomial-time, any candidate it breaks also fails the QPT target.

### Benhamouda–Blazy–Ducas–Quach restricted WE

- Honest algorithms: classical PPT.
- False-word hiding for the stated outer smoothness language: the paper states statistical soundness for its restricted WE, so that particular statistical claim is adversary-model independent.
- Scope: restricted ciphertext-derived languages with a correctness/soundness gap, explicitly not generic NP.
- Generic NP result in the paper: interactive three-round HVZK, not offline witness release.

### RQC HPS

- Honest algorithms: classical PPT.
- Stated adversary model: polynomial-time adversaries in the computational KV-smoothness definition.
- Hardness: 2-IRSD + decisional FIRSD.
- Quantum status here: UNPROVED. No silent PPT->QPT substitution.
- Conclusion: useful restricted-language HPS architecture, not a generic-NP arbitrary-QPT source extractor.

### Final project obligations unchanged

Still missing:

1. a public/offline generic-NP compiler whose projection is genuinely witness-restricted rather than ambient-linear;
2. arbitrary-QPT final-key recovery -> ORIGINAL source witness or an independently justified QPT-hard break;
3. malicious-secure erased setup/abort and auxiliary-input composition;
4. concrete practical parameters.

The stopping condition is not met.

---

## 9. Reproducible validation

`linear_hps_wprf_run114_check.py` is deterministic and standard-library-only.

Two finalized executions were byte-identical.

It checks **69,272 assertions**, including:

- exact all-witness projective-hash equality;
- the complete conditional law `H | p` for every tested matrix/word/key fiber over `F_2`, `F_3`, and `F_5`;
- 2,112 structured-witness language cases using Boolean, low-Hamming-weight, and coordinate restrictions;
- 41,712 explicit public-pseudowitness hash recoveries on intended false words;
- 740 public linear-membership solution controls;
- approximate-correctness arithmetic controls.

These tests validate finite algebra only. They do not establish security of any computational HPS construction.

---

## 10. Next handoff

The next constructive target should not be “find a restricted-language WPRF” in the abstract; HPS already supplies that syntax.

The sharper target is:

**build a post-quantum HPS/WPRF whose projected evaluation is bound to a nonlinear source-validity predicate, while any ambient/public pseudowitness is useless, and whose arbitrary-QPT key recovery is process-extractable to an ORIGINAL source witness.**

Two paths are worth testing next:

1. whether lattice HPS smoothness can be made sensitive to a short/rank-constrained witness **without** exposing a public unrestricted projection or entering Run 110's public decoding radius; and
2. whether Hair–Sahai's low-rank source extractor can be used inside the projected-hash relation itself, rather than merely after a supplied representation has already been obtained.

Any construction in which the public projection factors through a public linear ambient witness should now be rejected immediately by Theorem 2.
