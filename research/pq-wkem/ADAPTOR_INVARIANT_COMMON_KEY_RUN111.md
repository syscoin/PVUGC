# Run 111 — adaptor common-value boundary: supplied completion extracts NP witnesses, but unique/full-signature common keys are impossible

## Status

Verified starting PR head:
`568446e21cedb83c07c20227cd9c443f51fabb82`
on branch `research/pq-wkem-validation-20260918`.
PR #1 was open, draft, and unmerged.

The latest substantive ordinary PR comment is `5842442762`, recording verified
publication of Run 109. Run 110 remains local-only after its safety-blocked
publication attempt; this run does not retry, rename, split, encode, or reroute that
payload.

This run follows the current hidden-input release handoff by testing a fresh 2026
primitive that appears unusually close to the missing true-instance requirement:
**adaptor signatures for arbitrary NP relations from Online/Offline NIZK**.

The positive news is real:

> a completed adaptor signature can be a supplied object from which a witness to an
> arbitrary NP relation is extractable.

That is much closer to the desired

\[
\text{released capability}\Longrightarrow\text{ORIGINAL witness}
\]

than ordinary encryption, ABE, or two-party sharing.

The negative result is equally sharp:

> the obvious way to turn completion into an offline same-key KEM is to use the
> completed signature, or a hash/hardcore image of it, as the common hidden value.
> This clashes with the fact that adaptor signatures fundamentally require
> non-unique signatures.

Erwig--Faust--Hostáková--Maitra--Riahi prove that a secure adaptor signature cannot
be built from a **unique signature scheme** for a hard relation.  The proof is
exactly the obstruction relevant here: the signer can produce the unique ordinary
signature by itself; because every successful adaptation must produce that same
signature, feeding it to the adaptor extractor reveals the hard-relation witness
without knowing one.

This closes a tempting route in which a unique post-quantum signature would have
served as the witness-independent KEM key.

A weaker possibility survives: all completed signatures could be non-unique while
sharing a hidden **invariant** value.  Goldwasser--Ostrovsky studied precisely such
"invariant signatures": all legal signatures agree under a polynomial-time
computable function, while the invariant is hard to predict from the unsigned
message.  But ordinary adaptor-signature extraction consumes the **full completed
signature**, not merely that invariant.

So the new target becomes an **extractable invariant adaptor**:

* every valid future witness produces some full completion;
* all completions have the same hidden invariant;
* the setup side can derive that invariant before erasure;
* arbitrary QPT recovery of the invariant yields a full completion or an ORIGINAL
  source witness.

No cited construction in this run supplies that final arrow.

No production path is changed.

---

## 1. New 2026 adaptor-signature result

Abe--Bui--Cong--Ohkubo--Shang--Takahashi--Tibouchi,
*Practical Adaptor Signatures for NP from Online/Offline NIZK*,
ePrint 2026/2155 / ASIACRYPT 2026, gives a practical adaptor-signature framework for
arbitrary NP relations.

The public abstract states the core functionality:

* a pre-signature is bound to a public instance `Y`;
* any party knowing `y` with

  \[
  \mathcal R(Y,y)=1
  \]

  can complete it into a valid signature;
* the pre-signature and full signature together allow the signer to extract `y`;
* the new Online/Offline NIZK separates proof work into offline and online parts;
* knowing the offline randomness permits extraction of the witness from the online
  part;
* the authors instantiate the AES-128 relation using VOLE-in-the-Head and the FAEST
  post-quantum signature scheme.

This is a genuine supplied-completion-to-NP-witness interface.

The full current 2026/2155 manuscript was not retrievable through the primary PDF
path in this run, so no theorem-level claim beyond the indexed current abstract is
imported.  In particular, the complete framework is not silently labeled QPT-secure
merely because the concrete signature component is FAEST.

---

## 2. Natural offline-KEM transform and its exact common-value condition

Abstract an adaptor scheme by a public pre-signature `pre` and a completion algorithm

\[
\sigma_w
\leftarrow
\mathsf{Adapt}(pre,w;\rho)
\]

for valid witnesses.

Suppose setup chooses a raw key `K` and tries the most direct one-mask construction:

\[
C=K\oplus z_0,
\tag{1}
\]

while witness `w` decapsulates via a public map `F`:

\[
K_w=C\oplus F(\sigma_w).
\tag{2}
\]

For **every** valid witness and every allowed completion randomness to recover the
same setup key `K`, it is necessary and sufficient that

\[
\boxed{
F(\sigma_w)=z_0
\quad
\text{for every valid completion.}
}
\tag{3}
\]

So the image of all valid completions under `F` must be a singleton.

This is the exact all-witness correctness condition.

If the final key is simply the full completed signature, then `F` is the identity and
(3) requires every valid completion to be identical.

That is the unique-signature route.

---

## 3. Unique-signature adaptor signatures are impossible

Erwig et al., PKC 2021, prove:

> Let `R` be a hard relation and `SIG` a signature scheme with unique signatures.
> Then there is no secure adaptor-signature scheme for `R` over `SIG`.

Their proof is directly relevant.

The attacker, given a hard relation instance `Y`:

1. generates its own signing key pair;
2. chooses a message `m`;
3. generates a pre-signature on `(m,Y)`;
4. generates an ordinary signature

   \[
   \sigma=\mathsf{Sign}_{sk}(m);
   \]

5. runs the adaptor extractor on `(pre,\sigma,Y)`.

Because the underlying signature is unique, any successful adaptation must produce
the exact same ordinary signature `σ`.  Adaptor correctness/extractability therefore
makes the extractor return a witness for `Y`, contradicting hardness.

Thus:

\[
\boxed{
\text{full adapted signature as the same key for all witnesses}
}
\]

cannot be obtained by selecting a unique-signature scheme and then building a
standard secure adaptor signature over it.

This is not only a classical-security issue.  The contradiction is a classical PPT
attack, so the same candidate is ruled out against QPT adversaries a fortiori.

---

## 4. Random hashing or Goldreich--Levin bits do not fix all-witness correctness

A second idea is to allow distinct full signatures but derive the key as random linear
or Goldreich--Levin bits of their encodings.

Let two valid witnesses produce distinct bit strings

\[
\sigma_1\ne\sigma_2\in\mathbb F_2^N.
\]

For a uniform `r`,

\[
\Pr_r[
 \langle r,\sigma_1\rangle
 =
 \langle r,\sigma_2\rangle
]
=
\frac12.
\tag{4}
\]

For `kappa` independent rows,

\[
\boxed{
\Pr[
 H_R(\sigma_1)=H_R(\sigma_2)
]
=
2^{-\kappa}.
}
\tag{5}
\]

So a normal random-linear/GL extraction of `kappa` bits almost certainly makes two
different valid completions derive **different KEM keys**.

This is the opposite of the required every-witness same-key correctness.

Run 102's quantum Fourier/GL machinery is still useful for turning response
correlation into extraction, but it cannot manufacture the common value: before GL
can be used as the final key layer, the valid completions must first be
canonicalized/invariant.

This is an important correction to a tempting composition of Run 102 with adaptor
signatures.

---

## 5. The surviving weaker object: invariant signatures

Goldwasser--Ostrovsky define an **invariant signature** as a signature scheme for
which all legal signatures of a document are identical under a polynomial-time
computable function `I`, while the invariant is hard to predict from an unsigned
document.

Thus a non-unique signature scheme can still have

\[
I(\sigma_1)
=
I(\sigma_2)
=
\cdots
=
Z_m.
\tag{6}
\]

This is exactly the common-value condition (3) without demanding a unique full
signature.

The old work shows a classical equivalence between invariant signatures and
non-interactive zero knowledge.

That makes invariant signatures a much better conceptual match than unique
signatures.

But two additional properties are needed for this project.

### 5.1 Pre-signature invariant hiding

The setup publishes an adaptor pre-signature bound to `Y`.

Ordinary invariant-signature unpredictability is defined from an **unsigned**
document.  Our adversary receives strictly more correlated information:

\[
(pk,m,Y,pre).
\]

We therefore need

\[
Z_m=I(\sigma)
\]

to remain hidden against arbitrary QPT adversaries **given the entire pre-signature
view**.

No such theorem is imported from the invariant-signature literature or from the
2026 adaptor abstract.

### 5.2 Invariant recovery must source-extract

The standard adaptor extractor takes a **full signature** together with the
pre-signature.

If an adversary only recovers

\[
Z_m=I(\sigma),
\]

the existing extractor has no syntactic input to consume.

Therefore the true-instance requirement needs an additional reduction

\[
\boxed{
\text{recover invariant }Z_m
\Longrightarrow
\text{full valid completion or ORIGINAL witness}.
}
\tag{7}
\]

Without (7), invariant recovery is another supplied-value endpoint rather than the
desired arbitrary-QPT source extractor.

So the missing primitive is not ordinary invariant signatures, ordinary adaptor
signatures, or their names placed side by side.  It is an **extractable invariant
adaptor** with explicit QPT guarantees.

---

## 6. Why using a normal hash of the completed signature does not solve extraction

Suppose setup uses

\[
K=H(\sigma)
\]

for a public compression/hash.

Even ignoring the all-witness disagreement from Section 4, an adversary that recovers
`K` has not supplied `σ`.

Adaptor extraction needs `σ`.

Preimage resistance says that recovering a preimage should be hard; it does not give
a reduction that transforms the recovered hash output back into a signature.

A quantum-valid Goldreich--Levin style reduction can extract an underlying string
from a **predictor for many random linear predicates** of that same string.  Exact
recovery of one conventional hash output is a different interface.

Thus a non-injective KDF/hash wrapper remains a separate theorem obligation, matching
the boundary already recorded in Run 102.

---

## 7. Positive use of Online/Offline NIZK randomness in a ceremony

There is nevertheless a useful component in the 2026 construction.

The abstract says the witness can be extracted from the online NIZK part **knowing the
randomness used in the offline part**.

This fits the project's allowed setup model better than an online release server:

* a distributed ceremony may temporarily generate offline randomness;
* at least one honest participant can contribute entropy;
* the public pre-signature/offline proof material can remain after setup;
* the temporary extraction randomness may be erased operationally;
* a security reduction can conceptually retain the extraction trapdoor/randomness.

If a future construction made unauthorized FINAL-key recovery yield a valid online
completion, this architecture could provide the desired

\[
\text{completion}\Longrightarrow\text{NP witness}
\]

step without requiring honest users to have quantum hardware.

The unsolved arrow remains

\[
\text{FINAL-key recovery}
\Longrightarrow
\text{completion}.
\]

This is narrower than the original source-transfer problem and worth retaining.

---

## 8. Fresh Batch IT-MAC result: programmed randomness is not offline completion

Liu--Liu,
*Batch IT-MAC: Program the Randomness in Succinct VOLE*,
ePrint 2026/2159 (24 September 2026), addresses a closely related dependency problem.

The public abstract starts from affine tags

\[
\boldsymbol\sigma
=
\Delta\boldsymbol x+\boldsymbol k
\]

and notes that previous succinct chosen-input VOLE did not let the authenticator key
`k` be fixed in advance.

Their new batch-MAC permits the key vector to be generated beforehand from a short
seed and later authenticates a chosen message vector with **two messages**.  The
abstract gives:

* \(O(m^{2/3}\lambda)\) communication under DCR;
* \(\operatorname{poly}(\log m,\lambda)\) communication under LWE;
* a CRS in both cases;
* applications to constrained PRFs, 2-message 2PC, and succinct ZK.

This is useful evidence that "fix correlated randomness before the future input" is
not inherently impossible under LWE.

But it remains a **two-message** primitive.

The later input still enters a later message.  It therefore does not supply the
public noninteractive completion token required when nobody remains online after
setup.

The full 2026/2159 proof was not available through the primary PDF path in this run,
so the exact adversary model and any QPT theorem are left unverified.

---

## 9. Relation to the current lattice/EPHF path

Runs 108--110 narrowed the lattice functional-commitment route to a hidden-input
source-extractable projection mechanism:

* exact gadget basis projection leaks the target hash;
* affine linearization admits gadget pseudowitnesses;
* ordinary small-noise gadget projection remains publicly decodable.

Run 111 reaches the same missing object from a completely different direction.

Adaptor signatures already give:

\[
\boxed{
\text{full valid completion}
\Longrightarrow
\text{NP witness}.
}
\]

What they do not give is a **common hidden completion value** that:

1. setup can compute without a witness;
2. every valid witness can derive;
3. false instances hide against QPT;
4. arbitrary QPT recovery source-extracts.

That is almost exactly the hidden-input EPHF/WPRF capability isolated by Runs
107--110.

The convergence is useful: two unrelated literatures are now pointing to the same
primitive boundary rather than to another transport or source compiler.

---

## 10. Exact validation

`adaptor_invariant_common_key_run111_check.py` is deterministic and
standard-library-only.

Finalized executions are byte-identical.

It verifies:

1. the exact one-mask common-value condition for all small valid-witness sets;
2. the semantic equality/extraction skeleton of the unique-signature adaptor
   impossibility;
3. explicit non-unique completion families sharing one invariant while the ordinary
   adaptor extractor still requires the full completion;
4. for every pair of distinct bit strings through seven bits, exact one-row
   Goldreich--Levin collision probability `1/2`;
5. exact multi-row controls confirming `kappa` GL bits collide with probability
   \(2^{-\kappa}\);
6. a two-message affine-MAC dependency toy showing that pre-fixing authenticator
   randomness does not remove the later chosen-input message.

These are finite functionality/algebra checks.  The unique-signature impossibility
itself is a literature theorem, not inferred from the checker.

---

## 11. QPT/security ledger

### Unique-signature shortcut

Refuted unconditionally for standard adaptor signatures over a hard relation by a
classical PPT attack from Erwig et al.

Therefore it is also refuted for the project's QPT target.

### 2026 Online/Offline-NIZK adaptor framework

The indexed abstract provides arbitrary-NP completion/extraction functionality and a
concrete AES-128 instantiation using FAEST.

The full current theorem was not audited from the primary manuscript in this run.
No blanket QPT-security claim is made.

### Invariant signatures

The definition and NIZK equivalence are classical historical results.

No QPT pre-signature-invariant-hiding theorem or QPT invariant-to-witness extractor is
imported.

### Random linear / GL final-key wrapper

For distinct completions, all-witness key equality occurs with probability
\(2^{-\kappa}\), so this direct wrapper fails correctness rather than security.

Run 102 remains relevant only **after** a common underlying value exists.

### Batch IT-MAC

The fresh abstract gives an LWE-based polylog-communication two-message construction,
but the exact QPT adversary model is unverified and the primitive remains interactive.

### Still unproved

1. an efficient extractable invariant adaptor from independently justified QPT-hard
   assumptions;
2. pre-signature hiding of the common invariant against arbitrary QPT attackers;
3. arbitrary-QPT invariant/FINAL-key recovery -> ORIGINAL witness;
4. malicious-secure setup/abort and auxiliary-input composition for a complete
   construction;
5. practical end-to-end resources.

The stopping condition is not met.

---

## 12. Next handoff

Do not pursue a unique-signature adaptor route; it is formally impossible under the
standard adaptor definition.

The most concrete surviving target is:

\[
\boxed{
\text{extractable invariant adaptor}
}
\]

or an equivalent hidden-input source EPHF/WPRF.

Three questions should drive the next pass:

1. Can a **post-quantum invariant signature** be composed with an adaptor-like
   supplied-completion extractor without falling into the Erwig uniqueness
   contradiction?
2. Can Online/Offline NIZK offline randomness serve as an erased extraction trapdoor
   while the public object exposes only a witness-invariant completion value?
3. Can Run 102's one-copy QPT extractor be adapted from random-linear predicates of a
   hidden string to a predictor for that invariant, so that FINAL-key recovery yields
   a full completion rather than only a compressed value?

Any proposal that uses the full completed signature as a universal same key, or
hashes distinct completions with ordinary random/GL hashing and assumes they agree,
should be rejected immediately.

The practical generic-NP PQ WKEM remains open.
