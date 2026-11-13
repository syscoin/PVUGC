# Run 55 — hidden local selectors do not bind a common representation: a public pseudowitness list defeats the sparse-test repair

## Status

Starting verified PR head: `88792d576d2699dbe0fb5e03cb76fcbca1868e0c` (Run 54).

Run 53 produced a useful local semantic primitive: every honest local 3-CNF block is one-hot with squared norm `1`, while the explicit signed lift of a violated block has squared norm `7`. Its failure was **componentwise switching**: if component `j` publicly announces that it tests block `j`, a false attacker can use a different exact signed representation whose tested block is one-hot.

Run 54 tried to bind the component representations with hidden telescoping edge pads. The semantic idea worked, but the natural linear native-preimage realization let the complete public transcript cancel those pads before witness evaluation.

This run tests a different repair:

> keep the tested block itself secret.

A share capsule chooses a hidden local block (or hidden subset of blocks) and amplifies the error on those coordinates. A real source representation is one-hot in every block, so it is intended to decode for every selector. A false signed representation is large only in its malformed block, so if the selector hits that block it is intended to fail.

One possible implementation motivation would be to hide the selector inside an LWE-pseudorandom outer sample. This run deliberately gives that idea **more power than a concrete LWE implementation**: first assume the selector is perfectly hidden. The complete-output audit still breaks the sparse-selector design on the Run-53 false core because there is a public list of only eight exact signed pseudorepresentations and the native residual can be evaluated on all of them.

The positive local norm theorem from Run 53 is unchanged. This run does **not** prove an impossibility theorem for a genuinely source-witness-selective nonlinear compiler. It rules out hidden sparse local testing when the public output still admits the current exact-representation/native-residual interface.

No external literature or web search was used. Production code is unchanged.

---

## 1. The eight-representation false core

Use the Run-53 unsatisfiable 3-CNF consisting of all eight sign patterns of one width-3 clause over variables `(x1,x2,x3)`.

Equivalently, each clause excludes exactly one Boolean assignment

\[
f\in\{0,1\}^3.
\]

For every Boolean assignment `p`, Run 53 gives an efficiently computable signed exact representation

\[
y(p)
\]

of the common affine relation

\[
B y=d.
\]

Its structure is exact:

* seven clause blocks are one-hot and have squared norm `1`;
* the unique block whose excluded assignment is `p` has the inclusion/exclusion signed lift and squared norm `7`.

Thus the eight public vectors

\[
\mathcal Y=\{y(p):p\in\{0,1\}^3\}
\]

form a polynomial-size pseudowitness list, with a bijection

\[
p\longleftrightarrow J(p)
\]

between list elements and their unique malformed block.

The checker independently rebuilds the `32 x 59` relation, verifies `B y(p)=d` for all eight vectors, and verifies that the malformed-block map is a permutation of the eight blocks.

---

## 2. Constructive attempt: a perfectly hidden one-block selector

Consider one binary share `kappa`. Setup secretly chooses

\[
J\leftarrow\{0,\ldots,7\}
\]

and publishes a capsule intended to test block `J` much more strongly than the other blocks.

The hoped-for behavior is:

* a genuine source representation is one-hot in block `J`, so it recovers `kappa`;
* a false `y(p)` with `J(p)=J` sees the norm-7 malformed block and should fail;
* a false `y(p)` with `J(p)\ne J` is one-hot in the tested block and therefore behaves like an honest local opening.

The intended cryptographic benefit is that `J` is hidden. An attacker supposedly cannot know which `p` to choose.

To avoid hiding a failure behind an unproved LWE auxiliary-input claim, grant the candidate an **ideal selector-hiding primitive**: `J` is perfectly hidden, and every `p != J` returns the exact real share. The one tested pseudorepresentation may return an arbitrary adversarial bit.

That idealization is already broken.

### Theorem 2.1 — hidden one-block selector majority attack

For every hidden `J` and every share bit `kappa`, the eight public pseudorepresentations produce a multiset containing at least seven copies of `kappa`.

Therefore a public attacker that evaluates the capsule on all eight `y(p)` and takes the strict majority recovers `kappa` exactly, without learning `J`.

#### Proof

Exactly one list element has malformed block `J`. The other seven are one-hot in block `J` and, by the ideal candidate semantics, return `kappa`. The remaining output is arbitrary. Seven equal bits against one arbitrary bit have strict majority `kappa`. QED.

This argument is stronger than a selector-distinguishing attack: it never tries to infer the secret selector.

### N-of-N consequence

If the construction uses independent binary shares

\[
K=\kappa_1\oplus\cdots\oplus\kappa_N,
\]

and every share capsule uses one hidden tested block, the attacker runs the eight-element majority attack **separately on every share capsule**, obtains every `kappa_i`, and XORs them.

Thus N-of-N root composition does not rescue the one-hidden-block design.

The checker executes 4,000 random `(kappa,J)` fixtures and adversarially flips the one tested output. The majority attack recovers all 4,000 shares. The proof above, not the test count, establishes the result.

---

## 3. Hidden subsets: an exact combinatorial threshold

Generalize a share capsule to secretly test a subset

\[
S\subseteq\{0,\ldots,7\},\qquad |S|=s.
\]

In the strongest favorable abstraction for the candidate, every `y(p)` with `J(p) notin S` returns the exact share, while outputs for `J(p) in S` may be arbitrary.

Then there are exactly

\[
8-s
\]

guaranteed correct outputs in the public eight-element list.

For binary shares, strict majority is therefore information-theoretically guaranteed whenever

\[
8-s\ge5,
\]

i.e. whenever

\[
\boxed{s\le3.}
\]

The checker exhausts every hidden subset, both share bits, and every possible assignment of arbitrary tested outputs. It verifies the exact minimum number of correct outputs:

| tested blocks `s` | minimum correct list outputs | strict majority guaranteed? |
|---:|---:|:---:|
| 0 | 8 | yes |
| 1 | 7 | yes |
| 2 | 6 | yes |
| 3 | 5 | yes |
| 4 | 4 | no |
| 5 | 3 | no |
| 6 | 2 | no |
| 7 | 1 | no |
| 8 | 0 | no |

This table does **not** say `s>=4` is secure. It says only that the worst-case binary-majority proof stops there.

For long random share strings, a different repeated-value attack often extends farther because all untested list elements return the same share while independently bad outputs are unlikely to collide. That extension is model-dependent, so it is not promoted to a theorem here.

---

## 4. Complete-public-output residual landscape

The hidden-selector idea is especially exposed in the current native affine capsule family.

Let

\[
c=B^T t+E,
\]

\[
\beta=d^T t+e_0+\mu\kappa,
\]

where the hidden selector is encoded in the error vector `E` by amplifying one block or a subset of blocks.

For **every** exact representation `y` satisfying `B y=d`, the public residual is

\[
\rho(y)=\beta-y^T c
        =\mu\kappa+e_0-y^T E.
\]

Nothing restricts this contraction to a source witness. Every signed `y(p)` is public and exact, so an attacker computes all eight residuals directly from the complete transcript.

More strongly, for two exact representations `y,y'`,

\[
\boxed{
\rho(y)-\rho(y')=-(y-y')^T c=-(y-y')^T E.
}
\]

The secret term cancels because

\[
B(y-y')=0.
\]

Hence the entire **relative residual landscape over the pseudowitness list is public**. Hiding the identity of the selected block does not hide the outputs obtained by evaluating all public exact representations.

The checker validates 4,000 complete residual identities and 32,000 pairwise-difference identities over 500 random capsules with a hidden 17x-amplified block.

This is the relevant distinction between **native encryption** and **source-witness transfer**. An outer source-level API that says "reject invalid witnesses" is not a secrecy boundary when the public ciphertext still exposes the inner linear contraction on arbitrary exact pseudorepresentations.

---

## 5. Why a standard-LWE selector wrapper would not answer this attack

A natural hope is that the block selector could be hidden by adding its amplified error only after an ordinary LWE-pseudorandom base sample. If a valid standard-LWE hybrid could be established with all setup-derived auxiliary material, that might indeed hide `J` as a computational secret.

But Theorem 2.1 does not recover `J`.

It grants **perfect selector privacy** and simply evaluates all eight public pseudorepresentations. Therefore proving that `J` is LWE-hidden would not repair the one-block selector construction. A surviving design must ensure that false exact representations themselves cannot all be fed into the release interface, or that *every* false representation in the public list is simultaneously prevented from yielding the real share.

Separately, a concrete trapdoor-generated public short encoder would need a full auxiliary-input LWE/SIS analysis; this run does not assume that away. The list attack makes that issue downstream for the sparse-selector candidate.

---

## 6. Local quotient visibility diagnostic

There is also a direct public-noise diagnostic for an additive selector.

Inside one seven-row 3-CNF block, the public local affine constraints are normalization plus three first marginals, so their transpose has dimension four. The block has a three-dimensional local kernel.

For a selector vector

\[
\eta\in\{\pm1\}^7,
\]

any local kernel vector `k` gives the public projection

\[
k^T c=k^T E.
\]

The checker exhausts all 128 Rademacher selector patterns for each of the eight blocks over `F_101`. Exactly 8 patterns per block lie in the four-dimensional local affine row space and are invisible to all local kernel probes; the other

\[
\boxed{120/128=15/16}
\]

have a nonzero local quotient component.

This is only a finite diagnostic for this block/noise family, not the main theorem. The main list attack does not need to identify `J` at all.

---

## 7. Dense testing loses the local advantage

One way to defeat the guaranteed survivor list is to test many blocks in every share.

On the eight-clause core, if `s` blocks receive amplified iid ternary coordinate errors:

* an honest one-hot representation contributes exactly `s` iid ternary terms;
* a false representation whose malformed block is tested contributes `s+6` iid ternary terms, because the malformed width-3 lift has seven nonzero coefficients instead of one.

Consider a generous scalar acceptance rule

\[
|R|\le T.
\]

For each `s=1,...,8`, the checker finds the smallest integer `T` giving honest success at least

\[
1-2^{-20}.
\]

Since `s<=8`, the extreme honest tails are still too large to discard at that target, so the minimum is simply `T=s` and honest success is exactly one. Exact ternary convolution gives:

| tested `s` | guaranteed untested false reps | false success if malformed block tested |
|---:|---:|---:|
| 1 | 7 | 0.5061728395 |
| 2 | 6 | 0.7174211248 |
| 3 | 5 | 0.8468729360 |
| 4 | 4 | 0.9206421785 |
| 5 | 3 | 0.9603718945 |
| 6 | 2 | 0.9808219539 |
| 7 | 1 | 0.9909641898 |
| 8 | 0 | 0.9958402407 |

This exposes the tradeoff:

* sparse testing preserves the strong local norm contrast but leaves a large public list of exact survivors;
* testing nearly all blocks suppresses the guaranteed survivor count, but additive scalar noise has diluted the local `1` versus `7` block gap into `s` versus `s+6`, and high honest completeness makes the tested false representation decode with very high probability.

The checker also runs a **diagnostic-only** correlated full-list Monte Carlo with shared per-block noise. Across 20,000 trials each:

* `s=1`: mean accepted false representations `7.50295`;
* `s=4`: `7.6726`;
* `s=7`: `7.9358`;
* `s=8`: `7.96785`.

At least five of the eight public false representations were accepted in every sampled `s=1,7,8` trial and in `99.98%` of sampled `s=4` trials. These Monte Carlo counts are not a proof and are not used as one; the exact marginal probabilities and combinatorial survivor theorem are the proved statements.

---

## 8. What is proved, tested, conjectural, and still missing

### Proved in this run

1. On the Run-53 false core, the eight exact signed representations form a public polynomial-size list with one unique malformed block each.
2. Even with a **perfectly hidden** one-block selector, seven of the eight list elements return the real binary share under the intended sparse-test semantics; majority recovers the share exactly.
3. N-of-N XOR composition does not repair that one-block design because the attack recovers each share independently.
4. For a hidden tested subset of size `s<=3`, strict binary majority recovers the share for every possible behavior of tested pseudorepresentations.
5. In an additive semantic capsule, all exact pseudorepresentation residuals and all pairwise residual differences are public; selector secrecy does not prevent list enumeration.
6. In the exact ternary dense-test model, the minimum threshold meeting honest success `>=1-2^-20` is `T=s` for `s<=8`, with the exact false probabilities in the table above.

### Implemented and actually executed

`hidden_selector_run55_check.py` was run twice after finalization with byte-identical JSON output. It performed:

* all eight exact false-core relation checks;
* 4,000 ideal hidden-one-block majority attacks;
* exhaustive worst-case binary hidden-subset checks for every `s=0,...,8`;
* 4,000 complete residual identities and 32,000 pairwise-difference identities;
* exhaustive `8 * 128` local Rademacher selector quotient checks;
* exact ternary convolutions for `s=1,...,8`;
* 80,000 correlated full-list Monte Carlo diagnostics.

The tests validate the implementation and finite identities. They do not establish generic cryptographic security or impossibility.

### Conjectural / not established

* No concrete LWE-hidden-selector construction is claimed secure. The list attack intentionally bypasses selector recovery, so selector privacy alone would not help.
* No theorem here rules out a nonlinear/computational source-witness-selective evaluator that refuses all eight signed pseudorepresentations at the cryptographic level.
* No arbitrary-QPT early-key-recovery -> source-witness/LWE/SIS reduction is obtained.
* No malicious-secure ceremony composition or final practical parameter set is claimed.

---

## 9. Handoff

Run 54 showed that a **publicly linear common-binding pad** can cancel before witness evaluation. Run 55 now shows that simply hiding **which local test is active** also does not solve switching when the complete public output still lets the attacker evaluate a polynomial list of exact pseudorepresentations.

The next viable common-representation mechanism must therefore defeat a stronger requirement:

> for a false statement, the complete public transcript must prevent **every efficiently enumerable exact pseudorepresentation in a covering list** from yielding the real share/key, not merely hide which member is currently disfavored.

On the present linear native interface, that requires leaving the public affine residual world, because `beta-y^T c` is available for every exact `y`. A surviving construction still needs a genuine cryptographic binding of all local checks to one source witness, with a complete-output reduction to an independently justified PQ assumption rather than a software-level witness check or a newly named WE-equivalent release primitive.

The stopping condition is not met.
