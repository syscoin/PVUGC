# Run 120 — public assignment pseudowitness attack on the noisy one-hot affine release

## Status

Verified starting PR head: `a0803edfa691f184e33ca92620471a81c17c611c` on branch
`research/pq-wkem-validation-20260918`. PR #1 was open, draft, and unmerged. The latest
substantive ordinary PR comment was `5843580758`, recording verified publication of
Runs 104–108 and 110–111.

Relevant exact branch checkpoints were read before this run, including Run 100
(self-tensor source amplification), Run 102 (one-copy QPT extraction), Run 109
(hidden-input EPHF boundary), Run 110 (noisy gadget projection barrier), Run 111
(adaptor common-value boundary), and the current literature assessment/compiler files.

This run continues the local Run-119 handoff. Runs 117–118 gave a useful semantic
one-hot affine compiler: every satisfying assignment gives a shortest affine preimage,
and every sufficiently short supplied preimage yields an ORIGINAL satisfying
assignment. Run 119 then showed that a constant centered-Gaussian norm gap cannot by
itself enforce validity.

The new result makes that obstruction explicit and end-to-end:

> **Every Boolean assignment, including an arbitrary public assignment on a false
> formula, already gives an exact affine preimage for the Run-117/118 compiler, with
> squared Euclidean norm less than three times the honest norm. Therefore the natural
> noisy projective-hash / noisy-target release from Runs 115–116 lets a classical
> attacker decapsulate on false statements with overwhelming probability whenever the
> corresponding honest Gaussian decoder has overwhelming correctness.**

This refutes the direct composition

`one-hot affine compiler + zero-centered noisy linear HPS/LWE wrapper`.

It does **not** refute nonlinear carriers, superconstant source gaps, hidden
witness-restricted encodings, or generic PQ WKEMs.

No production path is changed.

---

## 1. Exact public assignment lift

Let `phi` be a 3CNF on `n` variables and `m` clauses. The Run-117/118 compiler produces
an integer matrix and target

\[
M_\phi z=t_\phi.
\]

Let

\[
B=n+m.
\]

For each variable there is a two-coordinate one-hot group. For each clause there is a
group indexed by its locally satisfying 3-bit assignments. Group sums equal one and
clause first moments are tied to global variable bits.

Run 118 already established the following constructive fact. For **every** Boolean
assignment `a`, not only satisfying assignments, there is a public deterministic map

\[
a\longmapsto z(a)
\]

such that

\[
\boxed{M_\phi z(a)=t_\phi}
\tag{1}
\]

and, if `V(a)` clauses are violated,

\[
\boxed{
\|z(a)\|_1=\|z(a)\|_2^2=B+2V(a).
}
\tag{2}
\]

For a violated clause, this uses the local affine identity

\[
011+100-111=000
\]

and its coordinatewise complements. Thus the bad local assignment is represented by
three allowed satisfying local assignments with coefficients `(+1,+1,-1)`.

Because `V(a)<=m`, every assignment lift obeys

\[
\boxed{
\|z(a)\|_2^2=B+2V(a)\le B+2m<3B.
}
\tag{3}
\]

This is efficient and completely public.

If `phi` is false, then **every** Boolean assignment violates at least one clause. In
particular the all-zero assignment is not an ORIGINAL witness, yet anyone can compute
`z(0^n)` and (1) still holds exactly.

This is the crucial distinction:

* the compiler has a strong **short supplied-preimage -> source witness** theorem at
  the exact shortest threshold;
* but it also has an efficiently computable **source-invalid exact affine preimage**
  only a constant norm factor away.

That second fact is fatal to a centered-noise validity filter.

---

## 2. Natural noisy projective release

Consider the Run-115/116 release over modulus `q`:

\[
c=M_\phi^T s+e,
\tag{4}
\]

\[
y=t_\phi^T s+f,
\tag{5}
\]

where `s` is the hidden LWE/hash secret and `e,f` are centered errors. To mask a setup
bit `K`, choose centers

\[
c_0=0,
\qquad
c_1=\lfloor q/2\rfloor
\]

and publish

\[
d=c_K-y\pmod q.
\tag{6}
\]

Any vector `z` satisfying the affine equation (1) computes

\[
\begin{aligned}
z^Tc+d
&=z^T(M_\phi^Ts+e)+c_K-(t_\phi^Ts+f)\\
&=c_K+e^Tz-f
\pmod q.
\end{aligned}
\]

Hence

\[
\boxed{
z^Tc+d=c_K+e^Tz-f\pmod q.}
\tag{7}
\]

Equation (7) depends only on the affine equality `M_phi z=t_phi`. It does **not** know
whether `z` came from a valid source witness.

Therefore on a false statement, the public assignment lift `z(0^n)` is already a
complete candidate decapsulation representation.

No lattice problem must be solved to obtain it.

---

## 3. Exact Gaussian attack

Take the favorable idealized case in which all coordinates of `e` and the target noise
`f` are independent centered Gaussians with variance `sigma^2`.

For a vector `z`, the residual in (7) is

\[
X_z=e^Tz-f
\sim
N\!\left(0,\sigma^2(1+\|z\|_2^2)\right).
\tag{8}
\]

A valid one-hot satisfying witness has

\[
\|z_h\|_2^2=B,
\]

so

\[
\sigma_h=\sigma\sqrt{1+B}.
\tag{9}
\]

The public assignment pseudowitness satisfies (3), so

\[
\sigma_a
=
\sigma\sqrt{1+\|z(a)\|_2^2}
<
\sigma\sqrt{1+3B}.
\tag{10}
\]

Consequently

\[
\boxed{
\frac{\sigma_a}{\sigma_h}<\sqrt 3.
}
\tag{11}
\]

Let the decoder accept the nearest center whenever the centered magnitude of the
residual is at most a threshold `T_lambda` below half the center separation.

If honest correctness tends to one, then necessarily

\[
T_\lambda/\sigma_h\to\infty.
\tag{12}
\]

By (11),

\[
T_\lambda/\sigma_a
>
\frac{1}{\sqrt3}
T_\lambda/\sigma_h
\to\infty.
\tag{13}
\]

For a centered Gaussian this immediately implies

\[
\boxed{
\Pr[|X_{z(a)}|\le T_\lambda]\to1.
}
\tag{14}
\]

Thus any Gaussian threshold sequence giving overwhelming honest correctness also
gives overwhelming decapsulation success to the public source-invalid assignment
pseudowitness.

On a false statement, this is unauthorized FINAL-key recovery by a classical
polynomial-time algorithm.

Therefore the direct composition fails QPT security a fortiori.

---

## 4. Finite parameter corollary

A conventional subgaussian correctness choice is

\[
T_\lambda
=
\sigma_h\sqrt{2(\lambda+1)\ln2}.
\tag{15}
\]

The standard Gaussian Chernoff bound gives honest rejection at most

\[
2\exp\left(-\frac{T_\lambda^2}{2\sigma_h^2}\right)
=2^{-\lambda}.
\tag{16}
\]

Let

\[
C^2=\sigma_a^2/\sigma_h^2<3.
\]

The same bound gives pseudowitness rejection at most

\[
2\exp\left(-\frac{T_\lambda^2}{2C^2\sigma_h^2}\right)
=
2^{1-(\lambda+1)/C^2}.
\tag{17}
\]

So even at the worst constant ratio approaching `sqrt(3)`, pseudowitness **rejection**
is exponentially small. Its acceptance tends to one.

The checker evaluates the exact Gaussian `erfc` tail and (17) for security parameters
32, 64, 128, and 256 across several compiler sizes.

This strengthens the Run-119 constant-gap warning into an explicit public attack on
the actual Run-117/118 representation.

---

## 5. Why a standard-LWE anchor does not repair the attack

A tempting repair after Run 119 is to publish an independent standard-LWE anchor

\[
b_0=U^Ts+e_0
\]

with uniform `U`, and treat the structured value (4) as bounded auxiliary leakage.

Lai--Swarnakar--Woo, *Leaky LWE: Learning with Errors with Semi-Adaptive Secret- and
Error-Leakage*, IACR Communications in Cryptology 2025, proves a useful theorem of
exactly this flavor: ordinary LWE remains hard in the presence of bounded noisy linear
leakage of the secret and error, even when the leakage matrix is chosen after seeing
the public LWE matrix, under the paper's Gaussian/norm conditions. Their Theorem 3 is
explicitly stated for **PPT adversaries**. The paper also allows structured/hinted LWE
matrices only when the corresponding underlying LWE distribution itself is assumed
hard.

Primary sources:

- https://doi.org/10.62056/ah89ksuc2
- https://research.aalto.fi/en/publications/leaky-lwe-learning-with-errors-with-semi-adaptive-secret-and-erro/

That theorem is a promising **auxiliary-output composition tool**, but it does not
solve the present attack.

The reason is conceptual and exact:

> Leaky LWE makes the *LWE challenge* pseudorandom **given the leakage**. It does not
> replace the leakage itself by uniform randomness.

Our attacker ignores `b_0`. It uses the public structured block `c`, the mask `d`, and
the publicly computed exact affine pseudowitness `z(a)` directly in (7).

Therefore even a perfect proof that

\[
b_0\approx U
\quad\text{given }c
\]

cannot hide the key when `c` itself already supports false-statement decapsulation.

This is an important correction to an otherwise attractive reading of Leaky LWE.

### Quantum status of the literature theorem

The source theorem quantifies over PPT adversaries. This run does **not** silently
replace PPT by QPT.

Its reduction appears structurally favorable for a future quantum lift because it is
based on a straight-line LWE reduction plus statistical Gaussian arguments, but a
formal QPT statement would still need the source game rewritten with QPT adversaries
and the statistical hybrids checked as trace-distance/quantum-side-information
statements.

None of that is necessary for the attack above: the attack is classical.

---

## 6. What this rules out

The following composition should now be treated as closed:

1. compile generic NP/3SAT into the Run-117/118 one-hot affine equation;
2. publish a zero-centered noisy linear projective hash of that affine relation;
3. rely on the constant honest/false norm gap to separate valid source witnesses from
   ambient affine representations;
4. optionally append a standard-LWE anchor and invoke leakage robustness.

It fails because step 1 itself gives an efficient source-invalid affine
pseudowitness with constant-factor projected noise.

This is stronger than merely saying the false minimum norm is too close to the honest
minimum. The attacker does not have to solve a minimum-preimage problem at all: the
pseudowitness is generated from any public assignment.

---

## 7. Surviving construction requirements

A new source/carrier interface must avoid **both** of the following:

### Public invalid representation

There must not be a polynomial-time public sampler that produces a source-invalid
representation in the honest decoding band.

The one-hot compiler violates this maximally: every assignment gives one.

### Centered constant-factor noise filtering

If invalid representations evaluate to the same canonical value plus merely a
constant-factor larger centered noise, negligible honest failure also makes them
accepted overwhelmingly.

Thus a viable design needs at least one qualitatively different mechanism:

* a **superconstant** evaluation separation compatible with polynomial resources;
* a nonlinear projective map for which invalid representations do not evaluate to the
  canonical value plus centered noise;
* a computationally hidden/restricted representation class where finding a usable
  source-invalid representation is independently QPT-hard;
* or a process-extractable WPRF/HPS-style mechanism whose security reduction does not
  factor through a publicly samplable affine relaxation.

Hair--Sahai's supplied-low-rank source extractor remains relevant precisely because
finding a low-rank false representation is not the same as writing down an arbitrary
ambient affine solution. But their security theorem is classical generic-group, not a
concrete PQ result, and a release mechanism must actually enforce that rank restriction
against arbitrary key recovery.

---

## 8. Exact validation

`public_affine_pseudowitness_noise_run120_check.py` is deterministic and
standard-library-only.

The finalized output was executed twice and is byte-identical.

It verifies:

1. across deterministic 3CNF fixtures, every Boolean assignment maps to an exact affine
   preimage with `l1 = l2^2 = B + 2V(a) < 3B`;
2. several explicitly false formulas have public all-zero assignment lifts that satisfy
   the affine equation while being source-invalid;
3. 240 randomized exact identities of the form
   `z^T c+d = c_K + z^T e-f`;
4. arbitrary additional standard-LWE-looking anchor data does not enter the attack;
5. exact Gaussian tail probabilities and Chernoff upper bounds for multiple `B` and
   `lambda` values;
6. finite controls of the constant-standard-deviation asymptotic theorem.

These are algebra/functionality/distribution controls. They are not computational
LWE tests and do not establish security of any surviving construction.

---

## 9. QPT/security ledger

### Honest algorithm model

The compiler, projective evaluation, and attack are classical polynomial-time.

### Adversary model

The attack is classical polynomial-time. Therefore any candidate vulnerable to it is
also insecure against arbitrary QPT adversaries.

### Hardness assumption

None is used by the attack.

### Reduction model

No rewinding, extraction, random oracle, QROM programming, or quantum measurement is
used. The attack directly evaluates public linear data with a public affine
pseudowitness.

### Exact conclusion

The **specific** composition of the Run-117/118 one-hot affine compiler with the
Run-115/116 zero-centered noisy linear release is refuted for false-statement hiding
under the Gaussian threshold mechanism above.

This is not a general impossibility theorem for lattice WPRFs/HPS or witness KEMs.

### Still unproved

1. a generic-NP public encoding whose usable representation class is not publicly
   samplable on false statements;
2. a complete standard-QPT-LWE/SIS or other independently justified PQ reduction for
   such an encoding;
3. arbitrary-QPT true-instance final-key recovery to ORIGINAL witness or an allowed
   independent hardness break for a complete scheme;
4. malicious-secure setup/abort and complete auxiliary-output composition;
5. practical parameters and resource estimates.

The stopping condition is not met.

---

## 10. Next handoff

Do **not** spend another pass tuning the Gaussian noise of the one-hot affine release.
The public assignment lift is a structural attack, not a parameter bug.

The highest-value next direction is to search for a source representation with this
stronger property:

\[
\boxed{
\text{valid witness} \to \text{usable short/structured representation},
\quad
\text{but no public efficient sampler produces a usable false representation.}
}
\]

Two concrete places remain worth testing:

1. whether the Hair--Sahai weighted-table/MinRank source space admits a **concrete PQ
   carrier** whose evaluation is only useful on low-rank representations, not on the
   ambient span; and
2. whether LWE vector-trapdoor-hash / hidden-bits machinery can supply a nonlinear
   witness-restricted public evaluation interface rather than merely a proof system.

The latter literature does give black-box LWE-based dual-mode NIZK/hidden-bits
constructions, but a NIZK is not by itself a same-key offline witness release. Any
attempt must still pass the WPRF/common-value and arbitrary-QPT recovery tests from
Runs 102 and 113.
