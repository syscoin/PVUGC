# Run 103 — hidden-subspace consistency bundles: perfect false hiding, self-certifying witness erasures, and extractable Fourier support

## Status

Verified starting PR head: `93ae96ba977d96e435c41c86ffeb037e8dbc2ff5` on
`research/pq-wkem-validation-20260918`.  PR #1 was open, draft, and unmerged.

This run returns to the earlier random-subspace rank-noise sampler in
`ODD_SPAN_AND_SUBSPACE_RANK_NOISE.md`, but changes its use in an important way.

The old exact-cutoff sampler had an honest rank-one signal

\[
\alpha_1 \approx q^{-(n-D+1)}
\]

and, when the hidden subspace was not exposed, ordinary scalar decoding paid an
inverse-square signal cost.  Publishing the hidden subspace would let a witness identify
the good erasures, but it also makes the relevant public masking subspace explicitly
testable and leaks the bit on true statements without a witness.

The new construction keeps the subspace hidden but uses **several independent noise
samples under the same hidden subspace and the same public random direction**.  A valid
witness can recognize a good hidden subspace by cross-sample consistency without being
told the subspace.  This changes honest recovery from the old inverse-square scale to
essentially an inverse-good-subspace-probability scale.

At the same time:

* false statements are **perfectly information-theoretically key hiding**, even against
  unbounded/QPT attackers and even across all repetitions;
* every nonzero Fourier mode of one complete consistency bundle contains a supplied
  source matrix below the semantic rank-extraction threshold;
* publishing the hidden subspace is proved unsafe by an explicit classical
  membership/orientation attack;
* the remaining arbitrary-QPT obligation is narrowed to a quantitative
  decoder-response-mass step.  The source channel has no nonextractable Fourier support,
  but a successful arbitrary decoder has not yet been proved to put nonnegligible
  *squared response mass* on that support without an additional source/intersection
  enumerator bound.

This is a concrete release algorithm plus a focused remaining theorem.  It is not yet a
practical generic-NP WKEM.

No production path is changed.

---

## 1. Source interface

Work over `F_q`.  Let

\[
C_x\subseteq \mathbb F_q^{n\times c}
\]

be a public statement-derived linear matrix space under the Frobenius pairing.  The
orientation is chosen so that `n` is the smaller side when useful; transposition
preserves rank.

Fix an integer extraction cutoff `D`.

Required source properties:

### YES / all-witness completeness

Every valid ORIGINAL source witness `w` efficiently gives a nonzero

\[
Y_w\in C_x,\qquad
d_w:=\operatorname{rank}(Y_w)<D.
\tag{1}
\]

### Supplied-low-rank ORIGINAL-source extraction

Every supplied nonzero

\[
Y\in C_x,\qquad
\operatorname{rank}(Y)<D
\tag{2}
\]

efficiently yields an ORIGINAL source witness.

### NO gap

For a false statement,

\[
0\ne Y\in C_x
\quad\Longrightarrow\quad
\operatorname{rank}(Y)\ge D.
\tag{3}
\]

Hair--Sahai's MinRank compiler, together with the separately recorded field-flexible
binary scalar descent, is one candidate source interface: honest rank one, extraction
through rank `R`, and false minimum rank `>R`, so `D=R+1`.  Hair--Sahai's *encryption*
theorem itself remains classical generic-group security and is not imported here.

---

## 2. One hidden-subspace consistency bundle

Let

\[
m=n-D+1.
\tag{4}
\]

Choose a uniformly random `m`-dimensional subspace

\[
U\le \mathbb F_q^n
\]

and **do not publish `U`**.

Define the matrix subspace

\[
W_U
=
\{E\in\mathbb F_q^{n\times c}:
      \operatorname{col}(E)\subseteq U\}.
\tag{5}
\]

Equivalently, each column of an element of `W_U` lies in `U`.

Let

\[
C_x^\perp
=
\{Z:\langle Z,Y\rangle_F=0\ \forall\,Y\in C_x\}.
\]

Choose one public random direction

\[
H\leftarrow\mathbb F_q^{n\times c}.
\tag{6}
\]

For a raw bit `b in {0,1}` and a consistency width `T`, independently sample

\[
Z_t\leftarrow C_x^\perp,
\qquad
E_t\leftarrow W_U,
\qquad t=1,\ldots,T,
\]

uniformly, and publish

\[
\boxed{
(H,C_1,\ldots,C_T),
\qquad
C_t=Z_t+E_t+bH.
}
\tag{7}
\]

Only `H` and the `C_t` are public.  The ephemeral `U,Z_t,E_t` are discarded.

Setup/encapsulation is statement-only and classical.  No trapdoor or online party is
introduced.

---

## 3. Exact false-statement perfect hiding

For fixed hidden `U`, put

\[
S_U=C_x^\perp+W_U.
\tag{8}
\]

Its orthogonal complement is

\[
S_U^\perp
=
C_x\cap W_U^\perp
=
\{Y\in C_x:
  \operatorname{col}(Y)\subseteq U^\perp\}.
\tag{9}
\]

But

\[
\dim U^\perp=D-1.
\]

Therefore every matrix in `S_U^\perp` has rank at most `D-1`.

If `x` is false, (3) implies

\[
S_U^\perp=\{0\}
\]

for **every** possible hidden subspace `U`.  Hence

\[
\boxed{
S_U=\mathbb F_q^{n\times c}.
}
\tag{10}
\]

Because `Z_t` and `E_t` are independent uniform variables on two subspaces, their sum is
uniform on the sum subspace.  Thus on a false statement each

\[
D_t:=Z_t+E_t
\]

is uniform on the full ambient matrix space, even conditioned on `U`; the `D_t` are
independent across `t`.

Consequently

\[
(C_1,\ldots,C_T)
=
(D_1+bH,\ldots,D_T+bH)
\]

is independent uniform for either value of `b`, conditioned on the complete public `H`.

This remains true for arbitrarily many independent bundles and arbitrarily many key
bits.

Therefore:

\[
\boxed{
\text{false statement}
\Longrightarrow
\text{perfect full-public-view key hiding}.
}
\tag{11}
\]

The adversary may be computationally unbounded and may have arbitrary quantum
auxiliary information independent of the fresh encapsulation randomness.  QPT hiding
is immediate because the two classical public distributions are identical.

No LWE, SIS, MinRank average-case assumption, generic-group model, random oracle, or
QROM is used for (11).

---

## 4. Witness self-certification without publishing `U`

Let a valid witness supply nonzero `Y in C_x` of rank

\[
d=\operatorname{rank}(Y)<D.
\]

Call a hidden subspace **good for `Y`** when

\[
\operatorname{col}(Y)\subseteq U^\perp.
\tag{12}
\]

The exact probability is

\[
\boxed{
\alpha_d
=
\frac{\begin{bmatrix}n-d\\m\end{bmatrix}_q}
     {\begin{bmatrix}n\\m\end{bmatrix}_q},
\qquad
m=n-D+1.
}
\tag{13}
\]

For rank one,

\[
\boxed{
\alpha_1
=
\frac{q^{D-1}-1}{q^n-1}.
}
\tag{14}
\]

The witness first computes

\[
a=\langle H,Y\rangle_F.
\tag{15}
\]

If `a=0`, discard the bundle.

Otherwise compute

\[
x_t=a^{-1}\langle C_t,Y\rangle_F.
\tag{16}
\]

Because `Y in C_x`, the `Z_t` term always vanishes.

### Good hidden subspace

If (12) holds, every `E_t in W_U` is orthogonal to `Y`, so

\[
x_1=\cdots=x_T=b
\tag{17}
\]

**exactly**.

### Bad hidden subspace

If (12) does not hold, the linear functional

\[
E\mapsto\langle E,Y\rangle_F
\]

is nonzero on `W_U`.  A uniform `E_t in W_U` therefore maps to a uniform field element.
The values `x_t` are independent uniform elements of `F_q`.

This gives a witness-visible consistency test although `U` itself remains hidden.

---

## 5. Decoder and exact error scaling

For each bundle:

1. discard it if `a=0`;
2. otherwise compute all `x_t`;
3. accept only if

   \[
   x_1=\cdots=x_T\in\{0,1\};
   \]

4. return that common bit from the first accepted bundle.

For a rank-`d` witness, a bundle is genuinely good and usable with probability

\[
p_{\rm good}
=
\alpha_d(1-1/q).
\tag{18}
\]

A bad hidden subspace produces the **opposite** bit in all `T` positions with probability

\[
p_{\rm wrong}
=
(1-\alpha_d)(1-1/q)q^{-T}.
\tag{19}
\]

With `L` independent bundles, a conservative error bound is

\[
\boxed{
\Pr[\mathrm{error}]
\le
e^{-L\alpha_d(1-1/q)}
+
L(1-\alpha_d)(1-1/q)q^{-T}.
}
\tag{20}
\]

The first term pessimistically treats "no genuinely good bundle" as failure even though a
bad bundle can occasionally agree on the correct bit.

Choose

\[
L
=
\left\lceil
\frac{A}{\alpha_d(1-1/q)}
\right\rceil.
\tag{21}
\]

Then

\[
\boxed{
\Pr[\mathrm{error}]
\le
e^{-A}
+
\frac{A+O(\alpha_d)}{\alpha_d q^T}.
}
\tag{22}
\]

Thus it suffices to take roughly

\[
T
\ge
\log_q\!\frac{A}{\alpha_d\varepsilon}
\tag{23}
\]

for target error `e^-A + epsilon`.

The important change from the old hidden-subspace scalar decoder is that the expensive
number of independent hidden subspaces is now

\[
\boxed{
L=\Theta(\alpha_d^{-1}),
}
\tag{24}
\]

not an inverse-square signal count.  The consistency width `T` grows only
logarithmically in the desired false-accept probability.

For rank one at the exact cutoff,

\[
L
\asymp
q^{\,n-D+1}.
\tag{25}
\]

This can still be too large; the improvement removes one exponent, not the underlying
ambient-minus-gap cost.

---

## 6. Exact complete-bundle Fourier support

The consistency mechanism has a second useful property.

For a joint Fourier character

\[
\mathbf Y=(Y_1,\ldots,Y_T),
\]

conditioned on hidden `U`, the data part `(D_1,...,D_T)` is uniform on `S_U^T`.  Hence
the character expectation is one exactly when

\[
Y_t\in S_U^\perp
\quad\forall t
\]

and zero otherwise.

Averaging over the hidden `U` gives

\[
\boxed{
\widehat P(\mathbf Y)
=
\mathbf 1[Y_1,\ldots,Y_T\in C_x]\,
\Pr_U\left[
\operatorname{span}\bigl(
 \operatorname{col}Y_1,\ldots,\operatorname{col}Y_T
\bigr)
\subseteq U^\perp
\right].
}
\tag{26}
\]

Let

\[
r_{\cup}
=
\dim\operatorname{span}\bigl(
 \operatorname{col}Y_1,\ldots,\operatorname{col}Y_T
\bigr).
\]

Then

\[
\boxed{
\widehat P(\mathbf Y)
=
\begin{cases}
\displaystyle
\frac{\begin{bmatrix}n-r_{\cup}\\m\end{bmatrix}_q}
     {\begin{bmatrix}n\\m\end{bmatrix}_q},
& r_{\cup}\le D-1,\\[2ex]
0,&r_{\cup}\ge D.
\end{cases}
}
\tag{27}
\]

Therefore every **nonzero** Fourier mode of the complete data bundle has at least one
nonzero component

\[
Y_t\in C_x,\qquad
\operatorname{rank}(Y_t)\le r_\cup\le D-1.
\tag{28}
\]

Under the source interface, that component yields an ORIGINAL source witness.

So:

\[
\boxed{
\text{the bundle has zero nonextractable Fourier support}.
}
\tag{29}
\]

This is stronger than merely making high-rank modes small.

It does **not** yet prove that arbitrary key recovery outputs or samples such a mode
with nonnegligible probability.

---

## 7. Exact squared-spectrum/intersection enumerator

Let

\[
K_U
=
C_x\cap W_U^\perp.
\tag{30}
\]

For one width-`T` data bundle, Parseval gives the exact chi-square mass

\[
S_T
=
\sum_{\mathbf Y\ne0}
|\widehat P(\mathbf Y)|^2.
\]

Squaring (26) and exchanging the order of summation yields

\[
\boxed{
1+S_T
=
\mathbb E_{U,U'}
\left[
|K_U\cap K_{U'}|^T
\right].
}
\tag{31}
\]

This is the correct source statistic for the next QPT extraction step.

It replaces a raw rank enumerator by an **intersection enumerator of
source-extractable low-rank subspaces**.

The one-copy mixed-advice operator-Fourier inequality from the immediately preceding
research checkpoint can be applied if the corresponding normalized complete-key
squared mass is polynomially controlled.  Equation (31) now tells us exactly what must
be bounded.

The tiny checker also shows why this is not automatic: on a two-dimensional rank-one
true source with a unique good hidden subspace and `T=3`,

\[
S_T=\frac{4^T-1}{49}=\frac{63}{49}>1.
\]

Increasing consistency width improves honest self-certification but can increase the
squared Fourier mass.  A new QPT theorem must respect this tradeoff rather than simply
assuming that zero nonextractable support gives nonnegligible Fourier-sampling success.

---

## 8. Publishing the hidden subspace is provably unsafe

A tempting simplification is to publish `U` so the witness can immediately test (12).
That destroys true-statement source security.

If `U` is public, then so is

\[
S_U=C_x^\perp+W_U.
\]

Suppose

\[
s=\dim K_U>0.
\]

Given one public direction `H` and any ciphertext component `C`, the two candidate
orientations are

\[
C
\quad\text{and}\quad
C-H.
\]

Exactly one is guaranteed to lie in `S_U`, according to the hidden bit, unless

\[
H\in S_U.
\]

Because `H` is uniform,

\[
\Pr[H\in S_U]=q^{-s}.
\]

A classical adversary can therefore test subspace membership and recover the bit with

\[
\boxed{
1-\frac12 q^{-s}
}
\tag{32}
\]

success.

On every subspace that is good for an honest witness, `Y in K_U`, so `s>=1`.  Thus
publishing `U` gives an unauthorized success probability at least

\[
1-\frac1{2q}.
\]

The hidden-subspace consistency mechanism is therefore not cosmetic: hiding `U` is
necessary for the source-binding goal.

---

## 9. Hair--Sahai binary-source resource implication

The previously recorded field-flexible scalar descent gives a binary matrix source with:

* honest rank one;
* source extraction through rank `R`;
* false minimum rank at least `R+1`;
* `R=floor(log_2 N)` in the logarithmic-gap regime;
* only `N+1` columns before optional zero padding.

Transpose the source so that

\[
n=N+1,\qquad D=R+1.
\]

Then

\[
m=n-D+1=N-R+1
\]

and

\[
\boxed{
\alpha_1
=
\frac{2^R-1}{2^{N+1}-1}
\approx
2^{-(N+1-R)}.
}
\tag{33}
\]

At 128-bit correctness error, taking `A=128 ln 2`, the checker records:

* `N=8`: already thousands-to-millions of subcapsule operations depending on the
  consistency target;
* `N=16`: roughly millions of bundles and about a hundred-fifty consistency samples
  per bundle;
* `N=32`: tens of billions of bundles;
* `N=64`: the count is astronomically larger.

These are only operation-count proxies; every subcapsule also contains a large matrix.
They are not deployment benchmarks.

Asymptotically, the direct Hair--Sahai source therefore remains impractical:

\[
\Theta(2^{N-R})
\]

bundles are needed.

If some future source compression makes the effective rank-source dimension
`N=O(log lambda)`, this count can be polynomial in the security parameter.  Merely
saying `N=polylog(lambda)` is insufficient: for `N=omega(log lambda)` the displayed
cost can still be superpolynomial.

This makes Jin's advertised polylogarithmic online verifier relevant, but the full
2026/2063 reduction and exact resulting matrix/code dimensions remain unavailable in
the present primary-source fetch path.  No efficiency claim is imported from its
abstract.

---

## 10. Quantum-security ledger

### Honest algorithm model

All source compilation, subspace sampling, orthogonal-mask sampling, encapsulation,
and witness decapsulation are classical.

They are PPT only when `L`, `T`, the source dimensions, and matrix sizes are
polynomial in the security parameter.  Equation (33) shows that this fails for the
uncompressed direct Hair--Sahai source at general polynomial-size `N`.

### False-statement adversary model

Equation (11) is perfect classical-distribution equality conditioned on every hidden
`U`.  It therefore holds against unbounded adversaries and arbitrary QPT adversaries,
including arbitrary quantum auxiliary information independent of the fresh
encapsulation randomness.

### Hardness distribution

No computational hardness assumption is used for false hiding.

The source interface is a semantic/source-extraction condition.  Hair--Sahai supplies
such an algebraic rank gap/extractor in its source compiler, but its own generic-group
encryption theorem is not used as PQ evidence.

### Reduction model

The new false-hiding and correctness theorems are direct finite-field linear algebra.

The complete-bundle Fourier support theorem is information theoretic.

No rewinding, random oracle, QROM, or superposition-query assumption occurs in these
steps.

### Exact true-instance conclusion

Every nonzero **supplied channel Fourier mode** yields an ORIGINAL source witness.

This is stronger than supplied-low-rank extraction alone.

### Still UNPROVED

A successful arbitrary-QPT FINAL-key recoverer has not yet been proved to yield or
sample a channel-supported mode with nonnegligible probability for this bundle without
an additional quantitative bound such as (31).

Thus arbitrary-QPT recovery-to-ORIGINAL-witness extraction for the complete bundle is
still **UNPROVED**.

The immediately preceding one-copy mixed-advice operator method remains applicable
when the normalized squared spectrum is polynomially controlled; (31) gives the exact
new source statistic.

---

## 11. Literature boundary

Hair--Sahai, arXiv:2609.18275v1, explicitly proves NP witness encryption only in the
**classical prime-order generic-group model** and a logarithmic-gap homogeneous
MinRank source theorem.  The algebraic MinRank source interface is reusable; its
generic-group security theorem is not concrete post-quantum security.

Chatterjee--Mu--Vasudevan, arXiv:2510.03752v1, bases PKE on planted MinRank over
**uniform random** matrix generators.  The present statement-derived source does not
have that distribution, so their average-case security is not imported.

The older random-subspace rank-noise note in this repository supplied the exact
Gaussian-binomial Fourier cutoff but paid inverse-square honest signal and did not
use cross-sample hidden-subspace consistency.  Run 103's new contribution is the
consistency bundle, its perfect false-statement composition, the complete joint
Fourier-support theorem, and the public-subspace attack.

---

## 12. Exact validation

The finalized standard-library checker is executed twice with byte-identical JSON.

Its exact binary `3 x 2` fixture uses:

* a true two-dimensional source whose three nonzero matrices all have rank one;
* a false two-dimensional MRD-style source whose three nonzero matrices all have rank
  two;
* cutoff `D=2`, hence hidden subspaces have dimension `m=2`.

It verifies:

1. all seven hidden two-dimensional subspaces of `F_2^3`;
2. for the false source and **every** hidden `U`,
   `C_false^perp + W_U` is the full 64-element ambient matrix space;
3. the rank-one honest good-subspace probability is exactly `1/7`;
4. every nonzero supported joint Fourier mode at width `T=3` contains only rank-one
   nonzero source components;
5. exact bundle chi-square

   \[
   S_3=63/49;
   \]

6. the exact intersection-enumerator identity (31);
7. the binary correctness probabilities
   `p_good=1/14` and `p_wrong=3/56` for `T=3`;
8. the public-`U` attack on the good true fixture has codimension two and succeeds
   with probability `7/8`;
9. the Hair--Sahai binary interface ledger for `N=8,16,32,64`.

The tests validate the implementation and finite identities, not a cryptographic
assumption.

---

## 13. Next handoff

The most useful next work is now source-specific rather than another generic noise
variant.

1. For the actual compressed GapMDP/MinRank source, compute or bound the intersection
   statistic

   \[
   \mathbb E_{U,U'}|K_U\cap K_{U'}|^T.
   \]

   A polynomial normalized bound would plug directly into the one-copy arbitrary-QPT
   extractor.

2. Obtain the full current Jin 2026/2063 construction and determine whether its
   polylogarithmic verifier/source representation can make
   `n-D=O(log lambda)` **and** preserve every-low-rank ORIGINAL-witness extraction.

3. Search for a witness-restricted public way to identify good hidden subspaces
   without revealing `S_U`.  Equation (32) rules out simply publishing `U`.

4. Do not revert to a public complete subspace description, ordinary random MinRank,
   or a renamed structured-hardness assumption.

The stopping condition remains unmet.
