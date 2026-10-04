# Run 108 — SIS functional commitments give a succinct witness-local opening interface, but fixed-matrix common-target linearization is publicly preimageable

## Status

Verified starting PR head:
`5a612472b4f5e16120a6a07097ef25788415cb94`
on branch `research/pq-wkem-validation-20260918`.
PR #1 was open, draft, and unmerged.

The latest substantive PR comment was `5839832728`, recording verified publication
of Runs 100–103. Runs 104–107 remain local-only after separate safety-blocked
publication attempts. This run does not retry, rename, encode, split, or reroute any
previously denied material.

Exact current repository inputs read before this run include Runs 42, 72, 73, 90, 92,
95, 102 and 103, together with the published literature assessment.

This run audits the full current de Castro–Peikert functional-commitment paper:

* Leo de Castro, Chris Peikert, **Functional Commitments for All Functions, with
  Transparent Setup and from SIS**, ePrint 2022/1368 / EUROCRYPT 2023.

It also audits the adaptive-security boundary in:

* Hoeteck Wee, David J. Wu, **Lattice-Based Functional Commitments: Fast Verification
  and Cryptanalysis**, ASIACRYPT 2023.

The principal result is a correction and a new barrier.

### Correction

Run 107 was too pessimistic in suggesting that a polynomial-size generic-NP
statement-to-local-opening adapter was itself unavailable.

For every bounded-complexity verifier circuit, de Castro–Peikert already provide a
transparent, statement-only, standard-SIS functional commitment whose opening proof
is publicly computable from the function and an arbitrary later input.  Instantiating
the committed function as the NP verifier `f_x(w)=R(x,w)` gives a succinct,
witness-local short-opening interface without setup knowing a witness.

### New barrier

The natural attempt to turn those witness-dependent opening equations into the
fixed-matrix same-target preimage interface needed by a dual-Regev/common-key release
is **unconditionally broken**.

The fixed-matrix linearization must expose the robust-encoding gadget blocks.  Any one
of those blocks has an efficient short preimage for *every* target by gadget
decomposition.  Therefore the common target acquires a public short preimage
independent of any witness.

Randomizing a gadget block but publishing a short map back to the gadget does not
help: composing that public map with gadget inversion again gives a public preimage
of every target.

This is a source-transfer failure before LWE/SIS hardness is reached.

No production path is changed.

---

## 1. Exact de Castro–Peikert opening interface

Let `q` be the commitment modulus, and let

\[
g=(1,2,4,\ldots,2^{\ell-1})^T,
\qquad
\ell=\lceil\log_2q\rceil.
\]

For a bounded function

\[
f:X\to Y
\]

and a transparent uniformly random public matrix `C`, their deterministic
homomorphic-evaluation algorithm produces

\[
(C_f,S_{f,x})=\operatorname{Eval}(f,C,x)
\]

such that

\[
\boxed{
(C-\operatorname{Rep}(x)\otimes g^T)\,S_{f,x}
=
C_f-\operatorname{Rep}(f(x))\otimes g^T.
}
\tag{1}
\]

The non-optional commitment output `C_f` is unaffected by whether the optional input
`x` is supplied.

Construction 3.5 is therefore:

* `Setup`: uniform public `C`;
* `Commit(C,f)`: `C_f=Eval(f,C)`;
* `Open(C,f,x)`: run the same public deterministic `Eval(f,C,x)` and output
  `S_{f,x}`;
* verification: norm-check `S` and equation (1).

No committer secret or input-specific trapdoor is needed by `Open`.

For bounded circuits, Theorem 3.3 gives a polynomial-time opening and a norm bound of
the form

\[
\|S_{f,x}\|_1\le O(w)^D
\]

for circuit depth `D` and gadget width `w=n\ell`.

This is a genuinely useful source interface.

---

## 2. Generic NP instantiation

For statement `x_stmt`, define the public Boolean verifier function

\[
f_{x_{\rm stmt}}(w):=R(x_{\rm stmt},w)\in\{0,1\}.
\tag{2}
\]

Setup knows `x_stmt`, hence knows the complete verifier function description, but
does not know any satisfying witness.

It can publish

\[
C_f=\operatorname{Commit}(C,f_{x_{\rm stmt}}).
\]

Later, any candidate witness `w` locally computes

\[
S_w=\operatorname{Open}(C,f_{x_{\rm stmt}},w).
\]

For a valid witness,

\[
f_{x_{\rm stmt}}(w)=1.
\]

Using the compressed Boolean-output variant for notational simplicity, every valid
witness therefore satisfies an equation of the form

\[
\boxed{
A_w s_w=t_1,
\qquad
A_w:=C-G_w,
\qquad
t_1:=c_f-e_1,
}
\tag{3}
\]

where

\[
G_w=w^T\otimes g^T.
\]

The target `t_1` is the **same for every valid witness**.  The matrix `A_w` varies
with the witness.

For an invalid witness the honest public opening instead satisfies the corresponding
`y=0` target.

This corrects the exponential truth-vector adapter from Run 107:

\[
\boxed{
\text{generic bounded verifier}
\to
\text{polynomial-size witness-local short opening}
}
\]

is available from the de Castro–Peikert homomorphic computation.

It is not yet a KEM.

---

## 3. Selective versus adaptive binding is a real security limitation

The base de Castro–Peikert binding theorem is **selective-input**.

The adversary names the target opening input before seeing the public parameters.
Their Definition 2.3 quantifies over probabilistic polynomial-time adversaries.

Remark 2.5 states that adaptive/full evaluation binding can be obtained generically
by guessing the eventual opening input, losing a factor

\[
|X|.
\tag{4}
\]

For an `m`-bit NP witness domain,

\[
|X|=2^m.
\tag{5}
\]

Thus the black-box selective-to-adaptive guessing reduction loses

\[
\boxed{2^m.}
\tag{6}
\]

The paper suggests complexity leveraging with inverse-subexponential SIS hardness.
For a generic NP witness whose length is polynomial in the security parameter, this
is not a polynomial-loss standard reduction and must not be hidden inside a
"standard SIS" label.

The local finite checker includes a simple shift experiment showing the underlying
distributional issue: if an opening input is chosen *after* seeing a random public
matrix, the derived shifted matrix need not remain uniformly distributed.  This is
only an illustration of the proof-model boundary, not an attack on the actual
functional commitment.

### QPT classification

The published definition explicitly says probabilistic polynomial-time, not QPT.

The visible selective-binding reduction in Theorem 3.7 is straight-line: it embeds
one normal-form SIS challenge, invokes the adversary, and algebraically converts two
accepted openings into a SIS solution.  This gives a credible path to a **selective
QPT** theorem if normal-form SIS at the exact parameters is assumed QPT-hard, but
that quantum theorem is not what the paper states and is not claimed here as already
proved.

The adaptive case additionally inherits the exact `|X|` guessing loss.

---

## 4. Adaptively secure lattice functional commitments exist, but under a nonstandard correlated-hint assumption

Wee–Wu's ASIACRYPT 2023 paper explicitly distinguishes selective and adaptive
security.  Its succinct bounded-depth functional commitment (Construction 4.2 /
Corollary 4.8) is adaptively secure in the comparison table, but relies on the
structured **BASISstruct** assumption.

The authors prove only `BASISrand` from standard SIS.  They explicitly state that
they do not know an analogous reduction for `BASISstruct`.

Their Section 6 further interprets the structured assumption as SIS/LWE remaining
hard in the presence of correlated preimage/trapdoor information and discusses its
relation to evasive LWE.

Thus this adaptive alternative lands in the same correlated-short-hint territory
already isolated by Runs 80 and 95.

It is not an independently justified standard-SIS/QPT endpoint for this project.

---

## 5. Tempting fixed-matrix linearization

Equation (3) is witness-dependent because

\[
G_w=\sum_{i=1}^{m}w_iG_i,
\tag{7}
\]

where `G_i` is zero outside input block `i` and contains the standard robust gadget
matrix in that block.

A natural attempt is to linearize the bilinear terms `w_i s_w`.

Define the fixed public matrix

\[
\boxed{
\mathcal A
=
[C\mid -G_1\mid\cdots\mid -G_m].
}
\tag{8}
\]

A valid witness forms

\[
z_w
=
(s_w,\;w_1s_w,\ldots,w_ms_w).
\tag{9}
\]

Then

\[
\begin{aligned}
\mathcal A z_w
&=
Cs_w-\sum_iG_i(w_is_w)\\
&=
(C-G_w)s_w\\
&=
t_1.
\end{aligned}
\]

Hence

\[
\boxed{
\mathcal A z_w=t_1
}
\tag{10}
\]

for every valid witness.

At first glance this looks exactly like the fixed-matrix/common-target interface
needed by the dual-Regev skeleton from Run 95.

It is not source-binding.

---

## 6. Unconditional public-preimage attack on the linearization

Let

\[
G_{\rm base}=I_n\otimes g^T
\]

be the robust gadget matrix inside any coordinate block `G_i`.

For every target column

\[
t\in\mathbb Z_q^n,
\]

the public gadget decomposition algorithm computes a short binary vector

\[
d=g^{-1}(t)
\]

(blockwise) satisfying

\[
\boxed{
G_{\rm base}d=t.
}
\tag{11}
\]

Its \(\ell_1\) norm is at most

\[
n\ell=w.
\tag{12}
\]

Now take the common target `t_1` from (10).

Pick **any one** input coordinate `i`.  Put the gadget decomposition of `-t_1` in
the rows touched by `G_i`, set the base `s` block to zero, and set every other
linearization block to zero.

This constructs a public vector `z_pub`, requiring neither a witness nor a functional
commitment opening, such that

\[
\boxed{
\mathcal A z_{\rm pub}=t_1.
}
\tag{13}
\]

Moreover,

\[
\boxed{
\|z_{\rm pub}\|_1\le w
}
\tag{14}
\]

per target column.

For bounded circuits the honest functional-commitment proof bound is already
\(O(w)^D\), so the public gadget preimage is not some astronomically long relation
that can simply be filtered out.  It is at the natural gadget scale.

Therefore a dual-Regev/common-target capsule using `mathcal A,t_1` is immediately
broken: the attacker computes the same kind of short target preimage that honest
witnesses would use for decryption.

This is a classical algebraic attack and hence also a QPT attack.

It does not break the de Castro–Peikert functional commitment.  It breaks the
**fixed-matrix linearization used to turn its openings into a KEM capability**.

---

## 7. Randomizing the gadget blocks with public preimages does not repair the attack

A natural next repair replaces `G_i` by a more random-looking matrix `B_i` and
publishes a short matrix `R_i` such that

\[
B_iR_i=G_i.
\tag{15}
\]

An honest witness then replaces the block `w_i s_w` by

\[
R_i(w_is_w).
\]

But public gadget inversion still gives `D` with

\[
G_iD=t_1.
\]

Therefore

\[
\boxed{
B_i(R_iD)=t_1.
}
\tag{16}
\]

So the public map `R_i` composes with the public gadget inverse to give a public
target preimage under the randomized block.

If `R_i` is short enough for honest correctness, the composed attack is also
polynomially short; exact norms must be checked for any concrete parameterization,
but there is no source witness in the attack.

This is also the correlated-short-preimage shape behind the aligned-hint barrier of
Run 95: publishing preimages that reach the semantic challenge direction is not
covered by plain transverse related-trapdoor LWE.

---

## 8. The structured gadget channel is independently dangerous

Even if one tried a release that did not directly accept the gadget-only preimage,
the dual-Regev first component for a matrix containing gadget blocks exposes terms of
the form

\[
G_{\rm base}^Ts+e.
\tag{17}
\]

For the standard powers-of-two gadget, these observations decompose by secret
coordinate:

\[
s_j+e_{j,0},
\quad
2s_j+e_{j,1},
\quad
4s_j+e_{j,2},
\ldots
\tag{18}
\]

instead of mixing all secret coordinates as a random LWE matrix does.

The checker includes a bounded-noise control with

\[
q=257,\qquad
g=(1,2,4,8),\qquad
|e_i|\le3.
\]

If two secret candidates fit the same observations, their difference `delta` must
satisfy centered

\[
|\delta|,|2\delta|,|4\delta|,|8\delta|\le6.
\]

The only field element satisfying all four inequalities is `delta=0`; hence the
secret coordinate is uniquely recoverable in that regime by enumerating only `q`
candidates.

This is a finite control, not a theorem that every possible LWE parameterization with
a gadget block is broken.  The unconditional public target-preimage attack in
Section 6 is already sufficient to reject the direct linearized KEM.

---

## 9. Relation to Run 95

Run 95 built a fixed-matrix common-target compiler using published aligned preimage
directions and showed that the Waters–Wee–Wu standard-LWE theorem does not cover
those directions: any normalized relation forces the challenge direction into their
row span.

Run 108 reaches the same boundary from a different source compiler.

The functional commitment itself avoids publishing a global map `F`; a witness
computes its own short opening locally.  That is a genuine improvement.

But forcing all witness-dependent matrices `A_w` into one fixed linear matrix by
explicitly exposing the input gadget directions creates an even simpler failure:
those gadget directions publicly span every target with short coefficients.

Randomizing them and publishing short maps back to the gadget recreates the
aligned-preimage view.

Thus the exact surviving interface is:

\[
\boxed{
\text{witness-dependent short equation}
\quad
A_w s_w=t_1,
}
\tag{19}
\]

not a transparent fixed-matrix short-preimage relation.

---

## 10. What this changes from Run 107

Run 107 correctly identified a source-specific WPRF / witness-gated capability as the
right missing abstraction, but its discussion of a generic-NP-to-local-opening
adapter was too pessimistic.

The de Castro–Peikert construction gives such a polynomial-size **opening adapter**
for arbitrary bounded verifier circuits:

* transparent statement-only setup;
* no witness known at setup;
* every later input computes its own short opening;
* all valid inputs have the same Boolean output target.

What remains missing is not local opening.

It is a release mechanism that consumes the **witness-dependent equation** (19)
without:

* linearizing through public gadget blocks;
* publishing aligned short preimage maps;
* requiring an online evaluator;
* precomputing every witness;
* or assuming a WE/WPRF-equivalent primitive.

That is a narrower target.

---

## 11. Exact validation

`sis_fc_common_target_run108_check.py` is deterministic and standard-library-only.
The finalized output is byte-stable across repeated executions.

It validates:

1. public powers-of-two gadget inversion for every field value in `F_257`;
2. **400** random fixed-matrix linearizations:
   * the honest algebraic identity
     \(\mathcal A z_w=t\);
   * an independently generated gadget-only public preimage of the same arbitrary
     target;
   * attack norm at most `n*ell`;
3. **150** randomized-block controls with public maps `R` satisfying `BR=G`, confirming
   that `R` composed with gadget inversion again gives a public target preimage;
4. **200** two-opening difference identities;
5. an exact adaptive-shift toy where post-setup input selection changes the shifted
   matrix distribution;
6. the exact `2^m` selective-to-adaptive input-guessing loss for witness lengths
   32, 64, 128, 256, and 512;
7. the bounded-noise gadget-channel uniqueness control above.

The checker does not reimplement the authors' homomorphic `Eval`; the functional
commitment correctness and norm bounds come from the cited theorem.

---

## 12. QPT / dependency ledger

### Honest algorithm model

The de Castro–Peikert setup, commit, and opening algorithms are classical polynomial
time for bounded-complexity function families and polynomial parameters.

### Source/opening conclusion

Unconditionally from their correctness theorem, a valid NP witness can locally
compute a short opening satisfying a common-output target equation.

### Binding adversary model

The paper's base evaluation-binding theorem is stated for PPT adversaries and
selective opening inputs.

A QPT version is therefore `UNVERIFIED`.  Its visible reduction is straight-line, so
a selective-QPT extension is plausible under exact QPT-hard normal-form SIS, but it
must be stated and proved explicitly.

Adaptive input security under the paper's generic transformation loses `|X|`; for a
generic `m`-bit witness this is `2^m`.

### Wee–Wu adaptive alternative

The adaptively secure succinct functional commitment uses `BASISstruct`, which the
authors do not reduce to standard SIS.  Its LWE analogue is discussed in
evasive-LWE/correlated-preimage terms.

It is not an acceptable standard-QPT assumption here.

### Release-layer attack

The fixed-matrix common-target linearization is broken by a deterministic classical
public-preimage algorithm, independent of any computational assumption.

### Still unproved

1. a public/offline release directly consuming witness-dependent equations
   `A_w s_w=t_1` under standard QPT-hard assumptions;
2. arbitrary-QPT FINAL-key recovery -> ORIGINAL witness or independent QPT-hardness
   break for such a release;
3. adaptive source-binding at generic witness scale under a standard polynomial-loss
   QPT reduction;
4. malicious-secure setup/abort if a future repair introduces setup secrets;
5. practical final parameters and resource estimates.

The stopping condition is not met.

---

## 13. Next handoff

Do **not** linearize the functional-commitment opening equation with explicit gadget
blocks again.

The highest-value next target is a release primitive whose public matrix/ciphertext
can remain witness-independent while the witness supplies the matrix tag `w` and
short opening `s_w` only at decapsulation time.

Three concrete possibilities merit audit:

1. **tagged/identity-dependent lattice encryption without authority-issued keys**:
   can a public SIS opening itself serve as the identity secret key without exposing
   a universal gadget preimage?
2. **source-specific WPRF on the functional-commitment opening language**:
   the opening language now has a polynomial-size generic-NP adapter; can one build a
   PQ WPRF for this structured short-equation language rather than for generic NP?
3. **Run-102 extraction composition**:
   design a noisy public channel whose only useful Fourier/operator modes encode
   accepted functional-commitment openings, so arbitrary QPT final-key recovery
   samples an opening and then either verifies an ORIGINAL witness or yields a
   QPT-SIS break.

Any construction that forms one fixed source matrix by appending the public robust
gadget blocks should be rejected immediately by Section 6.

The practical generic-NP PQ WKEM remains open.
