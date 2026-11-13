# Run 100 — self-tensor source amplification: gap powers with root-support ORIGINAL-witness extraction

## Status

Verified starting PR head: `0f8c44db5f1d11e1a7fea7fa8b92f42dcfc0e230` on branch
`research/pq-wkem-validation-20260918`. PR #1 was open, draft, and unmerged.

This run continues the Run-96/98/99 Hamming-spectral release route. It does **not**
complete the practical PQ witness KEM.

The new constructive point is that an existing statement-derived linear source code can
be tensor-powered without setup knowing a witness:

* a valid low-weight source relation tensors to an equally explicit valid relation;
* a false-instance minimum-distance gap is raised to a power;
* crucially, **every sufficiently low-weight tensor-code word exposes a sufficiently
  low-weight base-code fiber**, so a base ORIGINAL-witness extractor remains usable
  even for adversarial tensor codewords that are not pure tensors.

That last item is the source-transfer property needed by this project. The ordinary
tensor-product minimum-distance theorem alone would not be enough.

The main negative result is equally important: tensoring with a fixed
statement-independent auxiliary code cannot improve the Run-96/99 false spectral
leakage at fixed honest decoding signal. The useful amplification comes specifically
from self-tensoring the **statement-derived gap source**.

Arbitrary-QPT recovery of the final key on true statements still does not imply that
the adversary supplies a low-weight tensor codeword. Run 97's decoder-rigidity
barrier therefore remains central.

No production path is changed.

## 1. Source interface inherited from Runs 96–99

Let

\[
C_x\subseteq \mathbb F_q^m
\]

be the public statement-derived linear relation code, of dimension `k`.

The source interface needed here is:

### True statement

Every valid ORIGINAL NP witness `w` efficiently yields a nonzero relation

\[
y_w\in C_x,\qquad \operatorname{wt}(y_w)\le d.
\]

No fixed normalization functional is required. This is why the Run-98 random-direction
release is a better fit than the original fixed-anchor Run-96 syntax.

For extraction, assume a base theorem of the exact form

\[
0\ne y\in C_x,\quad \operatorname{wt}(y)\le B
\quad\Longrightarrow\quad
\text{efficient extraction of an ORIGINAL source witness},
\tag{1}
\]

for some threshold `B >= d`.

This run does **not** assume Jin 2026/2063 has already been verified to satisfy (1).
That exact point remains to be audited from the full current proof.

### False statement

Every nonzero source relation has

\[
\operatorname{wt}(y)\ge D,
\qquad
D\ge \gamma d.
\tag{2}
\]

Runs 96/98/99 then reduce false hiding to the Hamming spectrum / noisy syndrome of
this code.

## 2. Tensor source compiler

For a positive integer `t`, define the ordinary tensor-power code

\[
C_x^{\otimes t}
\subseteq
(\mathbb F_q^m)^{\otimes t}
\cong \mathbb F_q^{m^t}.
\tag{3}
\]

If `G_x` is any `k x m` generator for `C_x`, a generator for the tensor code is

\[
G_x^{\otimes t}.
\tag{4}
\]

Therefore the public compiler is statement-only and classical.

For fixed constant `t`:

* length becomes `m^t`;
* dimension becomes `k^t`;
* setup and witness tensoring remain polynomial time whenever the base compiler is
  polynomial.

Allowing `t` to grow with the security parameter requires a separate efficiency audit;
this run does not silently treat growing tensor powers as polynomial.

## 3. Honest witness transport

A true witness relation `y_w` gives

\[
Y_w = y_w^{\otimes t}\in C_x^{\otimes t}.
\tag{5}
\]

Its Hamming weight is exactly

\[
\operatorname{wt}(Y_w)
=
\operatorname{wt}(y_w)^t
\le d^t.
\tag{6}
\]

Thus the Run-98 random-direction capsule can use the tensor source without setup ever
seeing a source witness.

Every valid source witness remains usable; all-witness correctness is not replaced by
a special planted witness.

## 4. False minimum distance powers exactly

If the base false-instance code has minimum distance `D`, then

\[
\boxed{
d_{\min}(C_x^{\otimes t})=D^t.
}
\tag{7}
\]

The upper bound is achieved by tensoring `t` minimum-weight base codewords.

For the lower bound, use induction. Every axis-parallel one-dimensional fiber of a
tensor-code word is a base-code word. Take a nonzero fiber in one axis. It contains at
least `D` nonzero positions. The corresponding fibers in the next axis are nonzero
base-code words and each has at least `D` support positions. Repeating through all
`t` axes gives at least `D^t` nonzero entries.

Hence the true/false Hamming-gap ratio becomes

\[
\boxed{\gamma^t.}
\tag{8}
\]

Gap amplification by tensoring is a standard coding/hardness technique; this run does
not claim novelty for (7)–(8). Bhattiprolu–Guruswami–Lee–Ren explicitly use tensoring
to amplify sparse-vector gaps. The new question here is whether tensoring preserves
the exact **ORIGINAL-source extraction interface** needed by the WKEM.

## 5. New source-transfer lemma: sparse tensor words expose sparse base fibers

The tensor source has a useful property stronger than minimum distance.

View a word

\[
Z\in C_x^{\otimes t}
\]

as a `t`-dimensional `m x ... x m` array.

Every axis-parallel one-dimensional fiber of `Z` lies in `C_x`: this is immediate
from the tensor-span definition.

Let

\[
W=\operatorname{wt}(Z)>0.
\]

### Theorem 1 — root-support fiber lemma

There exists a nonzero axis-parallel fiber `z in C_x` satisfying

\[
\boxed{
\operatorname{wt}(z)^t\le W.
}
\tag{9}
\]

Equivalently,

\[
\operatorname{wt}(z)\le W^{1/t}.
\]

#### Proof

Let `S` be the support of `Z`, so `|S|=W`. For axis `i`, let `pi_i(S)` be the
projection obtained by deleting coordinate `i`; its points index the nonempty
axis-`i` fibers.

Suppose for contradiction that **every** nonempty fiber in **every** axis has more
than `W^{1/t}` support points. Then for every `i`,

\[
|\pi_i(S)|
<
W/W^{1/t}
=
W^{(t-1)/t}.
\tag{10}
\]

The discrete Loomis–Whitney inequality gives

\[
W^{t-1}
\le
\prod_{i=1}^t |\pi_i(S)|.
\tag{11}
\]

But (10) makes the right side strictly smaller than `W^{t-1}`, a contradiction. ∎

### Corollary 1 — tensor source extraction

If the base source extractor handles every nonzero base relation of weight at most `B`,
then

\[
\boxed{
0\ne Z\in C_x^{\otimes t},
\quad
\operatorname{wt}(Z)\le B^t
\Longrightarrow
\text{ORIGINAL source witness}.
}
\tag{12}
\]

The extractor finds a minimum-support nonempty axis fiber, obtains a nonzero
`z in C_x` with `wt(z)<=B`, then invokes the base extractor.

This is significant because an adversarial tensor relation need not be a pure tensor.
The extraction theorem applies to **every supplied tensor-code word** within the
threshold.

It remains a supplied-representation theorem. It does not convert arbitrary QPT
final-key recovery into such a word.

## 6. Effect on the Run-96/98 Hamming-spectral release

For any linear code `C`, recall

\[
S_C(\beta)
=
\sum_{0\ne y\in C}
\beta^{2\operatorname{wt}(y)}.
\tag{13}
\]

Run 99 identified this exactly as the chi-square distance of the q-symmetric-noise
syndrome from uniform.

For the tensor source define

\[
S_t(\beta)
=
S_{C_x^{\otimes t}}(\beta).
\tag{14}
\]

On a false statement, dimension and distance give the coarse bound

\[
\boxed{
S_t(\beta)
\le
(q^{k^t}-1)\beta^{2D^t}.
}
\tag{15}
\]

Let the worst honest tensor signal be

\[
\tau=\beta^{d^t}.
\tag{16}
\]

Because `D >= gamma d`,

\[
\boxed{
S_t(\beta)
\le
(q^{k^t}-1)\tau^{2\gamma^t}.
}
\tag{17}
\]

With the Run-98 erasure decoder, `L = Theta(A/tau)` repetitions suffice for honest
reliability. For `kappa` final raw key bits the coarse small-leakage expression scales
as

\[
\kappa L S_t
\lesssim
\kappa A q^{k^t}\tau^{2\gamma^t-1}.
\tag{18}
\]

If

\[
\tau=\lambda^{-c},
\]

a sufficient distance-only exponent condition is

\[
\boxed{
c(2\gamma^t-1)\ln\lambda
-
k^t\ln q
-
\ln(\kappa A)
=
\omega(\ln\lambda).
}
\tag{19}
\]

This is **not automatically improved by tensoring**. Both the gap and the code
dimension are powered. The relevant comparison is the actual source's `gamma` versus
`k`, together with `ln q / ln lambda`, and preferably the exact tensor weight
enumerator instead of (15).

The checker includes two synthetic ledgers showing both behaviors: one where a
second/third tensor power improves the coarse exponent and one where powering the
dimension overwhelms the gap.

No claim about Jin's actual parameters follows without its exact `k,m,d,D`.

## 7. Run-99 capacity barrier under tensoring

Let `n_act` be the number of nonzero columns of a full-row-rank generator `H` of the
base relation code.

For the Kronecker generator

\[
H^{\otimes t},
\]

a tensor column is nonzero iff every constituent base column is nonzero. Therefore

\[
\boxed{
n_{\rm act}^{(t)} = n_{\rm act}^t.
}
\tag{20}
\]

Run 99's information-theoretic necessary condition for negligible false syndrome TV
becomes

\[
\boxed{
\left(\frac{k}{n_{\rm act}}\right)^t
\le
\frac{H(E_{\beta_t})}{\ln q}+o(1),
\qquad
\beta_t=\tau^{1/d^t}.
}
\tag{21}
\]

This is an actual necessary condition on the tensor source, not a chi-square proof
artifact.

For small per-coordinate noise,

\[
1-\beta_t
=
1-\tau^{1/d^t}
\approx
\frac{\ln(1/\tau)}{d^t}.
\tag{22}
\]

Thus the useful diagnostic quantity is

\[
\boxed{
\rho=\frac{k\,d}{n_{\rm act}}.
}
\tag{23}
\]

Up to the logarithmic terms inside the q-ary entropy, tensoring tends to help the
capacity ratio when `rho<1` and eventually hurts when `rho>1`.

Equation (21), not this approximation, is the theorem. The checker evaluates (21)
directly on synthetic `rho=1` and `rho=2` rows; the latter eventually violates the
necessary condition as `t` grows.

For a practical construction we should compute (21) on the **actual** source rather
than infer feasibility from gap factor alone.

## 8. Negative theorem: a fixed auxiliary tensor cannot help at matched honest signal

A tempting cheaper variant is to tensor `C_x` with a fixed public auxiliary code

\[
A\subseteq\mathbb F_q^n
\]

that is independent of the statement.

Suppose honest decapsulation uses a fixed nonzero auxiliary vector `a_h in A` of
weight `d_A`, and let

\[
\delta_A=d_{\min}(A)\le d_A.
\]

### Theorem 2 — matched-signal auxiliary no-go

At fixed honest signal, a statement-independent auxiliary tensor cannot reduce the
Run-96/99 false spectral sum.

Take a minimum-weight `a_min in A`. The tensor code contains the injective subcode

\[
\{y\otimes a_{\min}:y\in C_x\}.
\]

Therefore

\[
S_{C_x\otimes A}(\beta)
\ge
S_{C_x}(\beta^{\delta_A}).
\tag{24}
\]

If the honest tensor relation has weight at most `d d_A` and we match an honest signal
`\tau`, then

\[
\beta^{d d_A}=\tau.
\]

The corresponding base-code noise parameter is

\[
\beta_0=\tau^{1/d}=\beta^{d_A}.
\]

Since `delta_A <= d_A` and `0<beta<1`,

\[
\beta^{\delta_A}\ge\beta^{d_A}=\beta_0.
\]

Because `S_C(beta)` is monotone increasing in `beta`,

\[
\boxed{
S_{C_x\otimes A}(\beta)
\ge
S_{C_x}(\beta_0).
}
\tag{25}
\]

So an auxiliary ECC/tensor factor that does not inherit the **statement-dependent
false gap** cannot improve the statistical false-hiding metric at the same honest
signal. It may strictly worsen it.

This separates useful **self-tensor gap amplification** from cosmetic public
tensor padding.

## 9. Exact finite controls

The fresh deterministic checker uses the binary `[3,2,2]` even-parity code.

For tensor powers:

* `t=1`: length 3, dimension 2, distance 2, weight enumerator
  `1 + 3 z^2`;
* `t=2`: length 9, dimension 4, distance 4, weight enumerator
  `1 + 9 z^4 + 6 z^6`;
* `t=3`: length 27, dimension 8, distance 8, weight enumerator
  `1 + 27 z^8 + 54 z^12 + 108 z^14 + 54 z^16 + 12 z^18`.

Every nonzero word in the `t=2` and `t=3` codes was checked fiber-by-fiber. Every
nonempty axis fiber belonged to the base code and the minimum fiber support satisfied
the exact integer inequality

\[
(\min{\rm fiber\ weight})^t\le W.
\]

At `beta=1/2` the exact spectral sums are

\[
S_1=3/16,
\]

\[
S_2=75/2048\approx0.0366211,
\]

\[
S_3=7140315/17179869184\approx0.000415621.
\]

The corresponding distance-only upper bounds are `3/16`, `15/256`, and `255/65536`.

For a fixed repetition auxiliary code, the matched-signal lower bound (25) is met
with equality in the tested fixture. For a fixed full-space auxiliary code whose
minimum distance is below the honest auxiliary vector's weight, the product leakage
is much worse (`105/256` versus matched base `3/256`).

These are exact small-code algebra/probability controls only.

## 10. Literature scope

Tensoring itself is not a new gap-amplification idea. Bhattiprolu, Guruswami, Lee and
Ren, arXiv:2410.02636v3 / FOCS 2025, explicitly state that their sparse-vector gap is
further amplified using tensoring, and their merged v3 includes the finite-field MDP
setting.

Jin, ePrint 2026/2063 (approved 19 September 2026), publicly states a Karp–Levin
reduction from satisfiability of `polylog(lambda)`-size circuits to GapMDP over a prime
field of size `lambda^{omega(1)}` with approximation
`omega(log lambda)`. The public page still does not expose the exact
`m,k,d,D,n_act`, tensor behavior, or the "every low-support word -> ORIGINAL witness"
threshold needed to instantiate this run's formulas.

Hair–Sahai arXiv:2609.18275v1 remains a classical generic-group WE construction with a
logarithmic homogeneous-MinRank gap. Its public theorem is not a concrete PQ security
theorem, and MinRank tensoring is not silently substituted for the Hamming source used
here.

## 11. Quantum-security ledger

### Honest algorithm model

All operations in this run are classical. For fixed tensor power `t`, generator
tensoring, witness tensoring, fiber extraction, and the Run-98 release remain
polynomial time when the base source compiler is polynomial.

### False-statement adversary

When the exact Run-96/99 statistical syndrome bound is negligible, hiding is against
an **unbounded** adversary, hence arbitrary QPT adversaries as well.

The tensor lemmas add no quantum assumption.

### Hardness distribution and assumptions

No computational hardness assumption is introduced by this run.

The only conditional source inputs are the base Hamming-gap compiler and its exact
ORIGINAL-witness extraction threshold. Whether Jin's current reduction provides the
needed parameters and extraction theorem remains **UNVERIFIED**.

### Reduction model

The new source-transfer result is deterministic classical algebra/combinatorics.
The false-hiding implication is information-theoretic.

There is no rewinding, random oracle, QROM programming, superposition-query oracle, or
quantum extraction step in these theorems.

### Exact established conclusions

Conditioned on the base source interface:

1. every valid witness yields a tensor relation of weight at most `d^t`;
2. false minimum distance is `D^t`;
3. every supplied tensor relation of weight at most `B^t` yields an ORIGINAL source
   witness;
4. the Run-96/99 spectral and capacity formulas specialize exactly as above;
5. fixed statement-independent auxiliary tensoring cannot improve false spectral
   leakage at matched honest signal.

### Still UNPROVED

1. arbitrary-QPT early FINAL-key recovery on a true statement -> supplied low-weight
   tensor relation;
2. arbitrary-QPT early FINAL-key recovery -> ORIGINAL witness or independent
   QPT-hardness break by another route;
3. Jin's exact base source parameters and all-low-support extraction theorem;
4. complete malicious-secure setup/abort and auxiliary-input composition;
5. practical final parameters/resource estimates.

Therefore the stopping condition is not met.

## 12. Next handoff

The next high-value audit is now quantitative and source-specific:

1. obtain the full current Jin 2026/2063 proof and extract exact
   `m,k,d,D,n_act`, plus the exact theorem converting **every** sufficiently
   low-support codeword into an accepting SNARG proof and then an ORIGINAL source
   witness;
2. evaluate the base and small constant tensor powers using the **actual weight
   enumerator or a proved upper bound**, not only minimum distance;
3. compute the exact Run-99 capacity condition (21) and the diagnostic
   `rho=k d/n_act`;
4. only if a small constant tensor power improves the false channel at polynomial
   cost, return to the true-instance arbitrary-QPT extraction barrier from Run 97.

The current result is a genuine source compiler transformation and a no-go theorem for
fixed auxiliary tensor padding, not a completed WKEM.
