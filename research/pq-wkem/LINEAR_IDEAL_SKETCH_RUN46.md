# Run 46 — linear compression of high-degree ideal masks: exact public-separator barrier

## Status

Starting verified PR head: `d7f9b8959e0052b621e236689e6743f0397d0700` (Run 45), open/draft/unmerged.

Run 45 left one explicit route open: keep the useful source-ideal property

\[
R(w)=0\quad\text{for every valid witness }w,
\]

but avoid the exponential complete monomial coefficient vector by publishing a **compressed** representation of a high-degree ideal element. This run makes that constructive attempt for the broadest transparent linear version I could formulate: a polynomial-size public linear sketch of a uniformly linearly seeded high-degree ideal mask.

The result is negative but exact. Linear compression does not create witness restriction. Once the complete compressed output is audited, it has the same affine-coset dichotomy as a public linear code: either the key shift lies in the compressed mask image and **nobody**, including a witness, gets statistical key information from that sketch; or the shift lies outside and Gaussian elimination gives **everybody** an exact key extractor. A randomized public sketch almost always falls into the first case once the mask-image dimension exceeds the sketch dimension; deliberately preserving a linear witness evaluator forces the second case and therefore a public separator.

This is **not** a new general affine-subspace theorem: Run 41 already proved the identical-or-publicly-disjoint law for public affine subspace mixers. The new result is its precise application to the unresolved Run-45 compression route, including the seeded high-degree ideal representation, witness-linear-decoder theorem, and exact random-sketch resource calculation. It closes **public linear sketching / linear witness evaluation** as a way to compress Run 45. It does not rule out nonlinear or computational compression.

No external literature or web search was used. Production code is unchanged.

---

## 1. Candidate: seeded high-degree ideal mask plus public linear sketch

Work over `F_q`, q prime. Let `P` be any finite-dimensional coefficient/representation space large enough to contain the high-degree source-ideal elements under consideration. The dimension of `P` may be exponential; it need never be materialized if the maps below have succinct implementations.

For a fixed public statement `x`, let

\[
G_x:F_q^r\to P
\]

be a public **linear** mask generator whose image consists of source-vanishing objects. Concretely, in Run 45 one may take columns of `G_x` to be high-degree multiples of the public source equations. Sample a uniform polynomial-size seed

\[
\rho\leftarrow F_q^r,
\]

and let

\[
R=G_x\rho.
\]

Let `e_0 in P` denote the constant-one/key-shift direction. Instead of publishing all coefficients of

\[
K e_0 + R,
\]

choose a public linear sketch

\[
S_x:P\to F_q^m
\]

and publish only

\[
\boxed{c=S_x(K e_0+G_x\rho).}
\tag{1}
\]

Define the public compressed mask matrix and key-shift vector

\[
A=S_xG_x\in F_q^{m\times r},\qquad b=S_xe_0\in F_q^m.
\tag{2}
\]

Then the **complete published capsule** is exactly

\[
\boxed{c=A\rho+Kb.}
\tag{3}
\]

This model includes:

- a huge-degree ideal element generated from only polynomially many random seed coordinates;
- a sketch evaluated without expanding the full monomial basis, provided `S_x G_x` is computable succinctly;
- arbitrary statement-dependent public `S_x` and `G_x`;
- public invertible row mixing of the sketch;
- any number of source equations/multipliers, as long as the final seed-to-sketch map is linear.

It is therefore a real attempt to exploit Run 45's source-ideal annihilation while reducing the public representation size from the full coefficient vector to `m=poly(lambda,|x|)` field elements.

---

## 2. Complete-output theorem

### Theorem 1 — identical or publicly separated

For uniform `rho in F_q^r`, exactly one of the following holds.

#### Case A: `b in col(A)`

Choose `rho_0` with `A rho_0=b`. Then

\[
A\rho+Kb=A(\rho+K\rho_0).
\]

Translation by `K rho_0` permutes the uniform seed space. Hence for **every** key value

\[
\boxed{c\mid K\ \text{is the same uniform distribution on }\operatorname{col}(A).}
\tag{4}
\]

The complete compressed public output contains zero information about `K`. This is decoder-independent: an unbounded witness decoder cannot beat random guessing from this sketch alone.

#### Case B: `b notin col(A)`

Finite-dimensional duality gives a vector

\[
\lambda\in F_q^m
\]

such that

\[
\lambda^TA=0,\qquad \lambda^Tb=1.
\tag{5}
\]

It is found by Gaussian elimination on the public system

\[
A^T\lambda=0,\qquad b^T\lambda=1.
\]

For every seed and every key,

\[
\boxed{\lambda^Tc=K.}
\tag{6}
\]

Thus the `q` key-conditioned supports are disjoint public affine cosets and a classical polynomial-time party recovers the exact key.

`□`

### Consequence for Run 45 compression

Linear sketching does not interpolate between the two Run-45 outcomes. It merely moves the same question into the compressed image:

\[
\boxed{b=S_x(1)\in \operatorname{im}(S_xG_x)?}
\]

- If yes, the sketch has perfect key hiding but cannot supply witness-only key information.
- If no, the sketch has an exact public key extractor.

The high algebraic degree and potentially exponential uncompressed support of `G_x rho` do not change this complete-view statement.

---

## 3. Stronger statement for linear witness decoders

Suppose a valid witness `w` is intended to derive a public-vector linear decoder `lambda_w` and output

\[
D_w(c)=\lambda_w^T c.
\]

Normalize it so that

\[
\lambda_w^Tb=1.
\tag{7}
\]

Then

\[
D_w(c)=K+(\lambda_w^T A)\rho.
\tag{8}
\]

### Lemma 2 — exact or uniform, no intermediate advantage

For uniform `rho`:

- if `lambda_w^T A=0`, then `D_w(c)=K` with probability `1`;
- if `lambda_w^T A != 0`, then `(lambda_w^T A)rho` is uniform in `F_q`, so `D_w(c)` equals `K` with probability exactly `1/q`.

This is because every nonzero linear functional on `F_q^r` is surjective and all fibers have size `q^(r-1)`.

Therefore any linear witness decoder with success strictly greater than `1/q` on a fixed setup **must itself be a separator satisfying (5)**. But (5) is a public linear system. Its existence is efficiently detectable and one such separator is efficiently recoverable without the witness.

So there is no hidden "witness-only" linear functional inside the sketch. The witness may point to a separator, but it cannot make the separator secret.

---

## 4. Randomized setup gives a public true/false distinguisher

Allow setup to randomize `S_x,G_x`, hence `A,b`. Define the public event

\[
E=[b\notin\operatorname{col}(A)].
\tag{9}
\]

For a fixed setup, Theorem 1 says the optimal key-recovery probability from the complete sketch is

\[
1\quad\text{on }E,
\qquad
1/q\quad\text{on }\neg E.
\tag{10}
\]

Suppose some valid witness using a linear decoder has average success `s` over setup randomness. Even granting success `1` on every exposed setup and only `1/q` otherwise,

\[
s\le \Pr[E]+(1-\Pr[E])/q.
\]

Hence

\[
\boxed{
\Pr[E\mid x\in L]
\ge
\frac{s-1/q}{1-1/q}.
}
\tag{11}
\]

On a false statement, the public algorithm "if E, use separator; otherwise guess uniformly" succeeds with probability

\[
\frac1q+\left(1-\frac1q\right)\Pr[E\mid x\notin L].
\tag{12}
\]

Thus any claimed false-instance bound `1/q+eta` forces

\[
\boxed{
\Pr[E\mid x\notin L]\le \frac{\eta}{1-1/q}.
}
\tag{13}
\]

The event `E` is publicly computable by Gaussian elimination. Therefore, if an efficient generic construction in this class had a nonnegligible gap between (11) and (13), repeated fresh setup trials would give a randomized polynomial-time decision procedure for the source language.

This is a **complexity consequence for this candidate class**, not a claim that `NP != BPP` or a general impossibility theorem for witness encryption.

For `q=5`, the executed numeric controls give:

| average linear witness success `s` | forced `Pr[E | true]` lower bound |
|---:|---:|
| 0.60 | 0.50 |
| 0.80 | 0.75 |
| 0.95 | 0.9375 |
| 0.99 | 0.9875 |

---

## 5. Why a generic random sketch kills witness decodability

There is a complementary quantitative fact directly relevant to Run 45.

Assume `e_0` is linearly independent of a `d`-dimensional mask space `V`. Choose a uniformly random public linear map

\[
S:P\to F_q^m.
\]

After fixing a basis of `V` plus `e_0`, their images are independent uniform vectors in `F_q^m`. Thus:

- `A` is a uniform `m x d` matrix;
- `b` is an independent uniform vector in `F_q^m`.

Conditioned on `rank(A)=r`,

\[
\Pr[b\in\operatorname{col}(A)\mid r]=q^{r-m},
\tag{14}
\]

so

\[
\boxed{
\Pr[E]=1-\mathbb{E}[q^{\operatorname{rank}(A)-m}].
}
\tag{15}
\]

The exact number of `m x d` matrices of rank `r` is

\[
N_{m,d}(r)
=
\prod_{i=0}^{r-1}
\frac{(q^m-q^i)(q^d-q^i)}{q^r-q^i},
\tag{16}
\]

which makes (15) explicitly computable.

When `d>=m`, the probability that `A` already has full row rank is

\[
\boxed{
\Pr[\operatorname{rank}(A)=m]
=
\prod_{i=0}^{m-1}(1-q^{i-d}).
}
\tag{17}
\]

On that event `col(A)=F_q^m`, so `b in col(A)` automatically and **no decoder can learn K from the sketch**.

For the executed `q=5,m=4` controls, the exact separator probability falls from about `0.1918` at `d=4`, to `0.03962` at `d=5`, `0.007975` at `d=6`, and `1.278e-5` at `d=10`; meanwhile full-row-rank probability rises to `0.9999840` at `d=10`.

So a generic random compression of a rich high-degree mask space tends to erase the key shift into the mask image. To preserve a useful **linear** witness observable, setup must deliberately keep a codimension-one direction visible. But Theorem 1 says that visible direction is exactly the public separator.

---

## 6. Explicit high-degree source-ideal fixture

The checker includes a source relation with two valid witnesses:

\[
g(z)=z(z-1)=0,
\]

so `w=0` and `w=1` are both valid. For total degree `D=32`, use the `31` mask generators

\[
z^i g(z),\qquad 0\le i\le 30.
\]

Each generator vanishes at both witnesses. The uncompressed coefficient ambient space has 33 coordinates, while the published sketch has only `m=8` coordinates.

To make the intended witness evaluation survive, the pre-scramble sketch contains evaluation at `z=0` and `z=1` as two rows, plus six random rows. A fresh random invertible `8 x 8` row mixing matrix hides which rows were evaluations syntactically.

Both witness decoders still recover the key exactly after undoing the row mixing **at the level of their linear functional**. But the public system (5) finds a separator directly from `(A,b)` without knowing either witness or the pre-scramble row identities. In the executed fixture:

- degree: `32`;
- mask seed dimension: `31`;
- sketch dimension: `8`;
- `400/400` capsules decoded by witness `0`;
- `400/400` capsules decoded by witness `1`;
- the public separator decoded the same `400/400` keys;
- no mask seed, source witness, or hidden pre-scramble row was given to the separator algorithm.

This fixture is an implementation sanity check for the theorem, not a security experiment.

---

## 7. Relation to Run 41 and Run 45

Run 41 already proved that a public uniform affine-subspace channel is either identical across keys or publicly coset-decodable. This run does not relabel that theorem as a new primitive.

What is new here is the exact closure of a specific Run-45 handoff:

1. Run 45's high-degree ideal element can be generated from a polynomial seed without materializing all monomials.
2. A public **linear** compression of that object is nevertheless exactly of the form `A rho + Kb`.
3. If a linear source-witness evaluator survives the compression with nonrandom advantage, it is a public dual separator.
4. A generic random sketch instead drives `b` into `col(A)` and destroys *all* key information.
5. Thus high degree, sparse arithmetic generation, and random row mixing do not by themselves solve the missing witness-restricted encoding when the final public representation and witness evaluator remain linear.

The surviving Run-45 direction must therefore use a genuinely nonlinear/computational compressed representation or a different source compiler. Merely saying "store the ideal polynomial as a circuit" is not enough: if the final capsule exposes a public linear seed-to-output map, this theorem applies; if it exposes a nonlinear computational map, a new complete-output reduction is required.

---

## 8. Implemented validation

`linear_ideal_sketch_run46_check.py` is standard-library-only and was executed twice with deterministic seed `460045001`; both JSON outputs were byte-identical.

Fresh executed work in this run:

- `320` random complete-coset fixtures over `F_5`;
  - `124` had `b in col(A)` and exact enumeration confirmed identical key-conditioned distributions;
  - `196` had `b notin col(A)` and public Gaussian-elimination separators recovered every enumerated key;
  - `42,892` distinct/support points were checked across these exact distributions;
- `500` independent all-or-uniform decoder fixtures;
  - `41` exact-decoder cases (`lambda^T A=0`);
  - `459` nonzero cases whose exhaustively enumerated scalar noise histogram was exactly uniform;
  - `2,500` scalar histogram bins checked;
- the degree-32 two-witness ideal fixture described above, with `400` fresh capsules;
- `3,000` random-sketch trials for each mask dimension `d=1..10` at `q=5,m=4`, compared against the exact rank-count formula (15)-(16);
- exact full-row-rank probabilities from (17);
- the true-instance completeness/public-exposure numeric bounds in Section 4.

The tests validate the finite-field identities and the implementation. The security conclusion comes from Theorem 1, not from absence of attacks in testing.

---

## 9. Proved claims, conjectures, and remaining obligations

### Proved in this run

1. Exact complete-output dichotomy for a uniformly linearly seeded public linear sketch `c=A rho+Kb` over any finite field.
2. Exact all-or-uniform law for every normalized linear witness decoder.
3. Efficient public recovery of a separator whenever any such nonrandom linear decoder exists on a fixed setup.
4. The randomized-setup public-event bounds (11)-(13).
5. Exact random-sketch separator probability via finite-matrix rank counts.
6. Public invertible row mixing cannot hide the separator, because it only changes `(A,b)` by an invertible left action.

### Implemented / tested

The standard-library checker implements finite-field Gaussian elimination, public separator extraction, exact distribution enumeration, the all-or-uniform law, the degree-32 ideal-sketch fixture, random invertible row scrambling, and exact rank-count probabilities. Counts are listed in Section 8 and the captured JSON.

### Not proved / still open

- No impossibility theorem for nonlinear, stateful-at-setup-but-erased, or computational compression.
- No reduction for a nonlinear high-degree ideal circuit encoding to LWE/SIS or another independently justified PQ assumption.
- No arbitrary-QPT early-key-recovery -> source-witness/PQ-break theorem for a surviving **efficient** construction.
- No complete false-instance hiding theorem for such a surviving nonlinear representation.
- No malicious-secure ceremony / auxiliary-input composition for a surviving inner primitive.
- No final practical parameters or resource estimate for a complete WKEM.

The stopping condition is **not met**.

---

## 10. Next handoff

The next constructive attempt should no longer spend a run on public linear compression of Run 45. That class is now fully audited.

A useful next target is one of:

1. **Nonlinear computational compression of source-ideal masks** where witness evaluation is efficient but the complete published representation has a reduction to an independently justified PQ assumption. The reduction must include the statement-dependent auxiliary data and cannot assume the missing witness-release functionality.
2. **A stronger source compiler / metric gap** that can plug into the positive Run-42/43 SIS-bound supplied-preimage interface, avoiding the near-threshold false affine fibers that killed ordinary preimage encryption.
3. A construction that combines source binding with a standard-assumption native KEM in a way that proves arbitrary early key recovery yields either an actual source representation or a standard PQ break, rather than only showing intended-decoder correctness.

For the ideal route specifically, the next question is now sharply nonlinear: can one publish a polynomial-size arithmetic/coded object representing a high-degree random ideal element such that *every* valid witness evaluates the same key, while the object is computationally hiding on false statements under LWE/SIS **without** exposing a public linear seed-to-output separator and without assuming a WE-equivalent obfuscator?
