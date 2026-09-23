# Run 54 — hidden edge-pad common binding, and why the natural linear native encoding cancels in the complete public view

## Status

This run starts from Run 53 rather than restarting the search.  Run 53 gave a useful positive primitive: for a constant-arity Boolean constraint, the signed local-view representation has an exact blockwise gap (`||z_b||_2^2 = 1` iff the normalized integral block is one-hot; otherwise it is at least `3`).  Its concrete 3-CNF false core nevertheless permits **componentwise witness switching**: each component can be opened with a different exact global signed representation whose currently tested block is one-hot.

Run 54 asks whether a setup-time secret can bind those component openings to one common assignment without knowing a source witness and without remaining online.

The answer is split:

* **Positive semantic lemma.** Hidden random edge pads over the shared assignment marginals give exact common-assignment binding *if one reasons only about the decapsulated plaintext expressions*.  A genuine witness cancels all pads, while any switched sequence on the Run-53 false core is information-theoretically masked.
* **Negative complete-output result for the natural linear implementation.** In the native dual-preimage capsule, those same edge pads occur as additive linear coefficient vectors.  Their incidence sum is zero, so anyone can sum the **public ciphertext components before using a witness**.  The hidden pads then cancel exactly and expose an ordinary aggregate preimage capsule.  Any exact Run-53 signed false representation can evaluate that aggregate.  Public linear witness re-encodings do not fix this: the ciphertext coefficient can be pulled back with the transpose of the public encoder.

This is not a completed WKEM and not a generic impossibility theorem.  It rules out this natural linear realization of the new semantic binding idea and sharpens what a surviving common-representation binder must hide.

---

## 1. Source relation inherited from Run 53

Write the common affine representation as

\[
B y = d,
\]

and let

\[
P y = p \in \mathbb F_q^n
\]

be the public projection to the shared Boolean assignment marginals.  A genuine source witness supplies an exact `y` in which every local-view block is one-hot.  On the Run-53 eight-clause contradiction, every Boolean assignment `p` also has an exact **signed** representation `y(p)`: seven blocks are one-hot and the unique violated 3-clause is represented by the seven-entry inclusion/exclusion vector of squared norm `7`.

For the concrete false core used below:

* `n = 3` Boolean assignment coordinates;
* there are all eight 3-literal sign patterns, equivalently one block excludes each `f in {0,1}^3`;
* each block has seven allowed local rows;
* the affine system has `59 = 3 + 8*7` representation coordinates and `32 = 8 + 8*3` equations.

For every `p in {0,1}^3`, the checker independently verifies `B y(p)=d`.

---

## 2. Constructive attempt: hidden telescoping edge pads

Consider `m` component capsules laid out on a path.  Setup chooses independent uniform edge pads

\[
r_1,\ldots,r_{m-1}\leftarrow \mathbb F_q^n
\]

and defines `r_0=r_m=0`.  Let component `j` use the incidence difference

\[
\Delta r_j = r_j-r_{j-1}.
\]

For the moment ignore how this quantity is encoded publicly.  If component `j` is opened using an assignment marginal `p_j`, let its plaintext contribution be

\[
\kappa_j - \langle \Delta r_j,p_j\rangle.
\]

The key shares satisfy `sum_j kappa_j = K`; equivalently one component may carry `K` and the rest zero.

Summing all components gives

\[
K - \sum_{j=1}^m \langle r_j-r_{j-1},p_j\rangle
=
K + \sum_{e=1}^{m-1}\langle r_e,p_{e+1}-p_e\rangle.
\]

### Lemma 2.1 — common witness completeness

If all components use the same assignment `p`, then every edge difference is zero and the output is exactly `K`.

This preserves the requirement that **every valid witness obtains the same key**.  Setup does not need to know which valid witness will later be used.

### Lemma 2.2 — semantic switching mask

Fix any sequence `(p_1,...,p_m)` with at least one adjacent mismatch.  If the corresponding `r_e` is uniform in `F_q^n`, then

\[
\langle r_e,p_{e+1}-p_e\rangle
\]

is uniform in `F_q` whenever `p_{e+1}-p_e != 0`.  Therefore the entire summed plaintext is uniform in `F_q` conditioned on all other pads and on the complete assignment sequence.

This is an exact information-theoretic statement about the **idealized plaintext algebra**.

### Application to the Run-53 eight-clause false core

Component `j` can make its target block one-hot only by choosing an assignment `p_j` different from the assignment excluded by clause `j`.  There are `7^8 = 5,764,801` such locally valid sequences.  None is constant: a constant assignment `p` necessarily fails the component whose excluded assignment is exactly `p`.

The checker counts their adjacent-mismatch distribution exactly:

| adjacent mismatches | sequence count |
|---:|---:|
| 0 | 0 |
| 1 | 84 |
| 2 | 2,268 |
| 3 | 29,394 |
| 4 | 217,724 |
| 5 | 947,274 |
| 6 | 2,264,118 |
| 7 | 2,303,939 |

It also exhausts every ordered nonzero Boolean difference over `F_5`; for each of the 56 differences, all `5^3=125` edge pads produce each scalar field value exactly 25 times.

So **before considering the public encoding**, this does solve Run 53's switching problem cleanly.

---

## 3. Natural native-preimage implementation

The obvious way to realize the hidden pads inside the existing native preimage mechanism is

\[
a_j = B^T s_j + e_j + P^T(r_j-r_{j-1}),
\]

\[
b_j = d^T s_j + e_{0,j} + \mu\kappa_j.
\]

For any exact representation `B y_j=d`, writing `p_j=P y_j`, its residual is

\[
\begin{aligned}
\rho_j(y_j)
&= b_j-y_j^Ta_j \\
&= \mu\kappa_j
 - \langle r_j-r_{j-1},p_j\rangle
 + e_{0,j}-y_j^Te_j.
\end{aligned}
\]

Thus the desired hidden-edge-pad formula is implemented exactly.

At this point the construction looks materially better than Run 53 if only the individual residuals are considered.  The complete public output changes the conclusion.

---

## 4. Complete-output cancellation theorem

Every `a_j,b_j` is public.  Therefore anyone can form

\[
A=\sum_j a_j,
\qquad
b=\sum_j b_j.
\]

But

\[
\sum_j (r_j-r_{j-1})=0.
\]

Hence the edge pads disappear **before any witness is supplied**:

\[
\boxed{
A=B^T S+E,
\qquad
b=d^T S+E_0+\mu K
}
\]

where `S=sum_j s_j`, `E=sum_j e_j`, and `E_0=sum_j e_{0,j}`.

For **any** exact representation `B y=d`, including a Run-53 signed false representation,

\[
\boxed{
 b-y^TA=\mu K+E_0-y^TE.
}
\]

The hidden edge pads have contributed exactly zero security to this publicly derived aggregate capsule.

This is a deterministic complete-output attack on the proposed binding layer.  It does **not** prove that every possible parameterization of the remaining aggregate noisy capsule is insecure; it proves that the new semantic one-time pad itself vanishes from a public derived view, so any security would have to come entirely from the old aggregate preimage/noise mechanism.

That is exactly the mechanism for which Runs 43, 47, and 53 already exposed the global-gap problem.

---

## 5. Public linear coordinate scrambling does not hide this cancellation

A natural repair is to put component `j` in a different public linear witness coordinate system.  Let

\[
y_j' = E_j y
\]

for a public linear encoder `E_j`, and let `a_j'` be the public coefficient vector evaluated by that encoded witness.

This does not make the coefficient functional private.  Anyone computes the pullback

\[
\boxed{\tilde a_j = E_j^T a_j'}
\]

because

\[
\langle y_j',a_j'\rangle
=\langle E_jy,a_j'\rangle
=\langle y,E_j^Ta_j'\rangle.
\]

Therefore every public **linear** witness re-encoding can be returned to a common source coordinate system before the components are combined.  If the hidden edge terms telescope for a common `y` as public linear functionals, the attacker can perform that same pullback and telescoping on the public ciphertext coefficients.

The checker validates this identity on 200 random signed-permutation re-encodings (400 encode/pullback assertions), but the statement above is the proof and does not depend on that special test family.

This result is deliberately scoped.  It does not rule out a nonlinear/computational witness encoder for which no polynomial-size public pullback exists.  Such an encoder would, however, need its own complete-output reduction rather than being assumed witness-selective.

---

## 6. Concrete bounded-noise complete-view break

To ensure the cancellation is not merely symbolic, the checker instantiates the full 59-coordinate Run-53 false relation with

* `q = 4093`;
* binary phase `mu = 2046`;
* iid ternary errors;
* target-block error coordinates scaled by `L=8` and all other representation coordinates at unit scale;
* one public component for each of the eight clause blocks.

For a Run-53 signed false representation `y(p)`:

* across all eight component errors, the target-block part contains exactly `14` nonzero coefficients of magnitude `L` (seven ordinary one-hot targets plus seven coefficients in the unique malformed target block);
* all unit-scale terms, including the eight scalar `e_0` terms, contribute at most `106+8 wt(p) <= 130` in absolute value.

Therefore every bounded error realization satisfies

\[
|E_0-y^TE|
\le 14\cdot 8+130
=242.
\]

The nearest binary centers are separated by roughly `q/2`; the half-decision radius is `floor(q/4)=1023`.  Thus

\[
242 < 1023
\]

and **every** such false exact representation recovers the bit from the publicly aggregated capsule for this candidate parameterization.

The checker ran 500 fresh seeded full-capsule trials and observed 500/500 false recoveries.  More importantly, the deterministic bound above proves the result for *all* ternary error realizations in this tested parameterization; the Monte Carlo count is only an implementation check.

This does not claim that `q=4093,L=8` is a secure or recommended LWE parameter set, nor that all choices of `q,L` fail by the same deterministic inequality.

---

## 7. Exact target-only padding diagnostic

After public edge-pad cancellation, the best remaining hope for this family is the Run-53 blockwise noise gap aggregated into one scalar residual.  In an optimistic diagnostic that keeps only the strongly weighted target-block errors:

* an honest `m`-block representation contributes `S_m`, a sum of `m` iid ternary variables;
* a false representation with one malformed 3-clause contributes `S_{m+6}`.

For each tested `m`, the checker finds the smallest integer threshold giving honest success at least `1-2^-20` and then evaluates the **exact** false success probability using integer convolution:

| m | threshold | honest success | false success |
|---:|---:|---:|---:|
| 8 | 8 | 1.0 | 0.9958402407 |
| 16 | 14 | 0.9999992102 | 0.9999211503 |
| 32 | 22 | 0.9999997137 | 0.9999962448 |
| 64 | 31 | 0.9999991911 | 0.9999973642 |
| 128 | 45 | 0.9999993702 | 0.9999988482 |
| 256 | 64 | 0.9999993126 | 0.9999990724 |
| 512 | 90 | 0.9999990974 | 0.9999989547 |

This is an exact finite diagnostic for that simplified error model, not a general LWE impossibility result.  It does show why losing the hidden common-assignment pad is serious: after collapse to a single global residual, the false representation differs by only six extra local coefficients while completeness forces a wide acceptance region.

---

## 8. What is proved, implemented, tested, and still conjectural

### Proved in this run

1. The hidden-edge-pad plaintext identity and exact same-key completeness for any common assignment.
2. Information-theoretic uniform masking of any fixed switched assignment sequence with at least one nonzero edge difference.
3. On the Run-53 all-eight-clause false core, no locally valid switching sequence is constant.
4. In the natural linear native-preimage encoding, public summation cancels every hidden edge pad before witness evaluation and yields an ordinary aggregate preimage capsule.
5. Public linear witness re-encoding does not hide a linear coefficient functional: `E_j^T a_j'` is a public pullback.
6. For the explicit `q=4093, mu=2046, L=8` bounded-ternary candidate, the aggregate false residual has deterministic magnitude at most 242, so the false bit always decodes under the stated nearest-center rule.

### Implemented and actually executed

`check_common_binding_run54.py` independently builds the 32-by-59 false-core relation, signed representations, edge-pad incidence system, native capsules, aggregate public attack, public linear re-encoding controls, and exact ternary convolutions.  It was executed twice after finalization with byte-identical JSON output.

### Not proved

* No reduction from arbitrary QPT early key recovery to a source witness or to LWE/SIS is obtained.
* The run does not rule out a nonlinear/computational edge binder whose cancellation happens only after genuine witness evaluation and is not publicly pullbackable.
* The run does not prove insecurity for every error distribution or every parameter choice of the aggregate capsule.
* No malicious-secure setup ceremony, auxiliary-input composition theorem, or practical end-to-end WKEM parameters are claimed.

---

## 9. Handoff

The constructive idea was useful: **hidden telescoping pads are sufficient for common-representation binding at the plaintext algebra level**.  The failure is more specific than Run 53's switching attack: a linear public encoding exposes a derived view in which the very pads that solve switching cancel before witness use.

A next candidate must therefore satisfy both conditions simultaneously:

1. a common witness causes hidden consistency terms to cancel so every valid witness gets the same `K`; and
2. the complete public output must not admit a polynomial-time pullback/aggregation that performs the same cancellation without a source witness.

Public linear coordinate changes are now ruled out for this purpose.  A surviving direction would need a genuinely nonlinear/computational witness-dependent cancellation mechanism with a reduction to an independently justified PQ assumption, while avoiding the Run-45/46/51/52 public-support and interpolation failures.  Merely naming that missing evaluator as an assumption would not meet the project goal.
