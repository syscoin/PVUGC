# Run 75 — ideal telescoping clause masks give perfect false-instance hiding; compact GGM domain covers exist, but component constrained keys destroy the difference-only invariant

**Status:** substantive constructive source-encoding attempt, an exact complete-public-output hiding theorem in the ideal difference-only model, a polynomial-size domain-cover result for 3CNF, and exact failures of the two most direct compact realizations. **Not a completed generic-NP witness KEM.**

Starting verified PR head: `e38d109a74bda5050840135800f4fe3a8d156aea`.

No external literature or web search was used. Production code is unchanged.

## 1. Starting point from Runs 72–74

The current record has separated two obligations:

1. **native one-way transport after a parent capability exists** — Run 72 gives a clean standard-LWE construction for this layer;
2. **source-witness transfer** — the public offline source layer must ensure that all uses of the witness refer to one global witness rather than independently selectable local values.

Run 74 closed the direct compact-high-degree circuit workaround when repeated witness reads are public independent choices. It left open a different possibility:

> let each local constraint release only a *masked share* indexed by a full witness point, and arrange the masks so that shares telescope only when all constraints use the same point.

This run develops that route exactly.

## 2. Ideal telescoping difference construction

Let a CNF have clauses

\[
C_1,\ldots,C_m
\]

over witness domain

\[
W=\{0,1\}^n.
\]

Let

\[
S_c=\{w\in W:C_c(w)=1\}
\]

be the assignments satisfying clause `c`.

Let `G` be any finite abelian group. For a key `K in G`, setup samples independent uniform masks

\[
R_j(w)\leftarrow G
\qquad
(j=1,\ldots,m-1,\; w\in W),
\]

and defines the endpoints

\[
R_0(w)=0,\qquad R_m(w)=K.
\]

For every clause, the intended public object exposes **only**

\[
D_c(w)=R_c(w)-R_{c-1}(w)
\qquad\text{for } w\in S_c.                         \tag{1}
\]

Think of (1) as an ideal constrained evaluator. The complete public output may even contain the entire allowed table; the theorem below still holds.

### Correctness

If `w` is a valid source witness, then `w in S_c` for every clause and

\[
\sum_{c=1}^m D_c(w)
=
R_m(w)-R_0(w)
=
K.                                                    \tag{2}
\]

Thus every valid witness recovers the **same** key.

The setup never uses or knows a witness.

## 3. Exact complete-public-output false-instance hiding

### Theorem 1 — perfect hiding in the ideal difference-only model

If the CNF is false, then for every two keys `K,K' in G`, the complete public distributions

\[
\{D_c(w):w\in S_c,\; c=1,\ldots,m\}
\]

are identical.

This is information-theoretic and holds even if the adversary is given every allowed value, not merely polynomially many evaluations.

### Proof

Let

\[
\Delta=K'-K.
\]

Because the formula is false, for every `w` there exists at least one missing clause edge. Choose one such index

\[
g(w)\in\{1,\ldots,m\}
\quad\text{with}\quad
w\notin S_{g(w)}.
\]

Given one set of masks for key `K`, define masks for key `K'` by

\[
R'_j(w)=
\begin{cases}
R_j(w), & j<g(w),\\
R_j(w)+\Delta, & j\ge g(w),
\end{cases}
\]

and set `R'_m(w)=K'=K+\Delta`.

For every *published* edge `(c,w)` we have `c != g(w)`.

* If `c<g(w)`, neither endpoint was shifted.
* If `c>g(w)`, both endpoints were shifted by the same `Delta`.

Therefore

\[
D'_c(w)=R'_c(w)-R'_{c-1}(w)=D_c(w)
\]

for every public value.

The map from the original random masks to the shifted masks is a bijection, so the transcript distributions are exactly identical. ∎

### Converse on true instances

If some `w` satisfies every clause, (2) is a public key-recovery equation. So the ideal object has the exact desired semantic dichotomy:

* true instance + witness: recover `K`;
* false instance: even the full allowed table is perfectly independent of `K`.

For `G=F_2`, the checker independently reconstructs the complete affine output distribution. It verifies the equivalent linear-algebra statement:

\[
v_K\in\operatorname{im} M
\iff
\text{the formula is false},                         \tag{3}
\]

where `M` maps the independent internal masks to all published edge values and `v_K` is the key-offset vector.

Across 720 fresh small formulas, (3) matched satisfiability in all 720 cases: 192 false instances had identical key cosets and 528 true instances exposed the key. This is validation of the exact theorem, not its basis.

## 4. Why this is not the Run-74 occurrence split

In Run 74, independently satisfying local blocks was enough because each block directly released its locally accepting output.

Here an assignment can still be selected separately per clause, but the outputs carry hidden witness-point-dependent masks:

\[
D_c(w_c)=R_c(w_c)-R_{c-1}(w_c).
\]

If `w_c != w_{c+1}`, the adjacent terms do not cancel.

In the ideal model, there is no public operation that converts `R_c(w_c)` into `R_c(w_{c+1})`. That exact difference-only restriction is what enforces global consistency.

This is the constructive progress of the run.

## 5. A compact domain restriction for 3CNF really exists

The ideal table is exponential. The first compression question is whether the **clause domains** themselves can be represented compactly.

For a non-tautological 3CNF clause, the forbidden set is one subcube fixing at most three witness bits to the clause's unique falsifying pattern.

A GGM-style tree constrained key can represent the complement by a disjoint prefix cover.

### Adjacent-function variable ordering

An interior mask function `R_j` participates only in clauses `C_j` and `C_{j+1}`.

Choose its input permutation so that the union of the variables occurring in those two clauses appears first. That union has at most six variables.

For either adjacent clause, all of its at most three constrained positions therefore lie among the first six positions.

### Prefix-cover bound

Order the clause's fixed positions as

\[
p_1<p_2<p_3\le 5
\]

(zero based; omit positions for narrower clauses).

Partition satisfying inputs by the first constrained position at which they differ from the falsifying pattern. Before that mismatch, only free positions need enumeration.

The number of cover nodes is

\[
\sum_t 2^{p_t-(t-1)}.
\]

With at most three fixed positions among the first six, the worst case is positions `3,4,5`, giving

\[
8+8+8=24.                                             \tag{4}
\]

So every required clause restriction of an adjacent GGM mask function has a constrained key of at most **24 subtree seeds**. A difference edge needs two such mask functions, so the naive representation would use at most 48 subtree seeds per clause edge, plus descriptions.

The checker validates the cover exactly and observes the sharp bound 24 over 366,720 assignment/cover checks.

Thus the first compression problem is **not** the size of the simple clause domain. It can be handled with constant-many GGM subtree seeds per edge.

## 6. Complete-public-output failure of the naive GGM realization

The problem is what those subtree seeds expose.

To evaluate

\[
D_c(w)=R_c(w)-R_{c-1}(w)
\]

using ordinary independently keyed GGM PRFs, the direct constrained-key implementation publishes:

* a constrained evaluator for `R_{c-1}` on `S_c`;
* a constrained evaluator for `R_c` on `S_c`.

That is strictly more than the ideal functionality, which exposes only their **difference**.

### Last-edge attack

For the last clause,

\[
D_m(w)=K-R_{m-1}(w).
\]

The naive component view lets the adversary evaluate `R_{m-1}(w)` on every `w in S_m`, while the intended edge evaluator gives `D_m(w)` on that same domain.

Every nonempty clause has a locally satisfying `w`, so

\[
\boxed{K=D_m(w)+R_{m-1}(w)}                           \tag{5}
\]

is immediate, even when the complete CNF is false.

The checker exercises this on 900 fresh guaranteed-unsatisfiable CNFs and recovers the key in 900/900 cases.

### General mismatch correction

The last-edge equation is only the shortest break. If all component values are exposed, then for arbitrary locally satisfying choices `w_c`,

\[
\sum_c D_c(w_c)
=
K
+
\sum_{j=1}^{m-1}
\bigl(R_j(w_j)-R_j(w_{j+1})\bigr).                   \tag{6}
\]

But the two component constrained keys adjacent to layer `j` reveal exactly the two correction terms in (6).

So the naive GGM component view restores the Run-74 splice algebraically even though the **ideal difference oracle** does not.

This distinction is important:

> compact constrained evaluation of the components is not a construction of compact constrained evaluation of their difference.

## 7. Why simply demanding exact XOR-key homomorphism in clear coordinates also fails

A natural repair is to ask for a PRF family in which a single "difference key" evaluates the difference:

\[
F_{k\oplus k'}(x)
=
F_k(x)\oplus F_{k'}(x).                              \tag{7}
\]

Then a constrained key for `k_{c-1} xor k_c` might appear to avoid exposing the components.

For ordinary explicit bitstring keys and outputs, however, exact XOR-key homomorphism is incompatible with standard PRF pseudorandomness.

### Theorem 2 — public-image distinguisher

Let

\[
F:\mathbb F_2^\kappa\times X\to\mathbb F_2^\ell
\]

have a public evaluation algorithm and satisfy exact key homomorphism (7).

For any fixed input `x`, the map

\[
k\mapsto F_k(x)
\]

is linear over `F_2`. For chosen inputs

\[
x_1,\ldots,x_t,
\]

the stacked transcript

\[
T(k)=
(F_k(x_1),\ldots,F_k(x_t))
\in\mathbb F_2^{t\ell}
\]

lies in a linear subspace of dimension at most `kappa`.

Because the evaluation algorithm is public, an adversary computes that subspace by evaluating the basis keys

\[
e_1,\ldots,e_\kappa
\]

on the chosen inputs.

A real PRF transcript is **always** in the computed image.

A truly random-function transcript is uniform in `F_2^{t ell}` and lands in the image with probability at most

\[
2^{\kappa-t\ell}.                                    \tag{8}
\]

Thus once

\[
t\ell\ge \kappa+\lambda,
\]

there is a polynomial-query distinguisher with advantage at least

\[
1-2^{-\lambda}.                                      \tag{9}
\]

This is unconditional and applies equally to a QPT adversary, since the attack is classical Gaussian elimination.

An affine homomorphism is no better: subtract the public `F_0(x)` offset first.

### Scope

The theorem is specifically about an **explicit vector-space representation** where the key-homomorphic relation can be tested by public linear algebra.

It does **not** rule out:

* a hidden-coordinate group/module where image membership is computationally hard;
* approximate/noisy key homomorphism;
* an encoding whose outputs become clear only after a full valid telescope;
* another independently justified PQ primitive implementing difference-only constrained evaluation.

The checker validates the public-image attack on 1,250 fresh linear families. Every real homomorphic transcript was in its public image; zero of the sampled random transcripts landed there. The theorem supplies the exact probability bound, not the empirical zero count.

## 8. What this says about GGM

Ordinary GGM gives compact constrained evaluation on the simple clause domains, but its subtree state is a seed for **one component function**.

For the difference of two GGM trees:

* publishing both constrained seed sets leaks the components and breaks by (5);
* publishing only the XOR of corresponding seeds would require the seed expansion to preserve XOR in a way ordinary GGM does not;
* making the entire clear-output family exactly XOR-key-homomorphic falls under Theorem 2.

A secure compression therefore needs a different representation: the public token must support **difference-only** constrained evaluation without giving either mask function in clear coordinates.

This is narrower than "build WE from scratch", but chaining such tokens for all CNF clauses would already yield the privacy functionality of witness encryption, so it must be treated as a substantive cryptographic primitive, not a renamed assumption.

## 9. Relation to the earlier complete-public-view input-label attack

The ideal construction does not assign a reusable public input label to each bit value.

It instead associates independent hidden masks with the **entire witness point** at each telescoping layer. That is why the ideal complete transcript survives the Run-74 split.

The naive GGM compression fails for a different reason: it exposes the hidden component functions that the ideal proof requires to remain available only through their adjacent differences.

So this run does not repeat the old "both input labels are public" candidate. It isolates a more specific compression boundary.

## 10. Malicious-secure setup / N-of-N composition

Conditionally on a secure difference-only constrained evaluator, the allowed ceremony model composes naturally:

* operator `i` samples an independent key share `K_i` and its own mask-function chain;
* its public clause tokens expose only the corresponding differences;
* the final WKEM key is the sum/XOR of all operator shares;
* one honest operator's false-instance hiding is enough to hide the final key;
* dishonest operators may abort rather than complete setup.

However, a malicious-secure proof would still need public well-formedness checks showing that each completed operator transcript really encodes one telescoping chain and the committed final share, without revealing the component masks.

That setup proof is **not** supplied here because the central difference-only primitive itself is still missing.

## 11. Fresh validation actually executed

`telescoping_clause_prf_run75_check.py` is standard-library-only and deterministic.

It was executed twice with byte-identical JSON.

The captured run validates:

* 720 complete ideal-output affine-distribution fixtures:
  * 192 false instances had the key-offset vector inside the random-mask image, hence identical key distributions;
  * 528 true instances had the key offset outside that image and expose the key;
* 400 satisfying-witness telescopes, all recovering the exact key bit;
* 366,720 prefix-cover assignment checks;
* maximum adjacent-clause variable union 6;
* maximum observed constrained prefix cover 24 nodes, matching (4);
* 900/900 guaranteed-false instances broken by the naive component constrained-key view;
* 1,250/1,250 explicit XOR-homomorphic PRF transcripts lying in their public linear image;
* zero sampled random-function transcripts in those images, with the exact random membership upper bounds ranging from `2^-8` through `2^-24` in the executed parameter sets.

The tests validate finite algebra and implementation. They do not establish cryptographic security.

## 12. Current boundary

### Proved positive result

There is an exact ideal source encoder for CNF in which:

* setup knows the statement but no witness;
* every valid witness recovers the same key;
* the **complete false-instance output is perfectly key-independent**;
* clause-domain restriction itself has a polynomial/constant-size GGM prefix cover for 3CNF.

### Proved failures

The two direct compact realizations fail:

1. ordinary component-wise GGM constrained keys expose the masks and recover `K` on a false instance;
2. replacing them with a clear-output exact XOR-key-homomorphic PRF gives a public-image distinguisher.

### Remaining central obligation

Construct a practical PQ **difference-only clause-constrained evaluator** with collusion security:

\[
\textsf{Eval}_{c}(w)=R_c(w)-R_{c-1}(w)
\quad\text{only for } C_c(w)=1,
\]

such that the complete set of clause tokens does not expose either component function or an efficiently testable global linear image.

A plausible next direction is a noisy/hidden-coordinate lattice encoding in which adjacent differences compose but the component coordinates remain LWE-hidden until a full valid telescope. That direction needs an explicit algorithm and a reduction to ordinary LWE/LWR (or another independently justified PQ assumption); merely naming "constrained PRF", "functional encryption", or "obfuscation" is not sufficient.

The arbitrary-QPT **final-key recovery -> source witness / independent PQ break**, complete auxiliary-input composition, malicious-secure setup proof, and practical end-to-end parameters all remain unresolved.

The stopping condition is therefore not met.
