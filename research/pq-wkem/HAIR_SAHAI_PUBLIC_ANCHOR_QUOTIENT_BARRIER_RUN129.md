# Run 129 — Hair–Sahai public anchor quotient collapses to a witness-free public class

**Status:** focused falsification at the Run-128 bottleneck. This run proves that the most natural linear canonical quotient of the actual Hair–Sahai statement-derived source space is public and witness-free on every satisfiable statement. It therefore cannot be the missing hidden all-witness canonical value. This is **not** a general impossibility theorem for nonlinear/secret-mode canonicalization, and it is **not** a completed PQ witness KEM.

**Starting verified PR head:** `76e5b632cf00b4372955b871aadd59ded84c5167` on branch `research/pq-wkem-validation-20260918`.

Production/workflow code is unchanged.

## 1. Exact primary-source structure used

Primary source rechecked this run: Isaac M. Hair and Amit Sahai, *Witness Encryption via Prime-Order Generic Groups*, arXiv:2609.18275v1 (16 September 2026), especially Sections 4.3–4.6.

For a Boolean assignment `b`, the paper stacks weighted pair tables as

\[
A(b)=
\begin{pmatrix}
h_1(b)v(b)v(b)^T\\
h_2(b)v(b)v(b)^T\\
\vdots
\end{pmatrix},
\qquad
v(b)=(1,b_1,\ldots,b_N)^T.
\]

The weight list includes the constant polynomial `h=1`. The public source space is

\[
\mathcal S_x=\left\{\sum_b \lambda_b A(b):
\sum_b \lambda_b h(b)q_s(b)=0\ \text{for every source equation }q_s
\text{ and listed weight }h\right\}.
\]

If `b` is satisfying, the unit coefficient on that assignment obeys every source constraint, so

\[
A(b)\in\mathcal S_x.
\]

Hair–Sahai Section 4.6 gives a deterministic polynomial-time algorithm for an ordered basis of `S_x` from the statement. This run uses only those algebraic facts. The paper's classical generic-group encryption security is not imported.

## 2. The public anchor

Choose one of the known constant-weight `h=1` blocks and let

\[
\alpha(A)
\]

be its `(0,0)` entry. Since `v_0(b)=1`, every assignment encoding satisfies

\[
\alpha(A(b))=1. \tag{1}
\]

This is true for satisfying and nonsatisfying Boolean assignments and is unaffected by the paper's appended zero columns.

For a satisfiable statement, some satisfying `b` has `A(b) in S_x` and (1), so the restriction

\[
\alpha|_{\mathcal S_x}:\mathcal S_x\to\mathbb F_p
\]

is a nonzero public linear functional.

Define the public anchor-zero subspace

\[
\mathcal K_x=\mathcal S_x\cap\ker\alpha. \tag{2}
\]

Because `alpha|S_x` is nonzero,

\[
\dim \mathcal K_x=\dim\mathcal S_x-1. \tag{3}
\]

Thus the quotient `S_x/K_x` is exactly one-dimensional on every satisfiable statement.

## 3. Theorem — the normalized quotient class is publicly computable without a witness

**Theorem 1 (public anchor-quotient collapse).** Given the public Hair–Sahai basis of a satisfiable statement space `S_x`, one can deterministically compute in polynomial time a matrix

\[
U_x\in\mathcal S_x,
\qquad \alpha(U_x)=1, \tag{4}
\]

without finding any satisfying assignment. For every valid ORIGINAL witness `b`,

\[
A(b)-U_x\in\mathcal K_x, \tag{5}
\]

and therefore

\[
[A(b)]_{\mathcal S_x/\mathcal K_x}=[U_x]_{\mathcal S_x/\mathcal K_x}. \tag{6}
\]

The right side is completely public.

**Proof.** Let `B_1,...,B_k` be the publicly computed basis of `S_x`. Since `alpha|S_x` is nonzero, at least one basis vector has `alpha(B_i) != 0`. Set

\[
U_x=\alpha(B_i)^{-1}B_i.
\]

This proves (4) and is polynomial-time field linear algebra. For any satisfying `b`, both `A(b)` and `U_x` are in `S_x`, while (1) and (4) give

\[
\alpha(A(b)-U_x)=0.
\]

Hence the difference lies in (2), proving (5) and (6). ∎

This does **not** require enumerating the satisfying witnesses. It uses the public exact-span basis that Hair–Sahai already computes.

## 4. Dual form — every public linear invariant of this quotient is just the public anchor

Let `L:S_x -> Y` be any public linear map satisfying

\[
\mathcal K_x\subseteq\ker L. \tag{7}
\]

Then for every satisfying assignment,

\[
L(A(b))=L(U_x). \tag{8}
\]

The value on the right is witness-free computable from the public basis and `L`.

Equivalently, the dual of `S_x/K_x` is one-dimensional. On `S_x`, every scalar linear functional annihilating `K_x` is a scalar multiple of `alpha|S_x`. Public affine-linear maps add only a public constant and do not change the conclusion.

So the Run-128 suggestion

> derive a compact canonical quotient/value from every Hair–Sahai witness

cannot be realized by quotienting the **public source space** by its natural public anchor-zero/null direction and then treating the resulting one-dimensional class as hidden. The canonical class is already available to witness-free setup and to every observer.

## 5. Why this is more than the trivial observation that one matrix coordinate equals one

The important point is not merely that `(0,0)=1` on honest tables. It is that the **entire public statement-derived source space** admits a public decomposition

\[
\mathcal S_x=\mathcal K_x\oplus\operatorname{span}\{U_x\}, \tag{9}
\]

and every honest witness encoding lies in the same public affine slice

\[
U_x+\mathcal K_x. \tag{10}
\]

Thus any linear canonicalizer that deliberately forgets all anchor-zero source directions has already forgotten exactly enough to make the witness class public. Adding more public kernel directions cannot restore witness restriction.

This closes the most direct “normalize by the constant block / quotient the source nullspace” route.

## 6. Honest-difference span versus ambient source kernel

Let

\[
\mathcal D_x=\operatorname{span}\{A(b)-A(b_0): b,b_0\in W_x\} \tag{11}
\]

be the exact linear span of differences among honest satisfying encodings. Always

\[
\mathcal D_x\subseteq\mathcal K_x, \tag{12}
\]

because every honest encoding has anchor one.

A quotient by `D_x` is a different object. It need not collapse as far as the public quotient by `K_x`. But `D_x` is defined by the satisfying set itself; Hair–Sahai's public linear source constraints do not in general identify it exactly.

The finite validation below contains literal v1 examples where

\[
\dim \mathcal K_x>\dim \mathcal D_x.
\]

Those extra anchor-zero directions are ambient source-space pseudodirections: they obey the public source constraints but are not generated by honest-witness differences. This is the same structural danger seen in Runs 114/120 under a sharper, source-specific lens.

Therefore a repair that says “use the exact honest affine hull instead” does not solve the public-encoding problem for free. Efficiently identifying or evaluating that source-restricted affine class without a source witness is precisely another form of the missing source gate.

## 7. What this theorem does and does not rule out

### Ruled out by this run

A candidate fails immediately if its all-witness canonical value is obtained by:

1. taking the actual public Hair–Sahai source space `S_x`;
2. modding out by `K_x=S_x cap ker(alpha)` or any larger public linear kernel; and
3. applying a public linear/affine function to the resulting class.

The canonical value is then computable from the public basis via `U_x`; no witness is needed. A classical attacker already computes it, so such a construction cannot meet a QPT-hiding goal.

### Not ruled out

This is **not** an impossibility theorem for:

* a nonlinear source-restricted canonical function;
* a secret-mode projective/evasive evaluation whose public transcript does not reveal the corresponding linear functional;
* a one-shot dual-mode primitive in which a witness can evaluate a hidden value but the complete Ext view cannot resample that value;
* a construction based on a different source compiler.

Those surviving routes must still pass Run 126's complete-Ext-view resampling test and provide the arbitrary-QPT recovery -> ORIGINAL-witness / independently justified QPT-hardness-break arrow.

## 8. Consequence for the Hair–Sahai route

Hair–Sahai remains useful as the **last semantic arrow**:

\[
\text{supplied nonzero source matrix of rank }\le R
\Longrightarrow
\text{ORIGINAL satisfying assignment}.
\]

Run 129 shows that the front end cannot be obtained just by linearly quotienting the same public source space into one canonical witness class. The quotient either:

* uses the public anchor kernel and becomes witness-free/public as above; or
* uses a finer source-restricted difference structure, in which case computing/evaluating that structure is the missing cryptographic problem rather than a free consequence of the MinRank compiler.

This sharpens the next target: a viable dual-mode lattice/HPS/WPRF-like layer must bind the **correct hidden value** to source-restricted structure that is not reconstructible from the public `S_x` basis alone.

## 9. QPT / assumption ledger

| Item | Honest model | Adversary model | Hardness assumption | Reduction model | Exact conclusion |
|---|---|---|---|---|---|
| Theorem 1 | classical polynomial-time field linear algebra | none | none | direct | public normalized quotient representative exists on every satisfiable Hair–Sahai source space |
| Linear-invariant corollary | classical public evaluation | none | none | direct quotient linear algebra | any public linear map annihilating `K_x` gives a witness-free public canonical value |
| Attack on such a candidate | classical PPT | therefore also QPT | none | explicit public computation | candidate hidden-value claim fails |
| Hair–Sahai supplied-low-rank extraction | classical polynomial time when representation is supplied | not arbitrary key-recovery extraction | algebraic theorem from v1 | direct source extraction from supplied matrix | retained |
| Full generic-NP PQ WKEM | classical public/offline | arbitrary QPT | exact independently justified PQ assumptions required | still missing | **UNPROVED** |

No classical generic-group theorem is promoted to QPT security. No lattice/MinRank assumption is introduced.

## 10. Reproducible finite validation

`hair_sahai_anchor_quotient_run129_check.py` is deterministic, standard-library-only, and implements the **literal v1 base-2 Hair–Sahai weights** for small fields satisfying

\[
p>\max\{2^N,2NR\}.
\]

It constructs the assignment encodings, coefficient constraints, and source matrix spaces directly for six satisfiable examples. It then computes `U_x` and `K_x` only from each public source basis and checks every satisfying assignment.

Two finalized executions were byte-identical. The captured output checks **33 satisfying witnesses** across six actual weighted-table spaces:

| case | `dim S_x` | `dim K_x` | `dim D_x` | witnesses | ambient extra `dim(K)-dim(D)` |
|---|---:|---:|---:|---:|---:|
| `N2_and_zero` | 3 | 2 | 2 | 3 | 0 |
| `N3_and_gate` | 4 | 3 | 3 | 4 | 0 |
| `N4_and_gate_plus_free_bit` | 8 | 7 | 7 | 8 | 0 |
| `N4_linear_two_choice` | 9 | 8 | 7 | 8 | 1 |
| `N4_hamming_weight_two` | 7 | 6 | 5 | 6 | 1 |
| `N4_two_independent_choices` | 5 | 4 | 3 | 4 | 1 |

Every case has quotient dimension exactly one and every honest quotient coordinate is exactly the public scalar `1`. Three cases exhibit strict ambient pseudodirections `D_x subsetneq K_x`.

The finite checker validates algebra/implementation only. It is not evidence for any computational hardness claim.

Final local SHA-256 before publication:

* checker: `d714b35d67168adaed874a63cb4509e8cfee2424e8f2b31e7da960e2d0e3c713`
* captured stdout: `d13c477cb841b101488b1f1b9d4360ed1a745e4d017fe6628b95e36fc80adc2d`

## 11. Precise next handoff

Do **not** spend the next pass trying a larger public linear quotient of the Hair–Sahai source space; Run 129 closes that natural branch.

The highest-value constructive target is now narrower:

1. define a **statement-specific one-shot hidden canonical function** whose witness evaluator uses source-restricted structure beyond the public `S_x/K_x` quotient;
2. require a dual Ext mode in which the correct recovered value yields a source-bearing low-rank object, while the complete Ext view cannot itself sample the value or a compatible Hash secret (Run 126);
3. reduce false-statement hiding and the no-resampling property straight-line to exact QPT-hard standard assumptions, not a renamed correlated/evasive assumption; and
4. only then compose the final low-rank object with Hair–Sahai's supplied-representation extractor.

In parallel, the other Run-79 branch remains worthwhile: compute the complete rank-weight/spectral profile for a precisely specified **correlated Ext distribution**, not the public anchor quotient. That is a different question and is not answered here.

The complete practical generic-NP public/offline PQ witness-KEM stopping condition remains **unmet**.
