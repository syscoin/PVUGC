# Run 59 — proper-subset path coupling still splices, and scalar word fingerprints collapse the affine endpoint

**Status:** constructive follow-up to Run 58. This run tests two natural repairs to the signed-permutation column-splicing break:

1. couple **several target columns at once** and secret-share the key across those larger local path tests; and
2. attach a multiplicative **word fingerprint** to every branch so that different column routes should carry different scalars.

Both repairs have exact complete-view failures in the affine-transport setting below. These are scoped barriers, not a generic impossibility theorem for every nonlinear/computational binder, not an attack on LWE/SIS, and not a completed witness KEM.

Starting verified PR head: `3bd0b0d1391f7061ba32fc8c07c13d3c7bd62385` (Run 58). The Run-58 signed-permutation routing theorem and false-target attack were read before this pass. No external literature or web search was used. Production code is unchanged.

---

## 1. Repair A: couple a whole subset of columns

Run 58 allowed a different route for every target column. The obvious repair is to make one release component depend on a set

\[
S\subseteq[d]
\]

of columns and require **one common branch word for all columns in \(S\)**. One can then secret-share the final key across many such subset components, hoping that overlapping subsets force one global source word.

The following signed-diagonal family shows that independent subset components do not provide that implication, even when every component contains \(d-1\) of the \(d\) target columns.

### 1.1 Public transport family

Fix \(d\ge2\) and let the word length be

\[
L=d-1.
\]

For every layer \(i\in\{1,\ldots,d-1\}\), use two signed-permutation matrices

\[
A_{i,0}=I_d,
\]

and

\[
A_{i,1}
=
\operatorname{diag}(1,\ldots,
\underbrace{-1}_{i},
\ldots,1,
\underbrace{-1}_{d}).
\tag{1}
\]

For a word

\[
w=(w_1,\ldots,w_{d-1})\in\{0,1\}^{d-1},
\]

all layers commute and

\[
A(w):=\prod_{i=1}^{d-1}A_{i,w_i}
=
\operatorname{diag}
\left(
(-1)^{w_1},\ldots,(-1)^{w_{d-1}},
(-1)^{\sum_i w_i}
\right).
\tag{2}
\]

Choose the public target

\[
T=\operatorname{diag}(1,\ldots,1,-1).
\tag{3}
\]

### 1.2 No global witness

If \(A(w)=T\), the first \(d-1\) diagonal coordinates force

\[
w_1=\cdots=w_{d-1}=0.
\]

But then the final coordinate of \(A(w)\) is \(+1\), whereas the final coordinate of \(T\) is \(-1\). Therefore

\[
\boxed{\nexists w:\ A(w)=T.}
\tag{4}
\]

So the source statement is false.

### 1.3 Every proper subset has a common local route

For a subset \(S\subsetneq[d]\), say that \(w\) is an \(S\)-route if

\[
A(w)e_j=Te_j
\qquad\text{for every }j\in S.
\tag{5}
\]

There is an explicit route for **every proper subset**.

* If \(d\notin S\), choose \(w=0^{d-1}\). Every selected first coordinate is \(+1\), exactly as in \(T\).
* If \(d\in S\), then because \(S\ne[d]\), some \(j<d\) is omitted from \(S\). Choose the unit word \(w=e_j\). Coordinate \(j\) flips, but it is not tested. Every selected first coordinate remains \(+1\), and the final coordinate flips to \(-1\), exactly matching \(T\).

Hence

\[
\boxed{
\forall S\subsetneq[d],\quad
\exists w_S:\ A(w_S)|_S=T|_S,
}
\tag{6}
\]

while (4) holds globally.

This is stronger than a pairwise-consistency counterexample: the false target is locally satisfiable on **every** strict subset, including every leave-one-out set of size \(d-1\).

---

## 2. Exact N-of-N subset-splicing theorem

Let

\[
S_j=[d]\setminus\{j\},
\qquad j=1,\ldots,d.
\tag{7}
\]

Each \(S_j\) has a local route by (6):

* for \(j=d\), use \(w^{(d)}=0^{d-1}\);
* for \(j<d\), use \(w^{(j)}=e_j\).

Yet there is no one word belonging to every local witness set, because satisfying all leave-one-out restrictions would satisfy every target column and contradict (4).

Therefore the family has the exact property

\[
\forall j,\ W_j\ne\varnothing,
\qquad
\bigcap_{j=1}^d W_j=\varnothing.
\tag{8}
\]

### Theorem 2.1 — independently decodable proper-subset shares do not bind one source word

Suppose a release architecture assigns a key share \(\kappa_j\) to every local component \(S_j\), and has the completeness property:

> any word that satisfies the target on \(S_j\) can recover \(\kappa_j\) with the component's advertised honest success probability.

The shares may be combined N-of-N, e.g.

\[
K=\kappa_1\oplus\cdots\oplus\kappa_d.
\tag{9}
\]

On the false instance (1)-(3), a public adversary uses the explicit different local words \(w^{(j)}\) above. Every component is locally true, so the adversary obtains every share with the same local completeness guarantee as an honest local user, and then reconstructs \(K\).

No global source witness is produced because none exists.

The same conclusion holds for any family of independently decodable components indexed by proper subsets: equation (6) supplies a potentially different local word for each component. It does not matter how densely the subsets overlap, whether all pairs are tested, whether all leave-one-out sets are tested, or even whether **every proper subset** is tested.

### Scope

This theorem does **not** reject a component that itself couples all \(d\) columns, nor a nonlinear/computational cross-component binder that proves all subset decoders used the same word. It rejects the attempted repair “increase the local column width and combine independently decodable subset shares.”

That distinction is the point: redundancy of local consistency tests is not common-representation binding.

---

## 3. Concrete noisy affine-transport realization

The preceding theorem is semantic. The same splicing occurs in the actual noisy affine transport form used in Runs 56-58.

For each proper subset component \(S\), restrict every diagonal transition to the selected coordinates and independently sample hidden frame matrices

\[
R_0,\ldots,R_{L-1}\in\mathbb Z_q^{|S|\times|S|}.
\]

Program

\[
R_L=R_0T_S+\Delta\kappa_S I,
\tag{10}
\]

where \(T_S\) is the target restricted to \(S\), and publish

\[
C_{i,b}
=
R_{i+1}-R_iA^{(S)}_{i,b}+E_{i,b}.
\tag{11}
\]

For a local route \(w\), let

\[
P_{i+1}(w)
=
A^{(S)}_{i+1,w_{i+1}}\cdots
A^{(S)}_{L-1,w_{L-1}}.
\]

The ordinary path evaluator gives the exact telescoping identity

\[
\sum_{i=0}^{L-1}C_{i,w_i}P_{i+1}(w)
=
R_L-R_0A^{(S)}(w)
+
\sum_{i=0}^{L-1}E_{i,w_i}P_{i+1}(w).
\tag{12}
\]

For every explicit false-instance local route in (6),

\[
A^{(S)}(w)=T_S,
\]

so

\[
\boxed{
F_S(w)
=
\Delta\kappa_S I+N_S(w).
}
\tag{13}
\]

Because all restricted transitions are signed diagonal, right multiplication by every suffix merely flips error-column signs. If scalar transcript errors lie in \(\{-1,0,1\}\), every output entry of \(N_S(w)\) is a sum of exactly \(L=d-1\) signed ternary terms and obeys

\[
|N_S(w)_{a,b}|\le d-1.
\tag{14}
\]

Thus the false splicer receives **exactly the honest local noise law**, not a weakened approximation.

The checker used \(q=257\), binary phase \(\Delta=128\), and full matrix telescoping. Across 850 fresh false-global N-of-N trials at \(d=3,4,6,8\), every local component decoded its programmed share and all **850/850** global keys were recovered. The maximum observed centered share error was exactly the relevant deterministic bound in each dimension: \(2,3,5,7\).

The tests validate the implementation and finite identities. Equation (13), not the empirical success count, is the claim.

---

## 4. Repair B: scalar word fingerprints

A more aggressive response to Run 58 is to make different branch words carry different multiplicative fingerprints.

Choose public nonzero scalars

\[
\alpha_{i,b}\in\mathbb F_q^*,
\]

and replace

\[
A_{i,b}
\quad\text{by}\quad
B_{i,b}=\alpha_{i,b}A_{i,b}.
\tag{15}
\]

For a word \(w\),

\[
B(w)
=
\lambda(w)A(w),
\qquad
\lambda(w)
=
\prod_i\alpha_{i,w_i}.
\tag{16}
\]

If \(A(w)=T\), a path therefore reaches only the **projective** target

\[
\lambda(w)T.
\]

This looks attractive: different column-spliced words should usually carry different \(\lambda\)'s.

The linear transport itself defeats that idea on multi-witness instances.

---

## 5. Affine-line endpoint collapse

For one scalarized transport channel, define the endpoint functional

\[
\mathcal L_\lambda(R)
=
R_L-\lambda R_0T.
\tag{17}
\]

Let \(M_B\) be the complete public linear transport operator mapping hidden frames to all branch records. Every valid word \(w\) gives a structured path evaluator \(Q_w\) satisfying

\[
Q_w M_B=\mathcal L_{\lambda(w)}.
\tag{18}
\]

### Theorem 5.1 — two distinct valid fingerprints make the endpoint itself public

Suppose there are two valid source words \(w,w'\) with

\[
A(w)=A(w')=T
\]

and

\[
\lambda(w)\ne\lambda(w').
\]

Then both

\[
\mathcal L_{\lambda(w)},
\qquad
\mathcal L_{\lambda(w')}
\]

lie in the public row span of \(M_B\).

Their difference is

\[
\mathcal L_{\lambda(w)}
-
\mathcal L_{\lambda(w')}
=
(\lambda(w')-\lambda(w))\,R_0T,
\]

so the endpoint-start functional \(R_0T\) lies in the same row span. Substituting back gives

\[
\boxed{
R_L\in\operatorname{rowspan}(M_B).
}
\tag{19}
\]

Therefore a public Gaussian-elimination algorithm can synthesize a linear evaluator \(Q_{\rm end}\) with

\[
Q_{\rm end}M_B(R)=R_L
\]

without learning either source witness or either fingerprint.

If an affine-fingerprint construction stores the key carrier directly in the shared endpoint \(R_L\), exact complete-output secrecy is gone.

This is an exact linear-algebra statement. It does not claim the public evaluator has small coefficients under every noisy modular parameterization.

### Why random branch fingerprints trigger the condition

Fix any two distinct words \(w\ne w'\). If every \(\alpha_{i,b}\) is sampled independently uniformly from \(\mathbb F_q^*\), then

\[
\Pr[\lambda(w)=\lambda(w')]=\frac1{q-1}.
\tag{20}
\]

To see this, choose any position on which the words differ and condition on every scalar except one scalar used only on one side of the ratio \(\lambda(w)/\lambda(w')\). That remaining uniform nonzero scalar makes the ratio uniform in \(\mathbb F_q^*\).

Hence for a fixed pair of valid witnesses, random scalar fingerprinting produces two distinct endpoint lines with probability

\[
1-\frac1{q-1}.
\tag{21}
\]

The checker exhaustively confirmed the one-layer law over \(\mathbb F_{17}\): among 256 ordered nonzero scalar pairs, exactly 16 collide, probability \(1/16\).

---

## 6. A one-layer complete-output fixture, including small noise

The endpoint collapse is visible without a general linear solver.

Take one dummy layer with

\[
A_0=A_1=I.
\]

Both one-bit words are valid for the same target \(T=I\). Choose distinct public fingerprints \(\alpha_0,\alpha_1\). The exact records are

\[
C_0=R_1-\alpha_0R_0,
\qquad
C_1=R_1-\alpha_1R_0.
\tag{22}
\]

Then publicly

\[
\boxed{
R_1
=
\frac{\alpha_1C_0-\alpha_0C_1}
{\alpha_1-\alpha_0}.
}
\tag{23}
\]

The checker sampled 1,200 random exact \(3\times3\) frame pairs over \(\mathbb F_{257}\) and distinct nonzero fingerprints and recovered \(R_1\) in **1200/1200** cases.

A small-noise fixture shows that noise does not automatically save the idea. Set

\[
\alpha_0=1,\qquad \alpha_1=2,
\]

and publish

\[
C_0=R_1-R_0+E_0,
\]

\[
C_1=R_1-2R_0+E_1.
\]

Then

\[
\boxed{
2C_0-C_1
=
R_1+2E_0-E_1.
}
\tag{24}
\]

For ternary errors, every scalar residual is deterministically bounded by three. The exact two-error histogram is

\[
\{-3:1,-2:1,-1:2,0:1,1:2,2:1,3:1\}.
\]

With \(q=257\), binary phase 128, and \(R_1=128K\,I\), the public endpoint decoder therefore succeeds for **every** bounded-error realization. The checker executed 10,000 fresh trials and decoded **10000/10000** endpoint bits; maximum observed absolute error was three.

This is not an LWE attack. It is a short public cancellation created by the two valid fingerprint branches.

---

## 7. What this run proves

### Proved

1. The signed-diagonal family (1)-(3) has **no global source word**.
2. Every proper subset of target columns nevertheless has a common local route.
3. The \(d\) leave-one-out local witness sets are all nonempty but have empty joint intersection.
4. Consequently, any architecture that independently releases N-of-N/threshold shares to proper-subset routes can be spliced on this false instance; increasing local width all the way to \(d-1\) does not create common-representation binding.
5. In the concrete noisy affine transport, each false local route has exactly the ordinary honest telescoping/noise law.
6. For scalar word fingerprints, two valid words with distinct fingerprints force the bare shared endpoint functional \(R_L\) into the complete public transport row span.
7. Independent uniform nonzero branch scalars collide on any fixed pair of distinct words with exact probability \(1/(q-1)\).
8. The one-layer fingerprints \(1,2\) give the short noisy public identity (24), with deterministic ternary error bound three.

### Implemented / actually tested

The deterministic standard-library checker was finalized and executed twice; the two JSON captures were byte-identical.

It checked:

* every proper subset for every \(d=2,\ldots,12\): **8,177** subset routes total;
* zero global witnesses in every one of those dimensions;
* nonempty leave-one-out witness sets with empty global intersection in every dimension;
* **850/850** complete noisy false-global N-of-N key recoveries using full matrix affine-transport telescoping at \(d=3,4,6,8\);
* **1,200/1,200** exact random-fingerprint endpoint recoveries;
* the exact \(\mathbb F_{17}^*\) collision law \(16/256=1/16\);
* **10,000/10,000** noisy short-fingerprint endpoint decodes;
* the exact nine-point ternary distribution of \(2E_0-E_1\).

Checker SHA-256:

`106c593bc4ce75c7a23e0b14b418504e805b272cf4021efc68536dccb4dddf62`

Captured validation SHA-256:

`37e2887a53f27469b58aa4d18e719fbb7fe4e2e09f04c9493bf5b4a96c4796f3`

### Not proved

This run does **not** show that every full-column transport or every nonlinear cross-subset binder is insecure.

It does **not** prove that all modular/noisy scalar-fingerprint row-span evaluators are short. The short noisy break is proved for the explicit \(1,2\) dummy-branch fixture; the general theorem is exact/noiseless row-span membership.

It does **not** attack standard LWE/SIS, and it does not produce the required arbitrary-QPT early-key-recovery reduction for a surviving construction.

Finally, it does not say a compiler must fingerprint semantically redundant/dummy witness bits. A compiler could try to quotient such redundancies. What is rejected is the natural independent random per-branch scalar fingerprint mechanism in a linear affine transport, especially when its varying fingerprints are supposed to be the source of anti-splicing security.

---

## 8. Handoff

Run 58 showed that one-column signed-permutation routing is too weak. This run shows two immediate repairs are also insufficient:

* **larger local column subsets:** even every leave-one-out target, or every proper subset, can be locally satisfiable with mutually inconsistent words while the global target is false;
* **linear scalar word fingerprints:** if fingerprints vary across two valid words, the complete affine transport row span already contains the shared endpoint; a simple \(1,2\) fixture keeps the public endpoint evaluator short under ternary noise.

A surviving construction therefore needs a genuinely **global common-word binder** whose successful evaluation cannot be decomposed into independently decodable proper-subset views, and whose anti-splicing tag is not merely a witness-dependent scalar inserted into a public linear transport.

The central obligations remain unchanged:

1. polynomial-size generic-NP same-key completeness for **every** valid source witness;
2. complete false-instance hiding under every public auxiliary output;
3. arbitrary QPT early-key recovery \(\rightarrow\) source-witness extraction or break of an independently justified PQ assumption;
4. malicious-secure erased-setup / N-of-N-root composition after the inner primitive is sound; and
5. concrete practical end-to-end parameters.

The stopping condition is not met.
