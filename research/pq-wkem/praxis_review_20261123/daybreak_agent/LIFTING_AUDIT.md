# Focused Proof Audit of Praxis Lemma B.9 (`LIFT`)

## Scope and conclusion

This note audits only the claimed deterministic polynomial-time lifting step in Lemma B.9 of Tse, Vanjani, and Vesely, *Praxis: Practical Witness Encryption for NP*, IACR ePrint 2026/2971. The audited statement assumes that $q$ is prime, $2\beta<q$, and $24\beta^4<q^3$, and takes as input a nonzero

\[
v\in\mathbb F_q^{N+1},\qquad v_0=0.
\]

It claims a deterministic algorithm, polynomial in $N$ and $\log q$, that returns a nonzero integer vector $x$ with $\lVert x\rVert_\infty\le\beta$ whose reduction modulo $q$ is a nonzero scalar multiple of $v$, or returns $\bot$ if no such vector exists.

**Conclusion:** within this bounded scope, I found no counterexample and no proof-breaking mathematical gap. The rank argument, the prefix-lattice invariant, the fixed-dimensional integer-program search, the saturation step, and the stated bit-size bounds can all be justified. There are minor expository omissions concerning how to organize the HNF/SNF computations in coefficient space and how to retain the final bounded witness; these are routine completions and do not invalidate either correctness or polynomial running time.

This is not a broader security conclusion about Praxis, its reductions, its assumptions, or its parameter choices.

## Audited construction

After dropping coordinate $0$, permuting the remaining coordinates so that a nonzero entry is first, and scaling over $\mathbb F_q$, assume $v_1=1$. For each $i\in[N]$, define

\[
\mathcal L_i=\{x\in\mathbb Z^i:x\bmod q=x_1(v_1,\ldots,v_i)\}.
\]

A vector is *bounded* when \(\lVert x\rVert_\infty\le\beta\). The algorithm maintains a lattice

\[
\mathcal M_i\subseteq\mathcal L_i
\]

of rank at most three that contains every bounded point of $\mathcal L_i$. It starts with $\mathcal M_1=\mathbb Z$, extends from $i$ to $i+1$ through a rank-at-most-four lattice $\mathcal N$, discovers the real span of all bounded points of $\mathcal N$ by fixed-dimensional integer feasibility, and replaces $\mathcal N$ by its intersection with that span.

## 1. Normalization and the meaning of a bounded lattice point

Because $v_0=0$ and $v\ne0$, some coordinate among $1,\ldots,N$ is nonzero. Permuting those coordinates and scaling $v$ by a nonzero field element preserve the set of nonzero scalar multiples of $v$. Thus the normalization $v_1=1$ is harmless.

For $x\in\mathcal L_N$, reduction modulo $q$ gives

\[
x\bmod q=(x_1\bmod q)v.
\]

If $x$ is bounded and $x_1\equiv0\pmod q$, then all coordinates of $x$ are zero modulo $q$. Since $|x_j|\le\beta<q/2$, this forces $x_j=0$ over the integers for every $j$. Consequently, every nonzero bounded point of $\mathcal L_N$ is exactly a short nonzero multiple of $v$, and conversely every such multiple has its unique bounded integer representative in $\mathcal L_N$. Prepending coordinate $0$ recovers the original $(N+1)$-coordinate vector.

## 2. Why bounded points span dimension at most three

Take any four bounded points and any four coordinate positions. Let $A\in\mathbb Z^{4\times4}$ be the resulting minor matrix, with the four vectors as rows. Modulo $q$, every row of $A$ is a scalar multiple of the same restricted vector, so

\[
\operatorname{rank}_{\mathbb F_q}(A\bmod q)\le1.
\]

This implies $q^3\mid\det A$. One precise justification is Smith normal form: if $\det A\ne0$, at most one invariant factor is nonzero modulo $q$, so at least three invariant factors are divisible by $q$. Their product, $|\det A|$, is therefore divisible by $q^3$. If $\det A=0$, the assertion is immediate. Equivalently, after invertible integral row and column operations modulo $q$, three rows can be made coordinatewise divisible by $q$, again exposing a factor $q^3$.

On the other hand, the Leibniz determinant formula gives

\[
|\det A|\le4!\beta^4=24\beta^4<q^3.
\]

The only integer divisible by $q^3$ with magnitude strictly below $q^3$ is zero. Hence every $4\times4$ minor of any four bounded points vanishes over $\mathbb Z$. The four points are linearly dependent over $\mathbb R$, so the real span of all bounded points has dimension at most three.

## 3. The extension lattice contains every bounded lift

Assume $\mathcal M_i$ has rank $r\le3$, lies in $\mathcal L_i$, and contains every bounded point of $\mathcal L_i$. Let $b_1,\ldots,b_r$ be a lattice basis of $\mathcal M_i$. Extend each $b_j$ by a last coordinate $c_j\in[0,q)$ satisfying

\[
c_j\equiv (b_j)_1v_{i+1}\pmod q.
\]

Write the extension as \(\widetilde b_j\in\mathbb Z^{i+1}\), and define

\[
\mathcal N=\langle\widetilde b_1,\ldots,\widetilde b_r,qe_{i+1}\rangle_{\mathbb Z}.
\]

Every generator lies in $\mathcal L_{i+1}$, so $\mathcal N\subseteq\mathcal L_{i+1}$. The generators are linearly independent: a relation among them projects in the first $i$ coordinates to a relation among the basis $b_1,\ldots,b_r$, forcing all of those coefficients to vanish, after which the coefficient of $qe_{i+1}$ also vanishes. Thus

\[
\operatorname{rank}\mathcal N=r+1\le4.
\]

Now let $y\in\mathcal L_{i+1}$ be bounded. Its prefix $y'\in\mathbb Z^i$ is a bounded point of $\mathcal L_i$, hence $y'\in\mathcal M_i$. Write $y'=\sum_j a_jb_j$ with $a_j\in\mathbb Z$. The vector $\sum_j a_j\widetilde b_j$ has prefix $y'$, and its last coordinate is congruent to $y_1v_{i+1}$, as is $y_{i+1}$. Their last coordinates differ by an integer multiple of $q$, which can be corrected with $qe_{i+1}$. Therefore $y\in\mathcal N$.

This proves the essential containment invariant used by the iteration.

## 4. Why at most 32 fixed-dimensional integer programs suffice

Let $k=\operatorname{rank}\mathcal N\le4$, and let

\[
G:\mathbb Z^k\longrightarrow\mathcal N
\]

be the injective generator map. A coefficient vector $a\in\mathbb Z^k$ represents a bounded point exactly when

\[
-\beta\le (Ga)_j\le\beta\qquad(j=1,\ldots,i+1).
\]

These are $2(i+1)$ linear inequalities in at most four integer variables.

Suppose coefficient vectors $a_1,\ldots,a_s$ of previously found bounded points span the rational subspace

\[
A=\operatorname{span}_{\mathbb Q}\{a_1,\ldots,a_s\}\subseteq\mathbb Q^k.
\]

Because $G$ is injective over $\mathbb R$, testing whether $Ga$ lies outside the real span of the previously found points is equivalent to testing whether $a\notin A$. Let

\[
A^\perp_{\mathbb Z}=\{f\in(\mathbb Z^k)^*:f(a_j)=0\text{ for every }j\}.
\]

This free abelian group has rank $k-\dim A\le4$. Choose an integer basis $f_1,\ldots,f_m$. Its common real kernel is exactly $A$. Therefore an integer vector $a$ lies outside $A$ exactly when some $f_t(a)\ne0$. Since $f_t(a)\in\mathbb Z$, this is equivalent to

\[
f_t(a)\ge1\quad\text{or}\quad f_t(a)\le-1
\]

for some $t$. Appending each alternative to the box system gives at most $2m\le8$ integer feasibility programs per search round.

Every successful round increases the dimension of the discovered bounded span by one. Section 2 bounds the final dimension by three. Hence there can be at most three successful rounds, followed by one unsuccessful round certifying that no bounded point lies outside the current span. This gives at most

\[
4\cdot8=32
\]

integer programs per extension. Lenstra's fixed-dimensional integer programming algorithm is deterministic and polynomial in the number of inequalities and their bit length when the number of variables is fixed.

## 5. Saturation and the claimed fixed HNF dimension

Let $S\subseteq\mathbb R^{i+1}$ be the real span of the bounded points found after the search has certified completeness. Define

\[
\mathcal M_{i+1}=\mathcal N\cap S.
\]

It contains every bounded point of $\mathcal L_{i+1}$, because Section 3 puts every such point in $\mathcal N$, and the search makes $S$ the span of all such points. Its rank is $\dim S\le3$. It is saturated relative to $\mathcal N$ by construction.

The paper does not spell out the computation, but it can be performed entirely in coefficient space. If the discovered coefficient vectors span $A\subseteq\mathbb Q^k$, then

\[
K=\mathbb Z^k\cap A
\]

is the saturation of their integer span in $\mathbb Z^k$, and

\[
\mathcal M_{i+1}=G(K).
\]

A basis of $K$, and bases of the annihilator used in Section 4, are obtained by HNF or SNF applied to matrices having at most $k\le4$ rows or columns in the algebraically relevant dimension. Mapping the resulting basis through $G$ costs $O(i)$ arithmetic operations because the vectors have $i+1$ coordinates. Thus the reference to HNF computations in dimension at most four is defensible: all lattice-index and saturation work is fixed-dimensional, while the ambient-coordinate copying and multiplication is covered by the stated linear overhead.

## 6. Derivation of the \(18\beta^3\) basis bound

Let $d=\dim S\le3$, and choose $d$ linearly independent bounded points $w_1,\ldots,w_d$ found by the search. Choose a set $J$ of $d$ coordinates for which the $d\times d$ matrix

\[
B_J=(\pi_J(w_1),\ldots,\pi_J(w_d))
\]

has nonzero determinant $h$. The projection $\pi_J:S\to\mathbb R^d$ is injective. Let

\[
P=\pi_J(\mathcal M_{i+1})\subseteq\mathbb Z^d.
\]

The projected lattice $P$ contains the lattice generated by $\pi_J(w_1),\ldots,\pi_J(w_d)$. Therefore the index/determinant of $P$ divides the index of that generated sublattice:

\[
\det(P)\mid |h|.
\]

Each term in the determinant of $B_J$ has magnitude at most $\beta^d$, so

\[
|h|\le d!\beta^d.
\]

Put $P$ in HNF. Every HNF entry has magnitude at most $\det(P)$, hence at most $|h|$. Lift the HNF basis uniquely through the injective projection $\pi_J$ to a basis of $\mathcal M_{i+1}$.

For any other coordinate $t$, the coordinate functional on $S$ is determined by its values on the $w_j$. Applying Cramer's rule with denominator $h$, and then evaluating it on a projected HNF basis vector whose entries are bounded by $\det(P)$, bounds the lifted $t$-coordinate by

\[
d\cdot\frac{\det(P)}{|h|}\cdot d!\beta^d
\le d\cdot d!\beta^d.
\]

The selected coordinates obey the smaller bound \(|h|\le d!\beta^d\). Thus every entry of the maintained basis is bounded by

\[
d\cdot d!\beta^d\le18\beta^3
\]

for $d\le3$ and positive integral $\beta$. This supplies the derivation behind the paper's concise projection-and-Cramer argument.

## 7. Derivation of the bounded coefficient size

At the next extension, the generator matrix of $\mathcal N$ has $k\le4$ columns. The entries inherited from the maintained basis have magnitude at most $18\beta^3$; each appended residue lies in $[0,q)$; and the last generator is $qe_{i+1}$. Hence every generator entry has magnitude at most

\[
C=\max\{18\beta^3,q\}.
\]

For a bounded point $y=Ga$, choose $k$ coordinate rows on which the square generator submatrix $D$ is nonsingular. It has nonzero integer determinant, so $|\det D|\ge1$. By Cramer's rule, each coefficient $a_j$ is the quotient of a determinant in which one column of $D$ is replaced by the corresponding coordinates of $y$. The replacement column has entries of magnitude at most $\beta$, and the other $k-1$ columns have entries of magnitude at most $C$. The Leibniz formula yields

\[
|a_j|
\le k!\beta C^{k-1}
\le24\beta C^3
=24\beta\max\{18\beta^3,q\}^3.
\]

Because $2\beta<q$, every quantity in this bound has $O(\log q)$ bits. In the fixed coefficient dimension $k\le4$, HNF/SNF computation of annihilators and saturations also preserves polynomial bit length. Every IP contains $O(i)$ inequalities with coefficients of $O(\log q)$ bits, so its input length is $O(i\log q)$, and the complete sequence of $N-1$ extensions is polynomial in $N$ and $\log q$.

## 8. Output bookkeeping

During the final extension, every successful feasibility search returns an actual bounded point. If the final bounded span is nonzero, the algorithm can retain and return any nonzero bounded point produced during that search. If the search certifies that the bounded span is zero, it returns \(\bot\). The paper says only that the algorithm "returns a nonzero one" and does not spell out this bookkeeping, but retaining one witness requires no additional lattice argument and only polynomial storage.

## 9. Residual caveats that are not identified flaws

1. The paper compresses the coefficient-space HNF/SNF construction into a sentence. The explicit construction in Section 5 fills this expository gap.
2. The paper compresses the final witness-retention step. Section 8 supplies the missing bookkeeping.
3. The supplied context states that the associated Lean reduction uses exhaustive search rather than formalizing this efficient lifting algorithm. Accordingly, that formalization does not by itself certify the polynomial-time implementation of Lemma B.9. This is a formalization-coverage limitation, not a counterexample to the mathematical argument audited here.
4. This audit establishes only that the claimed lifting algorithm has a defensible correctness and polynomial-bit-complexity proof under its stated inequalities. It makes no claim about unrelated portions of the construction or proof.

## Sources and actions actually used

### Supplied source material

- The task supplied the precise scope and a transcription/summary of the lifting claim, including the hypotheses $2\beta<q$, $24\beta^4<q^3$, the prefix lattices, the rank-three invariant, the rank-four extension, the 32 fixed-dimensional feasibility programs, saturation, and the two Cramer bounds.
- Paper: Tse, Vanjani, and Vesely, *Praxis: Practical Witness Encryption for NP*, IACR ePrint 2026/2971, <https://eprint.iacr.org/2026/2971.pdf>.

### Web retrieval actions

The paper text was inspected through the provided full-PDF web reference rather than by downloading or modifying the PDF:

1. Opened the supplied PDF reference `turn623665588view0` at extracted line 4500 with a long response. The returned PDF view was `turn506063186view0`; it included the end of Lemma B.9 around extracted lines 4405--4409 and surrounding Appendix B material.
2. Opened `turn506063186view0` at extracted line 4320 with a long response. The returned view was `turn573735152view0`; it included Lemma B.9 in full at extracted lines 4380--4409 on paper page 53, together with the immediately preceding context.

No other paper, external mathematical reference, repository, or source file was used for this audit. The citations `[Len83]` and `[KB79]` were relied on only at the standard-result level already invoked by the paper: deterministic polynomial-time integer programming in fixed dimension and polynomial-time HNF computation. Their texts were not separately retrieved.

### Computation and testing

- No numerical experiment, brute-force search, symbolic algebra computation, proof-assistant run, mathematical or cryptographic program, Daybreak scan, repository scan, or security scanner was executed.
- The determinant, saturation, and coefficient-size checks above were deductive proof checks performed from the supplied lemma and the retrieved paper text.
- The only local shell actions were filesystem bookkeeping to inspect the authorized report directory, create `research/pq-wkem/praxis_review_20261123/daybreak_agent`, and verify this report after writing it. No project code or data was read or modified.

