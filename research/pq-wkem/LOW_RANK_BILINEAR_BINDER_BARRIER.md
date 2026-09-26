# Low-rank bilinear binder barrier

## Status

This run starts from the verified PR #1 head

`bef87e9648041433c4c272ff34c92daf3850bd11`

and from the published Run-30 Hankel-recurrence checkpoint.  The earlier
complete-public-view input-label attack, native-encryption versus source-witness
transfer distinction, odd-span/rank-noise results, and public-prover-transfer
gap remain in force.

This note tests a different constructive idea: compress a table of
witness-dependent random carrier values by a hidden **bilinear low-rank
factorization** over a product representation domain.  The candidate has a
useful local property: a single inconsistent pair can be statistically hidden
with exponentially small leakage using only polynomial rank.  The complete
public local-evaluation surface nevertheless admits a polynomial-size false
decoder by low-rank completion on two disjoint candidate sets.

This is a barrier for this binder/compression family, not a generic
impossibility theorem and not a completed witness KEM.  No outside literature
or web search was used.

## 1. Candidate

Let the representation domain be

\[
    X=[M]\times[N]
\]

and work over a prime field \(\mathbb F_q\).  Setup samples independent hidden
vectors

\[
    U_i,V_j \leftarrow \mathbb F_q^r
\]

and key shares

\[
    k_0\leftarrow\mathbb F_q,\qquad k_1=K-k_0.
\]

Define the hidden carrier matrix

\[
    P_{ij}=\langle U_i,V_j\rangle
\]

and the two local share surfaces

\[
    F_0(i,j)=k_0+P_{ij},\qquad
    F_1(i,j)=k_1-P_{ij}.                         \tag{1}
\]

The intended use is as a consistency layer: a candidate representation
\((i,j)\) that is locally admissible for side 0 exposes \(F_0(i,j)\), and a
candidate locally admissible for side 1 exposes \(F_1(i,j)\).  The lower layer
that makes those values witness-restricted is deliberately not assumed secure
here; the point is to audit whether the carrier itself prevents splicing.

This is a natural nonlinear compression attempt for the Run-22 idea of
independent random representatives.  Instead of one independent scalar per
cell, the \(MN\) carrier values are generated from only \(r(M+N)\) hidden field
elements.

### 1.1 Honest correctness

For every common representation \(x=(i,j)\),

\[
    F_0(x)+F_1(x)=K.                              \tag{2}
\]

Thus every valid common representation recovers the same key exactly.

## 2. Positive local result: one inconsistent pair is almost perfectly hiding

Take two distinct cells \(x\ne y\).  The public pair is

\[
    (F_0(x),F_1(y)).
\]

Because \(k_0\) is uniform, the first coordinate is uniform and independent of

\[
    S=F_0(x)+F_1(y)=K+\Delta,\qquad
    \Delta=P_x-P_y.                               \tag{3}
\]

So key dependence is exactly the translation behavior of \(\Delta\).

### Theorem 2.1 — exact one-pair law

If \(x,y\) share exactly one row or one column, then

\[
    \Delta \sim q^{-r}\delta_0+(1-q^{-r})U_{\mathbb F_q}. \tag{4}
\]

If they differ in both row and column, then

\[
    \Delta \sim q^{-2r}\delta_0+(1-q^{-2r})U_{\mathbb F_q}. \tag{5}
\]

Consequently, for two distinct keys \(K,K'\), the exact total-variation
distance of the one-pair transcript distributions is respectively

\[
    q^{-r}\quad\text{or}\quad q^{-2r}.             \tag{6}
\]

#### Proof

Suppose first that \(x=(i,j)\) and \(y=(i,j')\), \(j\ne j'\).  Then

\[
    \Delta=U_i\cdot(V_j-V_{j'}).
\]

The two vectors in this inner product are independent and uniform in
\(\mathbb F_q^r\).  For every nontrivial additive character \(\psi_t\),

\[
  \mathbb E[\psi_t(\Delta)]
   =\Pr[V_j-V_{j'}=0]
   =q^{-r}.                                        \tag{7}
\]

The same calculation applies to a shared column.  A distribution on
\(\mathbb F_q\) whose every nonzero Fourier coefficient is the same constant
\(c\) is exactly \(c\delta_0+(1-c)U\), proving (4).

If both row and column differ, \(P_x\) and \(P_y\) use disjoint hidden vectors
and are independent.  Each inner product has nonzero Fourier coefficient
\(q^{-r}\), so their difference has coefficient \(q^{-2r}\), proving (5).
Translating the spike by \(K-K'\ne0\) changes exactly its mass \(c\), giving
(6).  QED.

For \(q=2,r=\lambda\), even the worst one-pair leakage is \(2^{-\lambda}\).
So pairwise hiding by itself looks excellent.

## 3. Complete-output false instance

The joint view defeats that conclusion.

Let

\[
    R=r+1
\]

and choose disjoint row-anchor sets \(A_0,A_1\), disjoint column-anchor sets
\(B_0,B_1\), all of size \(T\ge R\).  Choose a target row \(i_\star\) outside
both row-anchor sets and target column \(j_\star\) outside both column-anchor
sets.

Define the two locally admissible candidate sets

\[
\begin{aligned}
S_0={}&(A_0\times B_0)
      \cup(\{i_\star\}\times B_0)
      \cup(A_0\times\{j_\star\}),\\
S_1={}&(A_1\times B_1)
      \cup(\{i_\star\}\times B_1)
      \cup(A_1\times\{j_\star\}).                  \tag{8}
\end{aligned}
\]

The target cell \((i_\star,j_\star)\) is deliberately omitted.  Because the
anchor row and column sets are pairwise disjoint,

\[
    S_0\cap S_1=\varnothing.                       \tag{9}
\]

Therefore the source relation "one representation belongs to both local
candidate sets" is false: there is no source witness.

Each surface in (1) has rank at most \(R\).  For example,

\[
 F_0(i,j)
 = [\,1\;\;U_i^\top\,]
   \begin{bmatrix}k_0\\V_j\end{bmatrix}.           \tag{10}
\]

The analogous factorization for \(F_1\) replaces \(k_0,V_j\) by
\(k_1,-V_j\).

### Theorem 3.1 — disjoint-cross completion attack

Suppose the anchor block \(F_b[A_b,B_b]\) has the same rank \(L_b\) as the
complete matrix \(F_b\).  From only the values indexed by \(S_b\), a public
algorithm recovers the omitted value

\[
    F_b(i_\star,j_\star).                          \tag{11}
\]

Hence, when this condition holds for both sides, the false instance recovers

\[
    \boxed{K=
      F_0(i_\star,j_\star)+F_1(i_\star,j_\star)}.   \tag{12}
\]

No source witness, hidden factor, or setup secret is recovered.

#### Proof

Find an invertible \(L_b\times L_b\) minor

\[
    Q_b=F_b[I_b,J_b],
    \quad I_b\subseteq A_b,\ J_b\subseteq B_b.
\]

The queried set \(S_b\) contains the complete vectors

\[
    F_b(i_\star,J_b),\qquad F_b(I_b,j_\star).
\]

Since \(Q_b\) is a rank basis for the full matrix, the usual exact rank
factorization identity gives

\[
 F_b(i_\star,j_\star)
  =
 F_b(i_\star,J_b)\,
 Q_b^{-1}\,
 F_b(I_b,j_\star).                                 \tag{13}
\]

All quantities on the right are public local outputs.  Apply (13) separately
to the two disjoint candidate sets and add the results.  Equation (2), which
holds algebraically at the omitted common target cell, yields (12). QED.

The attack uses, per side,

\[
    |S_b|=T^2+2T                                   \tag{14}
\]

local values and polynomial-time finite-field Gaussian elimination.

## 4. The completion event is overwhelming with polynomial anchors

The attack above is not based on hoping for a rare nonsingular minor.

For a side whose share \(k_b\ne0\), the row vectors

\[
    (1,U_i),\quad i\in A_b
\]

span \(\mathbb F_q^{r+1}\) exactly when \(T-1\) independent uniform difference
vectors span \(\mathbb F_q^r\).  The same statement holds for the column
factors \((k_b,\pm V_j)\).  Thus each factor succeeds with probability

\[
 p_{\rm aff}(q,r,T)
   =
 \prod_{h=0}^{r-1}
   \left(1-q^{h-(T-1)}\right).                    \tag{15}
\]

If \(k_b=0\), only the \(r\)-dimensional linear factors need span, and their
success probability is at least (15).  Because the four anchor sets use
disjoint independent \(U\)- or \(V\)-samples, a uniform sufficient bound for
both sides is

\[
    \Pr[\text{completion attack succeeds}]
      \ge p_{\rm aff}^4.                           \tag{16}
\]

Set

\[
    T=R+s=r+1+s.
\]

A union bound gives

\[
  1-p_{\rm aff}
    \le \sum_{h=0}^{r-1}q^{h-(r+s)}
    < \frac{q^{-s}}{q-1}.                          \tag{17}
\]

Therefore

\[
 \Pr[\text{success}]
   \ge 1-\frac{4q^{-s}}{q-1}.                     \tag{18}
\]

This creates a direct asymptotic contradiction with the attractive one-pair
view.  Over \(\mathbb F_2\), choose

\[
    r=\lambda,\qquad s=\lambda.
\]

Then

* worst one-inconsistent-pair key leakage is exactly \(2^{-\lambda}\);
* the false joint-view attack succeeds with probability at least
  \(1-4\cdot2^{-\lambda}\);
* \(T=2\lambda+1\);
* the total number of required local values is

\[
  2(T^2+2T)=O(\lambda^2).                          \tag{19}
\]

The diagnostic false relation itself is polynomial size: take
\(M=N=2T+1=4\lambda+3\), with the anchor sets represented as fixed ranges.
Thus this is not an exponential-domain artifact.

If each requested local value is decoded incorrectly with probability at most
\(\epsilon\), no independence assumption is necessary.  The union bound gives

\[
  \Pr[\text{false key recovery}]
   \ge p_{\rm aff}^4 - 2(T^2+2T)\epsilon.          \tag{20}
\]

## 5. Statistical consequence

Let \(\delta\) bound failure of the public decoder (including completion
failure and local-value errors).  For two distinct keys \(K_0,K_1\), define the
event that the deterministic attack outputs \(K_0\).  Its probability is at
least \(1-\delta\) under key \(K_0\) and at most \(\delta\) under key \(K_1\).
Therefore the complete false-transcript distributions obey

\[
   \operatorname{TV}(\mathsf{View}_{K_0},
                     \mathsf{View}_{K_1})
      \ge 1-2\delta.                               \tag{21}
\]

So the candidate can move from exponentially good pairwise hiding to almost
perfect joint distinguishability after only polynomially many disjoint local
queries.

## 6. Why this is distinct from Runs 27--30

This break is not the Run-27 affine-hull attack on a fixed public feature map,
not Run-28 finite differencing, not Run-29 rational interpolation, and not
Run-30 univariate Hankel recurrence learning.

The hidden carrier is nonlinear in the secret factors \(U,V\).  The attacker
does not identify those factors and does not learn the whole function.  It
uses the determinantal rank variety directly: two **different disjoint**
crosses each determine the same omitted cell of its shifted share surface.

This is nevertheless philosophically consistent with the complete-view lesson
from those runs: a succinct shared hidden generator creates correlations that
a false instance can combine.

## 7. Scope and remaining constructive route

This result rejects the natural low-rank bilinear/product-factor compression
of the Run-22 representative table.

It does **not** reject:

* statement-aware generators that deliberately destroy the relevant low-rank
  completion identities;
* a computationally hidden evaluator whose complete public interface cannot be
  queried as the low-rank surface above; or
* a different semantic compiler with a proved arbitrary-QPT
  recovery-to-source-witness / independent-PQ-break reduction.

A tempting response is to replace \(U_i,V_j\) with outputs of secret PRF seeds.
That is not a construction here: unless the public artifact provides a
non-circular witness-restricted way to evaluate those secret-seed outputs, it
simply restates the missing constrained-evaluation / witness-encryption
primitive.

The generic-NP inner WKEM therefore remains unresolved.

## 8. Validation actually executed

`low_rank_bilinear_binder_check.py` is a standard-library finite-field checker.

It performed:

* exact one-pair distribution enumeration for
  - \(q=3,r=1\), same row/column: spike weight and key-shift TV \(1/3\);
  - \(q=3,r=2\), same row/column: \(1/9\);
  - \(q=5,r=1\), same row/column: \(1/5\);
  - \(q=3,r=1\), different row and column: \(1/9\);
  and checked the complete probability vector against (4)--(5);

* exact same-point correctness checks on every random attack fixture;

* false disjoint-cross completion:
  - \(500/500\) at \(q=101,r=1,T=4\);
  - \(500/500\) at \(q=101,r=3,T=6\);
  - \(500/500\) at \(q=101,r=8,T=11\);
  - \(350/350\) at \(q=257,r=12,T=16\);
  - \(2000/2000\) at \(q=2,r=8,T=20\);
  - \(1199/1200\) at \(q=3,r=4,T=12\);

* exact evaluation of the sufficient-event probability (15) and bound (16)
  on several parameter sets, including a binary \(r=32,T=65\) case whose
  four-factor lower bound exceeds \(0.9999999990\);

* an exhaustive deliberately tiny \(q=2,r=1,T=2\) control over 2,048 setups
  per key.  At that tiny anchor size the completion attack is intentionally
  not overwhelming (976 and 882 successful recoveries for the two keys), and
  252 complete transcript values occur under both keys.  This is a useful
  check that the implementation does not silently assume the asymptotic
  spanning event.

The tests validate the finite algebra and the implemented attack.  They are
not evidence for security of another construction.

## 9. Handoff

The next constructive target should no longer be "make each inconsistent pair
look random."  Run 31 shows that this criterion is too weak even when its
leakage is exponentially small.

A surviving witness-restricted public encoding has to control the **joint
query geometry** of all locally recoverable values.  In particular it must not
place those values on a polynomial-dimensional algebraic variety from which
disjoint false candidate sets can complete a common hidden evaluation, unless
that completion itself yields a source witness or an independently justified
PQ break.

The stopping condition is not met.
