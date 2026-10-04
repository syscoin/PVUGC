# Run 70 — Multiplicative telescoping and transparent matrix-unit binders

## Scope and starting point

This run starts from verified PR head

`542199445749a3cae6605ac751bc24e50f8b5fa5`

and the Run-69 conclusion: explicit public linear-span masks and public
zonotopic/covariance geometry do not privilege source-witness evaluation over a
publicly optimized annihilator. The remaining direction named there was a
**nonlinear/computational key-bearing consistency mechanism**.

This pass therefore does **not** retry additive public subspaces. It tests two
more structured attempts:

1. a commutative multiplicative telescope whose secret factors cancel only for
   a globally consistent assignment; and
2. a noncommutative rank-one matrix-unit telescope intended to make inconsistent
   local choices multiply to zero rather than cancel in an affine span.

Both attempts are setup-without-witness and fully offline after setup. Both
fail under their complete public output, for different exact algebraic reasons.
The second failure is especially relevant to the earlier complete-public-view
input-label recovery attack: the left/right projective spaces of the public
rank-one matrices *are themselves recoverable labels*.

No external literature or web search was used. No production file is changed.
This is not a completed WKEM and does not claim an LWE/SIS break.

---

## 1. Constructive attempt A: commutative multiplicative telescoping

Work in a public prime-order group `G=<g>` of order `p`. The setup samples
secret group-label exponents but never needs a source witness.

For block `j`, let `A_j` be its accepted local assignments. Let `h` index
hidden consistency factors and let

\[
\alpha_{h,j,a}\in F_p
\]

be the exponent with which factor `X_h` participates in local row `a` of block
`j`. Setup also samples a block mask `R_j in G`, with

\[
K=\prod_j R_j.
\]

It publishes every accepted-row token

\[
\boxed{
T_{j,a}=R_j\prod_h X_h^{\alpha_{h,j,a}}.
}
\tag{1}
\]

The intended design chooses the secret exponent pattern so that a globally
consistent source witness `w` selecting one accepted row `a_j(w)` in each
block satisfies

\[
\sum_j \alpha_{h,j,a_j(w)}=0
\quad\text{for every }h.
\]

Then the offline witness computes

\[
\prod_j T_{j,a_j(w)}=K.
\]

This looks nonlinear compared with Runs 63–69: the public release operation is
multiplication, not a public linear functional on an additive coefficient
vector.

### 1.1 Exact complete-output theorem: multiplication linearizes in the exponent module

The relevant public attack does **not** take discrete logarithms.

Let public coefficients `y_{j,a} in F_p` satisfy

\[
\sum_{a\in A_j}y_{j,a}=1
\quad\text{for every block }j,                         \tag{2}
\]

and

\[
\sum_{j,a} y_{j,a}\alpha_{h,j,a}=0
\quad\text{for every hidden factor }h.                \tag{3}
\]

Because the group order is public, the attacker can exponentiate each *public*
`T_{j,a}` by the known scalar `y_{j,a}` and multiply:

\[
\begin{aligned}
\prod_{j,a} T_{j,a}^{y_{j,a}}
&=\prod_j R_j^{\sum_a y_{j,a}}
  \prod_h X_h^{\sum_{j,a}y_{j,a}\alpha_{h,j,a}}\\
&=\prod_j R_j\\
&=\boxed{K}.
\end{aligned}                                           \tag{4}
\]

No hidden exponent is recovered. No discrete logarithm is solved. Erasing
all setup exponents after publication does not change (4).

Thus a commutative multiplicative telescope does not eliminate the old signed
or fractional representation problem; it moves it into the public exponent
module. Any non-source pseudorepresentation satisfying (2)–(3) is already an
exact public key-recovery algorithm.

This statement is about the explicit monomial-token architecture (1). It is
not a generic impossibility theorem for every multiplicative or noncommutative
encoding.

---

## 2. False-family break 1: all-exclusions signed representation

Take `k` Boolean variables and one block for every `f in {0,1}^k`; block `f`
accepts every local row except `f`. The conjunction is false because every
Boolean assignment is rejected by its matching block.

Use the natural hidden-value-label telescope

\[
T_{j,a}=R_j\prod_{i=1}^k X_{i,a_i}^{\sigma_{j,i}},       \tag{5}
\]

where the setup chooses arbitrary incidence weights satisfying

\[
\sum_j \sigma_{j,i}=0
\quad\text{for every variable }i.                       \tag{6}
\]

Any globally consistent assignment would cancel each value label by (6).

Fix `f=0^k`. In every block `j != f`, choose row `f` with coefficient one. In
the malformed block `f`, use the exact signed row coefficients already
identified earlier in this record:

\[
q_f(a)=(-1)^{d_H(a,f)+1},\qquad a\ne f.                 \tag{7}
\]

They obey

\[
\sum_{a\ne f}q_f(a)=1,
\]

and their degree-one/value marginals are exactly those of `f`. Consequently
(2) holds in every block and (3) holds for every secret value label, regardless
of the actual hidden label values.

Equation (4) therefore recovers `K` on this **false statement**.

The checker instantiates a prime-order subgroup of `F_607^*` of order `101`
and performs this attack on 300 fresh random setups for `k=3`. It recovers the
exact group key in 300/300 trials. The attack routine receives only the public
table elements and known signed coefficients; it does not receive the label
exponents, block masks, or discrete logarithms.

---

## 3. False-family break 2: no negative token powers are needed

One might try to forbid signed use of public rows. In a normal prime-order
group that restriction is not meaningful: public scalar exponentiation exists
for every element of `F_p`. More importantly, an attack can use a fractional
pseudomarginal with no negative token power at all.

Consider the odd-cycle 2-coloring CSP on `n=5` variables. Edge block `j`
accepts only

\[
(0,1),\ (1,0).
\]

There is no Boolean witness on an odd cycle.

Publish

\[
T_{j,(a,b)}
=R_j X_{j,a}X_{j+1,b}^{-1}.                            \tag{8}
\]

For every edge put coefficient

\[
y_{j,(0,1)}=y_{j,(1,0)}=1/2\in F_p.                  \tag{9}
\]

Each block has total coefficient one. At every variable, the outgoing and
incoming value marginals are both `(1/2,1/2)`, so every hidden value label
cancels exactly. Thus

\[
\prod_j
T_{j,(0,1)}^{1/2}
T_{j,(1,0)}^{1/2}
=K.                                                     \tag{10}
\]

For `p=101`, `1/2=51`, so the public algorithm merely raises each table element
to the ordinary nonnegative integer power `51`. It performs neither a group
inversion nor a discrete logarithm.

The checker exhaustively verifies that the 5-cycle has zero source witnesses,
then executes 300 fresh random setups. Equation (10) recovers the exact key in
300/300.

This is useful because it separates the failure from the syntax of “negative
signed coefficients”: **local pseudomarginals in the public exponent field are
enough**.

---

## 4. Repair attempt B: noncommutative matrix-unit telescope

The commutative attack works because arbitrary scalar combinations of public
tokens remain available in one exponent module. A natural next repair is to
make order and state matching algebraic.

Let each layer use a `d`-dimensional state space over `F_q`. Setup samples
secret random invertible basis matrices

\[
S_0,\ldots,S_L\in GL_d(F_q).
\]

For a permitted transition `s -> t` from layer `j-1` to layer `j`, publish

\[
\boxed{
M_{j,s,t}=S_{j-1}^{-1}E_{s,t}S_j,
}
\tag{11}
\]

where `E_{s,t}=e_s e_t^T` is a matrix unit.

For consecutive transitions,

\[
M_{j,s,t}M_{j+1,s',t'}
=\delta_{t,s'}S_{j-1}^{-1}E_{s,t'}S_{j+1}.             \tag{12}
\]

Thus inconsistent hidden states multiply to the zero matrix. This genuinely
escapes the **commutative signed-product** theorem above.

Publish a start row

\[
\ell=e_{s_0}^T S_0
\]

and a key-bearing endpoint column

\[
b_K=K S_L^{-1}e_{t_*},\qquad K\in F_q^*.
\]

A valid directed accepting path `P` satisfies

\[
\boxed{\ell P b_K=K.}                                  \tag{13}
\]

So, at the native semantic level, this is a much stronger witness-restricted
binder than the commutative telescope: the product itself checks exact hidden
state continuity.

The complete public view still breaks it.

---

## 5. Complete-public-view matrix attack: the projective state labels are visible

Every public token (11) has rank one:

\[
M_{j,s,t}=c_{j-1,s}r_{j,t},
\]

with

\[
c_{j,s}=S_j^{-1}e_s,
\qquad
r_{j,s}=e_s^T S_j.                                     \tag{14}
\]

A rank-one public matrix reveals its column line

\[
C_{j,s}=\operatorname{span}(c_{j,s})
\]

and row line

\[
R_{j,t}=\operatorname{span}(r_{j,t})
\]

by ordinary Gaussian elimination/factorization. These are the supposedly
hidden state labels, up to projective scale.

At an internal layer,

\[
r_{j,s}c_{j,t}=\delta_{s,t}.                           \tag{15}
\]

Therefore, from the complete public tables alone, an attacker can identify
which incoming row-line and outgoing column-line represent the *same* hidden
state: the public pairing is nonzero exactly for the matching state. This is a
direct matrix analogue of complete-public-view input-label recovery.

But the attack can do more than recover state equivalence classes. It can
recover the key on some false instances with **no directed accepting path**.

### 5.1 Public scalar-gauge equations

Choose canonical public representatives

\[
\bar c_{j,s}=a_{j,s}c_{j,s},\qquad
\bar r_{j,s}=b_{j,s}r_{j,s}.                           \tag{16}
\]

For a token `s->t`, the public matrices determine the unique nonzero scalar
`m_e` satisfying

\[
\bar c_{j-1,s}\bar r_{j,t}=m_e M_e.
\]

Hence

\[
\boxed{m_e=a_{j-1,s}b_{j,t}.}                          \tag{17}
\]

For a hidden state that occurs on both sides of a layer, the public pairing
also gives

\[
\boxed{q_{j,s}=\bar r_{j,s}\bar c_{j,s}=a_{j,s}b_{j,s}.}
\tag{18}
\]

The public start anchor identifies its unique source line and gives

\[
a_{0,s_0}=\ell\bar c_{0,s_0}.                         \tag{19}
\]

The public endpoint gives

\[
\bar r_{L,t_*}b_K=b_{L,t_*}K.                          \tag{20}
\]

Equations (17)–(18) have the form

\[
x_u x_v=c_{uv}.
\]

Once one scale is known, every scale in the same **undirected gauge component**
is found recursively as

\[
x_v=c_{uv}/x_u.                                       \tag{21}
\]

If the endpoint row-line lies in the start line's gauge component, the attacker
obtains `b_{L,t_*}` and then from (20)

\[
\boxed{K=(\bar r_{L,t_*}b_K)/b_{L,t_*}.}               \tag{22}
\]

The computation uses scalar inversions in the public base field, but it never
inverts a rank-one token matrix and never uses a source path.

---

## 6. Explicit false matrix instance: alternating walk leaks K

Use three layers with two named states in the first two layers:

```text
layer 0:  start, C
layer 1:  A, B
layer 2:  accept, dummy
```

Publish only these directed transitions:

```text
start -> A
C     -> A
C     -> B
B     -> accept
```

There is **no directed start-to-accept path**: the only edge from `start` ends
at `A`, which has no outgoing edge.

Nevertheless the public scale graph contains the alternating chain

```text
a_start -- b_A -- a_C -- b_B -- a_B -- b_accept.
```

The first, second, third, and fifth links are token equations (17); the
`b_B -- a_B` link is the same-state pairing (18). Thus (21) reaches the
accepting scale and (22) recovers `K` exactly, despite the absence of any source
path.

The checker hides/shuffles all transition state names from the attack routine.
The routine receives only:

* the public rank-one matrices by layer;
* the public start row; and
* the public key-bearing endpoint column.

It factors the matrices, canonicalizes their public row/column lines, discovers
same-state pairings using (15), solves the scalar gauge component, and outputs
`K`.

Across fields `F_101`, `F_103`, and `F_107`, dimensions `d=2,3,4`, and 40 fresh
random bases per pair, the false relation has zero directed accepting paths in
all **360** trials and the complete-public-view attack recovers `K` in
**360/360**.

A separate true-path control executes 180 fresh setups and verifies (13) in
180/180.

This is not merely a failure to hide state names. Even after names are removed,
the projective state lines and their scalar-gauge relations are algebraically
recoverable from the complete public matrices.

---

## 7. What the two failures mean together

The two constructions bracket a useful boundary.

### 7.1 Commutative secret-factor cancellation

If the key-bearing object is a product of public monomial tokens, a public
pseudorepresentation in the exponent module is enough. Secret factors and
post-setup erasure do not help because the attacker cancels them symbolically.
The all-exclusions and odd-cycle controls show both signed and fractional
failures on explicit false statements.

### 7.2 Exact noncommutative state matching

Matrix units can make invalid *directed* state changes multiply to zero, so they
do escape the commutative exponent-span theorem. But a transparent rank-one
implementation reveals the hidden state lines and enough projective gauge
information to traverse an alternating undirected chain and recover the key on
a false instance.

This is a complete-public-output attack, not a failure of an assumed hardness
problem.

### 7.3 What is **not** proved

This run does **not** prove:

* that every noncommutative semigroup binder is insecure;
* that noisy/encrypted hidden-subspace matrices admit this exact factorization;
* an attack on LWE, SIS, module lattices, or another standard PQ assumption;
* a generic impossibility of witness encryption;
* a generic lower bound saying every compact NP encoding has the exact false
  gauge graph above.

It also does not claim that tests establish security or impossibility. The
proved claims are the displayed algebraic identities for the explicit
architectures.

---

## 8. Surviving constructive target

The next candidate now has a more precise job.

A surviving public offline binder must simultaneously prevent both:

1. **exponent-module pseudomarginals** — arbitrary public scalar powers of
   commutative tokens must not synthesize the key from a signed/fractional
   representation; and
2. **projective state-line recovery** — the complete public object must not
   expose factorable left/right labels and gauge equations that let an
   alternating non-witness walk reach the key.

The most concrete remaining direction is therefore a **computationally hidden
noncommutative/state representation** (for example, a noisy hidden-subspace
object) in which a real source witness can compose the correct transitions and
recover one common key, but arbitrary QPT access to the *entire* transcript
cannot recover the hidden state/gauge structure except by producing a source
witness or breaking an independently justified PQ assumption.

That is only a research target. No such reduction is supplied here. In
particular, replacing the matrices by “LWE-encrypted matrices” is not by itself
a construction: one still has to prove offline composability/correctness,
false-instance hiding, and arbitrary-QPT early-key recovery -> source witness
or standard PQ break without smuggling in a WE/obfuscation-equivalent release
primitive.

---

## 9. Tests actually executed

`multiplicative_matrix_binder_run70_check.py` is deterministic and
standard-library-only. The finalized checker was run twice and produced
byte-identical JSON.

Executed controls:

* all-exclusions multiplicative false family, `k=3`: **300/300** exact public
  key recoveries;
* odd 5-cycle 2-coloring: source-witness count exhaustively verified as zero,
  then **300/300** exact public key recoveries using only exponent `1/2=51 mod
  101` on the two accepted rows per block;
* matrix-unit false complete-output attack: `q in {101,103,107}`,
  `d in {2,3,4}`, 40 fresh random bases per pair, **360/360** exact key
  recoveries with zero directed accepting paths;
* matrix-unit honest path control: **180/180** exact key recoveries.

The matrix attack routine is not given hidden state labels, secret bases, or a
source path. It uses only rank-one factorization, public row/column pairings,
and base-field scalar arithmetic.

Checker SHA-256:

`e82ba0076f5695aec940c4812b94131d5ff614fa276e9bf0020d33250186a93e`

Captured validation SHA-256:

`417be1788636405ab519fb6094cae6e8c313812312dda42eeb128337171d81a1`

Passing these tests validates the finite implementation of the displayed
identities. It is not a cryptographic security claim.

---

## 10. Stopping-condition status

The stopping condition is **not met**.

Still unresolved:

* a complete practical generic-NP witness-restricted public encoding;
* a full-output QPT reduction to source-witness extraction or an independently
  justified PQ assumption;
* false-instance hiding for a surviving primitive;
* malicious-secure erased-setup composition with abort and at-least-one-honest
  security;
* auxiliary-input composition;
* concrete practical resource estimates for a complete construction.

The PR must remain draft and unmerged.
