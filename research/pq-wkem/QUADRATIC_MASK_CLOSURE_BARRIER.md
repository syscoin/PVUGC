# Nonlinear masked-carrier attempt: public closure decoder and a false-instance barrier

Starting checkpoint: PR #1 head
`e656fc72fd97e4d007ebac91ae2ad68511ea9f45`.

## Status

Run 24 showed that the nonlinear paraboloid short seed has genuine one-component
mixing, but a joint false public view reconstructs the shared seed.  This pass
does **not** return to that seed family.  It instead asks whether the Run-18
public quotient can be defeated by publishing a *masked carrier* and putting the
key behind a nonlinear pointwise relation.

The concrete attempt is

    U = h + m0,
    B = k*1 - P(h) + m1,                                (1)

in a public coefficient space of Boolean multilinear polynomials.  `m0,m1` are
sampled from public verifier-vanishing mask spaces and `P` is a public low-degree
pointwise polynomial; the first case is `P(T)=T^2`.

A valid witness `w` has `m0(w)=m1(w)=0`, so it recovers

    k = B(w) + P(U(w)).                                  (2)

Thus (1) is a genuine setup-without-witness, same-key, offline constructive
attempt.  It is not the previously rejected linear target `k*1+m`.

The complete coefficient output still fails.  There are two results:

1. for `P(T)=T^2`, expanding around the public `U` gives an efficiently
   enumerable public noise closure and hence a Gaussian-elimination decoder
   whenever `1` is outside that closure;
2. more decisively, there is an explicit **false** Boolean relation on which a
   public low-degree pseudo-functional annihilates the entire nonlinear noise
   for *every* bounded-degree pointwise `P`, and therefore recovers `k` exactly.

The second result violates false-statement hiding directly: no source witness
exists in that fixture.  It closes this explicit bounded-degree
constraint-generated coefficient-space direction, not nonlinear/computational
encodings in general.

No external literature or web search was used.  Production code is unchanged.

## 1. Coefficient model and honest correctness

Work over a prime field `F_q`.  Let

    A_L = span { x_T : T subseteq [n], |T| <= L },       (3)

where multiplication is Boolean multilinear (`x_i^2=x_i`) and all products used
by the construction are chosen to have degree at most `L` before publication.
The published object is the explicit coefficient vector in this basis.

For public verifier constraints `g_j`, let `M0,M1` be public linear spaces of
constraint-generated polynomials that vanish on every valid Boolean witness.
For example they can be spans of bounded-degree multiples of the `g_j`.

Setup samples a hidden polynomial `h`, masks `m0 in M0`, `m1 in M1`, and key
`k`, and publishes (1).  For every valid witness `w`, equation (2) is exact.
Setup does not know or use `w`.

The checker includes a true control with the relation

    x_1 + ... + x_4 = 2,                                 (4)

which has six Boolean witnesses.  Across 200 fresh setups all 1,200 witness
decodes returned the same sampled key.

## 2. Exact complete-output identity for the quadratic carrier

Take `P(T)=T^2`.  The public decoder can form

    D = B + U^2.                                         (5)

Because `h=U-m0`,

    D
      = k*1 - (U-m0)^2 + m1 + U^2
      = k*1 + 2 U m0 - m0^2 + m1.                       (6)

Define the public linear noise closure

    C_U = M1 + U*M0 + span{ a*b : a,b in M0 }.           (7)

Every non-key term in (6) lies in `C_U`.  The space is computable from the
complete public output `U` and the public mask bases; no setup randomness or
witness is needed.

If

    1 notin C_U,                                         (8)

Gaussian elimination computes a functional `lambda_U` satisfying

    lambda_U(C_U)=0,
    lambda_U(1)=1.                                       (9)

It then recovers

    lambda_U(D)=k.                                       (10)

This is stronger than applying the old linear quotient directly to `B`: it
first expands the nonlinear hidden carrier around the *public* masked value and
then quotients the full degree-two noise closure.

On a true statement, evaluation at any valid witness annihilates every term of
(7) and sends `1` to `1`, so (8) necessarily holds.  Thus the coefficient model
always has a public key decoder on true instances.  Whether its dual functional
can itself be converted to a source witness is a separate semantic obligation;
this observation alone is therefore not used as the decisive rejection below.

## 3. Explicit false relation

The false-instance attack needs no such extraction question.

Fix integers `n>=1` and a prime `q>n+1`.  Work on Boolean variables and use the
single public constraint

    g(x) = S(x) - r,
    S(x) = x_1+...+x_n,
    r = n+1.                                             (11)

There is no Boolean witness: `S(x)` is one of the integers `0,...,n`, and since
`q>n+1` none equals `n+1 mod q`.

Let `I_{<=L}` denote all Boolean-multilinear degree-at-most-`L` multiples of
`g`, for `L<=n`.  The setup masks in this pass are chosen from subspaces of this
truncated constraint ideal.

## 4. Formal Hamming-weight functional

For a squarefree monomial `x_T` of degree `t<=L`, define

    Lambda_r(x_T) = (r)_t / (n)_t,                       (12)

where

    (a)_t = a(a-1)...(a-t+1).                            (13)

The denominator is nonzero because `q>n+1` and `t<=n`.
Clearly

    Lambda_r(1)=1.                                       (14)

For `|T|=t<=L-1`, Boolean multilinearity gives

    S x_T
      = t x_T + sum_{j notin T} x_{T union {j}}.         (15)

Write `a_t=(r)_t/(n)_t`.  Since

    a_{t+1} = ((r-t)/(n-t)) a_t,                         (16)

we obtain

    Lambda_r(S x_T)
      = t a_t + (n-t) a_{t+1}
      = r a_t.                                           (17)

Therefore

    Lambda_r(g x_T)=0                                    (18)

for every multiplier monomial of degree at most `L-1`, and by linearity

    Lambda_r(I_{<=L})=0.                                 (19)

This is an explicit public pseudo-functional for the false relation.  It is not
an evaluation at a source witness; there is no source witness.

## 5. Quadratic false-instance break

Choose `h,m0` of degree at most `e` with `2e<=L`, take

    m0 in I_{<=e},
    m1 in I_{<=L},                                       (20)

and publish the quadratic instance of (1).

From (6), every non-key term is a multiple of `g` and has degree at most `L`:

* `m1 in I_{<=L}`;
* `U m0 in I_{<=L}` because `m0` is a multiple of `g`;
* `m0^2 in I_{<=L}` for the same reason.

Hence (19) gives immediately

    Lambda_r(B+U^2)=k.                                   (21)

This is a deterministic public decoder on a false statement.  It does not find
or assume a witness; none exists.

Because (21) holds for **every** setup randomness, complete transcript supports
for distinct keys are disjoint.  In particular their pairwise statistical
distance is exactly one.

## 6. General bounded-degree pointwise polynomial barrier

The attack is not specific to squaring.

Let

    P(T)=sum_{j=0}^d c_j T^j                            (22)

be any public scalar polynomial, and suppose all products in the explicit
coefficient output have Boolean degree at most `L<=n`.  The public object gives

    D_P = B + P(U)
        = k*1 + [ P(U) - P(U-m0) ] + m1.                 (23)

For every ordinary polynomial `P`, the bivariate difference

    P(X)-P(X-Y)                                          (24)

has zero constant term in `Y`; equivalently it is divisible by `Y`.  Therefore
`P(U)-P(U-m0)` is a multiple of `m0`, hence a multiple of the verifier
constraint `g`.  Under the stated degree bound it belongs to `I_{<=L}`.
Together with `m1 in I_{<=L}`, equation (19) gives

    Lambda_r(D_P)=k.                                     (25)

Thus **any bounded-degree pointwise nonlinear lift of this masked-carrier form
fails false-instance hiding in the explicit truncated coefficient model**.
The nonlinearity can change the public noise closure, but it cannot escape the
truncated verifier ideal, and the false formal Hamming functional annihilates
that entire ideal.

The checker exercises `P(T)=T^2`, `T^3`, and `T^5` on separate parameter sets;
all 450/450 sampled false transcripts recover the exact key via (25).

## 7. Why this is not the Run-18 attack repeated

Run 18 rejected the direct linear object

    F_k = k*1 + m.                                       (26)

A public functional annihilating the mask space alone exposed `k`.

Here the intended repair explicitly publishes a hidden random carrier `U` and
places `k` behind the nonlinear relation `P(h)`.  Applying a functional only to
`B` does **not** in general remove `P(h)`.

The new audit step is to compute `B+P(U)`, expand the hidden `h=U-m0`, and track
the entire nonlinear mask closure.  Section 2 gives a public closure decoder for
squaring; Sections 3--6 then give a false relation whose formal moment
functional annihilates every bounded-degree term produced by that expansion.
So this is a strict extension of the old quotient barrier to this nonlinear
masked-carrier family.

It is also different from Runs 22--24: there is no explicit finite-state cover,
no orbit sum, and no shared `H x` representative seed.  The failure occurs in
the succinct verifier-coefficient representation itself.

## 8. Efficiency implication and exact scope

The dense explicit feature dimension is

    N_L = sum_{j=0}^L binom(n,j).                         (27)

For fixed `L`, this is polynomial in `n`; reaching the full Boolean function
algebra at `L=n` costs `2^n` coefficients.  More generally, a family with
unbounded `L` in this dense basis ceases to have a fixed-polynomial output
bound.  The false family therefore hits precisely the parameter regime in
which this explicit bounded-degree coefficient representation is attractive.

This is **not** an impossibility theorem for every succinct representation.
The proof does not cover, for example:

* a computationally hidden representation whose internal constants cannot be
  read as public coefficients;
* a sparse/high-degree representation where the relevant nonlinear closure is
  not explicitly enumerable and whose security follows from an independently
  justified PQ assumption;
* an encoding whose masks are not contained in a bounded-degree
  constraint-generated vanishing ideal;
* a construction with an independently proved source-extraction reduction from
  its complete public output.

But using an ordinary arithmetic circuit merely to hide the decomposition of
(1) is not enough by itself: readable circuit constants expose the hidden
randomness unless a separate computational encoding is supplied.  Such an
encoding would be a new cryptographic obligation, not a consequence of this
algebra.

## 9. Validation actually executed

`quadratic_mask_closure_check.py` is standard-library only.  The fresh run
records:

* **true completeness:** 200 setups for `sum_{i=1}^4 x_i=2` over `F_101`; all
  six witnesses per setup decoded the same key, for 1,200/1,200 successful
  witness decodes;
* **false quadratic decoder:** 500/500 exact key recoveries on the no-witness
  instance `sum_{i=1}^8 x_i=9`, degree bound `L=4`, ambient feature dimension
  163;
* **public Gaussian closure decoder:** 80/80 exact recoveries using only the
  public span (7), not the closed-form `Lambda_r`; the measured closure rank was
  93 in every fixture inside ambient dimension 163;
* **higher-degree controls:** 150/150 exact recoveries each for `P=T^2`,
  `P=T^3`, and `P=T^5` on three separate false parameter sets;
* **exhaustive tiny distribution:** over `F_5`, `n=3`, `L=2`, all 15,625 setup
  randomness points per key were enumerated for keys 0 and 1; each support had
  size 15,625 and the support intersection was empty, so exact pairwise TV is
  1;
* **formal-moment recurrence:** all 93, 386, and 1,586 tested truncated
  constraint multiples were annihilated for `(q,n,L)=(101,8,4)`, `(103,10,5)`,
  and `(107,12,6)` respectively.

These executions validate the finite algebra identities and attack
implementation.  They do not prove security of any surviving construction and
no quantum hardware was used.

## 10. Result classification

**Constructive attempt:** nonlinear masked carrier (1), with exact same-key
witness decoding (2).

**Proved:** quadratic complete-output identity (6); public closure decoder
(7)--(10); false formal Hamming functional (12)--(19); exact quadratic
false-instance recovery (21); general bounded-degree pointwise recovery
(23)--(25); disjoint-key-support consequence.

**Implemented:** explicit Boolean coefficient algebra, verifier-mask sampling,
honest decapsulation, formal pseudo-functional, public Gaussian closure decoder,
higher-degree controls, and exhaustive tiny support comparison.

**Actually tested:** only the groups listed in Section 9 and the captured JSON.

**Conjecture:** none is needed for the stated break.  A computationally hidden
or otherwise non-coefficient witness-restricted encoder remains open.

**Stopping condition:** not met.  The missing core remains an efficient generic
NP public offline PQ encoding whose complete public view cannot be reduced to a
publicly enumerable verifier-vanishing closure, finite-cover observable, seed
reconstruction, or another already recorded attack, and whose arbitrary QPT
early-key recovery reduces to a source witness or an independently justified
PQ hardness assumption.
