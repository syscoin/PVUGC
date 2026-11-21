# Native/projective duality and a local perfect-correctness span barrier

## Status

This continuation starts from the Gap-OHLC checkpoint at PR head
`e5ba385676fa1be6bd60c50333af83fbf83f70f9`.

It does **not** complete the witness KEM.  It proves an exact dual description of
the binary additive capsule, rejects a natural "noise only on invalid local
states" repair, and gives a complete-public-view attack on naive public
repetition padding.

The main new distinction is:

- **source-witness transfer** is represented by a short/projective preimage
  `z` with `A z=b`;
- **native encryption/decryption** is the public linear code
  `C=im(A^T)` carrying the target bit `b^T s`.

Those are dual descriptions of the same public capsule and must be audited
together.  A short-preimage theorem alone is not a native-decoding hardness
theorem.

No external literature or web search was used.

## 1. Binary capsule and exact native/projective Fourier duality

Work over `F_2`.  Let

    A in F_2^(m x n),     b in F_2^m,

and consider the additive capsule

    c = A^T s + e,
    d = b^T s + e0 + K,

where `s` is uniform, `e` has iid Bernoulli(p) coordinates, `e0` is an
independent Bernoulli(p), and

    rho = 1 - 2p.

For the moment condition on the native target bit

    r = b^T s.

Let `P_r` be the distribution of `c` conditioned on `r`.  For every Fourier
label `z in F_2^n`,

    P_hat_r(z)
      = rho^wt(z)
          E[ (-1)^(s^T A z) | b^T s=r ].

For nonzero `b`, averaging a character over the affine hyperplane
`{s : b^T s=r}` gives the exact trichotomy

    P_hat_0(z) =
        rho^wt(z),     if A z=0,
        rho^wt(z),     if A z=b,
        0,              otherwise,

    P_hat_1(z) =
        rho^wt(z),     if A z=0,
       -rho^wt(z),     if A z=b,
        0,              otherwise.                    (1)

Therefore:

> the entire Fourier support on which the two native target-bit distributions
> differ is **exactly**
>
>     Z_b = { z : A z=b }.

The Run-9 odd-projective spectrum is thus not merely an attack heuristic.  It is
the exact dual spectrum of native target-bit decoding.

Restoring `(d,K,e0)` gives the previous complete-capsule identity as an immediate
corollary:

    E[ (-1)^(z.c + t d) ]
      = 1[A z + t b=0]
        rho^(wt(z)+t)
        (-1)^(t K),                                  (2)

for `t in {0,1}`.

Equation (1) makes the "native encryption versus source-witness transfer"
distinction precise: an adversary need not exhibit any particular projective
preimage.  It may decode the native bit from the complete noisy codeword by any
algorithm whatsoever.

## 2. Exact projective/native weight-enumerator transform

Define the projective-coset weight enumerator

    W_Z(x) = sum_{z : A z=b} x^wt(z).

Character expansion of the indicator `1[A z=b]` gives

    W_Z(x)
      = 2^(-m)
        sum_{s in F_2^m}
          (-1)^(b^T s)
          (1+x)^(n-wt(A^T s))
          (1-x)^wt(A^T s).                           (3)

No rank assumption is needed for the identity.

Thus the full projective spectrum is the exact signed transform of the native
codeword spectrum, partitioned by the target label `b^T s`.

Consequences:

1. minimum projective distance is only one statistic of the full native channel;
2. a construction may have no useful short public parity decoder and still have
   an efficient native decoder;
3. conversely, a claim that a native decoder is hard must survive the entire
   projective enumerator, not just the canonical witness.

The checker verifies (1) and (3) exactly on twenty fresh full-row-rank
`3 x 5` matrices using rational BSC probabilities (`p=1/4`), exhaustive
conditioned distributions, and exact integer polynomial coefficients.

## 3. Constructive attempt: accepting-span annihilator noise

The Gap-OHLC checkpoint suggests trying to stop accumulation of honest noise.

For a local predicate, let `v_a` be the canonical local encoding of an accepting
assignment `a`.  A natural setup-only strategy is:

1. compute the public accepting span

       V = span{ v_a : P(a)=1 };

2. sample local additive noise only from

       V^perp.

Then every canonical accepting local state sees **zero noise exactly**, so an
honest witness can traverse arbitrarily many local tests without the
`p=Theta(1/B)` correctness problem.

The hope is that a failed OHLC pseudostate lies outside `V` and therefore sees a
uniform local error.

That hope fails generically.

## 4. Perfect-correctness linear-span barrier

Let `S` be any collection of canonical encodings and let an additive noise
vector `e` satisfy

    <e,v> = 0      for every v in S.                  (4)

Then by linearity,

    <e,u> = 0      for every u in span(S).            (5)

Therefore any projective pseudostate that is a linear combination of legitimate
local accepting states is **information-theoretically invisible** to every
linear additive noise distribution having perfect correctness on those states.

This is independent of how `e` was generated, whether the setup was distributed,
and whether the coefficients selecting `e` were erased.

### Single-reject predicates give an explicit generic counterexample

Let a local predicate on `r>=2` bits accept every assignment except one
assignment `a*`.  This includes the local shape of a clause with one falsifying
assignment.

Use the binary OHLC local encoding:

- one two-coordinate one-hot block for each queried bit;
- one `2^r`-coordinate local-state block.

For every accepting `a`, let `v_a` be its canonical one-hot encoding.

The unique standard failed pseudostate at `a*` is

- queried wire blocks equal to the rejected assignment `a*`;
- local-state coordinate `1` on **every accepting assignment** and `0` on
  `a*`.

For every `r>=2`,

    u_fail = XOR_{a != a*} v_a.                       (6)

Reason: there are `2^r-1` accepting assignments, an odd number.  For each query
bit, among those assignments the value equal to `a*_j` appears
`2^(r-1)-1` times (odd), while the opposite value appears `2^(r-1)` times
(even).  The state-block identity is immediate.

Hence `u_fail` lies in the accepting span and every perfect-correctness linear
annihilator noise satisfies

    <e,u_fail> = 0.

So "put noise only in directions rejected by all accepting local states" cannot
repair clause-like Gap-OHLC.  The failed local pseudostate is built entirely out
of accepted local states.

The checker verifies (6), all local equations, and an explicit basis of the
annihilator for **every** single-reject predicate of arity 2, 3, and 4:
28 predicates and 220 annihilator-basis checks.

This is a rejection of this linear local-noise candidate, not a theorem against
nonlinear or computational encodings.

## 5. Complete-public-view warning: column repetition helps the native attacker

Another tempting response to a difficult projective enumerator is to add public
redundancy.

Let `A^(L)` be obtained by repeating every column of `A` exactly `L` times.

### Projective side

If `z` satisfies

    A z=b,

then a replicated preimage can place `z_j` in just one copy of column `j` and
zero in the other copies.  Therefore

    d_proj(A^(L),b) <= d_proj(A,b),

and the canonical witness may keep the same support size.

### Native side

A noiseless native codeword becomes

    A^(L)^T s
      = (x_1,...,x_1, x_2,...,x_2, ...),

with `L` identical copies of every original coordinate.

Under iid BSC noise, the public can majority-decode every repeated coordinate.
For odd `L`, the per-coordinate error is exactly

    p_L =
      sum_{i=(L+1)/2}^L binom(L,i) p^i (1-p)^(L-i).   (7)

After recovering the noiseless native word, public Gaussian elimination obtains
`s` when `A` has full row rank, or directly obtains `b^T s` whenever that
functional is well defined on the code.  No source witness is involved.

Thus repetition can leave witness/projective support unchanged while making the
**native** target bit dramatically easier to recover.

A fresh control with a full-row-rank `3 x 5` matrix, `L=9`, `p=0.08`, and
5,000 capsules produced:

    canonical witness decoder: 3986 / 5000
    public repetition/native decoder: 4584 / 5000

The simulation is only a check of the implemented attack.  The attack itself
follows from the exact repetition identity and majority formula (7).

## 6. Implication for the current construction search

The Gap-OHLC direction fixed an important semantic defect: it can create a
constant minimum odd-projective weight gap.

This run shows why that is still not enough.

A viable inner capsule must simultaneously satisfy:

1. **witness channel:** every valid source witness obtains the common raw key with
   high probability;
2. **projective spectrum:** the complete odd affine-preimage spectrum is
   controlled;
3. **native channel:** the target functional `b^T s` is not efficiently
   recoverable from the entire noisy codeword by a decoder that never outputs a
   projective preimage;
4. **source extraction:** arbitrary early recovery of the final key on a true
   statement reduces to a source witness or an independent PQ hardness break.

The natural perfect-correctness linear local-noise attempt fails by the
accepting-span theorem.  Public repetition/padding can make the native channel
easier while leaving source-witness transfer unchanged.

The surviving constructive requirement is therefore sharper:

> introduce a **nonlinear or computationally hidden global consistency
> mechanism** whose honest evaluation does not accumulate one independent error
> per proof block, but whose public output does not expose a native decoding
> route.

Calling such a mechanism "witness-restricted noise" is not a security
assumption; an actual construction and reduction are still missing.

No complete generic PQ WKEM, secure parameters, or production-code change is
claimed in this run.
