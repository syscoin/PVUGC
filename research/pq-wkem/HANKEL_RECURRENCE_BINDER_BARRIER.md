# Hankel-rank barrier for compact recurrence consistency binders (Run 30)

## Status

This run starts from PR head
`86bd6590c85ed0ce3f5ceba09322d89b87584f73` and the Run-29 bounded-degree
rational interpolation barrier.

It tests a different compact nonlinear carrier.  The carrier is not represented
as a bounded-degree rational function of its public index.  Instead it is a
hidden exponential sum / linear-recurrence sequence.  This is an explicit
attempt to escape the previous low-degree interpolation attack while retaining
statement-only setup and same-key cancellation.

The result is negative: polynomial **Hankel rank** gives another complete-output
learning attack.  A false disjoint-set instance recovers the key exactly from
`4(r+1)` intended local values by finite-field Gaussian elimination, without a
witness, the hidden roots, the hidden amplitudes, or setup randomness.

This is a scoped barrier for finite-Hankel-rank/linear-recurrence carriers.  It
is not an impossibility theorem for arbitrary succinct nonlinear circuits,
cryptographic PRFs, witness encryption, or generic PQ WKEM.

No outside literature or web search was used.  Production code is unchanged.

## 1. Constructive candidate

Work over a prime field `F_q`.  Setup samples distinct hidden roots

    lambda_1,...,lambda_r in F_q^* \ {1}

and hidden amplitudes

    a_1,...,a_r in F_q.

Define the carrier on public integer indices `t >= 0` by

    P_t = sum_{j=1}^r a_j lambda_j^t.                  (1)

Choose a key `K in F_q` and a uniform additive share `k0 in F_q`, with

    k1 = K-k0.

For two local candidate sets `S0,S1`, publish the intended local tables

    f0(t) = k0 + P_t        for t in S0,
    f1(t) = k1 - P_t        for t in S1.               (2)

The hidden roots and amplitudes are not published.  Setup needs the public
candidate sets and its own randomness but no common element/witness.

A witness `t in S0 intersect S1` decodes offline by

    f0(t)+f1(t) = K.                                   (3)

Thus every common representation recovers exactly the same key.  Carrier
evaluation by setup costs `O(r log t)` ordinary field operations using fast
exponentiation.  For polynomial-size local candidate sets, the published table
is polynomial-size.

This is only a consistency-layer candidate.  It does not by itself compress an
exponential generic-NP witness domain.

## 2. Positive local result: one inconsistent pair can be perfectly hiding

Fix two different indices `u != v`.  Put

    L_u = (lambda_1^u,...,lambda_r^u),
    L_v = (lambda_1^v,...,lambda_r^v).

Condition on any hidden roots for which `L_u != L_v`.  Sample the amplitude
vector `a` and `k0` uniformly.  For fixed `K`, the one-pair transcript is

    y0 = k0 + L_u a,
    y1 = K-k0-L_v a.                                  (4)

The linear map `(k0,a) -> (y0,y1)` has matrix rows

    ( 1,  L_u),
    (-1, -L_v).

Its rows can be dependent only with multiplier `-1`, which would require
`L_u=L_v`.  Hence it has rank two.  Uniform inputs therefore give the exact
uniform distribution on `F_q^2`, independently of `K`.

So this candidate is not rejected by inspecting one inconsistent pair.  The
failure is a genuinely complete-output learning failure.

The checker exhaustively verifies this at `q=7,r=2`, roots `(2,3)`, indices
`u=0,v=1`: for each tested key, all 49 transcript pairs occur exactly seven
times.

## 3. Finite-Hankel-rank reconstruction theorem

Consider any sequence

    y_t = c + sum_{j=1}^r b_j lambda_j^t,              (5)

where the `lambda_j` are distinct, nonzero, and different from `1`.  Delete all
terms with zero amplitude.  Let the active roots be

    Rho = {1 if c != 0} union {lambda_j : b_j != 0}

and let `L=|Rho| <= r+1`.

Then `y` has minimal linear recurrence order exactly `L`.

### 3.1 Hankel factorization

For any starting index `s`, form the `L x L` Hankel matrix

    H[i,j] = y_{s+i+j},    0 <= i,j < L.

Write the active amplitude at root `rho` as `A_rho`.  Then

    H = V diag(A_rho rho^s) V^T,                       (6)

where

    V[i,rho] = rho^i.

The roots are distinct, so `V` is a nonsingular Vandermonde matrix.  Every
active amplitude and every root is nonzero.  Therefore

    det H = det(V)^2 product_rho (A_rho rho^s) != 0.   (7)

Thus the Hankel rank is exactly `L` at every shift.

### 3.2 Exact recurrence recovery from consecutive samples

Let

    Q(X) = product_{rho in Rho} (X-rho)
         = X^L - sum_{j=0}^{L-1} c_j X^j.             (8)

Then

    y_{t+L} = sum_{j=0}^{L-1} c_j y_{t+j}             (9)

for every `t`.

Given any `2R` consecutive samples with `R >= L`, one can recover the minimal
recurrence in polynomial time without knowing the roots:

1. determine `L` by Hankel rank, or equivalently scan recurrence orders and use
   Gaussian elimination;
2. solve the nonsingular `L x L` Hankel system for the coefficients `c_j`;
3. extrapolate the sequence forward using (9).

The checker implements the second, independent formulation: it scans orders
`ell <= R`, solves all available recurrence equations by modular Gaussian
elimination, and selects the first consistent order.

Why can no `ell<L` recurrence pass the complete block?  Such a recurrence would
give a nonzero polynomial `Q_ell` of degree `ell` and a residual exponential
sum with coefficients `A_rho Q_ell(rho)`.  Vanishing at `L` consecutive indices
forces all those coefficients to zero by the same Vandermonde argument.  Then
`Q_ell` would have all `L` distinct active roots despite degree `<L`, a
contradiction.

## 4. Explicit false-instance complete-output break

Let

    R = r+1,
    S0 = {0,...,2R-1},
    S1 = {2R,...,4R-1}.                               (10)

The source consistency statement

    exists t in S0 intersect S1

is false because the sets are disjoint.

Nevertheless `f0` and `f1` from (2) are each exponential sums whose active root
sets are subsets of

    {1,lambda_1,...,lambda_r}.

Hence each has linear complexity at most `R`.  From the `2R` public values in
`S0`, the attacker reconstructs the complete recurrence of `f0`.  From the
`2R` public values in `S1`, it independently reconstructs the recurrence of
`f1`.  Choose any later public integer `T >= 4R`.  Extrapolation gives the two
off-domain values

    f0(T), f1(T),

and therefore

    K = f0(T)+f1(T).                                  (11)

The attack uses exactly `4R=4(r+1)` intended local values plus polynomial-time
finite-field linear algebra.  It never recovers a source witness because the
false instance has none, and it need not recover or factor the hidden roots.

If each intended local value is itself delivered by a sub-decoder with failure
probability at most `epsilon`, the attack succeeds with probability at least

    1 - 4R epsilon                                    (12)

by a union bound, with no independence assumption, whenever all `4R` local
values are correct.

Because (11) is a deterministic exact decoder on every generated transcript,
complete transcript supports for two different keys are disjoint.  Their
pairwise statistical distance is therefore exactly one.

## 5. What this adds to Run 29

Run 29 already identified the general danger of publicly polynomial-sample
learnable carrier families and instantiated it with bounded-degree polynomial
and rational interpolation.  The present construction tests an obvious escape:
make the carrier compact but not a low-degree rational function of the public
index, with secret bases raised to potentially large exponents.

That escape still fails.  The relevant complexity measure is not degree in the
index but **Hankel rank / linear state dimension**.  A sequence can have a
compact nonlinear hidden parameterization and high apparent algebraic
complexity while remaining exactly learnable from `O(r)` consecutive outputs.
No public feature basis and no hidden-root recovery is needed.

A surviving succinct carrier therefore cannot merely replace a bounded-degree
formula by a small linear recurrence, exponential sum, LFSR-like generator, or
other polynomial-Hankel-rank exact sequence.

This does not rule out a computationally unpredictable nonlinear state machine.
But using a secret PRF/PRG state as the replacement still leaves the central
problem: valid witnesses need public offline access to the required secret
function values while false instances must not obtain an equivalent evaluator.
That is the witness-restricted source-transfer obligation, not something this
run assumes away.

## 6. Validation actually executed

The fresh standard-library checker uses exact prime-field arithmetic and a
fixed seed.  It executed:

* 1,600 honest same-representation decodes across `q=101,257` and orders through
  `r=12`;
* exhaustive exact one-inconsistent-pair distributions at `q=7,r=2` for four
  keys: all 49 pairs occur with multiplicity seven for every key;
* exact false-instance key recovery in
  * 500/500 trials for each `r=1,2,3,5,8` over `F_101`,
  * 350/350 trials for `r=12` over `F_257`,
  * 250/250 trials for `r=20` over `F_1009`;
* 64 forced degenerate cases with zero amplitudes and/or zero key shares,
  including reduced-order and identically-zero share sequences;
* 500 long-continuation checks in which the learned recurrence predicts 50
  additional exact terms of each share sequence;
* exhaustive false-transcript enumeration at `q=23,r=1`: 11,109 setup points
  per key for keys `0,1,2`, support size 10,649 for each, and zero pairwise
  support intersections.  The attack's maximum index is 15, below the field
  multiplicative period 22, so this fixture is not relying on period wraparound.

These tests validate the finite algebra and implemented decoder only.  They do
not establish security of any surviving construction.

## 7. Remaining obligations

The requested generic public/offline PQ witness KEM is still not constructed.
A surviving inner encoding must simultaneously provide:

1. polynomial-size statement-only setup without source witness;
2. the same key from every valid witness;
3. complete-output false-instance hiding;
4. no polynomial-sample off-domain learner through linear quotient, finite
   cover, shared-seed recovery, intertwiner solving, finite differences,
   bounded-degree interpolation, or finite Hankel rank;
5. an actual reduction from arbitrary QPT early key recovery to source-witness
   extraction or an independently justified PQ-hard problem;
6. compatible malicious-secure setup/auxiliary-data composition and concrete
   resource estimates.

The previously proved ceremony result remains downstream of such an inner
primitive.  This Run-30 barrier is not the stopping condition.
