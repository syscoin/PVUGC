# Binary projective gap, projection spectrum, and a gap-OHLC repair target

## Status

This continuation starts from PR head `48965480dec1b888b83ae944e636d14fb7025a3b`
and the preceding projective-OHLC / weak-capsule amplification checkpoints.

It does **not** complete a witness KEM.  It proves two boundaries for the current
linear noisy route and gives one constructive semantic repair target:

1. random row projection suppresses only projection-created projective modes;
   exact projective modes of the original compiler survive with coefficient 1;
2. plain binary OHLC has an explicit padded false family whose one-violation
   public decoder becomes asymptotically as reliable as the honest decoder for
   iid BSC noise;
3. compiling a constant-gap local verifier into a binary one-hot local-state
   system gives a constant projective Hamming gap, including a modular-lift-safe
   Euclidean lower bound for every odd projective scalar over even moduli.

The third item is a concrete compiler interface, not a hiding proof.  A standard
perfect-completeness constant-soundness PCP/gap-CSP can in principle supply the
needed local gap with polynomial size, but no concrete PCP implementation or
constants are claimed or validated here.  The complete-public-view hiding and
true-instance key-recovery-to-witness/LWE reductions remain open.

No external literature or web search was used.

## 1. Exact random-projection spectral decomposition

Split a public homogeneous/projective relation into equations that are kept
exactly and equations that are randomly projected:

    C v = 0,
    J v = 0.

Setup samples a uniform matrix

    R <- F_q^(d x m)

and publishes only the projected second family

    R J v = 0.

Let `V` be any fixed set of candidate Fourier labels (for example labels with an
odd target coordinate), and let `w(v)>=0` be any weight independent of `R`.
Define

    S_R     = sum_{v in V: C v=0, R J v=0} w(v),
    S_exact = sum_{v in V: C v=0,   J v=0} w(v),
    S_C     = sum_{v in V: C v=0} w(v).

For a fixed candidate with `Jv != 0`, every row of `R` annihilates `Jv` with
probability `1/q`, independently.  Therefore

    E_R[S_R]
      = S_exact + q^(-d) (S_C - S_exact).             (1)

This identity is exact; it does not use a union bound or assume uniform
candidate labels.

Consequently, writing `S_acc=S_R-S_exact`, Markov gives for every `eta>0`

    Pr_R[S_R > S_exact + q^(-d)(S_C-S_exact)/eta]
      <= eta.                                          (2)

The important negative consequence is equally exact:

> random row projection cannot attenuate an exact projective mode of the
> original compiler at all.

The scale-3 Run-9 pseudowitness is one such mode.  Any repair that keeps the same
base compiler must fix its exact projective spectrum before projection can help.

The attached checker verifies (1) exactly with rational arithmetic by enumerating
all `2^(d*m)` projection matrices in a small binary fixture.

## 2. Binary local-state OHLC has an exact violation/weight interpretation

Work first over `F_2`.  Give each Boolean proof/wire variable a two-coordinate
block

    (x_0,x_1),     x_0+x_1=1.

Because the block has only two binary coordinates, this equation forces it to
be exactly one-hot.

For a local predicate `P:{0,1}^r->{0,1}`, introduce a block with one coordinate
`q_a` for each local assignment `a in {0,1}^r` and impose

    sum_a q_a = 1,
    sum_{a:a_j=1} q_a = x_j       for every queried position j,
    sum_{a:P(a)=1} q_a = 1.        (3)

Every solution block has odd Hamming weight.  If it has weight one, it equals
`e_a` for one local assignment.  The marginal equations force that assignment
to be the actual queried proof bits, and the final equation forces
`P(a)=1`.

Hence:

* if the local proof assignment satisfies the test, its one-hot local state is a
  valid block of weight one;
* if the local proof assignment fails the test, every block satisfying (3), if
  one exists at all, has Hamming weight at least three.

For AND/OR gates the four equations are nonsingular and the block is unique:
weight one for a correct gate and weight three for an incorrect gate.  The
checker exhausts every AND/OR input/output triple and all 16 two-input predicate
truth tables as a control.

Let a verifier instance have `W` proof-variable blocks and `G` local-test blocks,
and define

    B = W + G.

A genuine accepting proof has projective frequency weight exactly `B`.  If every
candidate proof assignment violates at least `nu` local tests, then every
`t=1` projective relation has

    wt(z) >= B + 2 nu.                               (4)

Over `F_2` there is no separate odd scale `t=3`: every nonzero projective scalar
is the same element `1`.

## 3. Modular-lift-safe version for even LWE moduli

The preceding gap also survives as a lower bound inside any even modulus.
Suppose the same `0/1` constraint matrix is interpreted modulo an even `q`, and
an odd projective label obeys

    H z = t b        (mod q),       t odd.             (5)

Reduce (5) modulo two.  Then

    H (z mod 2) = b  (mod 2).

If the binary compiler has gap (4), at least `B+2nu` centered coordinates of
`z` are odd.  Every odd centered integer has absolute value at least one, so

    ||z||_2^2 >= B + 2 nu.                            (6)

Including the target coordinate gives

    ||(z,t)||_2^2 >= B + 2 nu + 1.                    (7)

Thus a constant local-test soundness gap gives a constant Euclidean projective
gap against **all odd modular lifts**, not only the smallest integer scalar.
This directly addresses one of the Run-9 unresolved mode classes.

It does not bound the number of such modes or prove that their complete Fourier
mass is small.

## 4. Why plain OHLC plus iid BSC noise has no robust raw gap

The binary additive diagnostic capsule is

    c = A^T s + e,
    d = b^T s + e0 + K,

where all arithmetic is in `F_2` and every error bit is iid Bernoulli(`p`).  Put

    rho = 1 - 2p.

For any public projective relation `A z=b`, the public decoder

    d - z^T c

is the key plus the parity of `wt(z)+1` independent error bits.  Its exact key
success probability is

    P(z) = (1 + rho^(wt(z)+1))/2.                     (8)

A true one-hot proof has weight `B`, so

    P_h = (1 + rho^(B+1))/2.                          (9)

Now pad the explicit Run-9 false gadget with arbitrarily many locally satisfied
dummy gates.  The statement remains false while an explicit public relation has
exactly one violated nonlinear gate, hence weight

    B + 2.

Its false public decoder succeeds with

    P_f = (1 + rho^(B+3))/2.                         (10)

Fix any target honest raw success `h in (1/2,1)` and choose the coordinate-noise
rate so that `P_h=h`.  If `beta=2h-1`, then

    rho_B = beta^(1/(B+1)),

and

    P_f(B)
      = (1 + beta * rho_B^2)/2
      -> h.                                           (11)

More precisely,

    h - P_f(B)
      = (beta - beta^(1+2/(B+1)))/2
      = beta |ln beta|/(B+1) + O(B^-2).               (12)

So plain OHLC has a family of easy false statements where this public direct
projective decoder becomes asymptotically as reliable as the intended witness
decoder.  This does not by itself prove that every outer code is impossible,
but it rules out a **constant raw wiretap gap** for this iid-BSC/plain-OHLC
combination.  Any outer construction would have to exploit a vanishing
`O(1/B)` advantage or obtain secrecy from a different computational layer.

Fresh formula evaluation at target honest success `0.9` gives:

| B | false one-violation success |
|---:|---:|
| 5 | 0.8713271 |
| 55 | 0.8968249 |
| 1005 | 0.8998226 |
| 5005 | 0.8999643 |

These are exact formula evaluations, not Monte Carlo security estimates.

## 5. Constructive repair target: Gap-OHLC

The violation lemma suggests a concrete semantic repair rather than another
noise tweak.

Take a public local verifier with:

* perfect completeness: a valid source witness can generate a proof accepted by
  every local test;
* constant query size;
* `O(log n)` verifier randomness, so all random strings/tests can be enumerated
  in polynomial size;
* soundness gap: on a false source statement every proof assignment fails at
  least a constant fraction `delta` of the `G` tests.

Compile every proof bit and every local test with the blocks in Section 2.
Then:

* true source witnesses map to a polynomial-size vector of weight exactly `B`;
* false statements have no odd projective mode below

      B + 2 delta G;

* over every even modulus, every odd modular projective lift obeys the Euclidean
  lower bound

      ||(z,t)||_2^2 >= B + 2 delta G + 1.

A standard constant-soundness PCP/gap-CSP is the intended source of such a local
verifier.  This is not a new cryptographic assumption, but this run does not
instantiate or audit a concrete PCP and therefore makes no concrete overhead or
parameter claim.

The checker includes a synthetic constant-gap OR-CSP control in which every
wire assignment violates exactly half the local tests.  Its two affine
solutions both have the predicted weight `B+G`.  Keeping honest raw success at
`0.9`, the best direct projective decoder in this synthetic family tends to
about `0.82` rather than `0.9`, showing that a genuine local-test gap changes the
raw-channel geometry in the required direction.

## 6. Why this still does not complete the inner capsule

Gap-OHLC fixes only the **minimum projective weight** problem.

For iid memoryless noise, the complete false-view Fourier mass sums over every
odd projective mode.  A constant minimum distance does not bound that weight
enumerator, and there can be exponentially many proof assignments/modes.
Therefore this run does not infer

    S_odd < 1/4,

or any other complete-view hiding bound, from the gap alone.

This is the next precise constructive target:

1. instantiate a polynomial-size gap verifier/Gap-OHLC with useful concrete
   constants;
2. design a noise/projection layer whose **complete odd-projective weight
   enumerator** is bounded, not merely its minimum distance;
3. preserve a significantly better honest decoding channel;
4. prove arbitrary true-instance recovery of the privacy-amplified final key
   yields a source witness or a break of an independently justified PQ
   assumption.

Random row projection can help only with projection-created modes according to
(1); it cannot erase the exact Gap-OHLC spectrum.  A sparse hidden-query PCP
would avoid summing all public tests, but hiding the query from an adaptive
proof is precisely a designated-verifier/hidden-check problem and is not being
silently assumed here.

No secure WKEM, secure parameter set, or production-code change is claimed.