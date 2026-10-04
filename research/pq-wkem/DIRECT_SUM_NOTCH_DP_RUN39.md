# Run 39 — direct-sum attack on the logarithmic notched walk

## Status and scope

Starting verified draft head: `1a772a7bcdb1b3ee8dbdd6e031550f87fe49f58a`.

This run continues the exact surviving case left by Run 38.  No external
literature or web search was used.  The construction under audit is the Run-38
binary Gap-OHLC quotient capsule with the two-step notch cycle

- one always-active global coordinate hit (`p=1`), and
- one independent hit active with probability `4/5`,

repeated `C` times.  Run 38 observed that taking `C=Theta(log lambda)` defeats
the **naive** public support enumerator, because the raw support count becomes
quasi-polynomial.

The result here is negative for that surviving construction.  A polynomial-size
family of explicit false direct-sum statements has:

1. an exact polynomial-time public likelihood / MAP algorithm despite the large
   raw support; and
2. inverse-polynomial complete-view key distinguishing advantage when
   `C=Theta(log lambda)`.

Thus this logarithmic notch walk does not satisfy false-statement hiding.  The
attack is classical, so it also applies to the requested QPT security notion.
This is **not** a generic impossibility theorem for witness encryption or for all
high-entropy correlated channels.

## 1. False direct-sum family

Use the Run-38 false two-proof-bit gadget with predicate masks

```
(1, 2, 7, 7).
```

For every assignment to its two source bits, at least one of the four tests
fails, and the best assignment satisfies exactly `3/4` of the tests.  Hence the
source gap is exactly `1/4` and there is no accepting source witness.

Take the direct sum of `m` independent copies, with disjoint proof bits and
local-test blocks.  The conjunction is still false.  Because the source bits are
independent across copies, its optimum accepted fraction is still exactly
`3/4`, so the gap remains `1/4` rather than shrinking with `m`.

Let the local affine system be

```
H0 z = b0
```

over `F_2`, exactly as constructed by the Run-38 checker.  It has 20 local
coordinates, 18 independent affine constraints, and

```
dim ker(H0) = 2.
```

Fix any public affine reference `a0` satisfying

```
H0 a0 = b0,
```

and a public basis `k1,k2` of `ker(H0)`.

## 2. Canonical complete quotient for the direct sum

Run 38 represents the key shift by augmenting the public row-space system with
the affine right-hand side.  For `m` copies the odd/even characters are the
nullspace of the block system

```
[ H0                         | b0 ]
[     H0                     | b0 ]
[          ...               | ...]
[                H0          | b0 ].
```

A vector `(z_1,...,z_m,t)` lies in this nullspace iff, for every gadget `g`,

```
H0 z_g + t b0 = 0.
```

Because `H0 a0=b0`, this is equivalent to

```
z_g = t a0 + u_g,     u_g in ker(H0).
```

Therefore an explicit public basis is

- `(k1 in gadget g, t=0)` and `(k2 in gadget g, t=0)` for every `g`; and
- the one global odd vector `(a0,a0,...,a0,t=1)`.

So the complete quotient has exactly

```
2m + 1
```

coordinates: two local syndrome bits per gadget and one global parity bit.  The
key shift flips only the final parity bit in this basis.

This basis is merely a public invertible change of quotient coordinates; it does
not discard information.  The checker verifies the nullspace identity and full
rank for `m=1..6`.

## 3. Seven local transition types

For the deterministic public basis/reference used by the checker, the 16 local
test coordinates induce the following `(local syndrome delta, parity delta)`
multiset.  Syndrome values are encoded as `0,1,2,3` for the two kernel bits.

| syndrome delta | parity delta | multiplicity |
|---:|---:|---:|
| 0 | 0 | 2 |
| 0 | 1 | 2 |
| 1 | 0 | 3 |
| 1 | 1 | 1 |
| 2 | 0 | 4 |
| 3 | 0 | 1 |
| 3 | 1 | 3 |

The multiplicities sum to 16.  A global active noise step chooses one of the
`m` gadgets uniformly and then one of these 16 local coordinates uniformly.

## 4. Exact public histogram likelihood DP

Let

```
c_s = number of gadgets currently in local syndrome state s,  s=1,2,3,
c_0 = m-c_1-c_2-c_3,
p   = global parity bit.
```

The public state is therefore

```
(c_1,c_2,c_3,p).
```

For an active step, from local state `s`, a coordinate type `(d,q)` sends

```
s -> s xor d,
p -> p xor q
```

with exact probability

```
(c_s/m) * multiplicity(d,q)/16.
```

The optional Run-38 step is simply

```
(1/5) I + (4/5) T,
```

where `T` is the active-step transition operator.  One notch cycle is

```
T * ((1/5) I + (4/5) T).
```

Starting from `(0,0,0,0)`, iterate this exactly `C` times using rational
arithmetic.  This computes the **complete quotient distribution**, aggregated
only by the gadget-permutation symmetry.  That aggregation loses no information
for key distinguishing: the public construction and key shift are permutation
symmetric, so all labelled quotient points with the same histogram have equal
probability under each key.

For a resulting histogram `h`, let `P(h,p)` be its exact probability.  Key one
flips only `p`, so the complete quotient TV is

```
TV = sum_h | P(h,0) - P(h,1) |.                 (1)
```

The exact public MAP decoder compares these two likelihoods for the observed
histogram/parity.

### Complexity

After at most `2C` active opportunities, at most `2C` gadgets can have nonzero
syndrome.  Therefore

```
c_1+c_2+c_3 <= 2C,
```

and the number of reachable histogram/parity states is `O(C^3)`.  Each state has
at most 28 active transition branches (four current syndrome classes times seven
coordinate types).  Exact probabilities have only `O(C log m)` denominator bit
length, up to constant factors from 5 and 16.

Thus for

```
C = Theta(log lambda)
```

the exact likelihood/MAP algorithm is polynomial time.  The quasi-polynomial
**raw support count** from Run 38 was therefore not a hardness barrier on this
family.

The checker independently constructs the generic `2m+1`-dimensional quotient
and confirms exact TV equality with the histogram DP for `m=1,2,3,4` and
`C=1,2`.

## 5. Collision-free complete TV is exactly `(3/10)^C`

The direct-sum family also gives an analytic lower bound, not only a DP attack.

For one labelled gadget hit, define the signed local mass

```
d(s) = Pr[local syndrome=s, parity=0]
     - Pr[local syndrome=s, parity=1].
```

For an always-active mandatory hit, the exact signed masses are

```
s=0:  0
s=1:  1/8
s=2:  1/4
s=3: -1/8,
```

so

```
||d_M||_1 = 1/2.                                (2)
```

For the optional `p=4/5` slot, including its `1/5` inactive branch, they are

```
s=0:  1/5
s=1:  1/10
s=2:  1/5
s=3: -1/10,
```

hence

```
||d_O||_1 = 3/5.                                (3)
```

Now condition on all active hits landing in distinct gadgets.  Before the random
injective gadget labels are forgotten, the signed measure is a tensor product of
`C` mandatory slot measures and `C` optional slot measures, so its L1 norm is

```
(1/2)^C (3/5)^C.
```

Randomly assigning the distinct gadget labels does **not** create sign
cancellation.  Both slot types have the same sign pattern on every nonzero local
syndrome: `+,+,-` on states `1,2,3`; the optional zero state is positive; the
mandatory zero signed mass is exactly zero.  Consequently every nonzero term
contributing to a fixed unlabelled histogram has the same sign, determined only
by the number of syndrome-3 gadgets.  Symmetrization preserves the L1 norm.

Therefore the exact collision-free complete TV is

```
TV_distinct = (3/10)^C.                          (4)
```

This is the same base as the honest fixed-mode bias, not the Run-38 per-mode
false bound `(1/10)^C`.  The gap between those statements is precisely the
multimode complete-view effect.

## 6. Coupling back to the real with-replacement walk

There are at most `2C` active hits.  Couple the real process, which chooses a
gadget independently for each active hit, to an ideal process using distinct
gadgets until the first collision.

By a union bound,

```
epsilon_coll <= binom(2C,2)/m.                  (5)
```

For either key bit, the real and ideal public quotient distributions are within
TV at most `epsilon_coll`.  Hence by the triangle inequality for the two
key-conditioned distances,

```
| TV_real - (3/10)^C |
   <= 2 epsilon_coll
   <= 2 binom(2C,2)/m.                           (6)
```

The checker evaluates the exact DP for `C=1..6` and `m=100,1000,10000`; the
values converge to `(3/10)^C` exactly as (6) permits.

## 7. Polynomial-size false family with inverse-polynomial advantage

Let

```
C(lambda) = ceil(c log_2 lambda)
```

for any fixed constant `c>0`, and write

```
A_C = (3/10)^C.
```

Choose

```
m >= 4 binom(2C,2) / A_C.                       (7)
```

Then (5) gives `2 epsilon_coll <= A_C/2`, and therefore from (6)

```
TV_real >= A_C/2.                                (8)
```

The direct-sum statement is still polynomial size because

```
1/A_C = (10/3)^C
      = lambda^(c log_2(10/3)) * O(1),
```

so (7) uses only polynomially many constant-size gadgets.  Meanwhile `A_C` is
inverse-polynomial.  The exact public histogram MAP algorithm therefore guesses
the encapsulated raw key bit with probability

```
1/2 + TV_real/2
 >= 1/2 + A_C/4,                                 (9)
```

which is non-negligibly above one half.

This is a direct false-statement confidentiality failure.  There is no source
witness to extract on these statements; the attack does not need to solve LPN,
LWE, SIS, syndrome decoding, or another assumed hard problem.

The checker includes illustrative finite rows using

```
C = ceil(log_2(lambda)/4)
```

and the sufficient `m` from (7).  For example its exact calculations include:

- `lambda=256`: `C=2`, `m=267`, exact false TV about `0.08828`;
- `lambda=1024`: `C=3`, `m=2223`, exact false TV about `0.02684`;
- `lambda=16384`: `C=4`, `m=13828`, exact false TV about `0.008086`.

These are attack illustrations, not proposed security parameters.

## 8. What this closes and what remains open

### Proved in this run

- The explicit `2m+1` canonical quotient decomposition for the direct-sum gadget.
- The seven local transition types in the chosen public basis.
- An exact polynomial-time public histogram likelihood/MAP algorithm for
  `C=Theta(log lambda)`.
- Exact collision-free complete TV `(3/10)^C`.
- Coupling bound (6).
- A polynomial-size false family with inverse-polynomial public distinguishing
  advantage, equations (7)--(9).

### Implemented and actually executed

The standard-library checker:

- derives the local affine reference and kernel basis from the Run-38 gadget;
- verifies the canonical nullspace basis for `m=1..6`;
- constructs the full generic quotient and checks exact TV equality with the
  histogram DP for `m=1..4`, `C=1,2`;
- checks the mandatory/optional signed measures and their L1 norms exactly;
- computes exact finite convergence tables for `C=1..6`,
  `m=100,1000,10000`;
- computes the finite polynomial-family rows quoted above.

The final checker was executed twice and the captured JSON outputs were
byte-identical.

### Not proved

- A generic impossibility result for witness encryption.
- Insecurity of a different high-entropy correlated channel that does not reduce
  to this sparse direct-sum random walk.
- A completed generic-NP public offline PQ witness KEM.
- The still-required arbitrary-QPT early-key-recovery-to-source-witness or
  independently justified PQ-hardness reduction for any surviving construction.
- Malicious-secure setup composition and concrete end-to-end resource parameters
  for a surviving inner primitive.

## 9. Handoff

Run 38's surviving logarithmic notch walk is now rejected: its apparent
quasi-polynomial support does not prevent exact polynomial likelihood evaluation
on an explicit false direct-sum family, and the complete false-view advantage is
inverse-polynomial.

The next constructive attempt should therefore avoid sparse exchangeable walks
whose quotient likelihood collapses to a low-dimensional histogram DP.  A
credible surviving channel needs high entropy **and** a complete-view theorem or
reduction that survives polynomial direct sums, tensorization, symmetry
compression, and multimode aggregation.  Merely bounding every individual odd
Fourier mode is insufficient.
