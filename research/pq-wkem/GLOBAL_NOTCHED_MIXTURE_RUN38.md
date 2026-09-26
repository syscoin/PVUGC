# Run 38 — notched global mixture: a stronger Gap-OHLC filter, complete-view finite controls, and the true-source MAP composition barrier

## Status

Starting verified PR head: `5c0398955fe33cbc1f17ba8f7ace0a4c1f33ce82` (Run 37).

This run uses only the existing repository record, original derivation, and local
standard-library computation.  It does **not** complete a generic PQ witness KEM.

The constructive attempt is a two-step **notched global block-mixture** channel.
It improves Run 37's fixed-mode Gap-OHLC separation and has encouraging exact
complete-view behavior on small false instances.  The same run then proves why
every constant-step / polynomial-support version still fails the *source-witness
transfer* requirement on true statements: its exact public MAP decoder can be
composed with the already-recorded reconciliation layer and recovers the raw
source at least as reliably as the witness channel.

That distinction is important.  A weak raw capsule may be statistically useful
on false statements and still be unusable as a witness KEM because a public
true-statement decoder exists.

## 1. Two-step notched channel

Work over `F_2` with the Run-37 binary Gap-OHLC local-test blocks of size `L=4`.
For a projective/odd mode let `r` be the fraction of local tests on which its
local block has weight three rather than weight one.  One global coordinate
mixture step with activation probability `p` has exact Fourier coefficient

```
phi_p(r)
  = 1 - (p/2) (1 + 2r).
```

This is the Run-37 identity written directly in terms of the violation fraction.

Now convolve two independent steps with

```
p1 = 1,
p2 = 4/5.
```

The resulting coefficient is

```
psi(r)
 = phi_1(r) phi_(4/5)(r)
 = (1/2-r)(3/5-4r/5)
 = (4/5)r^2 - r + 3/10.                       (1)
```

A genuine accepting one-hot witness has `r=0`, hence

```
psi(0) = 3/10.                                 (2)
```

For a Gap-OHLC false mode with `r >= 1/4`,

```
|psi(r)| <= 1/10  for every r in [1/4,1].       (3)
```

The bound is exact.  The roots are `1/2` and `3/4`; the unique interior vertex
is `r=5/8` where `psi=-1/80`; and the endpoint values at `1/4` and `1` are both
`1/10`.  Thus this cycle gives a factor-three fixed-mode separation:

```
honest bias             = 3/10,
every false fixed mode <= 1/10 in magnitude.   (4)
```

This is stronger than simply repeating the Run-37 `p=1/2` step.

If the cycle is repeated `C` times independently,

```
honest fixed-mode bias = (3/10)^C,
false fixed-mode bias <= (1/10)^C.              (5)
```

For `C=c log_2(lambda)`, these become respectively

```
lambda^(-c log2(10/3)),
lambda^(-c log2(10)),
```

with ratio `lambda^(-c log2 3)`.

This is only a fixed-mode statement.  It is not a complete-output hiding proof.

## 2. Exact complete-view quotient calculation

For a public linear-mask capsule

```
Y = U_R + B Delta + E
```

over `F_2^N`, quotient by the public mask subspace `R`.  A basis of `R^perp`
identifies a finite quotient group.  The complete key-conditioned distributions
are then just the quotient distribution of `E` and its translate by the quotient
of `Delta`.

The checker constructs that quotient exactly for the binary local-state compiler,
convolves the two steps with rational arithmetic, and computes

```
TV(P0,P1)
 = (1/2) sum_y |P0(y)-P1(y)|.                   (6)
```

It also computes every odd character coefficient where the quotient is small
enough.  Therefore the finite results below are complete-public-view results,
not prescribed-decoder experiments.

### 2.1 Explicit multimode controls

For the false two-proof-bit predicate tuple

```
(1,2,4)
```

(the three tests accept only `00`, only `01`, and only `10`), every source
assignment fails at least `2/3` of the tests.  The quotient has dimension three.
One notch cycle gives

```
complete TV             = 1/10,
complete MAP success    = 11/20,
largest odd coefficient = 1/10.
```

For the false tuple

```
(1,2,7,7)
```

the source gap is `1/4`, the quotient again has dimension three, and

```
complete TV             = 3/20,
complete MAP success    = 23/40,
largest odd coefficient = 1/10.                 (7)
```

Equation (7) is a useful warning: the complete view is strictly stronger than
the best individual false mode.  A fixed-mode theorem alone is not a
complete-view theorem.

### 2.2 Exhaustive small census

The checker exhausts every tuple of `G=2,3,4` nonconstant two-input predicates
(mask values `1..14`) whose source gap is at least `1/4`.

There are exactly

```
30,874 qualifying false instances.
```

Of those:

```
7,194 have no odd affine quotient mode and therefore perfect raw-bit hiding;
23,680 have a nontrivial odd quotient mode.
```

Across all 23,680 nontrivial cases, one notch cycle has worst exact complete TV

```
3/20,
```

hence worst exact public raw-bit MAP success

```
23/40 = 0.575.
```

The quotient dimensions in that nontrivial census are 3, 4, or 5.

This is an exhaustive finite census, **not** a theorem for arbitrary Gap-OHLC
instances.

A separate deterministic four-proof-bit/eight-test stress fixture has source gap
`1/4`, quotient dimension five, and

```
complete TV          = 29/160,
complete MAP success = 189/320.
```

That exceeds the small shared-query census bound `3/20`, demonstrating why the
census must not be promoted into a universal security claim.

## 3. Polynomial-support exact MAP theorem

The constant-step construction still has a fatal property for the desired
source-witness KEM.

Let `E` have public support `S` and publicly computable probabilities `mu(e)`.
For every observed `y` and raw bit `b`,

```
Pr[Y=y | B=b]
 = |R|^-1 sum_(e in S) mu(e)
     1[ y - b Delta - e in R ].                  (8)
```

Membership in public `R` is polynomial-time Gaussian elimination.  Therefore if
`|S|` is polynomial, both likelihoods in (8), and hence the exact MAP raw-bit
decoder, are polynomial-time public algorithms.

For one two-step notch cycle the support is at most quadratic in the number of
test coordinates, so (8) is polynomial time.

This by itself does **not** mean a weak false raw bit cannot later be privacy
amplified.  Run 9 already proved a weak-to-strong outer layer.  The real fatal
point is the *true-statement* source-transfer requirement.

## 4. True-source MAP composition barrier

Fix a true statement and a valid witness `w`.  Let a witness raw-bit decoder
have correctness

```
Pr[D_w(Y)=B] >= h.
```

The public MAP decoder from (8) is Bayes optimal, so

```
Pr[MAP(Y)=B] >= h.                              (9)
```

Now independently repeat the raw capsule, exactly as required by the recorded
reconciliation/privacy-amplification wrapper.  Conditioned on fixed public setup,
independent raw bits and independent capsule randomness make the per-capsule MAP
error indicators independent.  For a bounded-distance reconciliation code whose
guaranteed success event is "at most t raw errors", replacing witness estimates
with MAP estimates having no larger error probabilities cannot reduce that
success probability.

The same conclusion applies to the recorded RS syndrome wrapper after grouping
bits into symbols: independently lower per-bit error probabilities give no
larger symbol error probabilities, and the RS guaranteed event is again a
bounded number of symbol errors.

Once the public attacker reconstructs the exact raw source `X`, the final
2-universal hash is public, so it also reconstructs the final key.

Therefore:

> A polynomial-support inner capsule with a public exact MAP decoder cannot be
> turned into the required source-witness KEM by the existing independent
> reconciliation/privacy-amplification wrapper whenever the wrapper obtains its
> honest completeness solely from those raw capsule estimates.

This is a **source-witness transfer** failure, not a claim that the false raw
capsule lacks native weak encryption.

### 4.1 Exact true-instance controls

The checker contains two true source fixtures for one notch cycle.

For a one-test singleton-accept predicate (`mask=1`),

```
intended witness raw success = 13/20,
public complete MAP success  = 13/20.
```

For a one-test singleton-reject predicate (`mask=7`),

```
intended witness raw success = 13/20,
public complete MAP success  = 7/10.
```

So public decoding is respectively equal to and strictly better than the
intended witness decoder.

As a tiny bounded-distance outer control, use an odd-length repetition-coset
secure sketch.  At lengths 7, 15, and 31, the public MAP estimates recover the
raw source with exactly the same outer success as the witness in the first
fixture, and strictly greater success in the second.  These finite controls
validate the composition logic; the theorem follows from Bayes optimality and
independence, not from the experiments.

## 5. What survives: logarithmically many notch cycles

The preceding MAP theorem kills **constant-step / polynomial-support** versions.

Repeating the notch cycle `C=Theta(log lambda)` times makes direct support
enumeration cost

```
[N(N+1)]^C = 2^{Theta((log lambda)^2)}
```

when the number of test coordinates `N` is polynomial in `lambda`.  At the same
time (5) preserves inverse-polynomial honest fixed-mode bias and gives a stronger
false fixed-mode exponent.

For example, after three cycles,

```
honest fixed bias       = 27/1000,
false fixed bias bound <= 1/1000,
1 / honest_bias^2       ~= 1372.
```

These are channel/resource calculations, not a secure parameter set.

The logarithmic version therefore survives **only** the explicit support
enumerator.  Its complete true/false view is a structured low-weight-syndrome
random-walk problem derived from the source statement.  No reduction to LPN,
LWE, random syndrome decoding, SIS, or another independently justified PQ
assumption is proved here.  Naming that structured problem as an assumption
would violate the research requirement.

## 6. Claims classified

### Proved

* Exact notch-cycle coefficient (1).
* Honest coefficient (2).
* Uniform fixed-false bound (3) for violation fraction at least `1/4`.
* Exact finite-support likelihood formula (8).
* Polynomial-time exact MAP for polynomial support.
* Bayes-optimal true-source composition barrier (9) for the independent
  bounded-distance reconciliation wrapper.
* Logarithmic repetition formulas (5).

### Implemented / actually tested locally

The standard-library checker:

* verifies the notch polynomial with exact rational arithmetic on 6,266 rational
  violation points plus the exact roots/vertex/endpoints;
* exhausts all 30,874 small false predicate tuples described above;
* computes complete quotient distributions and TVs, not only fixed characters;
* checks the explicit larger four-bit/eight-test stress fixture;
* checks the two true-source MAP controls;
* checks bounded-distance outer composition at lengths 7, 15, and 31;
* emits the logarithmic-cycle resource table.

The final checker was run twice locally; the captured JSON was byte-identical.

### Not proved

* Any universal complete-view bound for arbitrary false Gap-OHLC instances under
  the logarithmic notch walk.
* Hardness of its structured syndrome distribution for arbitrary QPT attackers.
* Conversion of arbitrary true-statement final-key recovery into a source witness
  or an independently justified PQ-hardness break.
* A concrete audited PCP/Gap-OHLC with end-to-end constants.
* Malicious-secure distributed ceremony composition for a surviving inner
  primitive.
* Practical completed generic-NP PQ witness KEM.

## 7. Handoff

The useful outcome is a sharper split.

The notch filter is a real improvement to the Run-37 *fixed-mode* channel and
has encouraging exact complete-view behavior on finite false fixtures.  But
because one cycle has polynomial support, its public MAP decoder transfers the
same raw information to an unauthorized party on true statements; the existing
outer reconciliation then amplifies the attacker along with the witness.

The next credible inner candidate must therefore have both:

1. enough entropy/computational hiding that exact raw-bit likelihood is not
   publicly computable in polynomial time on true statements; and
2. a complete-view reduction showing that any QPT algorithm which nevertheless
   recovers the final key either yields a source witness or breaks an independently
   justified PQ assumption.

The logarithmic notch walk is a concrete candidate interface for (1), with a
better fixed-mode exponent than Run 37, but (2) remains completely open.
