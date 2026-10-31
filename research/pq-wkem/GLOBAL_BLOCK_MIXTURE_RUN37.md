# Run 37 — global block-mixture noise: constant Gap-OHLC spectral gap, polynomial-support complete-view break, and the logarithmic-walk boundary

## Status

This run starts from PR head `c0876497e8a3aeff80815c42415e8c94382021b7` and the already-recorded Run-36 product-noise barrier plus the earlier `BINARY_PROJECTIVE_GAP.md` interface.  It uses no external literature or web search.

It does **not** construct a completed witness KEM.  It establishes three scoped facts:

1. a genuinely correlated global noise step can exploit the Gap-OHLC constant violation gap without the `Theta(B)` product attenuation that killed the Run-36 scalar route;
2. the one-step / any polynomial-support version is nevertheless broken at the complete-public-view level by exact public likelihood computation;
3. convolving `T = Theta(log lambda)` global steps is a real surviving *interface-level* direction: honest fixed-mode bias remains inverse-polynomial while every fixed false Gap-OHLC mode gets a strictly worse polynomial exponent, and the trivial support enumerator becomes super-polynomial.  But the complete-view problem then becomes structured low-weight syndrome decoding in the statement-derived quotient.  No reduction from that structured problem to an independently justified PQ assumption is supplied here, so this is not a security claim.

The point of this run is to separate a real constructive spectral improvement from the stronger generic-NP security obligation.

## 1. Channel

Work over `F_2`.  Use the binary local-state OHLC/Gap-OHLC compiler.  There are `G` local-test blocks, each with `L` coordinates.  For a genuine accepting local state the test block has Hamming weight one.  On a failed local test every admissible local block has Hamming weight at least three.  If a false proof fails at least `nu >= delta G` tests, every corresponding projective frequency has test-block weight

```
w_test >= G + 2 nu >= (1 + 2 delta) G.
```

Ignore proof-variable coordinates for this noise layer.  One **global block-mixture step** samples noise `E` as follows:

```
with probability 1-p: E = 0;
with probability p: choose one of the G*L test coordinates uniformly and flip it.
```

This is correlated globally: at most one test coordinate is noisy in a step.  It is not iid coordinate noise.

For a frequency `z`, let `w = wt(z_test)`.  Its exact Fourier coefficient is

```
Phi_1(z) = E[(-1)^(z.E)]
         = 1 - 2 p w/(G L).                         (1)
```

Therefore an honest one-hot proof has

```
a := Phi_H = 1 - 2p/L,                              (2)
```

while every false Gap-OHLC mode with violation fraction at least `delta` has

```
Phi_F <= b := 1 - (2p/L)(1 + 2delta),                (3)
```

as long as the relevant coefficients stay in the nonnegative range when one wants a magnitude bound without sign bookkeeping.

This is a genuine constant raw separation.  Unlike product noise, honest bias does not contain a factor raised to `G`.

A particularly clean binary example is `L=4`, `p=1/2`, `delta=1/4`:

```
a = 3/4,
b = 5/8.
```

The checker exhaustively verifies (1) on small blocks and verifies the honest/false values above exactly with rational arithmetic.

## 2. Complete-output attack for polynomial-support noise

The fixed-mode result is not security.  Consider the generic public additive capsule

```
X = U_R + K Delta + E,
```

where

* `R` is a public linear subspace of `F_2^N` (the row-space mask),
* `U_R` is uniform on `R`,
* `Delta` is the public key-shift vector,
* `K in {0,1}` is uniform,
* `E` is independent noise with public distribution `mu`.

Suppose `supp(mu)=S` has polynomial size and each `mu(e)` is efficiently computable.  Then for every observed `x` and candidate key `k`,

```
Pr[X=x | K=k]
  = (1/|R|) * sum_{e in S} mu(e) * 1[x-k Delta-e in R].       (4)
```

Public Gaussian elimination gives a polynomial-time membership test for `R`.  Thus (4) is exactly computable in polynomial time by enumerating `S`.  Comparing the two values gives the public MAP key decoder.

This is stronger than finding one projective relation.  It audits the whole public output distribution.  By Bayes optimality its success is at least that of every fixed witness decoder on the same capsule distribution.  Therefore a polynomial-support noise layer cannot provide witness-only key recovery in this public linear-mask architecture.

For one global block-mixture step,

```
|S| <= 1 + G L,
```

so the attack is polynomial.

The checker includes an exact `F_2^8` fixture.  A designated witness character decodes with success `7/8`, while the public exact-likelihood decoder succeeds with probability `1` on one fixture (and equals `7/8` on a second control).  These are finite validation fixtures for (4), not security experiments.

## 3. T-step convolution is a nontrivial boundary, not a completed repair

Convolve `T` independent global block-mixture steps.  Fourier coefficients multiply:

```
Phi_T(z) = Phi_1(z)^T.                               (5)
```

Hence

```
honest fixed-mode bias = a^T,
false fixed-mode bias <= b^T.                        (6)
```

For `L=4`, `p=1/2`, `delta=1/4`, `a=3/4` and `b=5/8`.  If

```
T = c log_2(lambda),
```

then

```
a^T = lambda^(-c log_2(4/3)),
b^T = lambda^(-c log_2(8/5)).
```

Both are inverse-polynomial, but the false exponent is strictly larger.  A fixed false mode therefore loses polynomially more signal than an honest witness.  This is the first route in the current sequence that simultaneously:

* avoids the Run-36 `Theta(B)` product attenuation,
* uses a genuine constant-fraction Gap-OHLC semantic gap,
* and can make the trivial explicit-seed support `(1+GL)^T` super-polynomial while retaining polynomial honest amplification.

That is substantive progress at the **fixed-mode channel** level.

It is still not a generic-NP WKEM.

### 3.1 Why the support enumerator no longer proves a QPT break

For constant `T`, `(1+GL)^T` is polynomial and Section 2 applies directly.  For `T=Theta(log lambda)` and polynomial `G,L`, direct seed enumeration costs

```
(1+GL)^T = 2^{Theta((log lambda)^2)},
```

which is super-polynomial.  The resulting error has Hamming weight at most `T`; after quotienting by the public row space, exact key likelihood is a low-weight syndrome-distribution problem.

This observation is only a boundary.  This run does **not** assume that low-weight syndrome decoding for the statement-derived quotient is PQ-hard.  The quotient is highly structured by the public source compiler, and no reduction to random syndrome decoding/LPN/LWE or another independently justified assumption is given.

### 3.2 Complete Fourier mass still is not controlled

Gap-OHLC bounds every false mode's minimum local-test weight, but there may be exponentially many modes.  Equation (6) is a per-mode statement.  It does not imply that the complete odd Fourier mass, total variation, accessible quantum information, or arbitrary-QPT key-recovery advantage is negligible.

Indeed, applying the crude Parseval/union-style proof to exponentially many proof modes would force `T` to grow proportionally to the proof dimension in the worst case, at which point `a^T` is exponentially small and honest polynomial amplification is lost.  This does not prove the actual distribution insecure; it proves that minimum gap plus a fixed-mode bound is not the missing complete-view theorem.

## 4. What this does and does not establish

### Proved

* Exact one-step spectrum (1).
* Constant honest/false fixed-mode gap (2)-(3) for Gap-OHLC.
* Exact public likelihood formula (4) and polynomial-time MAP attack for polynomial-size noise support.
* Multiplicative T-step spectrum (5)-(6).
* Constant `T` is therefore dead in this architecture; `T=Theta(log lambda)` escapes only that trivial enumerator while retaining inverse-polynomial honest fixed-mode bias.

### Implemented / tested

The accompanying standard-library checker:

* exhaustively verifies the one-step Fourier identity on small block systems;
* checks the Gap-OHLC weight-to-bias formula with exact `Fraction` arithmetic;
* enumerates the complete `F_2^8` capsule distributions in two public-row-space fixtures and checks the exact MAP/witness success values;
* verifies T-step convolution against direct distribution convolution in small systems;
* emits exponent/resource tables for logarithmic `T`.

### Not proved

* False-statement complete-view hiding for logarithmic `T`.
* Hardness of the resulting statement-derived low-weight syndrome problem.
* Any reduction from arbitrary QPT early key recovery to a source witness or an independent PQ-hardness break.
* A concrete Gap-OHLC/PCP instantiation and end-to-end practical parameters.
* Malicious-secure ceremony composition for a surviving inner primitive.

## 5. Handoff

The useful surviving target is narrower than after Run 36.  A correlated global noise layer **can** turn a constant Gap-OHLC semantic violation fraction into a constant fixed-mode spectral gap without paying honest cost per test.  But low-entropy versions are publicly likelihood-decodable, while the logarithmic-walk version moves the problem into a structured low-weight syndrome distribution whose hardness has not been independently justified and whose complete Fourier mass is still uncontrolled.

A next successful step would need one of:

1. a reduction showing the logarithmic-walk quotient distribution is hard for arbitrary QPT adversaries under an independently justified PQ assumption despite the source-derived structure; or
2. a different high-entropy correlated channel for which the *entire* false quotient distribution, not only each fixed mode, has a polynomially checkable hiding bound while every valid source witness retains polynomial decapsulation probability.

Neither is supplied here, so the stopping condition is not met.
