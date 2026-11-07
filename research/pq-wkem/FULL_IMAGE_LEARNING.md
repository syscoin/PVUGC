# Full-image version of the known-sample boundary

**Research theorem only. No completed WKEM, deployment parameters, or generic
vector-key recovery theorem is claimed.** This extends `KNOWN_SAMPLE_BOUNDARY.md`.
No outside source was consulted and no priority claim is made.

## 1. Why source correlations need a separate argument

The sample-span lemma in the preceding note compares iid training and challenge
zero samples. A sender might instead correlate masking factors with its key or
with per-encapsulation public data. The iid lemma cannot silently be applied to
a different conditional challenge distribution.

For the specified rank encoder, however, the public numeric zero-ciphertext
core has the form F(theta), where theta lists all left/right/noise factors and
F is a public degree-two polynomial map. The following stronger result learns
the entire image span using independent synthetic factors. It does not require
the challenge's factor distribution to match that synthetic distribution.

## 2. Nonzero polynomial-function probability

Let f:F_q^v -> F_q be a nonzero polynomial function with a polynomial
representative of total degree at most delta. Reduce its exponents modulo
X_i^q-X_i; this does not increase total degree. The reduced representative has
each exponent at most q-1.

For uniform x,

    Pr[f(x)!=0] >= q^(-delta).

Proof: recursively choose the leading power d_i in each variable. On assignments
where its leading coefficient is nonzero, the polynomial is nonzero at at least
q-d_i choices of that variable. Induction gives a nonzero fraction at least
product_i(1-d_i/q). Each factor is at least q^(-d_i), and sum_i d_i<=delta. QED.

When q>delta, the usual elementary root-count induction also gives

    Pr[f(x)!=0] >= 1-delta/q.

Thus one may use

    alpha = max(q^(-delta), 1-delta/q).

The second term is harmless when nonpositive. For fixed delta, this gives a
constant lower bound uniform over field sizes: if q>2delta it exceeds 1/2;
otherwise q^(-delta)>=(2delta)^(-delta). For binary reduced polynomials the
more direct bound is 2^(-delta).

## 3. Learning the full image span

Let F:F_q^v -> F_q^m be public of coordinate degree at most c. Let Phi_d be the
S=binom(m+d,d) monomial feature map and put

    W = span{Phi_d(F(theta)): theta in F_q^v}.

Every linear functional lambda that is nonzero on W yields a nonzero polynomial
function lambda.Phi_d(F(theta)) of degree at most delta=c*d. Consequently a
uniform independent synthetic theta lies outside any proper current subspace
of W with probability at least alpha from Section 2.

Use S blocks of M independent samples, where

    M = ceil(log(S/epsilon)/alpha).

At the start of a block whose current span is not W, fix a separating linear
functional nonzero on W. A block with no rank increase has probability at most
(1-alpha)^M<=exp(-alpha*M). By a union bound, with probability at least
1-epsilon every non-full block increases dimension. There are at most S possible
increases, so the final learned span is exactly W.

This is a sufficient upper bound, not an optimized sample count. The event
'learned span equals W' covers *every* possible challenge factor choice,
including choices correlated with the key or selected adversarially after
training. A wrong message shift is still excluded only when the separating
polynomials assumed by the preceding theorem exist for the whole image F.

## 4. Consequence for the current rank-mask architecture

For a fixed legitimate source witness, all factor choices satisfy the rank-error
identity. The numerical core

    H(B)=sum_h L_h B R_h,
    P_i=H(B_i)+U E_i,
    C_zero=H(B0)+U E0

is a degree-two polynomial in its free masking-factor entries. For one scalar
key encoded as K*G, G nonsingular, rank error at most rho and t>=2rho+1, the
(rho+1)-minors supply separators. Take

    d=rho+1, delta=2(rho+1).

Full-image learning followed by the univariate gcd step recovers every scalar
key on the high-probability full-span event. Merely selecting these same factors
from a correlated seed or a PRG does not remove the public polynomial image or
its witness-dependent vanishing equations. The synthetic learner samples that
image directly without having to reproduce the sender's secret seed.

This conclusion is conditional on the precise publicly numeric representation
and its all-factor correctness identity. It must not be applied to encrypted
handles, a different nonalgebraic representation, unknown secret static data,
or a sampler whose challenge support is not contained in the public image.
Extra authenticated metadata need not be forged when the adversary uses only
the numerical core; metadata essential to changing that core would need separate
treatment.

The result is polynomial-time for fixed rho and polynomial-size numeric headers.
Its feature count can be enormous at concrete parameters or when rho grows.
Nothing here claims an efficient general solver for a vector payload's
multivariate equations, a break of ordinary false-instance WE, or impossibility
of PQ WE in general.

## 5. Exact small tests

Five local test groups passed:

- 2,320 nonzero binary reduced polynomials in selected degree/dimension ranges
  obeyed the nonzero-support lower bound.
- 1,378 nonzero reduced polynomials over F3/F5 obeyed both applicable bounds.
- Direct image-feature enumeration matched the learned span for a degree-two
  map over F2,F3,F5.
- A quadratic curve fixture recovered keys when challenge factors were
  deliberately concentrated on selected image points, after full-image training.
- A point-mass training negative control demonstrates why iid coverage alone
  does not cover an arbitrary other point of the image.

These validate the finite identities; the general proof is above. Counts are
not attack trials at cryptographic sizes and are not added to repeated earlier
runs. The requested efficient generic encoder and full-output hardness reduction
remain unconstructed.
