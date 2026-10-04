# Noisy witness-dual cover barrier

Starting checkpoint: PR #1 head
`c86485cd34ccf3c8b6dcef3eed3633ea33afd1c0`.

This continuation tests a natural post-quantum repair of the rejected exact
local-transfer tables: add LPN/LWE-shaped independent noise so that a genuine
witness is a short dual decoder while public quotient functionals are intended
to become too noisy.

The result is negative for the finite-cover transfer architecture.  The key
point is quantitative rather than merely algebraic: the saved false 2+3 cover
does not need a long public quotient.  It produces a target decoder with only a
constant-factor larger noise footprint than an honest witness.  For independent
additive character noise, its key bias is exactly the fifth power of the honest
bias.  Any inverse-polynomial honest bias therefore leaves inverse-polynomial
false-instance leakage.  For Gaussian/rounding decoding, a constant variance
factor likewise preserves high recovery probability whenever honest correctness
is driven high by an increasing decoding margin.

This does not rule out nonlinear/computational encodings whose false-cover
observable is not an additive combination of independently noised local tokens.

No external literature or web search was used.  Production code is unchanged.

## 1. Constructive attempt: noisy local transfer

Use the higher-locality cyclic transfer architecture from
`COVER_ORBIT_TELESCOPING.md`.  For each layer `i` and local state `s`, the exact
token was

    T_(i,s) = k_i + r_(i,s) - r_(i+1,tau_i(s))

in a finite abelian group G, with

    K = sum_i k_i.

A genuine fixed-point witness selects one token per layer and telescopes to K.

The repair tested here publishes a noised token

    Y_(i,s) = T_(i,s) + E_(i,s),                         (1)

where the noises are independent and identically distributed.  A witness uses
the same local path, obtaining

    K + Z_h,       Z_h = sum_i E_(i,s_i).                (2)

One then applies either:

* an additive character/parity decoder, as in LPN-shaped capsules; or
* q-ary/real reconciliation or rounding, as in LWE-shaped capsules.

The intended benefit is that a generic public linear functional could amplify
noise while a true witness has only n noise terms.

The complete-output question is whether the false finite covers from the exact
construction still have a comparably short decoder.

## 2. Exact character theorem on the 2+3 false cover

Use the false five-state monodromy

    pi = (0 1)(2 3 4),

which has no fixed state and hence no source witness.

Let O_2 and O_3 be the two monodromy orbits.  Summing all n-layer laps starting
from states in O_h gives, in the noiseless table,

    h K.

With the noised tokens, define

    A_2 = 2K + Z_2,
    A_3 = 3K + Z_3,

where Z_2 contains exactly 2n independent local noises and Z_3 contains exactly
3n independent local noises.  The two sets of token positions are disjoint.

The public false-instance estimator is

    A_f = A_3 - A_2 = K + Z_f,                           (3)

with

    Z_f = Z_3 - Z_2,                                    (4)

using exactly 5n independent noise positions with coefficients +1 or -1.

Let chi be any unit-modulus character of G, and put

    eta = | E[chi(E)] |.

For any distribution of E,

    E[chi(-E)] = conjugate(E[chi(E)]),

so the sign of a coefficient does not change the magnitude.

For an honest n-token path,

    gamma_h
      := | E[chi(Z_h)] |
       = eta^n.                                         (5)

For the false 2+3 estimator,

    gamma_f
      := | E[chi(Z_f)] |
       = eta^(5n)
       = gamma_h^5.                                     (6)

This equality is exact.

### Consequence for binary/parity key encoding

Suppose a key bit changes the relevant decoded character by a sign.  One noisy
honest observation then has prediction advantage gamma_h/2, while the false
2+3 cover has advantage gamma_h^5/2.

If the honest channel is intended to be polynomially amplifiable, gamma_h must
be nonnegligible.  More concretely, if for some fixed a

    gamma_h >= lambda^(-a),

then the false statement has the explicit public advantage

    gamma_f/2 >= (1/2) lambda^(-5a),                    (7)

which is still nonnegligible in the cryptographic sense.

Thus adding iid LPN-shaped noise does not convert the false cover into a hiding
distribution.  It changes an honest inverse-polynomial bias only into a fixed
power of that same bias.

If a construction supplies R=poly(lambda) independent replicas and chooses
gamma_h only large enough for majority/reconciliation, the conclusion is
unchanged: a fixed power of an inverse polynomial remains inverse polynomial.
No claim is needed about the optimal false-instance decoder; (3) itself is an
explicit polynomial-time distinguisher.

## 3. N-of-N setup roots do not change the exponent relation

Suppose N setup operators independently contribute local noise distributions
with per-token character magnitudes eta_j.  The honest combined-share character
magnitude is

    Gamma_h = product_j eta_j^n.                         (8)

On the same public 2+3 cover, each operator's local noise footprint is multiplied
by five, so

    Gamma_f
      = product_j eta_j^(5n)
      = Gamma_h^5.                                      (9)

Therefore N-of-N XOR/additive roots, by themselves, do not repair this inner
architecture.  They remain useful for malicious-setup composition once a sound
inner capsule exists, as proved in the earlier ceremony checkpoint; they do not
turn this noisy local-transfer capsule into one.

The same observation applies to polynomial t-of-X reliability replication:
replication can amplify an honest nonnegligible bias, but the false cover retains
a fixed-power nonnegligible bias.

## 4. Gaussian / rounding version

For an LWE-shaped control, take real iid Gaussian token noise

    E ~ N(0, sigma^2).

An honest n-token sum has

    Z_h ~ N(0, n sigma^2),

while (4) has

    Z_f ~ N(0, 5 n sigma^2).                             (10)

Encode two key symbols at centers separated by Delta and decode by nearest
center.  Put

    t = Delta / (2 sigma sqrt(n)).

Then the exact honest and false single-symbol correctness probabilities are

    P_h = erf(t / sqrt(2)),                              (11)
    P_f = erf(t / sqrt(10)).                             (12)

(up to the conventional wraparound qualification if one embeds this in Z_q).

The important asymptotic fact is immediate:

    if t(lambda) -> infinity, then both P_h and P_f -> 1. (13)

So parameterizing the honest witness for vanishing Gaussian rounding failure
does not make the constant-cover estimator hide the key.  It merely reduces the
false estimator's standardized margin by sqrt(5).

For example, at honest standardized half-distance t=6,

    P_h = 0.9999999980268247...
    P_f = 0.9927096...

and at t=sqrt(128),

    P_h is effectively 1 at double precision,
    P_f > 0.9999995.

The exact values are captured by the checker.

This is not a theorem about every LWE KEM.  It is a theorem about this specific
witness-dual local-transfer use of additive noise, where the false cover gives
the same signal with only five times as many independent local noise terms.

## 5. Why quotient-noise hardness does not rescue this architecture

The reason to try (1) was legitimate: a public quotient functional obtained by
generic Gaussian elimination can have large coefficients and therefore may be
too noisy to decode.

The finite-cover attack is different.  It uses only coefficients +1 and -1 and
only five honest-lap footprints.  It therefore avoids the hoped-for "long public
quotient" hardness entirely.

This distinguishes two statements:

* `there exists a public annihilator` is not automatically a break once noise is
  present; its norm matters;
* but this local-transfer architecture has a **specific short false annihilator**
  on the 2+3 cover, with constant norm/support blowup.

The second fact is what rejects the candidate.

## 6. Relation to native encryption vs. source-witness transfer

This candidate is a native noisy encryption channel.  Even if its ambient
quotient decoding problem were independently LWE/SIS-like, the 2+3 false cover
produces a special public decoder before any hardness assumption is invoked.

Therefore one cannot reduce arbitrary early key recovery to generic lattice
hardness for this construction: there is already an explicit false-instance
recovery statistic that uses no source witness and no lattice break.

This is the same methodological distinction maintained throughout the record:
native encryption hardness is not enough unless the complete public output
excludes semantic pseudowitnesses.

## 7. Validation actually executed

`noisy_cover_check.py` uses only the Python standard library.  It performs:

* 500 explicit noisy transfer-table trials over Z_101 verifying that the
  two- and three-orbit sums are exactly `2K+Z_2`, `3K+Z_3`, and their public
  difference is `K+Z_3-Z_2`;
* exact rational enumeration of the binary-noise character law on an honest
  two-token path and the ten-token 2+3 cover at p=1/4;
* exact verification that the false character bias is the fifth power of the
  honest bias;
* 1,000 random rational parameter checks of
  `(eta^n)^5 == eta^(5n)`;
* 500 random multi-operator checks of
  `(product eta_j^n)^5 == product eta_j^(5n)`;
* analytic Gaussian correctness values for several standardized margins;
* a fixed-seed Monte Carlo control with 200,000 honest and false Gaussian
  aggregate samples at n=64 and t=3, compared against the analytic formulas.

These checks validate the finite probability identities and the implementation.
They are not a security proof for any surviving construction.

## 8. Current boundary

Proved in this pass:

* the noisy 2+3 false cover has exact character bias `gamma_h^5`;
* any inverse-polynomial honest character bias leaves inverse-polynomial
  false-instance leakage;
* independent N-of-N operator noise preserves the same fifth-power relation;
* Gaussian/rounding noise suffers only a constant sqrt(5) SNR loss on the false
  estimator, so increasing the honest decoding margin also makes the false
  estimator reliable.

Rejected candidate:

* iid additive-noise hardening of the finite-local-state telescoping/witness-dual
  transfer architecture.

Still unresolved:

* a nonlinear or computationally hidden consistency mechanism for which a false
  finite cover does not induce a same-key observable with constant blowup;
* or a different inner PQ construction whose complete-output recovery reduces to
  source-witness extraction or an independently justified PQ assumption;
* end-to-end parameters and malicious-secure ceremony resource estimates after
  such an inner construction exists.

The stopping condition is not met.
