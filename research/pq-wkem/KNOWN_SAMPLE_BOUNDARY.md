# Public known-encapsulation samples and low-degree decryption

**Status: a scoped mathematical boundary and local validation, not a secure WKEM.**

This continuation starts from PR #1 at
`f7fecab3205c68c403ff5bed458e24be54c728cd`. Its public numeric rank-capsule
interface is recorded in `QUOTIENT_AND_PROBE.md`. No outside paper was fetched.
No literature-priority claim is made. All executable experiments used synthetic
small-field fixtures, not a deployed system or another party's ciphertext.

The previous cover compression was affine in its complete mask tape. Here the
mask sampler may be arbitrarily nonlinear. The question is whether *decryption
identities* can be learned from public, known-key encapsulations. A sender can
sample another ciphertext and retain its own key. That does not supply the key
of the independent challenge.

## 1. Distribution-free sample-span lemma

Let z_1,...,z_T,z be independent samples from any distribution on a finite
field vector space. Let s be the dimension of the span of its support. Then

    Pr[z not in span(z_1,...,z_T)] <= s/(T+1).

Proof: among any T+1 vectors, at most s are indispensable (outside the span of
all the others), since indispensable vectors are linearly independent. The
positions are exchangeable. The last is indispensable exactly on the event
in the statement. QED.

The probability averages over both the training set and the fresh sample. It
is not a uniform guarantee for every realized training set. No lower bound on
individual sample probabilities or uniformity of the source is assumed.

## 2. Scalar affine-key embedding with low-degree separators

Let Y be publicly samplable in F_q^m and let e be public. Encapsulation produces

    ct = Y + K e,  K <- F_q.

The sampler for Y need not be affine, uniform, or publicly invertible. Known-key
encapsulations give independent Y samples by subtracting their own known key
shifts. The challenge key is not given to the learner.

For this fixed true instance, suppose there exist polynomials f_i of degree at
most d with both properties:

1. Every f_i vanishes on the support of Y.
2. For every support point y and every nonzero c in F_q, at least one f_i(y+c e)
   is nonzero.

The polynomials can depend on a witness unknown to the learner. Let Phi_d list
all monomials of total degree at most d, including 1. There are

    S = binom(m+d,d)

features. From T known-zero samples form V=span{Phi_d(Y_j)}.

Every incorrect candidate k has Phi_d(ct-k e) outside V: one of the unknown
polynomials annihilates the entire zero-sample feature span but not this wrong
shift. The correct candidate belongs to V with probability at least

    1 - S/(T+1).

This follows directly from the sample-span lemma.

### Recover the scalar without enumerating the field

Compute a basis lambda_i of the annihilator of V. Substitute the public key line:

    g_i(Z) = lambda_i . Phi_d(ct-Z e).

These are univariate polynomials of degree at most d. Compute their greatest
common divisor g and then

    h = gcd(g, Z^q-Z).

Compute the second gcd using modular polynomial exponentiation in O(log q)
steps, not a length-q coefficient array or a scan over q keys. On the coverage
event, h=Z-K. Otherwise the algorithm can return failure. The two separation
properties ensure that a certified field root cannot be an incorrect key.
Identically zero equations and repeated roots must be handled explicitly.

With T=ceil(S/epsilon), the work is polynomial in S,m,d,log q,1/epsilon and success
is at least 1-epsilon. For fixed d and polynomial m this is a polynomial-time
algorithm. Growing d can make S exponential; no efficient general claim is made
in that regime.

If the source satisfies the separation/rank premise except with probability
at most delta per independent sample, a conservative coupling gives failure at
most

    S/(T+1) + (T+1)delta.

Changing uniform source coins to PRG-derived coins does not alone evade a
statement quantified over arbitrary samplable source distributions.

## 3. Application to one-base-field-scalar rank capsules

Suppose the numeric header is

    P_i=H(B_i)+noise_i,
    C=K G+H(B0)+noise_0,

where G is a public nonsingular t-by-t matrix. For some legitimate witness sigma,
suppose every zero-message sample satisfies

    rank(C+sum_i sigma_i P_i) <= rho,

and t>=2rho+1. This is the usual honest low-rank decoding condition.

Use all (rho+1)-minors of C+sum sigma_i P_i as the unknown separating polynomials.
They have degree rho+1 and vanish on the zero-message distribution. For c!=0,

    rank(E+cG) >= t-rank(E) >= rho+1,

so at least one such minor is nonzero. Section 2 applies with

    d=rho+1, m=(number of header matrices)*t^2.

No source witness, projection factor, error support, or target pad is given to
the learner. Fresh masks on every encryption do not prevent public training.
Authenticating the header does not prevent local sampling of its publicly
specified numeric core. A model with unavailable secret static sampling
parameters would need a separate analysis and is not silently included here.

### Scope: extraction, not an ordinary-WE impossibility

This is recovery on true instances. Ordinary WE requires privacy on false
instances only, so true-instance recovery is not by itself an ordinary-WE break.
It is relevant to the stronger requested early-release/extraction property.

For a universal fixed-rho, polynomial-size construction of this shape, combining
this public recovery algorithm with a uniform polynomial-time extractor that
actually finds a witness would give a witness-search algorithm. For relations
f(w)=x generated from a quantum-secure one-way function, that would contradict
one-wayness. This consequence concerns the specified challenge-extraction model;
it does not say that a ciphertext and key should admit public extraction in
every formulation.

This does not rule out growing rank, vector payloads, nonalgebraic decoding,
other mask models, AADP with circuit-growing degree, or generic computational WE.
Feature counts are running-time bounds for this algorithm, not lower bounds
against all other attacks or a certified concrete security level.

## 4. Vector keys remain a separate problem

For a base-field vector a and public shifts e_j, the same training gives

    lambda_i . Phi_d(ct-sum_j a_j e_j)=0.

These are multivariate equations. Unique finite-field solvability does not prove
efficient solvability. Nor has this particular system been reduced to an
independently random MQ instance. A single extension-field key represented by
several base-field coordinates is a vector case, not automatically Section 2.

The local sufficient test treats higher-degree key monomials as unrelated
unknowns, solves the relaxed linear system, and returns a key only when every
linear coordinate is forced and actual feature membership verifies. Unresolved
cases are not declared secure. Reduction modulo X^p-X is used only as an exact
function identity in the small prime-field fixtures, not as a complexity shortcut
for an arbitrary number of key coordinates.

## 5. Local validation record

The full code and captured results are preserved in the conversation artifact
`wkem_degree_learning_continuation`; this file records their scope, not a claim
that those local files have been committed by this documentation write.

- A saved n=2,D=3 compiler for Boolean x*y=0 has three valid witnesses. Its affine
  origin was shifted to rank three, so coefficient zero is not a valid witness.
- Over F17 and F257, 550 known-zero training samples per field gave 24/24 fresh
  scalar-key recoveries. Each header has 27 field coordinates and 406 quadratic
  features. The quadratic span dimension was 379. The linear feature span was
  full (dimension 28) in both cases, so this is not the earlier affine separator.
- All 72 independent witness/error-rank correctness checks passed.
- Exhaustive outer-product controls recovered 128/128 F2 and 2,187/2,187 F3
  masked scalar-message cases. These are synthetic algebra controls.
- A three-bit F8 multiplication-code fixture had learned feature dimension 352
  after 1,200 training samples. Sufficient linearization recovered 47/48 fresh
  keys; one was unresolved and no wrong key was returned. Enumeration of the
  eight keys independently checked uniqueness only; it is not part of recovery.
- Nine independent test groups passed. They cover nullspaces, symbolic scalar
  and vector translations, repeated roots, small-field function reduction, 280
  exact finite-distribution sample-span checks, an arbitrary nonlinear curve
  sampler, insufficient-training failures, full-support negative controls, and
  sufficient vector linearization.

The tests use fixed-seed RNGs and small fields. They are not cryptographic
parameters, PQ attack-cost estimates, end-to-end bridge tests, or a proof of the
unresolved vector-key case.

## 6. Uncompleted construction

No efficient generic PQ WKEM, full-output hardness reduction, adversary-based
early-release extractor, or malicious-secure distributed setup is supplied.
This result identifies a condition the encoder must avoid: public known-key
samples must not make its witness-dependent bounded-degree decryption relations
sufficient to recover fresh keys efficiently.

Raising a parameter, using many coordinates, adding outliers, or finding a test
inapplicable is not a security proof. Any proposed replacement still needs actual
algorithms, honest correctness, a full-public-output reduction and practical
parameters. The research PR remains draft and must not be treated as production
protection.
