# QPT Fourier extraction and first-odd-harmonic target filtering

## Status

This continuation starts from the exact native/projective duality already recorded
in `NATIVE_PROJECTIVE_DUALITY.md`.  It closes one narrower reduction gap: an
arbitrary QPT key predictor need not itself output a projective preimage, but its
prediction bias can nevertheless be converted into a sample from the squared
Fourier spectrum of that bias.  Combined with the exact capsule character law,
this gives a quantitative route from key prediction to a projective mode when
the nonextractable spectral tail is small.

A second construction changes only the target-coordinate noise so that every
key-dependent Fourier mode has projective scalar `t=+/-1`.  This removes the
previous odd-scalar normalization problem and makes low-support modes directly
extractable through the binary OHLC compiler.

**This is not a completed WKEM.**  The missing central theorem is still a
polynomially useful bound on the *complete nonextractable projective/native
spectrum* of an efficient inner capsule, plus composition from final-key
recovery to the raw-bit predictor considered here.  No new hardness assumption
is named in place of that theorem.

No external literature or web search was used.

## 1. Exact QPT predictor-to-Fourier sampler

Let `G` be a finite abelian group and let a QPT binary predictor on a classical
input `x in G` be purified to a unitary circuit `U_x` with a designated output
qubit.  Internal measurements and randomness are deferred coherently.  Define

    f(x) = Pr[guess=0 | x] - Pr[guess=1 | x]
         = <0| U_x^dag Z_out U_x |0>.

The reduction uses the circuit description coherently (and therefore also
`U_x^dag`); this is a non-black-box/circuit reduction, not an oracle-only
extractor.

Prepare

    |psi0> = |G|^(-1/2) sum_x |x>|0>.

Apply controlled `U_x`, then `Z_out`, then controlled `U_x^dag`.  For each x,

    U_x^dag Z_out U_x |0>
      = f(x)|0> + |perp_x>,

where `<0|perp_x>=0`.  Apply the group QFT to the x register.  With normalized
Fourier convention

    f_hat(xi) = E_x [ f(x) chi_xi(x) ],

the amplitude of `|xi>|0>` is exactly `f_hat(xi)`.  Hence a joint measurement
that accepts only the all-zero adversary workspace outputs

    Pr[output xi and clean] = |f_hat(xi)|^2.            (1)

The total clean probability is

    sum_xi |f_hat(xi)|^2 = E_x |f(x)|^2 <= 1.           (2)

This is exact and does not assume that the predictor emits a witness, Fourier
label, short vector, or any other structured object.

## 2. Quantitative extraction inequality

Let a uniformly random raw key bit `K` select complete classical capsule
distributions `P_0,P_1` on G.  Put `N=|G|` and define the difference density
relative to uniform measure

    g(x) = N (P_0(x)-P_1(x)).

If the predictor succeeds with probability `1/2+epsilon`, then

    4 epsilon = E_uniform [ g(x) f(x) ]
              = sum_xi g_hat(xi) conj(f_hat(xi)).       (3)

Let `T` be any set of Fourier modes that the semantic extractor can turn into a
source witness, and let `U` be the remaining key-dependent Fourier support.
Define

    Gamma_T^2 = sum_(xi in T) |g_hat(xi)|^2,
    Gamma_U^2 = sum_(xi in U) |g_hat(xi)|^2,
    F_T       = sum_(xi in T) |f_hat(xi)|^2.

By Cauchy-Schwarz and (2),

    4 epsilon <= Gamma_T sqrt(F_T) + Gamma_U.           (4)

Therefore, when `Gamma_T>0`,

    F_T >= ((4 epsilon - Gamma_U)_+ / Gamma_T)^2.       (5)

By (1), the QPT phase-sandwich sampler returns an extractable mode with exactly
probability `F_T`.  Thus arbitrary QPT prediction becomes source-witness
extraction whenever the nonextractable spectral tail is below the prediction
advantage and the extractable spectral L2 mass does not make (5) negligible.

Equation (5) is a reduction lemma, not a proof that those spectral hypotheses
hold for the current compiler.

## 3. Exact complete-output spectrum of the additive capsule

Let q be even and work over `Z_q`.  For public

    A in Z_q^(m x n),   b in Z_q^m,

sample uniform `s in Z_q^m` and publish the raw-bit capsule

    c = A^T s + e,
    d = b^T s + e0 + K q/2.                            (6)

Let `phi_e(y)` and `phi_0(t)` be the characteristic functions of the data and
target-coordinate noises.  For frequency `(y,t)`, averaging over s gives

    g_hat(y,t)
      = (1-(-1)^t)
        1[A y + t b = 0 mod q]
        phi_e(y) phi_0(t),                              (7)

up to the harmless Fourier sign/conjugation convention.

This is the full classical public transcript `(c,d)`, not the intended witness
decoder alone.  Equation (7) is exactly the native/projective duality in q-ary
form.

## 4. First-odd-harmonic target filter

The odd scalar `t` was a real obstruction: reduction modulo two shows that every
odd t has the correct binary parity, but a recovered mode with a large modular t
need not normalize to the `t=1` OHLC relation without changing the coefficient
geometry.

There is a target-coordinate distribution that removes every odd harmonic except
`+/-1`.

For even q define

    C_q = (1/q) sum_(x in Z_q) |cos(2 pi x/q)|,

and

    D_*(x) = 2 max(cos(2 pi x/q), 0) / (q C_q).         (8)

Then `D_*` is a probability distribution and its shift by q/2 has disjoint
support.  Moreover

    D_*(x) - D_*(x-q/2)
      = 2 cos(2 pi x/q)/(q C_q).                        (9)

The right side is a pure first harmonic.  Consequently

    phi_0(t)=0 for every odd t not in {+1,-1},
    phi_0(+/-1)=1/(2 C_q).                              (10)

Combining (7) and (10), every key-dependent mode obeys

    t in {+1,-1}.                                      (11)

For q=4 this specializes to the exact integral distribution `D_*=delta_0`, and
there are no other odd residues anyway.  Larger q gives the same spectral
filter, although (8) generally has irrational probabilities and therefore needs
finite-precision implementation treatment.

### Uniqueness under the exact design goals

Suppose a distribution P has disjoint support from its q/2 shift and the odd
part `P(x)-P(x-q/2)` has Fourier support only at `+/-1`.  Then that odd part is a
real first harmonic `a cos(2 pi x/q - theta)`.  Disjointness forces, pair by
pair,

    P(x) = max(a cos(2 pi x/q-theta),0).

Normalization fixes a.  Thus (8), up to a phase/translation when compatible
with the grid, is essentially forced by the two exact requirements.  The filter
is not an arbitrary newly named primitive.

## 5. Exact honest residual law

Use iid data-coordinate noise whose distribution is

    D_rho = rho delta_0 + (1-rho) Uniform(Z_q).         (12)

Every nonzero Fourier coefficient of `D_rho` equals rho.  If a valid canonical
OHLC witness vector z has Hamming weight B and satisfies `A z=b`, then the
witness computes

    r = d - z^T c
      = K q/2 + e0 - z^T e.                            (13)

The difference of the two residual distributions has only the `+/-1` harmonics,
and convolution with B data noises multiplies those harmonics by `rho^B`.
Since `D_*` and its half-shift initially have total variation one,

    TV(r|K=0, r|K=1) = rho^B,                          (14)

so the optimal raw-bit witness decoder has exact success

    P_h = (1 + rho^B)/2.                               (15)

This proves correctness of this raw diagnostic channel for a given witness; it
does not prove secrecy against the public native decoder.

## 6. Direct source extraction from low-support modes

The binary OHLC compiler has B sum-one blocks.  Interpret the same 0/1 matrix
and RHS over an even modulus q.  Let `(y,t)` be a key-dependent mode.  By (11),
`t=+/-1`, and changing sign if necessary gives

    A y = b mod q.                                     (16)

Reduce (16) modulo two.  Every one of the B block-sum equations has RHS one, so
each block contains at least one odd coordinate.  Therefore every solution has
at least B nonzero coordinates.

If

    wt(y) <= B,                                        (17)

then every block contains exactly one odd/nonzero coordinate and no block has
room for an additional even nonzero coordinate.  The reduction `y mod 2` is
therefore one-hot in every block.  The OHLC marginal/truth-table equations then
recover a genuine satisfying Boolean proof and hence the source witness.

Thus the semantic extractor set can be taken as

    T = { (y,t): t=+/-1, A y+t b=0, wt(y)<=B }.         (18)

This support argument avoids the earlier centered-Euclidean/no-wrap condition.
It uses only even-q parity and the exact one-hot block equations.

## 7. Finite-precision target sampling

For large q the exact probabilities (8) may be irrational.  If an implementable
rational distribution Q satisfies

    ||Q-D_*||_1 <= delta,

then every Fourier coefficient changes by at most delta.  In particular every
formerly zero unwanted odd harmonic has magnitude at most delta.  This gives an
explicit additional nonextractable spectral tail that must be included in
`Gamma_U`; it cannot simply be ignored.

The checker quantizes q=16 to denominator `2^20` and verifies the coefficient
bound.  This is a finite arithmetic demonstration, not a cryptographic parameter
recommendation.

## 8. Tests actually executed

`qpt_fourier_extraction_check.py` performs fresh standard-library checks:

1. exact DFT checks of (8)-(10) for q=8,10,12,16,20;
2. 36 residual-distribution checks of (15) for q in {8,12,16},
   rho in {0.7,0.85,0.93}, and B in {1,2,5,9};
3. a complete q=4 additive-capsule enumeration verifying (7), the advantage
   identity (3), and inequality (5) for all 255 nonempty subsets of the eight
   key-dependent Fourier modes;
4. an explicit q=5 two-dimensional phase-sandwich/statevector calculation in
   which every clean-workspace amplitude equals `f_hat(xi)` exactly to floating
   precision and the total clean probability matches Parseval;
5. q=16 rational quantization to denominator `2^20`, verifying that the largest
   unwanted odd harmonic is below the measured L1 perturbation.

The captured JSON records the exact counts and numerical tolerances.  These tests
validate finite identities only; they do not establish cryptographic hardness.

## 9. What remains unresolved

The new reduction removes two previous logical excuses:

- a successful QPT predictor need not voluntarily output a projective preimage;
  the phase-sandwich construction samples its Fourier spectrum;
- a recovered key-dependent mode need not have an arbitrary odd projective
  scalar; the target filter restricts the exact spectrum to `t=+/-1`.

But the central inner problem remains:

1. **spectral concentration / false hiding:** for an efficient generic-NP
   compiler, prove that the complete nonextractable mass `Gamma_U` is small
   enough while honest decoding (15) stays useful.  A minimum projective-distance
   theorem is insufficient because exponentially many longer modes can dominate;
2. **extractable mass:** ensure `Gamma_T` and the advantage parameters make (5)
   nonnegligible for the relevant true-instance adversary;
3. **final-key composition:** lift raw-bit prediction/extraction through the
   reconciliation/privacy-amplification layer and arbitrary final-key recovery;
4. **PQ assumption/interface:** if information-theoretic spectral control is not
   enough, identify a concrete computational layer and reduce it to an
   independently justified PQ assumption rather than naming the desired release
   property itself;
5. **setup/resources:** only after the inner theorem exists can malicious-secure
   N-of-N/t-of-X setup composition and concrete resource estimates be honestly
   finalized.

Accordingly, this run supplies a proved reduction lemma and a constructive
spectral filter, not the requested completed generic PQ witness KEM.
