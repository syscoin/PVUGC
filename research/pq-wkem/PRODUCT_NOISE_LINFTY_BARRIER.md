# Run 36 — product additive noise cannot exploit the Run-35 `l_infinity` gap at polynomial signal

**Status:** rejected constructive candidate plus an exact Fourier-moment barrier. This is **not** a completed witness KEM, PQ security proof, or deployment recommendation.

Starting checkpoint: PR #1 head `959d810abecda85ae8849c98abb2b5b1d8bb0dcd` after Run 35. No external literature or web search was used. Production code is unchanged.

## 1. Constructive attempt

Run 35 found a useful semantic property of the Run-32 normalized integer source compiler:

* every genuine Boolean witness has `Hx=0`, `x_h=1`, and `||x||_infinity=1`;
* on a false statement every normalized integer kernel vector has `||x||_infinity>=2`.

The most direct cryptographic use of that gap is to revisit the additive capsule

    C = H^T y + E + (Q/2) K e_h  mod Q,                 (1)

for even `Q`, but choose the scalar coordinate-noise law `mu` specifically so that its Fourier transform is large at frequency `1` and tiny at frequency `2`.

Let

    phi(k) = E_{E<-mu}[ exp(2 pi i k E / Q) ].           (2)

For iid coordinate noise, a valid normalized Boolean witness with `B` nonzero unit coordinates has target-character magnitude

    beta_H = |phi(1)|^B.                                 (3)

The hope is to keep (3) inverse-polynomial or constant while forcing every false normalized kernel vector to touch a coordinate with frequency at least `2`, making its complete-view key character negligible.

The exact scalar moment constraint below rejects that product-noise plan.

## 2. Exact scalar theorem: the second harmonic cannot be independently suppressed

### Theorem 1

For **every** probability distribution on `Z_Q`, write

    a = |phi(1)|.

Then

    |phi(2)| >= max(0, 2 a^2 - 1).                      (4)

### Proof

Put `U=exp(2 pi i E/Q)` and `m=E[U]=phi(1)`. Then

    E[(U-m)^2] = phi(2) - m^2.                           (5)

By the triangle inequality and the ordinary complex variance identity,

    |phi(2)-m^2|
      <= E[ |U-m|^2 ]
       = 1-|m|^2.                                        (6)

Therefore

    |phi(2)|
      >= |m|^2 - (1-|m|^2)
       = 2a^2-1.                                         (7)

When the right side is negative the trivial lower bound zero applies. QED.

This is a positive-definiteness constraint on a genuine noise distribution, not an assumption about Gaussian/BSC noise.

### Sharpness

For the symmetric two-point law supported on residues `+1,-1`,

    phi(1)=cos(2 pi/Q),
    phi(2)=cos(4 pi/Q)=2 phi(1)^2-1.                     (8)

Thus (4) is exactly attained whenever the displayed quantities are nonnegative. No more favorable scalar distribution can universally separate frequencies 1 and 2 at the same value of `|phi(1)|`.

## 3. Explicit false family from the Run-32 compiler

Use the unsatisfiable two-clause formula

    (z OR z OR z) AND (!z OR !z OR !z),                  (9)

and add `d` irrelevant source variables that occur in no clause. This preserves falsehood while increasing the compiler size.

The public normalized integer kernel vector obtained by setting all source variables to zero and solving the public slack equations has, in first-coordinate notation,

    z=0,
    positive-clause slacks=(0,2),
    negative-clause slacks=(1,0),                         (10)

with every dummy source variable zero. Including complements, the vector has exactly

    B = (# complementary pairs)+1                        (11)

coordinates of magnitude `1`, and **one additional coordinate of magnitude `2`**. It satisfies `Hx=0`, `x_h=1`, and is not a Boolean/source witness.

For `d=0` this is the earlier `(z,a,b,c,d)=(0,0,2,1,0)` pseudovector. Every irrelevant source pair adds exactly one new unit coefficient and does not alter the single coefficient `2`.

Hence under iid product noise its key-sensitive Fourier character has magnitude

    beta_F = |phi(1)|^B |phi(2)|.                        (12)

Because `x_h=1`, the key shift `(Q/2)K e_h` flips this character's sign between the two key values. Therefore the total-variation distance between the two **complete false-instance public distributions** is at least `beta_F`; this is a public distinguisher, not an intended false decoder.

Combining (3), (4), and (12) gives the exact scoped barrier

    beta_F >= beta_H * max(0, 2 beta_H^(2/B) - 1).       (13)

## 4. Consequence for polynomially amplifiable honest signal

Suppose parameters are tuned so the honest first-character signal is `beta_B`.

If

    log(1/beta_B) = o(B),                                (14)

which includes every constant or inverse-polynomial honest signal, then

    2 beta_B^(2/B)-1
      = 1 - 4 log(1/beta_B)/B + o(log(1/beta_B)/B),      (15)

and therefore

    beta_F / beta_H -> 1.                                (16)

So an iid/product additive channel cannot turn the factor-two `l_infinity` semantic gap into negligible false-instance leakage while retaining any non-exponentially-small honest Fourier signal. If an outer polynomial repetition/code can amplify `beta_H`, the explicit false statement retains asymptotically the same nonnegligible public character and is amplified too.

For the concrete target `beta_H=0.8` (single-character honest success `0.9` after phase alignment), (13) gives:

| B | false/honest bias ratio lower bound | false character success lower bound |
|---:|---:|---:|
| 6 | 0.8566355 | 0.8426542 |
| 64 | 0.9861020 | 0.8944408 |
| 256 | 0.9965164 | 0.8986066 |
| 1024 | 0.9991285 | 0.8996514 |
| 4096 | 0.9997821 | 0.8999128 |
| 16384 | 0.9999455 | 0.8999782 |

Moreover

    B * (1-ratio) -> 4 |ln 0.8| = 0.892574205...         (17)

exactly as predicted by the expansion.

This strictly generalizes the earlier iid-BSC padded-family observation for this route: it applies to **arbitrary scalar additive noise distributions**, including non-Gaussian and asymmetric laws, and it is driven specifically by the Run-35 `1`-versus-`2` infinity-norm witness gap.

## 5. Finite-modulus sharp controls

The symmetric two-point law `mu={-1,+1}/2` saturates the scalar bound on ordinary even moduli. Choosing `B` so that `|phi(1)|^B` is near `0.8` gives:

| Q | B | honest bias | false bias | false/honest ratio |
|---:|---:|---:|---:|---:|
| 16 | 3 | 0.7885805 | 0.5576106 | 0.7071068 |
| 32 | 12 | 0.7922957 | 0.7319857 | 0.9238795 |
| 64 | 46 | 0.8008853 | 0.7854965 | 0.9807853 |
| 128 | 185 | 0.8001349 | 0.7962820 | 0.9951847 |
| 256 | 741 | 0.7999477 | 0.7989841 | 0.9987955 |
| 512 | 2963 | 0.8000214 | 0.7997804 | 0.9996988 |

These are not merely a bad choice of noise: the same law attains the universal lower bound (4), so it is a sharp control for the scalar optimization problem.

## 6. Validation actually executed

`product_noise_linfty_run36_check.py` is standard-library-only. The captured run was generated from a fresh execution after the Run-35 files were read.

It performed:

* exhaustive rational-law checks of Theorem 1:
  * all 330 probability laws on `Z_5` with denominator 7;
  * all 924 probability laws on `Z_7` with denominator 6;
  * total `1,254` laws, with minimum numerical slack `-6.7e-16` (floating-point roundoff only);
* `10,000` additional seeded random laws across `Q in {5,7,11,17,31}`, with no violation;
* exact trigonometric sharpness controls for the symmetric two-point law at `Q=5,7,11,17,31,64,127,257`;
* explicit compiler construction of the padded false family for `d=0,1,2,4,16,64,256,1024`, verifying `Hx=0`, `x_h=1`, `l_infinity=2`, exactly `B` unit-magnitude coefficients and exactly one magnitude-2 coefficient in every case;
* the constant-honest-bias tradeoff through `B=16,384`, including convergence of `B(1-ratio)` to `4|ln 0.8|`;
* finite even-modulus saturation controls for `Q=16,32,64,128,256,512`.

The checker validates the finite Fourier identities and the explicit pseudovector family. It is not a PQ security experiment and does not establish security of any correlated or computational replacement.

## 7. Scope and next target

**Rejected by this run:** the direct product/iid additive-noise attempt to exploit the Run-35 `l_infinity` source gap by independently suppressing frequency 2 while preserving a useful frequency-1 witness signal.

**Not ruled out:**

* correlated noise across coordinates or repetitions;
* a statement-aware channel that does not factor through one scalar noise law;
* the previously recorded Gap-OHLC route, where a false relation differs on a constant fraction of local tests rather than at one coefficient;
* an independently justified computational source-binding layer.

The important surviving constraint is that a replacement must be audited on its **complete joint Fourier spectrum**. Exact source semantics alone do not let a product channel assign arbitrary attenuation to coefficient magnitude 2: positivity already couples that harmonic to the honest frequency.

The generic PQ WKEM stopping condition is not met. The next useful constructive direction is to combine a genuine constant-fraction semantic gap (for example the already-recorded Gap-OHLC interface) with a correlated/global channel and then prove a full-spectrum bound, rather than continue retuning a coordinatewise noise law.
