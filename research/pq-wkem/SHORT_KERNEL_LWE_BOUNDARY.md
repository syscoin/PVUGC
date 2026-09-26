# Normalized short-kernel witness transfer and the near-threshold false-vector barrier

**Status: constructive source compiler plus rejected noisy quotient/LWE-style capsule; not a completed witness KEM.**

This run starts from PR #1 head `93c57b1e54708a52b1296706cae10efb0276e344` and keeps the prior complete-public-view input-label, source-transfer, quotient, finite-cover, interpolation, Hankel, and low-rank-completion failures in force. No external literature or web search was used. Production code is unchanged.

The new direction is lattice-native: instead of trying to hide one carrier value per witness, compile a satisfying assignment into a **short normalized integer kernel vector**. Such a vector can cancel an arbitrary public row-space mask in one shot. This gives a real witness-to-decryption transfer that setup can prepare from the statement alone. The same audit also finds an explicit unsatisfiable family with a key-sensitive kernel vector only additive `+4` in squared norm above the honest extraction threshold, so the natural noisy quotient capsule has no useful norm gap.

## 1. Witness-preserving 3CNF -> normalized short kernel

Let a 3CNF have Boolean variables `z_1,...,z_n` and clauses `C_1,...,C_m`. Introduce one normalization coordinate `h`, one pair `(a_i, abar_i)` per Boolean variable, and two slack-bit pairs per clause. Put

    N = n + 2m

for the number of pairs, so the integer vector has `2N+1` coordinates.

For every pair `(u,ubar)` add the homogeneous row

    u + ubar - h = 0.                                      (1)

For clause `j` with three literal coordinates `l_1,l_2,l_3`, and first coordinates `s_{j,1},s_{j,2}` of its two slack pairs, add

    l_1 + l_2 + l_3 + s_{j,1} + 2 s_{j,2} - 4h = 0.      (2)

Call the resulting integer matrix `H` and let `g` select the `h` coordinate.

### Theorem 1 — exact honest encoding

Every satisfying assignment gives an integer vector `x` with

    Hx = 0,
    <g,x> = h = 1,
    ||x||_2^2 = N+1.                                      (3)

Construction: put `(1,0)` or `(0,1)` in every Boolean pair. If a clause has `t in {1,2,3}` true literals, represent `4-t in {3,2,1}` by two slack bits as

    3 -> (s1,s2)=(1,1),
    2 -> (0,1),
    1 -> (1,0).

Every pair contains exactly one `1`, so (3) follows.

### Theorem 2 — short normalized kernel vector extracts a satisfying assignment

Conversely, suppose an integer `x` obeys

    Hx = 0,
    h = 1,
    ||x||_2^2 <= N+1.                                    (4)

Then the variable pairs encode a satisfying Boolean assignment.

Proof. From (1), every pair is `(u,1-u)` with integer `u`. Its squared contribution is

    u^2 + (1-u)^2 = 1 + 2u(u-1) >= 1,                    (5)

with equality iff `u in {0,1}`. There are `N` pairs and `h^2=1`, so the global bound in (4) forces equality in every pair. Hence all variable and slack coordinates are bits. In a clause, if all three literals were false, the left side of (2) before `-4h` would be at most `s1+2s2 <= 3`, contradiction. Thus every clause has a true literal. QED.

This is a genuine source-witness transfer statement: a supplied normalized kernel vector below the threshold yields an actual 3CNF witness. It is **not** yet a theorem that arbitrary key recovery yields such a vector.

### Modular version

The largest row norm is the clause-row norm `sqrt(24)`. Let

    B = sqrt(N+1).

For a centered integer representative `x` with `||x||_2<=B`, if

    Q > 2 sqrt(24) B,                                     (6)

then `Hx = 0 mod Q` implies `Hx=0` over the integers: every row product has absolute value below `Q/2` by Cauchy-Schwarz. Therefore Theorem 2 also applies to short normalized modular-kernel vectors.

At the semantic level, composing a witness-preserving Boolean-circuit/Tseitin-to-3CNF reduction with this compiler gives the expected generic-NP route. This run implements and tests the 3CNF kernel compiler itself; it does not implement a complete arbitrary-verifier front end.

## 2. Natural offline noisy quotient capsule

The kernel representation suggests a direct public capsule. Work modulo an even `Q`. Let `g=e_h`. Setup/encapsulation chooses any row-space mask `y` and a small error vector `e`, and publishes

    c = H^T y + e + (Q/2) mu g mod Q,                     (7)

for key bit `mu in {0,1}`.

A holder of any normalized kernel vector `x` computes

    <x,c> = <x,e> + (Q/2) mu mod Q,                       (8)

because `Hx=0` and `x_h=1`. Nearest-half-modulus decoding recovers `mu` whenever

    |<x,e>| < Q/4.                                        (9)

All satisfying assignments therefore recover the same bit. Parallel copies could encode a longer key. A standard LWE-looking term can be placed inside `y`; it still cancels identically in (8), so LWE pseudorandomness does not repair a short false kernel vector.

This construction is attractive because setup knows only the statement matrix `H`; it never needs a source witness and nobody must return online after setup.

## 3. Complete-output audit: a false normalized vector just above the witness threshold

Take the unsatisfiable two-clause formula

    (z OR z OR z) AND (not z OR not z OR not z).           (10)

The compiler has `N=5` pairs and honest threshold `B^2=N+1=6`. There is no vector satisfying (4), as expected. But there is the following normalized kernel vector with `h=1`:

* variable pair `(z,zbar)=(0,1)`;
* positive-clause slack pairs `(0,1)` and `(2,-1)`;
* negative-clause slack pairs `(1,0)` and `(0,1)`.

It satisfies every row exactly, has

    ||x_false||_2^2 = 10 = B^2+4,
    ||x_false||_1   = 8  = B^2+2.                        (11)

The `+4` squared-norm gap is optimal for any unsatisfiable formula under this pair gadget: by (5), an `h=1` solution that is not fully Boolean must contain at least one nonbinary pair, and the cheapest nonbinary pair has squared cost `5` instead of `1`.

### Padding makes the multiplicative gap vanish

Add `d` additional variable pairs while retaining the unsatisfiable core. Give every added pair a Boolean value in the false vector. Then

    B_d^2                 = d+6,
    ||x_false,d||_2^2     = d+10 = B_d^2+4,
    ||x_false,d||_1       = d+8  = B_d^2+2.              (12)

Hence

    ||x_false,d||_2^2 / B_d^2 -> 1,
    ||x_false,d||_1 / B_d^2   -> 1.                      (13)

This padding is a counterexample to **this compiler/noise strategy**, not a generic impossibility theorem: a different front end could try to remove or gap-amplify irrelevant structure.

## 4. Concrete bounded-noise failure

Take independent coordinate noise

    e_i uniform in {-1,0,1}

and choose

    Q = 8 B^2.                                            (14)

For every honest Boolean witness, `||x||_1=B^2`, so

    |<x,e>| <= B^2 < Q/4 = 2B^2.                         (15)

Honest decoding is deterministic.

But on the padded false family,

    |<x_false,e>| <= B^2+2 < 2B^2 = Q/4                 (16)

for every `B^2>2`. Thus the **false statement also decrypts deterministically for every error sample**. The key-conditioned complete transcript supports are separated by the public false decoder, so their total-variation distance is exactly `1` for this instantiation.

The public row-space/LWE-style mask `H^T y` is irrelevant: the false vector cancels it exactly just as a real witness does.

## 5. Fourier view of the same failure

For independent ternary noise, the quotient character indexed by any modular kernel vector `x` has Fourier coefficient

    hat_nu(x)
      = product_i [1 + 2 cos(2 pi x_i/Q)] / 3.            (17)

A bit shift by `(Q/2)g` flips the sign of every character with odd `x_h`. Therefore for `x_h=1`, the total-variation distance between key-0 and key-1 quotient distributions is at least

    |hat_nu(x)|,                                          (18)

because the expectation of this unit-modulus character differs by `2|hat_nu(x)|` and `|E_P f-E_Q f| <= 2 TV(P,Q)`.

The checker evaluates (17) on the false family. With `Q=8B^2`, the coefficient rises toward one under padding:

* `d=0`:   `0.9443139289594088`;
* `d=64`:  `0.9968995458291138`;
* `d=256`: `0.9992035383025519`;
* `d=1024`: `0.9997996168946162`.

The deterministic decoder in Section 4 is already the stronger break for this parameter choice; (17) explains the complete-distribution geometry and shows why merely appealing to the row-space mask cannot help.

## 6. What is actually positive

This run does produce a nontrivial reusable source compiler:

    satisfying 3CNF witness
      -> normalized integer kernel vector of exact norm sqrt(N+1),

with the converse extraction theorem for every normalized vector at or below that threshold. Unlike the previous carrier tables, the transfer itself is public, compact, and setup-witness-free.

The failure is the **cryptographic gap** between that extraction threshold and all other key-sensitive kernel vectors. The explicit false family has a decrypting vector only additive `+4` in squared norm above the semantic threshold. A decryption mechanism driven only by ordinary isotropic/small error magnitude therefore cannot simultaneously treat the threshold vector as a reliable secret key and all slightly longer false vectors as useless.

A surviving lattice route would need something materially stronger, for example:

1. a statement compiler with a proven large gap: every normalized key-sensitive false kernel vector is polynomially/superlogarithmically farther than every honest witness vector under the actual decryption norm; or
2. a statement-aware error/encoding geometry that suppresses every false normalized kernel direction while preserving **all** honest witness directions, with a reduction for its full public output; or
3. a different computational mechanism where arbitrary early key recovery reduces to standard PQ hardness without relying on a short-vector gap that the false relation can nearly meet.

Simply adding an LWE-looking row-space mask, more repetitions, or a larger modulus does not fix the explicit false vector because it obeys the same exact kernel cancellation equation.

## 7. Validation actually executed

`short_kernel_wkem_check.py` is standard-library-only and was run locally.

It checked:

* 100 independently generated satisfiable 3CNF fixtures across 1--4 variables: witness vector construction and source-assignment extraction both exact;
* exhaustive tiny short-vector controls for several one-clause formulas; every enumerated normalized vector at/below `N+1` extracted a satisfying assignment;
* the explicit false family through 64 repeated contradiction pairs, checking `Hx=0`, absence of threshold extraction, and the exact norm/L1 formulas;
* the padded false family at `d=0,4,16,64,256,1024`, including the exact additive `+4` squared-norm and `+2` L1 gap;
* the sufficient no-wrap modulus bound (6);
* 200 fresh honest and 200 fresh false-capsule decodes at each `t=1,4,16,32` with ternary noise and `Q=8B^2`; all honest and all false attacks decoded the key;
* exact convolution of the false decoder noise through `t=32`; in every fixture the entire noise support lies inside the correct decoding interval, so failure probability is exactly zero, not merely unobserved;
* exact ternary-noise Fourier coefficients from (17), including the padded convergence values above.

The tests validate finite algebra and the implemented attack. They do not establish security for an unbroken replacement.

## 8. Remaining obligations

The requested efficient generic-NP public offline PQ witness KEM is still **not constructed**. In particular this run does not supply:

* a gap-amplified generic-NP short-kernel compiler compatible with a proven PQ hiding assumption;
* a full-output arbitrary-QPT early-recovery reduction;
* malicious-secure ceremony composition for a surviving inner primitive; or
* final concrete parameters/resource estimates for a complete WKEM.

The normalized short-kernel compiler is a constructive step, while the natural noisy quotient/LWE-style capsule is rejected by an explicit false-instance public decoder. The PR must remain draft/unmerged and no production protection should be inferred.
