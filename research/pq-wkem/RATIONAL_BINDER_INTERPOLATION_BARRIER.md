# Bounded-degree rational binders: perfect one-pair hiding, but complete-output interpolation recovers the key

**Status:** constructive nonlinear consistency-layer attempt, exact positive one-pair hiding theorem, exact complete-output false-instance attack, executable validation, and a scoped interpolation-family barrier. This is **not** a completed WKEM, a PQ security proof, or a deployment recommendation. Production code is unchanged.

Starting verified PR head: `a3687b2e7bf2ea53221d6bc291b9db226925466a`.

This run starts from `PRODUCT_BINDER_FINITE_DIFFERENCE_BARRIER.md`. Run 28 showed that a succinct product carrier can hide one inconsistent pair yet leak from a constant-size evaluation face through finite differences. The present attempt changes the hidden function family rather than perturbing that product: the carrier is a **rational function**, so the previous finite-difference identities do not directly isolate the hidden parameters.

The result is a different complete-output failure. A bounded-degree rational function is publicly reconstructible from polynomially many values on disjoint local domains. Once both shifted local functions are reconstructed as rational functions, their global algebraic identity reveals the key even though there is no common admissible representation.

No external literature or web search was used.

## 1. Constructive attempt

Work over a prime field `F_q`. Let `d>=1`. Setup samples

    N(z), D(z) in F_q[z],  deg N <= d, deg D <= d,

with `D` nonzero on all intended local candidate points. Define

    R(z) = N(z) / D(z).

For two local blocks, sample

    k_0 <- F_q,
    k_1 = K-k_0,

and let the intended locally recoverable values be

    f_0(z) = k_0 + R(z),
    f_1(z) = k_1 - R(z).                              (1)

The hidden parameters enter nonlinearly because of division. The direct coefficient representation has `2d+2` hidden field coefficients plus the additive key share. Evaluation costs `O(d)` field operations by Horner's rule.

This remains only a **consistency-layer** candidate. A complete generic WKEM would still need a sound local capsule that exposes `f_j(z)` only to locally admissible representations. The audit below grants exactly those intended local values and asks whether their complete public availability is already fatal.

### Exact honest correctness

For every point with `D(z) != 0`,

    f_0(z) + f_1(z) = K.                              (2)

Thus every common admissible representation recovers the same key, and setup need not know which representation will be used.

## 2. Positive theorem: one inconsistent pair is perfectly key hiding

The candidate has a stronger local property than the Run-28 product carrier.

Fix distinct `u != v` with `D(u),D(v) != 0`. Suppose the coefficients of `N` are independent uniform elements of `F_q`, while `D` is any value independent of `N` satisfying the non-pole condition. Because `d>=1`, the linear evaluation map

    N  ->  (N(u), N(v))

is surjective onto `F_q^2`: degree-one interpolation already realizes arbitrary values at two distinct points. Therefore `(N(u),N(v))` is exactly uniform on `F_q^2`.

Conditioned on any admissible `D`, the pair

    (R(u),R(v)) = (N(u)/D(u), N(v)/D(v))

is likewise uniform on `F_q^2`. Since `k_0` is independently uniform, for any fixed key `K`

    (f_0(u), f_1(v))
      = (k_0 + R(u), K-k_0-R(v))                     (3)

is the image of three independent uniform field elements under a rank-two affine map. Hence it is exactly uniform on `F_q^2`, independently of `K`.

So for every two keys `K,K'`,

    TV( Law(f_0(u),f_1(v) | K),
        Law(f_0(u),f_1(v) | K') ) = 0.                (4)

This is an exact positive theorem, not a computational assumption or a test-derived claim.

The checker exhaustively confirms it for `q=5,d=1,u=0,v=1`, enumerating all 16 affine denominators nonzero at both points, all 25 numerators, and all 5 additive shares. For keys `0,1,2`, all 25 output pairs occur with exactly the same multiplicity (80), and the three supports/distributions coincide.

## 3. Rational interpolation lemma

Let

    g(z) = A(z)/B(z),  deg A,deg B <= d,

and suppose `B(x_i) != 0` on `2d+1` distinct points `x_1,...,x_(2d+1)`.

Given only the samples `y_i=g(x_i)`, form the homogeneous linear equations

    A'(x_i) - y_i B'(x_i) = 0                        (5)

in the `2d+2` unknown coefficients of `A',B'`, each of degree at most `d`. There is always a nonzero solution because `(A,B)` is one.

Take any nonzero solution `(A',B')`. It cannot have `B'` identically zero: otherwise `A'` has `2d+1>d` roots and is zero too. Multiplying (5) by `B(x_i)` gives

    A'(x_i) B(x_i) - A(x_i) B'(x_i) = 0.             (6)

The polynomial

    H(z) = A'(z)B(z) - A(z)B'(z)

has degree at most `2d` and at least `2d+1` distinct roots, hence `H` is identically zero. Therefore

    A'/B' = A/B                                       (7)

as a rational function.

So **any** nonzero nullspace vector from the public system (5) reconstructs the same rational function, even when the coefficient representation is non-unique because numerator and denominator have a common factor. Gaussian elimination is sufficient; no hidden parameters or witness are required.

## 4. Explicit false-instance complete-output attack

Choose two fixed disjoint local candidate sets

    S_0 = {x_1,...,x_(2d+1)},
    S_1 = {y_1,...,y_(2d+1)},                         (8)

with all `4d+2` points distinct. Take `q > 4d+2`, and have setup condition only on `D` being nonzero on these public candidate points. The global common-representation statement is false because `S_0 cap S_1` is empty.

Nevertheless,

    f_0(z) = (N(z)+k_0 D(z))/D(z),
    f_1(z) = (k_1 D(z)-N(z))/D(z),                   (9)

so each local function is itself a rational function with numerator and denominator degree at most `d`.

From the `2d+1` values on `S_0`, the public interpolation lemma reconstructs the **entire rational function** `f_0`. Independently, the values on `S_1` reconstruct the entire rational function `f_1`.

But as rational functions,

    f_0(z)+f_1(z) = K                                 (10)

identically. The attacker therefore chooses any field point `z*` where the two reconstructed denominators are nonzero and outputs

    K = f_0(z*) + f_1(z*).                            (11)

Such a point exists because each reconstructed denominator has at most `d` roots; their union has at most `2d` roots, while the field already contains more than `4d+2` elements.

### Consequences

* The source statement (8) is false, so there is no source witness to extract.
* No setup secret is recovered or required.
* No rational-function pole needs to lie in either candidate set.
* The attack uses exactly `4d+2` intended local evaluations plus polynomial-time Gaussian elimination.
* Distinct-key complete-transcript supports are disjoint, because the deterministic decoder (11) maps every transcript to its unique key. Hence pairwise statistical distance is exactly one.

This is not the Run-28 finite-difference attack in another notation. It is an **off-domain reconstruction** attack: the two local sample sets never intersect, but each determines its whole hidden shifted function, and the key is recovered by evaluating the reconstructed functions at a point that was not required to be locally admissible.

## 5. Noisy local decoders

If each of the `4d+2` chosen local evaluations is decoded correctly with failure probability at most `epsilon`, then the exact interpolation attack succeeds whenever all selected values are correct. Without any independence assumption,

    Pr[key recovery] >= 1 - (4d+2) epsilon            (12)

by the union bound.

Thus polynomial local amplification does not repair this bounded-degree rational family: once honest/local error is driven sufficiently low, the explicit false decoder succeeds with correspondingly high probability.

## 6. General learnable-function barrier

The rational construction exposes a broader scoped criterion.

Let `F` be a public family of functions on a domain `X`. Suppose:

1. the shifted local functions `k+P` and `k-P` remain in an efficiently reconstructible family `G` whenever `P in F`;
2. there are public sample sets of size `M=poly(lambda)` from which a deterministic polynomial-time algorithm reconstructs the exact function in `G`; and
3. reconstructed functions can be evaluated at a common public domain point.

Then the zero-sum consistency binder

    f_0 = k_0 + P,
    f_1 = k_1 - P,
    k_0+k_1=K                                          (13)

cannot hide `K` on all false disjoint-set instances whose two local admissible sets contain such reconstruction sets. The attacker reconstructs `f_0` and `f_1` separately and evaluates their global identity `f_0+f_1=K` off the admissible sets.

This criterion contains the ordinary polynomial/finite-feature interpolation route as a special case, and the present rational family as a nonlinear parameterization example. The checker includes a separate Vandermonde control for polynomial spaces of dimensions 2,3,5,8,12 and recovers the key in every trial from disjoint unisolvent sets.

The scope is important. This is **not** an impossibility theorem for:

* succinct high-effective-degree arithmetic circuits that are not polynomial-sample learnable;
* keyed pseudorandom functions under an independently justified computational assumption; or
* statement-aware function families whose admissible sets deliberately lack efficient reconstruction sets.

However, invoking a hidden PRF is not by itself a WKEM construction: the PRF key cannot simply be published, and providing witness-only evaluation of a hidden PRF is itself a constrained-evaluation primitive requiring a non-circular construction and reduction. The source-witness-transfer obligation therefore remains.

## 7. Fresh validation actually executed

`rational_binder_check.py` is standard-library only. The captured run records:

* 2,000/2,000 exact common-representation decodes at `q=101,d=5`;
* exhaustive exact one-inconsistent-pair hiding at `q=5,d=1`: all 16 denominators nonzero at the two points, all numerator/share choices, 25 output pairs with equal multiplicity 80 for each of keys 0,1,2;
* exact false-instance rational interpolation recovery at `(q,d,trials)=(101,1,500),(101,2,500),(101,3,500),(101,5,500),(257,8,500),(1009,12,300)`, with recovery on every trial;
* exhaustive full rational-family support enumeration at `q=7,d=1`, disjoint sets `{0,1,2}` and `{3,4,5}`, all 12 denominators nonzero on all six points, all numerators and shares: 4,116 setups per key, support size 91 for each of keys 0 and 1, support intersection zero, exact pairwise TV one;
* polynomial learnability controls in dimensions 2,3,5,8,12: 500/500 total key recoveries from disjoint unisolvent sets.

The random rational tests deliberately accept interpolation nullity greater than one when cancellation lowers the reduced degree. The proof above shows that every nonzero nullspace solution still represents the same rational function, and the implementation chooses any solution with a nonzero denominator polynomial. Observed maximum nullity was two in the low-degree random cases and one in the higher-degree cases.

These tests validate exact finite-field identities and explicit reconstruction algorithms. They are not evidence for the security of a surviving construction and do not prove any quantum hardness claim.

## 8. Proved claims, implemented algorithms, and remaining gap

**Proved correctness:** every common admissible representation recovers exactly the same key via (2).

**Proved positive property:** one inconsistent pair has a transcript exactly uniform over `F_q^2` and independent of `K`, under uniform numerator coefficients and any independent denominator distribution conditioned on the two non-pole events.

**Proved break:** `2d+1` intended evaluations from each of two disjoint local candidate sets reconstruct `f_0` and `f_1` as rational functions and recover `K` exactly. With per-evaluation error at most `epsilon`, success is at least `1-(4d+2)epsilon` with no independence assumption.

**Implemented and tested:** modular rational interpolation by homogeneous Gaussian elimination, off-domain key recovery, exhaustive small-field one-pair distributions, exhaustive complete-transcript support separation, and polynomial-space controls.

**Not proved / not claimed:** a generic impossibility for all succinct nonlinear carriers; security or insecurity of a hidden PRF/constrained-PRF route; a generic-NP source-witness extractor; or arbitrary-QPT recovery reduction.

**Remaining central obligation:** construct a polynomial-size, statement-aware or computationally hidden witness-restricted evaluator whose complete public output is not efficiently learnable by quotienting, finite covers, shared-seed reconstruction, intertwiners, finite differences, or off-domain interpolation, while every valid witness recovers the same key and any unauthorized QPT early recovery reduces to a source witness or an independently justified PQ assumption. A secret-key evaluator is not enough unless its witness-only public interface is itself constructed without assuming WE-equivalent functionality.

The conditional N-of-N ceremony theorem from Run 19 remains downstream of that missing inner primitive. Full end-to-end parameters and setup composition are therefore still unresolved.

The stopping condition is not met.
