# Run 33 — composite-modulus prime filters: exact local erasure and complete-view splicing barrier

**Status:** constructive local Boolean/non-Boolean filter plus an exact false-instance complete-output break of the decomposed composition. This is **not** a completed witness KEM, a PQ security proof, or a deployment recommendation.

Starting checkpoint: PR #1 head `f885183381726b581f2b16000b49fb857e81a463` (Run 32). The normalized short-kernel compiler from Run 32 remains the semantic source representation. This run does not retry isotropic small noise, public coefficient masking, low-rank completion, polynomial/rational interpolation, or per-input label publication.

No external literature or web search is used. Existing production code is unchanged.

## 1. Motivation from the Run-32 pair gadget

For every normalized pair in the Run-32 compiler,

    (u, ubar) = (u, 1-u),

write its signed difference as

    d = u - ubar = 2u - 1.                              (1)

For a genuine Boolean pair, `u in {0,1}` and therefore `d in {-1,+1}`. For an integer non-Boolean pair, `d` is an odd integer with `|d| >= 3`.

The direct ternary-noise capsule failed because a coefficient `d=3` is only a constant-factor perturbation of `d=1`, and padding makes ordinary Euclidean/noise norms nearly identical. The constructive question here is different:

> Can a composite modulus make `d=+-1` a *perfectly decodable unit case* while making a chosen nonunit divisor of a non-Boolean `d` *perfectly hiding*?

For one fixed pair and one prime, the answer is yes, exactly.

## 2. Prime-filter capsule

Fix an odd prime `p` and put

    Q = 4p,
    Delta = Q/2 = 2p.                                   (2)

Let `H` be the public Run-32 integer matrix reduced modulo `Q`; it contains the pair row

    u + ubar - h = 0.                                   (3)

Let

    g   = e_h,
    v_j = e_{j,0} - e_{j,1}.                            (4)

For one bit `mu`, setup samples

    y <- Z_Q^m uniformly,
    Z <- {0,2} uniformly,                               (5)

and publishes

    C = H^T y + Z v_j + Delta mu g    (mod Q).          (6)

Setup uses only the statement matrix and no source witness.

For any public kernel character/vector `x` with

    Hx = 0 (mod Q),                                     (7)

write

    h = x_h,
    d = x_{j,0} - x_{j,1}.                              (8)

The public residual is

    <x,C> = Z d + Delta mu h    (mod Q).                (9)

If `h` is odd, then `Delta h = Delta (mod Q)`. The pair row (3) also implies that `d` is odd.

## 3. Exact scalar dichotomy

For odd `d`, conditioned on `mu`, the two possible residuals are

    S_0(d) = {0, 2d},
    S_1(d) = {Delta, Delta + 2d}        in Z_(4p).       (10)

### Lemma 1 — prime divisor gives perfect erasure

For odd `d`,

    S_0(d) = S_1(d)    iff    p | d.                    (11)

Otherwise the two sets are disjoint.

Proof. `0 != Delta (mod 4p)`. Equality of the two two-point sets must therefore swap their elements, requiring

    2d = Delta (mod 4p),

or equivalently

    d = p (mod 2p).                                     (12)

Because both `d` and `p` are odd, (12) is equivalent to `p|d`. If (12) fails, none of the four possible cross-equalities holds, so the supports are disjoint. QED.

Consequences for a *fixed supplied kernel vector*:

* Boolean `d=+-1`: the bit is decoded with probability 1 for every odd prime `p`.
* If `p|d`: the residual is statistically identical for `mu=0` and `mu=1`.

This is materially stronger than the Run-32 small-noise gap: it is an exact zero/one channel.

## 4. Complete-public-output theorem

The previous lemma concerns one residual. The requested primitive must survive the **entire public capsule**, so the complete distribution must be audited.

Let `R = im(H^T) <= Z_Q^n`. Since `y` is uniform, `H^T y` is uniform on `R`. The key-0 distribution is

    P_0 = U_R * (delta_0 + delta_(2v_j))/2,              (13)

and `P_1` is its translate by `Delta g`.

Characters of `Z_Q^n` are indexed by vectors `x`; the Fourier transform of `U_R` vanishes off

    R^perp = ker(H).                                     (14)

For `x in ker(H)`, the two-point factor is

    (1 + omega^(2d))/2,                                  (15)

while the key translation multiplies that coefficient by

    omega^(Delta h) = (-1)^h.                            (16)

Because of the pair row, if `h` is odd then `d` is odd. For odd `h`, (15) vanishes exactly when `p|d`.

### Theorem 2 — complete-view zero/one criterion

For the capsule (6):

* `P_0 = P_1` exactly **iff** every `x in ker(H)` with odd `x_h` satisfies

      p | (x_{j,0} - x_{j,1}).                           (17)

* If there exists one `x in ker(H)` with odd `x_h` and `p` not dividing its pair difference, then the public residual (9) has disjoint key-conditioned supports, so an efficient public decoder recovers `mu` with probability 1 and

      TV(P_0,P_1) = 1.                                   (18)

Thus the local prime filter has no intermediate complete-view leakage: for this exact two-point channel it is either perfectly hiding or perfectly distinguishable.

The important strengthening over a prescribed-decoder analysis is that **one bad pair in one chosen pseudovector is not enough**. For complete-view hiding at component `(j,p)`, divisibility must hold across the *entire target-sensitive kernel fiber*.

## 5. Bounded-vector coverage is real but only vector-wise

For a centered integer pair `(u,1-u)` with `u notin {0,1}`,

    d = 2u-1

is odd and `|d|>=3`, so it has an odd prime divisor `p<=|d|`. If `|u|<=U`, then

    |d| <= 2U+1.                                        (19)

Therefore the list of odd primes through `2U+1` catches every bounded non-Boolean pair **for that fixed vector**: at least one corresponding scalar channel is perfectly erased.

The checker verifies this exhaustively for all `u in [-64,64] \ {0,1}` using the 30 odd primes through 127.

This is a genuine local construction. It does **not** imply a WKEM, because a public adversary may use a different exact kernel vector for a different component.

## 6. Natural global composition and why it fails

A direct composition is to create one component for every pair/prime `(j,p)`, choose independent random share bits `mu_(j,p)` whose XOR is the final key `K`, and publish an independent capsule (6) for each share.

Every valid source witness has `d_j=+-1` for every pair. It therefore decodes every share perfectly and obtains the same final XOR key. Setup still knows only the statement.

If one fixed false vector had a bounded non-Boolean pair, Section 5 would hide at least one share from **that vector**. But the full public view does not force all shares to use the same vector.

## 7. Explicit false-instance two-vector splice

Use the same unsatisfiable Run-32 formula

    (z OR z OR z) AND (!z OR !z OR !z).                  (20)

Write the five first pair coordinates as

    (z, a, b, c, d),                                     (21)

where `(a,b)` are the two positive-clause slack bits and `(c,d)` the two negative-clause slack bits. Exact kernel equations at `h=1` reduce to

    a + 2b = 4 - 3z,
    c + 2d = 1 + 3z.                                    (22)

There is no all-Boolean solution; equivalently the source formula is false. But two exact normalized integer kernel vectors are

    x0: (z,a,b,c,d) = (0,0,2,1,0),
    x1: (z,a,b,c,d) = (0,2,1,1,0).                      (23)

Both satisfy every row of `H` exactly and both have squared norm 10, versus the Run-32 semantic threshold 6. Their pair differences are

    d(x0) = (-1,-1, 3, 1,-1),
    d(x1) = (-1, 3, 1, 1,-1).                           (24)

Hence:

* `x0` has Boolean/unit difference on pairs 0,1,3,4;
* `x1` has Boolean/unit difference on pair 2.

Together they cover **all five pairs** with `d=+-1` despite the absence of a source witness.

For every component `(j,p)`, choose `x0` except on pair 2, where choose `x1`. Since the selected difference is `+-1`, Lemma 1 gives disjoint residual supports for every odd prime `p`. The attacker therefore decodes **every independent share with certainty** and XORs them to the final key.

This is not merely a failure of an intended decoder. The selected `x` is a public complete-output distinguisher for that share, so each component itself has key-conditioned TV distance 1.

The checker exhausts all 32 Boolean pair assignments and confirms there is no Boolean kernel point, then performs 500 independent global-share experiments over primes `3,5,7,11,13`: 12,500 false-instance component decodes and 500/500 final-key recoveries.

As a control, on the true one-clause formula

    (z OR !z OR z),                                      (25)

both `z=0` and `z=1` source witnesses decode every component and recover the same XOR key. Across 300 setups, the checker performs 9,000 successful witness/component decodes with zero key failures.

## 8. Exact full-view controls

The checker also enumerates the **entire capsule distributions** for tiny one-pair relations.

For `p in {3,5}`, impose pair normalization and additionally

    d = p h.                                             (26)

Every odd-`h` kernel character has `p|d`; the complete key-conditioned distributions are exactly identical. The enumerated support sizes are 144 (`p=3`) and 400 (`p=5`).

Replacing (26) by

    d = h                                                (27)

makes an odd kernel vector with unit difference available. The two complete key-conditioned supports are disjoint (intersection zero) for both primes.

These finite enumerations validate the full-output Fourier criterion rather than only the scalar intended decoder.

## 9. What survives and what does not

### Proved / implemented in this run

1. An exact composite-modulus local filter in which Boolean pair differences `+-1` decode perfectly while a chosen odd prime divisor of a non-Boolean difference erases the bit perfectly.
2. The exact **complete-output** criterion (17), not merely a local-decoder statement.
3. Polynomial bounded-coefficient prime coverage for a fixed integer vector.
4. A concrete statement-only XOR-share composition with perfect honest correctness.
5. An explicit false 3CNF where two near-threshold exact kernel pseudovectors splice the component family and recover every share/final key with certainty.

### Rejected claim

It is **not** valid to argue that "every false vector has some bad pair, therefore some prime-filter share is hidden." Complete-view security needs one component to be hidden against **all** target-sensitive kernel characters simultaneously, or a mechanism that cryptographically forces all component evaluations to use one common representation. The explicit two-vector splice disproves the decomposed version.

### Remaining constructive target

The local arithmetic suggests an ideal global coefficient

    D(x) = product_j (x_{j,0} - x_{j,1}).                (28)

For a Boolean witness, `D=+-1`; for a bounded non-Boolean integer vector, `D` has an odd prime divisor. A single prime-filter channel driven by `D(x)` would therefore avoid the pair-by-pair splice at the *semantic* level.

But producing a **public compact capsule** whose hidden carrier is multiplied by (28) without revealing that carrier is exactly the missing witness-restricted computation problem:

* explicitly expanding (28) has `2^N` monomials and is excluded;
* a normal public arithmetic circuit exposes its hidden carrier/key constants;
* decomposing it into independently recoverable local shares reintroduces the splice above;
* simply naming a hidden compact evaluator would be the WE-equivalent release compiler already ruled out as an assumption.

This run does not claim an impossibility theorem for every compact nonlinear realization of (28). It identifies the precise global operation that would be needed and shows that the obvious polynomial-size decomposed realization is insecure.

## 10. Validation actually executed

`prime_filter_complete_view_check.py` is standard-library-only and was run locally. The captured JSON records:

* 510 exact scalar `(p,d)` support cases over `p=3,5,7,11,13` and odd `d in [-101,101]`: 86 identical channels exactly when `p|d`, 424 disjoint otherwise;
* all 127 non-Boolean integers `u in [-64,64]` covered by one of the 30 odd primes through 127;
* complete-capsule enumeration for `p=3,5`, with exact equality in the `d=ph` toy and zero support intersection in the `d=h` toy;
* 300 true-formula share setups, two witnesses each, 9,000/9,000 component decodes and zero final-key failures;
* exhaustive absence of a Boolean kernel point in the false contradiction gadget;
* exact verification of the two norm-10 pseudovectors and their pair-difference cover;
* 500 false global-share setups, 12,500/12,500 spliced component decodes and 500/500 final-key recoveries.

The tests validate finite algebra and the implemented attack. They are not a security experiment for an unbroken replacement and do not establish a generic PQ WKEM.

## 11. Remaining obligations

The stopping condition remains unmet. Still missing are:

* a polynomial-size global witness-restricted evaluator/binder that prevents the complete-view splice without assuming WE-equivalent functionality;
* a full arbitrary-QPT early-key-recovery reduction to source-witness extraction or an independently justified PQ assumption;
* false-instance hiding for the entire output of such an inner primitive;
* malicious-secure ceremony composition and concrete end-to-end parameters for a surviving construction.

The prime filter is a reusable exact local gadget; the decomposed global composition is rejected by a complete-output false-instance attack.
