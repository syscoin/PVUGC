# Quadratic short-seed sphere representatives: one-orbit mixing and joint-view recovery

Starting checkpoint: PR #1 head
`4ec427087e85aea5e4652f094982aa1d578380c8`.

## Status

Run 22 showed that **independent** same-key sphere representatives repair the
specific finite-cover `2K,3K` leakage, but one independent representative per
explicit state does not scale to generic NP. Run 23 tested the simplest short
seed compression `v_s=L_s z` and showed that a false orbit exposes a public
linear image of the seed; an explicit two-cycle makes that image invertible.

This pass makes a genuinely nonlinear attempt. It uses a rational/paraboloid
parameterization of one quadratic key fiber, but chosen here in polynomial form:
for a public label `x_s in F_q^m`, a hidden random matrix `H in F_q^(t x m)`, and
key `k in F_q`, define

    u_s = H x_s,
    v_s = (1, k - <u_s,u_s>, u_s) in F_q^(t+2).          (1)

On `W=F_q^(t+2)` use the hyperbolic quadratic invariant

    Q(a,b,u) = a*b + <u,u>.                              (2)

Then every state representative satisfies **exactly**

    Q(v_s)=k.                                            (3)

This is a polynomial-size hidden seed (`tm` field elements) that can name
exponentially many same-key representatives through their public labels. It is
not a linear representative map, and one balanced false orbit can have genuine
quadratic Gauss mixing rather than the Run-23 seed inversion.

The complete joint public view nevertheless breaks the candidate in general.
For every false cover orbit the transcript exposes both a quadratic statistic
and a linear statistic of the *same* hidden H. If the public orbit-label sums
span the label space, those linear statistics recover H exactly; one orbit of
length nonzero mod q then recovers k exactly. An explicit false family of m
public 2-cycles with labels `(2e_i,-e_i)` has this property for every odd prime
`q>=5`.

Thus this run gives both:

* a **positive local theorem**: balanced false components can statistically mix
  the key under a nonlinear short-seed map; and
* a **complete-output negative theorem**: cross-component correlations recover
  the common seed and key on a simple false relation.

This is not a generic-NP WKEM and does not meet the stopping condition. No
external literature or web search was used. Production code is unchanged.

## 1. Construction inside the existing finite-cover transfer

Retain the Run-22 permutation-cover transfer. There is a public finite state set
`S`, public monodromy permutation `pi:S->S`, and a source witness is a fixed
point `s=pi(s)`. Vertex pads are independent uniform vectors in W. A first-layer
state s carries representative `v_s`; the remaining transfer edges carry zero.
For one monodromy orbit O, the complete public transcript is a uniform affine
fiber determined only by the orbit sum

    Z_O = sum_(s in O) v_s.                              (4)

That complete-transcript theorem did not require representative independence,
so it applies unchanged here.

Choose public labels

    x_s in F_q^m,

hidden uniform

    H <- F_q^(t x m),

and key `k in F_q`. Define (1). A fixed point obtains exactly one v_s after one
lap, hence computes k by (3).

So the candidate achieves exact same-key correctness for every fixed point
without storing one independent vector per state.

## 2. Exact false-orbit sufficient statistic

For an orbit O of length h define

    tau_O = sum_(s in O) x_s in F_q^m,                  (5)
    M_O   = sum_(s in O) x_s x_s^T in F_q^(m x m).      (6)

Using (1), its public orbit sum is

    Z_O = (
             h,
             h*k - Tr(H M_O H^T),
             H tau_O
          ).                                            (7)

Proof: the first coordinate sums to h; the last coordinates sum to
`H sum x_s`; and

    sum_s <H x_s,H x_s>
      = sum_s x_s^T H^T H x_s
      = Tr(H M_O H^T).

By the Run-22 affine-fiber theorem, (7) is a complete sufficient statistic for
the public edge transcript on O.

Equation (7) is the central audit identity for this pass.

## 3. Positive local result: balanced false orbits really mix

Suppose

    tau_O = 0                                             (8)

and let

    r = rank(M_O).

Then the last coordinates in (7) are identically zero. The only hidden-seed
term is

    Y = Tr(H M_O H^T)
      = sum_(j=1)^t h_j^T M_O h_j,                       (9)

where the rows `h_j` of H are independent uniform vectors in F_q^m.

For any nonzero additive-character frequency `lambda in F_q^*`, diagonalize the
symmetric matrix M_O by congruence. A rank-r quadratic Gauss sum over one random
row has normalized magnitude exactly

    q^(-r/2).                                            (10)

The t rows are independent, hence

    | E[ psi(lambda Y) ] | = q^(-t r/2).                (11)

Parseval and Cauchy-Schwarz therefore give

    TV( Y, Uniform(F_q) )
      <= (1/2) sqrt(q-1) q^(-t r/2).                    (12)

If `h != 0 mod q`, changing k only translates the second coordinate of (7), so
for any k,k'

    TV( Z_O(k), Z_O(k') )
      <= sqrt(q-1) q^(-t r/2).                          (13)

If `h = 0 mod q`, the key term itself vanishes from (7), so that component is
perfectly key-independent.

### Explicit balanced two-cycle

Take labels `x` and `-x`, with x nonzero, in a false two-cycle. Then

    tau_O = 0,
    M_O = 2 x x^T,
    rank(M_O)=1                                          (14)

for odd q. Therefore a single false two-cycle that defeated the Run-23 linear
seed can now have pairwise key distance at most

    sqrt(q-1) q^(-t/2).                                 (15)

For example, in the exact `q=5,t=4,m=1` checker fixture, the quadratic mask
`2 ||H||^2` has distribution counts `(145,120,120,120,120)` out of 625. Its TV
distance from uniform is exactly `4/125=0.032`, below the bound `1/25=0.04`;
any two nonzero key shifts have exact TV distance `1/25`.

This confirms that the nonlinear map genuinely avoids the *single-orbit* linear
inversion theorem from Run 23.

## 4. Complete joint-view theorem: orbit-label rank recovers H

The local result is not enough because every component uses the same H.
Suppose the false cover has components `O_1,...,O_c`. Form the public label-sum
matrix

    T = [ tau_(O_1) | ... | tau_(O_c) ] in F_q^(m x c), (16)

and collect the last coordinates of all orbit sums as

    U = [ Z_(O_1).u | ... | Z_(O_c).u ]
      = H T.                                             (17)

### Theorem 4.1 — full-rank joint recovery

If

    rank(T)=m,                                           (18)

then the complete public transcript recovers H exactly.

Indeed a public right inverse `R in F_q^(c x m)` satisfies

    T R = I_m.

Therefore

    H = U R.                                             (19)

Once H is known, any component O_j with

    h_j != 0 mod q                                      (20)

reveals

    k = h_j^(-1)
        ( Z_(O_j).b + Tr(H M_(O_j) H^T) ).              (21)

No source fixed point is found or used.

This attack uses the complete sufficient statistics of the public transcript;
it is not an intended-decoder failure.

## 5. Explicit false family for every odd prime q>=5

Take m independent public label coordinates `e_1,...,e_m`. For every i create a
false two-cycle `(a_i,b_i)` with

    x_(a_i) =  2 e_i,
    x_(b_i) = -1 e_i.                                   (22)

For q>=5 these are distinct states/labels, and every component has length 2, so
there is no fixed point anywhere.

For component i,

    tau_i = 2e_i-e_i = e_i.                             (23)

Hence

    T = I_m.                                             (24)

The last coordinates of its orbit sum are exactly

    Z_i.u = H e_i,                                      (25)

so the public transcript literally reveals column i of H. After m components,
all of H is known. Since h_i=2 is invertible in every odd field, equation (21)
recovers k exactly.

For these labels

    M_i = (4+1)e_i e_i^T = 5 e_i e_i^T,                (26)

so one may write the key equation as

    k = (1/2)( Z_i.b + 5 ||H e_i||^2 ).                 (27)

At q=5 the quadratic coefficient happens to vanish and `Z_i.b=2k` directly;
this only makes the break simpler.

Thus a polynomial-size seed that gives attractive balanced-orbit mixing still
fails on a polynomial-size **joint** false public view.

## 6. Why this is different from Run 23

Run 23 used a linear invariant-preserving map `v_s=L_s z`. One false orbit could
expose an invertible linear image of z.

Here one balanced false orbit does **not** do that. The representative map is
nonlinear in H through `-||H x||^2`, and the explicit balanced two-cycle has a
provable Gauss-mixing bound.

The failure is instead cross-component correlation:

* each orbit leaks the linear projection `H tau_O`;
* sufficiently many public tau_O vectors span the label space;
* the common H is then reconstructed;
* the quadratic masking terms become computable and the key follows.

So the design requirement is stronger than "make every false orbit marginally
hiding": the **joint complete transcript** must not accumulate enough public
queries to reconstruct the hidden representative generator.

## 7. What a repair would have to change

This result does not prove that all nonlinear succinct generators fail. It rules
out this natural hyperbolic/paraboloid seed compiler and identifies a concrete
joint-view condition that future candidates must defeat.

A surviving generator would need at least one of:

1. no publicly decodable low-degree seed projections analogous to `H tau_O`;
2. fresh entropy per enough components that the joint public view cannot
   reconstruct one shared seed (which risks returning to exponential state);
3. a computationally hidden generator whose many public component observables
   are simulatable/reducible to an independently justified PQ assumption;
4. a semantic compiler guaranteeing every false component is balanced in a
   joint sense strong enough to keep the seed hidden, with a source-extraction
   proof for all violations.

Merely increasing t improves (13) but does nothing against (19): the attack
recovers every row of H exactly.

A per-orbit independent H would restore the local mixing theorem for an explicit
finite cover, but then setup needs to know/store one seed per component and this
does not solve generic-NP succinctification.

## 8. Validation actually executed

`quadratic_sphere_seed_joint_check.py` uses only the Python standard library.
Fresh checks include:

* 600 random same-key representative checks over `F_101`, verifying `Q(v_x)=k`;
* exhaustive `q=5,m=1,t=4` balanced two-cycle enumeration over all 625 H values,
  giving quadratic-mask counts `(145,120,120,120,120)`, exact TV to uniform
  `4/125`, and exact pairwise key-shift TV `1/25`;
* direct additive-character magnitude checks for that fixture against the
  `q^(-t/2)=1/25` Gauss prediction;
* 400 full padded false-cover trials at `q=101,m=6,t=5` for the explicit
  `(2e_i,-e_i)` family; every trial recovered all of H from the public orbit
  sums and then recovered k exactly;
* exhaustive `q=5,m=2,t=2` checks over all H and all keys for the four-state
  two-orbit family; every complete sufficient statistic recovered H and k;
* 300 random multi-orbit rank tests verifying `U=HT`, public right-inverse
  recovery whenever T has full row rank, and the key equation (21).

These are finite-algebra validations of the stated theorem and attack. They are
not evidence that a different generator is secure.

## 9. Result classification

**Proved:** exact same-key invariant; exact orbit statistic (7); balanced-orbit
Gauss/Fourier mixing bound; joint full-rank recovery theorem; explicit false
`m`-two-cycle family recovering H and k.

**Implemented:** standard-library checker for representative correctness,
balanced-orbit distribution, complete padded transcripts, right-inverse seed
recovery, and key recovery.

**Actually tested:** only the groups listed in Section 8.

**Conjecture:** none is required for the break. The possibility of a different
nonlinear/computational generator with joint-view security remains open.

**Stopping condition:** not met.
