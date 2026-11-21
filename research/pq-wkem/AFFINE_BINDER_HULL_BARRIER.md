# Zero-sum affine consistency binders collapse to affine-hull consistency

**Status: constructive aggregation attempt plus complete-output theorem and counterexample; not a completed WKEM.**

This run starts from PR head `498eb0c8ecdac9cf1a7af0711a853a7c83881b90` and the preceding rank-condenser, linear-MAC/flow, Fourier, sphere-representative, and masked-carrier results. No external literature was fetched. Production code is not modified.

The constructive target is the unresolved **dual-splicing** problem from the small-block rank-condenser route. The prior failure had several local blocks, each with an honest-looking low-rank representation at a different global parameter. Independent share decoding then let an attacker splice inconsistent local representations. A natural repair is to hide a random affine consistency MAC inside each local share so that the masks cancel only when every block uses the same global representation.

This run proves that the repair has a real information-theoretic consistency effect, but only at the level of **affine hulls** of the locally decodable candidate sets. Complete public access to enough local evaluations interpolates through those affine hulls. An explicit false two-block rank fixture has no common low-rank representation while its affine hulls intersect, and therefore recovers the key exactly. The noisy version survives without assuming independent decoder errors.

## 1. Constructive attempt: zero-sum affine blinders

Let the global representation parameter be

    x in F_q^d.

There are `T` local blocks. Setup samples

    k_1,...,k_T in F_q,       sum_j k_j = K,
    a_1,...,a_T in F_q^d,     sum_j a_j = 0,

and block `j` is intended to let a locally admissible representation `x` recover

    f_j(x) = k_j + <a_j,x>.                         (1)

The coefficients `a_j` are not intended to be public. They are supposed to be hidden inside the local noisy capsule.

For one common global representation `x`, correctness is exact before local decoder noise:

    sum_j f_j(x)
      = sum_j k_j + <sum_j a_j,x>
      = K.                                           (2)

For an inconsistent tuple `(x_1,...,x_T)`,

    sum_j f_j(x_j)
      = K + sum_(j<T) <a_j, x_j-x_T>.                (3)

If the `a_j` are uniform subject to their zero-sum constraint and at least one `x_j != x_T`, then the extra term in (3) is uniform over `F_q`. Thus at the abstract one-query level the idea really does information-theoretically bind inconsistent choices.

The question is whether the **complete public output** of local blocks lets the adversary evaluate enough `f_j` values to remove that binding.

## 2. Exact complete-table theorem

For each block let

    S_j subset F_q^d

be the nonempty set of locally decodable candidate representations. Consider the strongest clean idealization of the proposed local layer: the complete public view reveals the exact values

    { f_j(x) : x in S_j }

but not the coefficients `(k_j,a_j)` themselves. This is deliberately favorable to the consistency idea: it does not expose any additional local-capsule internals.

### Theorem 2.1 -- recoverability iff affine hulls intersect

Under uniform setup randomness subject to

    sum_j k_j = K,
    sum_j a_j = 0,

the following are equivalent:

1. `K` is determined by the complete evaluation tables;
2. `K` is a public linear combination of the table entries plus the known zero-sum relation on the `a_j`;
3. the affine hulls have a common point:

       intersection_j aff(S_j) != empty.             (4)

Moreover, if (4) is false, then the complete table distributions are **identical for every key `K`**. Thus the theorem is an exact all-or-nothing information-theoretic characterization, not only a linear-attack statement.

### Proof: common affine point gives recovery

Suppose `x*` lies in every `aff(S_j)`. For each block choose affine coefficients `lambda_(j,x)` supported on `S_j` such that

    sum_(x in S_j) lambda_(j,x) = 1,
    sum_(x in S_j) lambda_(j,x) x = x*.              (5)

Then

    sum_(j,x) lambda_(j,x) f_j(x)
      = sum_j k_j + <sum_j a_j, x*>
      = K.                                             (6)

So the complete public tables recover the key without a common actual candidate in the sets themselves.

### Proof: every public recovery identity yields a common affine point

Write all hidden variables as `(k_j,a_j)`. A public linear recovery identity may also add arbitrary multiples of the known constraints `sum_j a_j=0`. Thus if the key functional `sum_j k_j` is in the public row span there are coefficients `lambda_(j,x)` and one vector `mu in F_q^d` such that, as an identity in unrestricted hidden variables,

    sum_j k_j
      = sum_(j,x) lambda_(j,x) (k_j+<a_j,x>)
        + <mu, sum_j a_j>.                             (7)

Matching each independent `k_j` coefficient gives

    sum_x lambda_(j,x) = 1                            (8)

for every `j`. Matching each independent vector `a_j` gives

    sum_x lambda_(j,x) x = -mu                        (9)

for every `j`. Therefore the same point `x*=-mu` belongs to every affine hull.

### Proof: no common affine point gives perfect key hiding

The map from the uniform hidden affine space

    A = { (k_j,a_j) : sum_j a_j=0 }

to the complete table is linear, while

    H(k,a)=sum_j k_j

is the key functional. If the affine hulls do not intersect, the preceding equivalence says `H` is not in the row span of the observation map restricted to `A`. Finite-dimensional linear duality therefore gives a direction

    delta in A intersect ker(observation)

with

    H(delta) != 0.                                    (10)

Scaling `delta` by any field element changes the key by an arbitrary amount while leaving every table entry unchanged. Translation by this scaled direction is a bijection between every two key-conditioned hidden fibers. Since setup samples uniformly, the complete transcript distributions are identical for every key. QED.

### Interpretation

The proposed hidden affine MAC does not enforce

    intersection_j S_j != empty.

It enforces only

    intersection_j aff(S_j) != empty.                 (11)

This is strictly stronger than the earlier statement that *publicly exposed* telescoping linear MACs lie in a removable annihilator: here the `a_j` may remain completely hidden. The failure arises because multiple locally decoded values interpolate the hidden affine functions.

## 3. Explicit false splice over F2^2

Take two local candidate sets

    S_1 = {00, 01, 10},
    S_2 = {11}.                                       (12)

There is no common actual candidate. But

    aff(S_1) = F_2^2,

so `11` lies in both affine hulls. In fact

    11 = 00 + 01 + 10                                 (13)

as an affine combination over `F_2`, because the three coefficients sum to one.

Therefore every setup satisfies the exact public identity

    K
      = f_1(00) + f_1(01) + f_1(10) + f_2(11).       (14)

The checker recovered the key in 500/500 fresh setups.

The same counterexample works over every odd field using

    x* = (1,1)
       = -1*(0,0) + 1*(1,0) + 1*(0,1),                (15)

whose coefficients again sum to one. Over `F_101` the checker recovered the key in 500/500 fresh setups.

## 4. The false sets arise directly as local rank conditions

The counterexample is not only an abstract set system. Over `F_2`, let the global parameter be `(x,y)` and define two public affine matrix families

    M_1(x,y) = [ x  0 ]
               [ 0  y ],                              (16)

    M_2(x,y) = [ 1  x ]
               [ y  1 ].                              (17)

For semantic threshold `D=2`,

    rank M_1(x,y) < 2    iff    (x,y) in {00,01,10},  (18)

while

    det M_2(x,y) = 1 + xy,

so

    rank M_2(x,y) < 2    iff    (x,y)=11.             (19)

Hence the global two-block instance has **no common rank-<2 representation**, exactly the kind of consistency failure the rank-condenser aggregation layer was meant to reject. Nevertheless the hidden affine binder exposes `K` by (14).

The four evaluations in (14) have local matrix ranks

    0, 1, 1, 1.                                       (20)

Thus a rank-selective local channel that is perfect at rank zero and has useful rank-one correctness gives the false attacker the same four evaluation interfaces.

For the previously analyzed `q=2,D=d=2,m=1` local subspace-noise channel, raw rank-one bit correctness is `2/3`. With 63 independent local repetitions the exact majority correctness is

    h_63 = 0.9968806526003727...

for each rank-one evaluation. The rank-zero evaluation is exact. With no independence assumption between the three amplified rank-one decoder errors, a union bound already gives the false splice success

    >= 1 - 3(1-h_63)
     = 0.9906419578011182...                           (21)

If those three amplified errors are independent, exact parity success is

    (1 + (2 h_63 - 1)^3)/2
      = 0.9907002183612197...                          (22)

So adding the affine binder does not repair this explicit rank-local false family once the local channels are amplified to useful honest correctness.

## 5. Noisy decoder theorem without independence

The preceding argument does not require exact public tables.

Suppose a public affine-hull certificate uses table positions `i=1,...,L` with coefficients `lambda_i`, and public local algorithms produce estimates of the corresponding intended values. If every required local estimate is correct with probability at least `1-epsilon_i` on the same challenge transcript, then the affine key combination is correct whenever all of those estimates are correct. Therefore

    Pr[false key recovery]
      >= 1 - sum_i epsilon_i.                          (23)

No independence between errors is assumed.

For the four-position binary certificate (14), if all four local decoders have success `0.9`, the guaranteed combined success is at least `0.6`. This lower bound is tight from the four marginal success probabilities alone: put probability `0.6` on no errors and probability `0.1` on each of the four singleton-error patterns. Every marginal decoder succeeds with probability `0.9`, while the XOR key is correct with probability exactly `0.6`.

In the rank fixture one of the four positions has rank zero and is exact, yielding the stronger three-error bound (21).

This theorem does not say every local capsule exposes every candidate evaluation with high probability. It says that **if the proposed aggregation layer relies on those local decoders being usable for the candidate points in an affine certificate, correlation between their errors does not save it.**

## 6. Exhaustive finite-set census

The checker exhaustively enumerated all nonempty set pairs in small affine spaces and compared actual set intersection with affine-hull intersection.

* `F_2^2`: 225 pairs; 50 have disjoint actual sets; 8 of those 50 still have intersecting affine hulls.
* `F_3^1`: 49 pairs; 12 have disjoint actual sets; 6 of those 12 still have intersecting affine hulls.
* `F_3^2`: 261,121 pairs; 18,660 have disjoint actual sets; **17,628** of those still have intersecting affine hulls.

The exact public row-space criterion was checked on every pair for the first two spaces and on 1,029 sampled pairs for `F_3^2`; every check matched affine-hull intersection. A further 1,080 random systems with `T=2,3,4` over `F_2^3`, `F_3^2`, and `F_5^2` also matched the theorem.

These counts are combinatorial fixtures, not a distributional claim about a future compiler. They show that affine-hull false positives are common even in tiny spaces.

## 7. Complete-distribution controls

Two exhaustive controls verify the all-or-nothing transcript statement.

### Disjoint affine hulls

Over `F_2^2`, use

    S_1 = {00,11},
    S_2 = {01,10}.                                    (24)

The two affine hulls are disjoint. Exhausting every hidden `(a_1,a_2,k_1,k_2)` satisfying the zero-sum constraints gives exactly the same eight complete transcripts, with the same multiplicities, for `K=0` and `K=1`.

### Intersecting affine hulls but no actual common point

For (12), exhausting the same hidden space gives eight transcripts for each key and the two supports are disjoint. The key is therefore information-theoretically determined exactly as Theorem 2.1 predicts.

A further 80 random `F_3`, `d=1`, `T=3` systems were exhaustively enumerated over all hidden randomness and all three keys. In all 31 affine-hull-disjoint cases the three key-conditioned transcript distributions were identical; in all 49 affine-hull-intersecting cases the three supports were pairwise disjoint.

## 8. What survives and what fails

This run does **not** prove that zero-sum affine blinders are useless in every restricted geometry.

There is a real positive statement: if a compiler can prove

    intersection_j aff(S_j) != empty
        ==> source witness exists,                    (25)

then the ideal affine binder exactly converts local affine consistency into global key correctness/hiding. In particular, the earlier two-singleton splicing fixture has disjoint affine hulls, so this binder would hide the key there.

The new obstruction is that ordinary local candidate sets need not satisfy (25). The explicit rank families (16)-(19) already violate it. Therefore a useful next construction cannot merely hide linear MAC coefficients; it needs either:

1. a **proved affine-hull-extractable compiler** satisfying (25) with polynomial overhead and practical local decoding; or
2. a genuinely nonlinear/computationally hidden consistency authenticator whose recoverable values do not extend to local affine hulls, together with an independent PQ reduction.

The second route must also survive the previous bounded-degree mask-closure, complete-public input-label, finite-cover, shared-seed, intertwiner, and native-channel attacks. Calling such a layer a hidden MAC or consistency compiler is not itself a security assumption or a completed result.

## 9. Fresh validation actually executed

`affine_binder_hull_check.py` is standard-library only. The captured run records:

* 500/500 exact false-splice key recoveries over `F_2^2`;
* 500/500 exact false-splice key recoveries over `F_101^2`;
* exact verification that (16)-(19) produce the intended two local rank-<2 candidate sets and ranks `(0,1,1,1)` on the recovery certificate;
* the 63-repetition rank-one majority and the attack bounds (21)-(22);
* exhaustive pair censuses in `F_2^2`, `F_3^1`, and `F_3^2`;
* 1,080 random row-space iff affine-hull-intersection theorem checks;
* exact complete-distribution equality/disjointness controls over `F_2^2`;
* 80 exhaustive `F_3`, three-block hidden-fiber systems;
* a tight correlated-error fixture for the four-decoder `0.9 -> 0.6` noisy bound.

These validate the finite algebra and probability identities. They do not establish security for a surviving construction, do not use quantum hardware, and do not supply a completed PQ WKEM.

## 10. Handoff

**New proved result:** hidden zero-sum affine cross-block MACs enforce only affine-hull consistency. Their complete exact evaluation transcript reveals the key iff the local affine hulls intersect; otherwise it hides the key perfectly.

**New explicit break:** two affine rank families over `F_2^2` have no common rank-<2 representation, yet their local candidate affine hulls intersect and a four-evaluation public identity recovers the key. Amplified local rank decoders carry the attack to high probability without any independence assumption.

**Still unresolved:** a polynomial-size generic-NP local compiler with affine-hull extraction, or a nonlinear/computationally hidden consistency mechanism with a full-output arbitrary-QPT recovery reduction to a source witness or independently justified PQ hardness; then malicious-secure setup composition and concrete end-to-end resource estimates.

The stopping condition is not met.
