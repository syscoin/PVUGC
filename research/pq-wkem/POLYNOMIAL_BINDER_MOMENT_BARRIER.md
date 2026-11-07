# Hidden polynomial consistency binders: function-space hull theorem and efficient parity moment attack

**Status:** constructive nonlinear aggregation attempt, exact complete-output theorem, and explicit false-instance attacks. This is **not** a completed WKEM, a PQ security proof, or a deployment recommendation. Production code is unchanged.

Starting verified PR head: `cbde0e667a3dc6014e11ac98fd38c576413a2338`.

This run continues directly from `AFFINE_BINDER_HULL_BARRIER.md`. The affine binder had a real one-query consistency effect but complete access to several local evaluations extended each hidden affine function to the affine hull of its candidate set. The natural next repair is to replace the hidden affine function by a nonlinear polynomial (or, more generally, an arbitrary finite public feature space) while retaining the zero-sum cancellation required for every valid witness to recover the same key.

The result has two parts.

1. The Run-26 affine-hull theorem extends exactly to **any binder linear in a finite hidden coefficient vector**, no matter how nonlinear or statement-aware the public features are.
2. For the natural degree-`r` multilinear polynomial feature space on Boolean witnesses, an explicit false even/odd parity pair has matching moments through degree `r<n`. For every fixed `r`, those matching moments have an **efficient `n^r`-size seeded realization**, so complete local evaluation access yields a polynomial-time false-key decoder. A sparse degree-`n` parity feature defeats this specific parity attack, showing that the result is a bounded-function-space barrier rather than a blanket impossibility theorem.

No external literature or web search was used.

## 1. Constructive attempt: hidden nonlinear/function-space binders

Let `X` be the public representation domain and let

    phi : X -> F_q^m

be any public feature map. Its coordinates may be nonlinear polynomials, hashes, verifier-derived features, or any other public functions. Setup samples hidden block shares

    k_1,...,k_T in F_q,         sum_j k_j = K,
    a_1,...,a_T in F_q^m,       sum_j a_j = 0,

and block `j` is intended to let a locally admissible representation `x` recover

    f_j(x) = k_j + <a_j, phi(x)>.                         (1)

For one common representation `x`,

    sum_j f_j(x) = K.                                    (2)

Thus this is a genuine nonlinear strengthening of the Run-26 candidate when `phi` itself is nonlinear.

Equivalently, choose an `m`-dimensional public function space `V=span{phi_1,...,phi_m}` and hidden functions `P_j in V` with `sum_j P_j=0`; then `f_j(x)=k_j+P_j(x)`.

## 2. Exact complete-output theorem for arbitrary public features

Let `S_j subset X` be the nonempty set of candidate representations for which block `j` exposes the exact intended value `f_j(x)`. Consider the ideal complete public view

    { f_j(x) : x in S_j, j=1,...,T }.                    (3)

This deliberately strips away all other local-capsule internals. Define the feature-image affine hulls

    H_j = aff(phi(S_j)) subset F_q^m.                    (4)

### Theorem 2.1 -- recovery iff feature-image affine hulls intersect

Under uniform setup randomness subject to the two zero-sum constraints,

    K is determined by (3)
      iff
    intersection_j H_j is nonempty.                     (5)

If the intersection is empty, the **entire key-conditioned transcript distributions are identical for every key**.

### Proof: a common feature barycenter recovers `K`

If `y* in H_j` for every block, choose affine coefficients `lambda_(j,x)` with

    sum_x lambda_(j,x) = 1,
    sum_x lambda_(j,x) phi(x) = y*.                      (6)

Then

    sum_(j,x) lambda_(j,x) f_j(x)
      = sum_j k_j + <sum_j a_j, y*>
      = K.                                               (7)

### Proof: every universal linear recovery identity gives a common barycenter

Suppose the key functional is in the public observation row span, allowing the known relation `sum_j a_j=0`. Coefficient matching in the independent hidden variables gives, for every `j`,

    sum_x lambda_(j,x)=1,
    sum_x lambda_(j,x) phi(x)=-mu                        (8)

for one common vector `mu`. Hence `-mu` lies in every `H_j`.

### Proof: disjoint feature hulls give perfect hiding

If the hulls do not intersect, the key functional is not in the row span of the observation map restricted to the zero-sum hidden affine space. Finite-dimensional linear duality therefore gives a kernel direction that leaves all observations unchanged while changing the key by a nonzero field element. Scaling and translating that direction bijects every key-conditioned hidden fiber with every other. Uniform setup then gives identical full transcript distributions. QED.

This theorem strictly extends Run 26. Making `phi` nonlinear does **not** by itself prevent interpolation; it only replaces `aff(S_j)` by `aff(phi(S_j))`.

## 3. Degree-r polynomial specialization

Take Boolean representations

    X = {0,1}^n

embedded in an odd prime field `F_q`. Every polynomial function on `X` can be reduced to a multilinear polynomial. For degree bound `r`, let

    phi_r(x) = ( product_(i in A) x_i )_(|A|<=r).        (9)

Then hidden `a_j` are exactly the coefficients of a hidden multilinear polynomial `P_j` of degree at most `r`.

The constructive hope is that nonlinear degree might separate false local candidate sets whose ordinary affine hulls intersect.

## 4. Exact parity moment obstruction through every degree r<n

Let

    E = {x in {0,1}^n : sum_i x_i is even},
    O = {x in {0,1}^n : sum_i x_i is odd}.              (10)

These sets are disjoint, so the two-block source statement `x in E and x in O` is false.

For a squarefree monomial `x_A` of degree `t<n`, fixing all bits in `A` to one leaves at least one free bit. Exactly half of those completions have even parity and half have odd parity. Therefore

    Avg_E[x_A] = Avg_O[x_A] = 2^(-t) in F_q             (11)

for every `t<n`.

Consequently, for every `r<n`,

    Avg_E[phi_r(x)] = Avg_O[phi_r(x)] =: mu_r.           (12)

So `mu_r` lies in both feature-image affine hulls. By Theorem 2.1, every degree-`r` polynomial binder leaks the key on this false statement.

For two blocks, write `P_1=P` and `P_2=-P`. The decoder is especially simple:

    Avg_E[f_1] + Avg_O[f_2]
      = k_1+k_2 + Avg_E[P]-Avg_O[P]
      = K.                                               (13)

At degree `n`, the all-variable monomial separates the two parity classes: `x_1...x_n` is one only at the all-ones assignment, which belongs to exactly one parity class. Thus the obstruction is exactly a `<n` moment statement, not an assertion that every high-degree nonlinear binder fails.

## 5. Efficient polynomial-support attack for every fixed degree

Equation (13) written as a full average uses `2^(n-1)` table entries. That alone would not be an efficient cryptographic attack. For fixed `r`, however, the same matching moments have an explicit polynomial-size seeded realization.

Let

    n = 2^d

and identify the coordinate positions with the field `F_(2^d)`. Choose a uniformly random polynomial

    p(t) = a_0 + a_1 t + ... + a_(r-1) t^(r-1)          (14)

with coefficients in `F_(2^d)`, for `r<n`. Define the Boolean word

    x_t = Tr(p(t)) in F_2.                               (15)

### Lemma 5.1 -- every generated word has even parity

Because trace is linear,

    XOR_t x_t = Tr( sum_t p(t) ).                        (16)

For the constant term, `sum_t 1 = n = 0` in characteristic two. For `1<=j<=r-1<n-1`,

    sum_(t in F_(2^d)) t^j = 0.                          (17)

Hence the right side of (16) is zero for every seed.

### Lemma 5.2 -- the seed distribution is r-wise independent

At any `s<=r` distinct field points, evaluation of a random degree-`<r` polynomial is uniform on `F_(2^d)^s` by Vandermonde interpolation. Applying trace coordinatewise yields `s` independent unbiased bits. Therefore every monomial of degree at most `r` has expectation `2^(-s)`.

Toggle one fixed output bit. This maps every even word to an odd word, preserves `r`-wise independence, and therefore gives a second efficiently seeded distribution with exactly the same degree-`<=r` moments.

The number of seeds is

    |F_(2^d)|^r = n^r.                                  (18)

Thus for every fixed `r`, an attacker can evaluate the two local tables on `n^r` publicly generated even candidates and the corresponding `n^r` odd candidates, average with seed multiplicity, and apply (13). The attack uses `2 n^r` local evaluations and polynomial work.

If each chosen local value is produced by a noisy intended decoder with failure at most `epsilon`, the probability that every value used by this exact averaging attack is correct is at least

    1 - 2 n^r epsilon                                   (19)

by a union bound, with no independence assumption. When the raw local channel has constant bias and `r` is fixed, ordinary polynomial repetition can make `epsilon` inverse-polynomial enough for this particular attack. This statement is conditional on the local layer exposing those candidate evaluations; it does not assert that every future capsule does so.

## 6. Positive control: sparse degree-n parity feature defeats this false splice

To avoid overclaiming, consider the single public feature

    chi(x) = product_i (1-2x_i) = (-1)^(sum_i x_i).      (20)

It has degree `n` but a linear-size product description. Use two hidden coefficients `a,-a`:

    f_1(x)=k_1 + a chi(x),
    f_2(x)=k_2 - a chi(x).                               (21)

A genuine common `x` still cancels the masks exactly. On the false parity pair, `chi=+1` on `E` and `chi=-1` on `O`, so any one even/odd pair gives

    f_1(x_E)+f_2(x_O)=K+2a,                             (22)

which is uniform over `F_q` when `a` is uniform and `q` is odd. In the complete-table idealization, the two tables are constants with that same hidden offset, and the exact key-conditioned transcript distributions are identical.

Therefore the result is **not** “nonlinear binders are impossible” and not “degree n requires exponential description.” It says the natural bounded-degree/full-moment repair fails efficiently for constant degree, while a surviving succinct high-degree feature must be chosen so that false local candidate sets have no common feature barycenter and must still survive the rest of the WKEM public-output attacks.

## 7. A second exact low-degree certificate: the missing-all-ones family

There is another useful algebraic fixture. Let

    S_0 = {0,1}^n \ {1^n},
    S_i = {x : x_i=1},   i=1,...,n.                     (23)

Their actual intersection is empty. For every proper subset `A subsetneq [n]`, assign the point indexed by its support the affine coefficient

    lambda_A = (-1)^(n-|A|+1).                          (24)

For every proper monomial support `T subsetneq [n]`, inclusion-exclusion gives

    sum_(A subsetneq [n], A superset T) lambda_A = 1.   (25)

The coefficients also sum to one. Hence `phi_(n-1)(1^n)` lies in `aff(phi_(n-1)(S_0))`, while it is an actual point of every `phi_(n-1)(S_i)`. So degree `<n` again admits a false common feature barycenter. The degree-`n` all-variable monomial is zero on every point of `S_0` and one at `1^n`, so this particular certificate stops exactly at degree `n`.

This fixture is an algebraic control; (24) has exponential support as written, unlike the efficient constant-degree parity attack in Section 5.

## 8. Fresh validation actually executed

`polynomial_binder_hull_check.py` is standard-library only. The captured run records:

* 480 random finite-field checks of the general function-space theorem: public row-space key recovery matched feature-image affine-hull intersection in every case;
* 132 exact even/odd moment-equality checks for all degree bounds `r<n` across `q in {3,5,101}` and `2<=n<=9`;
* 24 degree-`n` parity-separation checks;
* 500/500 random false-instance key recoveries for an `n=8`, degree-5 hidden polynomial binder over `F_101`;
* exhaustive `q=3,n=3,r=2` hidden-polynomial enumeration: 6,561 setups per key, 19,683 decoder checks total, and zero transcript-support intersections between every pair of distinct keys;
* explicit `r`-wise even/odd seed generators for `(n,r)=(8,2),(8,3),(8,4),(16,2)`, checking every monomial subset through degree `r`; the seed-multiset sizes were `64,512,4096,256` respectively;
* 200/200 efficient degree-3 false-key recoveries at `n=8,q=101`, using exactly 512 even seeds and 512 toggled odd seeds per attack (`1,024` local evaluations, versus 93 monomial coefficients);
* exhaustive degree-`n` parity-character control at `q=5,n=4`: all five key-conditioned complete-table distributions were exactly identical;
* 501 exact inclusion-exclusion monomial checks for the missing-all-ones certificate for `2<=n<=8`.

These are finite algebra/distribution checks. They do not prove security for a surviving construction, do not use quantum hardware, and do not establish the arbitrary-QPT source-witness reduction.

## 9. What is proved, what is conjectural, and what remains

**Proved:** any zero-sum binder linear in a finite hidden coefficient vector has an exact complete-table criterion: key recovery iff the affine hulls of the public feature images intersect. This remains true for nonlinear public features.

**Proved:** every degree-`r<n` multilinear polynomial binder fails on the false even/odd parity pair in the complete-table model. For every fixed `r`, there is an explicit `n^r`-seed public attack, so the failure is computationally efficient when the intended local evaluation interface is efficiently callable.

**Implemented and tested:** the theorem checks, parity moments, explicit `r`-wise generators, random/exhaustive false-key recovery, and the sparse degree-`n` positive control listed above.

**Positive control, not a generic solution:** a one-feature degree-`n` parity character hides the key perfectly on this particular false pair while preserving same-point cancellation. This shows that growing algebraic degree or a statement-aware high-degree feature can change the geometry without requiring a dense exponential monomial basis.

**Conjectural next direction:** a viable consistency layer would need either (a) a polynomial-size statement-aware feature family whose local feature-image hull intersection provably implies a source witness, despite the false-moment examples above, or (b) a binder nonlinear/computational in its **hidden secret** so that complete local evaluations do not reduce to interpolation in a public finite feature space. Route (b) would need an independently justified PQ assumption and must not merely assume a PRF/WE-like evaluator that already contains the missing release primitive.

**Still unresolved:** the actual generic-NP inner WKEM, a full-output reduction from arbitrary QPT early key recovery to source-witness extraction or an independently justified PQ break, malicious-secure setup composition for that inner primitive, concrete end-to-end parameters, and reproducible full-system validation.

The stopping condition is not met.
