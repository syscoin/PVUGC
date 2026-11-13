# Succinct high-degree product binders: one-query hiding and complete-output finite-difference recovery

**Status:** constructive nonlinear-in-secret consistency attempt, positive one-query hiding theorem, exact complete-output false-instance attack, and a statement-independent finite-feature lower bound. This is **not** a completed WKEM, a PQ security proof, or a deployment recommendation. Production code is unchanged.

Starting verified PR head: `3dd01719369954391d5d5b76667ffb824506b983`.

This run starts from `POLYNOMIAL_BINDER_MOMENT_BARRIER.md`. Run 27 ruled out the natural bounded-dimensional binder

    f_j(x) = k_j + <a_j, phi(x)>

whenever complete local evaluation access makes the feature-image affine hulls intersect. It also recorded a useful positive control: the high-degree parity character is succinct and defeats that specific parity false splice. The open route was therefore a binder that is both succinct/high-degree and genuinely nonlinear in its **hidden secret**, rather than merely nonlinear in the public representation `x`.

The candidate below does exactly that. It has a real one-query statistical hiding property on false pairs. Nevertheless, the complete public output on a very small false candidate family gives a constant-query finite-difference attack that recovers the key for **every setup randomness**, including degenerate seeds. Thus the result separates a genuine local positive property from full-output security, rather than rejecting the candidate by reusing Run 27's feature-hull theorem.

No external literature or web search was used.

## 1. Constructive attempt: a hidden rank-one product carrier

Work over an odd prime field `F_q`. Let the Boolean representation be

    x = (x_1,...,x_n) in {0,1}^n,

with `n>=3`. Setup samples

    r, a_1,...,a_n <- F_q

and defines the hidden high-degree carrier

    P_(r,a)(x) = r * product_(i=1)^n (a_i + x_i).       (1)

For two local blocks, sample

    k_0 <- F_q,
    k_1 = K-k_0,

and let the intended locally recoverable values be

    f_0(x) = k_0 + P_(r,a)(x),
    f_1(x) = k_1 - P_(r,a)(x).                         (2)

The carrier has algebraic degree `n` in `x`, but only `n+1` hidden field parameters and `O(n)` arithmetic-circuit size when those parameters are available. Because the parameters occur multiplicatively, this is not a finite public feature map with a hidden linear coefficient vector of the Run-27 form.

### Exact common-representation correctness

For every `x`,

    f_0(x)+f_1(x)=K.                                   (3)

Thus any genuine common representation recovers the same key exactly. Setup does not need to know which representation is valid.

This is only a consistency-layer candidate: as in Runs 26-27, the local capsule would still have to expose `f_j(x)` only to locally admissible representations. The audit below deliberately grants exactly that intended local interface and no additional setup secret.

## 2. Positive result: a single false pair is statistically hidden

The candidate is not vacuously broken at the one-query level.

Let `u != v` be two Boolean points and suppose block 0 is queried only at `u` while block 1 is queried only at `v`. Their sum is

    f_0(u)+f_1(v)
      = K + Z,

where

    Z = r * Delta_a(u,v),
    Delta_a(u,v)
      = product_i(a_i+u_i) - product_i(a_i+v_i).        (4)

Because `u != v`, the polynomial `Delta_a(u,v)` is nonzero. Its total degree is at most `n-1`: the common degree-`n` monomial cancels.

Let

    p_0 = Pr_a[Delta_a(u,v)=0].                         (5)

Conditioned on `Delta != 0`, multiplication by uniform `r` makes `Z` exactly uniform on `F_q`. Conditioned on `Delta=0`, `Z=0`. Hence

    Law(Z) = p_0 * delta_0 + (1-p_0) * Uniform(F_q).   (6)

Since the hidden share `k_0` is uniform, the full two-coordinate transcript contains no more key dependence than this shifted sum. For any two distinct keys `K,K'`, therefore,

    TV(Transcript_K, Transcript_K') = p_0.             (7)

By the elementary Schwartz-Zippel bound,

    p_0 <= (n-1)/q.                                    (8)

Thus with a sufficiently large field the **single-pair** false transcript is statistically close to key independent. For the exhaustive control `q=5,n=3,u=000,v=100`, the checker obtains

    p_0 = TV = 9/25 <= 2/5.                            (9)

This is an actual positive theorem for the proposed nonlinear carrier. It is also precisely why the complete-output audit matters: one cannot reject the construction by looking only at one inconsistent pair.

## 3. Complete-output false instance

Consider the following two disjoint local candidate sets:

    S_0 = { (0,s,t,0,...,0) : s,t in {0,1} },
    S_1 = { (1,s,t,0,...,0) : s,t in {0,1} }.          (10)

They are disjoint because block 0 requires `x_1=0` while block 1 requires `x_1=1`. Thus the global common-representation statement is false. Both predicates have constant-size descriptions apart from the witness length.

Let

    R = r * product_(i=4)^n a_i,                       (11)

with the empty product interpreted as one when `n=3`. On these two faces,

    P(0,s,t,0,...,0)
      = R a_1 (a_2+s)(a_3+t),

    P(1,s,t,0,...,0)
      = R (a_1+1)(a_2+s)(a_3+t).                       (12)

Write the complete local values as

    Y_b(s,t) = f_b(b,s,t,0,...,0).                     (13)

Only eight field elements are used by the attack.

## 4. Exact finite-difference attack

Define the mixed second differences

    D_b = Y_b(1,1)-Y_b(1,0)-Y_b(0,1)+Y_b(0,0).         (14)

The additive key shares disappear. Direct expansion gives

    D_0 = R a_1,
    D_1 = -R(a_1+1).                                   (15)

Therefore the shared tail factor is public:

    R = -(D_0+D_1).                                    (16)

Now define first differences along the two free coordinates:

    E_b = Y_b(1,0)-Y_b(0,0),
    F_b = Y_b(0,1)-Y_b(0,0).                           (17)

Again by direct expansion,

    E_0+E_1 = -R a_3,
    F_0+F_1 = -R a_2.                                  (18)

Finally the two baseline entries satisfy

    B := Y_0(0,0)+Y_1(0,0)
       = K - R a_2 a_3.                                (19)

### Case 1: `R=0`

Then the carrier vanishes on all eight queried points, so (19) immediately gives

    K = B.                                             (20)

### Case 2: `R!=0`

Public division in `F_q` yields

    a_3 = -(E_0+E_1)/R,
    a_2 = -(F_0+F_1)/R,                                (21)

and therefore

    K = B + R a_2 a_3.                                 (22)

So **every** setup randomness is broken. There is no bad-seed probability and no witness search. The source statement is false, so source-witness extraction is impossible; the construction simply violates false-instance hiding.

The attack is constant query and constant algebraic work after eight local evaluations. It also does not need to recover `a_1`, `r`, or the individual tail factors `a_4,...,a_n`.

## 5. Why this is a complete-output failure, not a return to public feature interpolation

Run 27's theorem applies when the hidden secret enters linearly through a public finite feature vector. Here

    P_(r,a)(x)=r product_i(a_i+x_i)

is nonlinear in the hidden parameters. The one-query theorem in Section 2 confirms that this change has a real effect: a single inconsistent pair can be statistically hiding.

The failure appears only after the adversary combines several intended local evaluations. Finite differences cancel the unknown block offsets and expose low-dimensional algebraic invariants of the shared hidden carrier. The two contradictory faces then provide enough cross-face relations to reconstruct the exact correction term in (19).

Thus the new lesson is not merely "high degree fails." It is:

> A succinct high-degree carrier can still be globally learnable from the complete witness-restricted evaluation surface because low-dimensional restrictions expose algebraic derivatives of its shared hidden state.

Adding a hidden constant to `P` does not help: it cancels from every finite difference and from `P(x)-P(y)`. Multiplying by the fresh random scale `r` was already included and is exactly what gives the positive single-pair hiding theorem; the complete-face attack still recovers the scaled tail `R`.

This result is scoped to the rank-one product family and its direct constant-shift/scale variants. It is not an impossibility theorem for arbitrary succinct nonlinear hidden functions.

## 6. Noisy local decoders

Suppose the underlying local capsule does not reveal exact values deterministically, but each of the eight chosen candidate evaluations can be decoded with failure probability at most `epsilon` after whatever allowed local amplification is used.

The finite-difference decoder is exact whenever all eight local values are correct. Therefore, without **any** independence assumption among decoder errors,

    Pr[key recovery] >= 1 - 8 epsilon                   (23)

by a union bound.

So polynomial repetition that drives honest/local error below inverse polynomial also drives this explicit false-instance attack to high success. This is the same conservative success accounting used in Runs 26-27: no independent-error assumption is needed.

## 7. Additional lower bound: statement-independent finite features need exponential dimension

Run 27 left a possible escape through a statement-aware high-degree feature family. There is a simple reason the word **statement-aware** is essential.

Let a public feature map

    phi : X -> F_q^m                                   (24)

be fixed independently of the eventual local candidate sets. Suppose `|X|>=m+2`. Pick any `m+2` distinct points `x_1,...,x_(m+2)`. Their lifted vectors

    (1,phi(x_i)) in F_q^(m+1)                          (25)

are linearly dependent. Hence there are coefficients `alpha_i`, not all zero, with

    sum_i alpha_i = 0,
    sum_i alpha_i phi(x_i) = 0.                        (26)

Choose `i*` with `alpha_(i*) != 0`. Rearranging gives

    phi(x_(i*))
      = sum_(i != i*) lambda_i phi(x_i),

    lambda_i = -alpha_i/alpha_(i*),
    sum_(i != i*) lambda_i = 1.                        (27)

Therefore the disjoint sets

    A = {x_(i*)},
    B = {x_i : i != i*, alpha_i != 0}                  (28)

have intersecting feature-image affine hulls. By Run 27's exact theorem, the two-block zero-sum linear-secret binder leaks the key on the false statement `x in A` and `x in B`.

### Efficient adversarial construction

If `m=poly(n)` and `phi` is efficiently evaluable and fixed before the statement, an adversary needs only `m+2` explicit Boolean points, `m+2` feature evaluations, and one Gaussian-elimination nullspace computation. The sets `A,B` contain at most `m+2` listed points, so their membership predicates have polynomial-size descriptions.

Consequently, to guarantee separation for **all** disjoint candidate-set pairs with a statement-independent feature map, the lifted points must be linearly independent. This requires

    m >= |X|-1.                                        (29)

For `X={0,1}^n`, that is

    m >= 2^n-1.                                        (30)

This is an information-theoretic lower bound for the statement-independent finite-feature/linear-hidden-secret route. It does **not** rule out a feature map generated from the statement itself; the dependence argument chooses the false sets after seeing `phi`, so a statement-aware compiler avoids this direct diagonalization. It also does not apply to the nonlinear-hidden-secret product carrier of Sections 1-6.

The checker generated 400 random feature maps over `F_101` with dimensions 1 through 8, constructed the lifted nullspace certificate each time, and recovered the key in 1,200/1,200 fresh hidden-coefficient trials. The largest certificate used ten points, exactly the `m+2` bound in that range.

## 8. Fresh validation actually executed

`product_binder_check.py` is standard-library only. The captured run records:

* 2,000/2,000 exact same-representation key decodes for the product carrier at `q=101,n=8`;
* exhaustive one-pair transcript distributions at `q=5,n=3`: 3,125 setups per key, exact pairwise TV `9/25`, exactly equal to the independently enumerated `Delta=0` probability and below the `2/5` Schwartz-Zippel bound;
* nine additional exact `Delta=0` probability controls across `(q,n)=(5,3),(7,4),(11,5)`, all within `(n-1)/q`;
* 1,000 direct finite-difference identity checks over `F_101` for `n in {3,4,8,16}`;
* exact false-partition recovery in 1,000/1,000 random `q=101,n=3` trials, 2,000/2,000 random `q=101,n=8` trials, 1,000/1,000 random `q=101,n=16` trials, and 1,000/1,000 random `q=1009,n=12` trials;
* exhaustive `q=5,n=3` false-partition recovery over 6,250 setups for keys 0 and 1 combined; the two complete-transcript supports had intersection zero, hence exact TV distance one;
* 400 random statement-independent finite feature maps over `F_101`, with a lifted affine-dependence false certificate found in every case and 1,200/1,200 corresponding false-key recoveries.

These tests validate the finite-field identities, exact finite enumerations, and explicit attacks. They do not establish security for a surviving construction, do not use quantum hardware, and do not prove the missing arbitrary-QPT source-witness reduction.

## 9. Proved claims, implemented algorithms, conjectures, and remaining gap

**Proved:** the rank-one product carrier has exact common-representation correctness.

**Proved positive property:** for one inconsistent pair `u!=v`, the complete two-coordinate transcript has pairwise key statistical distance exactly `Pr[Delta_a(u,v)=0]`, at most `(n-1)/q`.

**Proved break:** the eight local evaluations on the contradictory faces (10) recover `K` exactly for every setup randomness via (14)-(22). Under per-evaluation failure at most `epsilon`, success is at least `1-8 epsilon` with no independence assumption.

**Proved lower bound:** any statement-independent feature map whose zero-sum linear-hidden-secret binder must separate every disjoint candidate-set pair requires feature dimension at least `|X|-1`; otherwise an efficiently constructible `m+2`-point false certificate exists when the map is efficiently evaluable and `m` is polynomial.

**Implemented and tested:** the product carrier, exact face decoder, exhaustive false-instance support comparison, one-pair distribution enumeration, Schwartz-Zippel controls, and lifted-feature nullspace certificate listed above.

**Not proved / not claimed:** a generic impossibility for all succinct nonlinear hidden function families; hardness of learning arbitrary arithmetic circuits from restricted evaluations; or security from the absence of another attack.

**Remaining central obligation:** construct a polynomial-size statement-aware or computationally hidden witness-restricted evaluator whose *joint complete public output* does not permit interpolation, finite-cover combination, pseudo-functional quotienting, shared-seed reconstruction, intertwiner recovery, or finite-difference learning, while giving every valid witness the same key and admitting an actual reduction from arbitrary QPT early key recovery to a source witness or an independently justified PQ assumption. A hidden PRF/evaluator cannot simply be assumed, because that would repackage the missing WE-like release primitive.

The conditional N-of-N ceremony theorem from Run 19 remains available only after such an inner primitive exists. Full end-to-end parameters and malicious-secure setup composition therefore remain downstream.

The stopping condition is not met.
