# Randomized same-key representatives: an information-theoretic finite-cover repair

Starting checkpoint: PR #1 head
`15f37c7f263946fd40fd2327802c28d875165f60`.

## Status

This pass changes the failed common-target transfer architecture. A valid state no longer carries the same additive element `K`. Instead, for one session-key symbol `k in F_q^*`, setup associates each candidate base state `s` with an independent random vector

    V_s <- S_k := {v in F_q^d : Q(v)=k},

where

    Q(v)=v_1^2+...+v_d^2.

A real fixed-point witness recovers one `V_s` and therefore the common key by computing the nonlinear invariant `Q(V_s)=k`. A false cover orbit of length `h>=2` sees only a sum of `h` independent sphere representatives. Those sums are statistically close to uniform in high dimension.

For an explicit finite permutation cover this removes the exact `2K,3K` Bezout leakage and the constant-factor noisy-cover leakage from the previous checkpoints. The proof below audits the complete public transcript, not only an intended decoder.

This is **not yet a generic-NP WKEM**. The construction samples one independent sphere representative per explicit base state. If the state space is made large enough that finding a fixed point can encode a generic NP witness, this output is exponential unless one has a succinct hidden programmable evaluator. Publishing an ordinary evaluator that contains the representative-generation secret exposes `k`; assuming an evaluator that releases the invariant only on a fixed point would simply restate the missing witness-restricted encoding. Thus the result is a positive finite-cover primitive plus a precise succinctification barrier, not the stopping condition.

No external literature or web search was used. Production code is unchanged.

## 1. Explicit permutation-cover construction

Let layers be `i=0,...,n-1`, with finite public state sets `S_i` and public bijections

    tau_i : S_i -> S_(i+1 mod n).

Let

    pi = tau_(n-1) ... tau_0

be the monodromy on `S_0`. A source witness in this restricted model is a fixed point `s=pi(s)`.

Let `V=F_q^d`, for odd prime q. Setup chooses:

* a nonzero key symbol `k in F_q^*`;
* independently for every `s in S_0`, a uniform `v_s in S_k`;
* independent uniform pads `r_(i,s) in V` at every layered vertex.

Only the first layer carries a representative. Publish vector tokens

    Y_(0,s) = v_s + r_(0,s) - r_(1,tau_0(s)),           (1)

and for `i>0`,

    Y_(i,s) = r_(i,s) - r_(i+1,tau_i(s)).               (2)

All arithmetic is in `V`.

### Honest correctness

For a one-lap path starting from `s in S_0`, summing its n public tokens gives

    L_s = v_s + r_(0,s) - r_(0,pi(s)).                  (3)

If s is a source witness (`pi(s)=s`), the pad cancels exactly:

    L_s = v_s,
    Q(L_s) = k.                                         (4)

Thus every valid fixed point returns the same key symbol even though different witnesses receive independent representatives.

This differs fundamentally from the rejected common-target tables: the common object is the **nonlinear invariant Q**, not a common additive group element.

## 2. Complete public-output normal form

The layered graph has one outgoing and one incoming edge at every vertex, hence is a disjoint union of directed cycles. A monodromy orbit

    O=(s,pi(s),...,pi^(h-1)(s))

corresponds to one directed layered cycle of length `nh`.

For a directed component C, write its edge messages `m_e`; exactly h of those messages are the independent representatives `{v_s : s in O}`, and the other messages are zero. The published edge vector is

    Y_e = m_e + r_tail(e) - r_head(e).                  (5)

The incidence map from vertex pads to edge differences has image

    H_C = { (z_e)_e : sum_(e in C) z_e = 0 },           (6)

and kernel consisting exactly of a common additive shift of every pad on C. Therefore uniform vertex pads induce the uniform distribution on `H_C`. Conditioned on the cycle sum

    Z_O = sum_(s in O) v_s,                             (7)

the **entire public edge transcript on C** is uniform on the affine fiber

    { (y_e)_e : sum_(e in C) y_e = Z_O }.               (8)

Equivalently, a perfect simulator given only `Z_O` may choose all but one edge uniformly and set the final edge to make the sum equal `Z_O`.

Consequences:

1. The complete transcript contains no more key information than the collection of orbit sums `{Z_O}`.
2. Different monodromy orbits are independent because they use disjoint pads and independent representatives.
3. Total-variation distance between full transcripts is controlled by the product distribution of the orbit sums; there is no hidden extra leakage in individual edges.

This is stronger than merely observing that pads telescope.

## 3. Fourier bound for one quadratic sphere

Let

    mu_k = Uniform(S_k)

on the additive group `V=F_q^d`, and let

    psi(t)=exp(2 pi i t/q).

For frequency `xi in V`, define

    muhat_k(xi) = E_(X<-mu_k)[ psi(<xi,X>) ].            (9)

For nonzero `xi`, use the additive-character expansion

    1[Q(x)=k]
      = q^(-1) sum_(t in F_q) psi(t(Q(x)-k)).            (10)

The `t=0` contribution to the numerator of (9) vanishes when `xi!=0`. For each `t!=0`, completing the square in every coordinate reduces the inner sum to a product of d quadratic Gauss sums. Each one-dimensional Gauss sum has magnitude `sqrt(q)`, so every product has magnitude `q^(d/2)`. The triangle inequality therefore gives

    | sum_(x:Q(x)=k) psi(<xi,x>) | < q^(d/2).           (11)

The same expansion at `xi=0` gives

    | |S_k| - q^(d-1) | < q^(d/2).                      (12)

For nonzero k and `d>=4`, put

    beta_(q,d)
      = q^(1-d/2) / (1-q^(1-d/2)).                     (13)

Then

    |muhat_k(xi)| <= beta_(q,d)       for xi != 0.      (14)

No Weil/Kloosterman bound is used here; the elementary Gauss-magnitude bound and an ordinary triangle inequality suffice.

## 4. Two representatives already mix

For h independent representatives,

    Z_h = X_1+...+X_h,

Fourier convolution gives

    E[psi(<xi,Z_h>)] = muhat_k(xi)^h.                   (15)

Parseval and Cauchy-Schwarz for the finite additive group imply

    TV(mu_k^{*h}, U_V)
      <= 1/2 sqrt( sum_(xi!=0) |muhat_k(xi)|^(2h) )
      <= 1/2 q^(d/2) beta_(q,d)^h.                     (16)

Every false monodromy orbit has `h>=2`, so it is enough to define

    eps_(q,d)
      = 1/2 q^(d/2) beta_(q,d)^2
      = q^(2-d/2) / (2(1-q^(1-d/2))^2).                (17)

Then every false orbit sum is at most `eps_(q,d)` from the same key-independent uniform distribution.

If a false cover has c monodromy orbits, a standard product hybrid gives

    TV( Transcript_k, Transcript_k' )
      <= 2 c eps_(q,d)                                  (18)

for any two nonzero key symbols k,k'. This is a complete-public-output, information-theoretic bound.

### Why the saved 2+3 cover no longer breaks

The old common-target table exposed exact `2K` and `3K`; with iid additive noise it exposed `K` with only a fivefold noise footprint.

Here the same two orbits expose

    Z_2 = X_1+X_2,
    Z_3 = X_3+X_4+X_5,                                 (19)

where all five X_i are independent uniforms on the sphere `Q(X)=k`. Neither is a scalar multiple of one common secret. By (16), `Z_2` is already close to uniform and `Z_3` is even closer. Bezout subtraction has no stable target to recover.

The checker exhaustively confirms this distinction on small fields.

## 5. General linear-combination mixing lemma

The same argument is not limited to coefficients 1. If

    W = a_1 X_1 + ... + a_h X_h,

with independent `X_j <- S_k` and every `a_j != 0`, then scaling a frequency by `a_j` merely permutes the nonzero frequencies. Therefore

    TV(W,U_V) <= 1/2 q^(d/2) beta_(q,d)^h.              (20)

So any public false linear functional that necessarily contains at least two **independent representative identities** is statistically washed out.

This is the useful design lesson from the construction: randomized same-key fibers can defeat constant-support fractional/cover combinations even when ordinary additive noise cannot.

It does **not** establish that every pseudowitness of a generic-NP compiler must involve at least two independent representatives. Constructing a succinct compiler with that property is the remaining central problem.

## 6. Concrete finite-cover parameters

For `d=8`, (17) becomes

    eps_(q,8)
      = 1 / (2 q^2 (1-q^(-3))^2).                      (21)

Thus a q of about kappa bits gives roughly `2*kappa` bits of statistical margin per false orbit before the polynomial orbit-count loss. One vector token uses 8 field elements, i.e. about `8*kappa` bits when `log2(q)~=kappa`.

The key symbol itself has `log2(q-1)` bits of entropy. A conventional KDF may compress it to the desired session-key length; that does not increase the information-theoretic entropy proven here.

These numbers are only for the explicit finite-cover primitive. They are not end-to-end generic-NP resource estimates because the number of explicit base states is the unresolved scaling issue.

## 7. Exact polynomial-time sphere sampling for q = 3 mod 4

The proof uses exact uniform sphere representatives. This need not require `Theta(q)` rejection.

Assume prime `q = 3 mod 4`, so `-1` is a nonsquare. Split

    Q(x)=Q(prefix)+a^2+b^2.

For a fixed residual `r`, the number of pairs `(a,b)` satisfying

    a^2+b^2=r

is exactly `q+1` for `r!=0` and exactly 1 for `r=0`.

An exact sampler is:

1. choose the first `d-2` coordinates uniformly;
2. set `r=k-Q(prefix)`;
3. if `r!=0`, accept the prefix; if `r=0`, accept it with probability `1/(q+1)`;
4. conditioned on acceptance, choose a uniform solution of `a^2+b^2=r`.

Every sphere point then has the same pre-normalization probability

    1 / (q^(d-2) (q+1)).                               (22)

For `r!=0`, a uniform solution can be generated in the quadratic extension `F_q[i]`, `i^2=-1`: find one element `z_0` with norm r, sample uniform nonzero t, form the uniform norm-one element `u=t/t^q`, and output `z_0 u`. A suitable `z_0` follows from one square root if r is a square; for nonsquare r, multiply a fixed public extension element of nonsquare norm by a square root of the quotient. For `q=3 mod 4`, square roots are ordinary modular exponentiations.

The prefix rejection probability is `O(1/q)`, so expected work is constant plus polynomial-time field arithmetic.

The checker validates the `q+1`/1 pair counts and the equal-weight identity for small `q=3 mod 4` fields.

## 8. What this proves and what it does not

### Proved here

* exact same-key correctness for every fixed point of an explicit finite permutation cover;
* an exact complete-transcript normal form: each cover component is a uniform affine fiber determined only by the sum of its sphere representatives;
* an elementary Fourier bound showing every false orbit of length at least 2 is statistically close to key-independent uniform;
* pairwise false-key transcript distance at most `2 c eps_(q,d)`;
* a polynomial-time exact uniform sphere sampler for primes `q=3 mod 4`;
* the same mixing bound for arbitrary nonzero linear coefficients on at least two independent representatives.

### Implemented and tested

`sphere_representative_check.py` exhaustively checks small-field sphere counts, convolutions, complete-transcript fiber multiplicities, the 2+3 diagnostic cover, non-unit coefficient mixing, and the exact sampler weighting identity. The captured JSON records only tests actually executed.

### Remaining central gap

This construction assigns independent hidden representatives to explicit base states. If there are only polynomially many explicit states, the fixed points are themselves easy to enumerate; if states encode generic NP witnesses, there are exponentially many and setup/output become exponential.

A secure generic-NP construction therefore still needs a **succinct hidden representative generator / consistency mechanism** that:

1. lets every valid witness obtain one representative with invariant k;
2. does not let the public evaluate an unmasked representative at arbitrary candidate witnesses;
3. makes every false/public pseudowitness combine at least two independent representative identities (or otherwise mix to hiding);
4. comes with an arbitrary-QPT key-recovery -> source-witness / independent-PQ reduction rather than assuming that release property.

An ordinary public circuit containing the representative-generation seed fails item 2 immediately. Assuming a circuit that hides the seed while conditionally releasing the representative would be an obfuscation/WE-equivalent shortcut and is not claimed here.

The stopping condition is therefore not met.
