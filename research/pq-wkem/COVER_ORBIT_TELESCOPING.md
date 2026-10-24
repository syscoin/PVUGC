# Cover-orbit attacks on higher-locality telescoping encodings

## Status

This continuation starts from PR head
`df64840da5f432e6180bd9c766bde5c04d45ec88` and the preceding
`LINEAR_MAC_FLOW_TABLE.md` result.

It makes a constructive attempt to repair affine-flow splicing by:

1. replacing one-bit/one-vertex pads with arbitrary finite-radius local states;
2. allowing the transfer law to live in an arbitrary finite abelian group,
   including exponent-2 groups intended to block division by 2;
3. then trying a nonabelian matrix/conjugacy version after the abelian repair
   fails.

All three are public offline transfers. Setup knows the statement and chooses
temporary random pads, but does not know a source witness. A legitimate globally
consistent local path recovers the same target after pads telescope.

The result is negative for these candidates:

* **Abelian cover-orbit theorem.** Every monodromy orbit of length `h` publicly
  exposes `h*K`. Two public orbits of coprime lengths expose `K` itself by
  Bezout, over *every* abelian group. This does not require division, discrete
  logarithms, a field structure, or a fractional LP solution.
* Therefore changing the transfer group to large 2-torsion does not repair the
  generic mechanism: a false 5-state local cover with orbit lengths 2 and 3
  exposes both `2K` and `3K`, hence `K=3K-2K`.
* **Nonabelian matrix/conjugacy attempt.** Replacing additive pads by
  conjugating frames converts an `h`-cycle into a public conjugate of `K^h`.
  For the implemented semisimple matrix family, conjugacy classes of `K^2`
  and `K^3` recover the conjugacy class of `K` efficiently by matching squared
  and cubed eigenvalues. Thus this natural nonabelian repair also fails on the
  same 2+3 cover, without using the earlier matrix inner-inverse attack.

These are architecture-specific theorems/counterexamples. They do not prove
impossibility of all nonlinear, nonlocal, or computational witness encodings.

No external literature or web search was used.

## 1. Higher-locality transfer as a local-state cover

Let layers be `i=0,...,n-1`. At layer i there is a finite public local-state set
`S_i`. Legal local extension is a bijection

    tau_i : S_i -> S_(i+1).

The maps may encode an arbitrarily large fixed-radius witness window, not merely
one variable. A global witness is a state `s in S_0` fixed by the monodromy

    pi = tau_(n-1) ... tau_1 tau_0.

This is the exact situation obtained when a finite-radius consistency table is
unrolled around a cyclic CSP: each legal window determines the next legal
window, and a globally consistent assignment is a closed lift.

A false source instance may have no fixed point even though every local
transition is legal.

The key question is whether secret random local pads can make the public
transition tokens reveal a common key only on fixed points.

## 2. Abelian telescoping candidate

Let `G` be any finite abelian group, written additively. Setup chooses:

* pads `r_(i,s) in G`;
* layer shares `k_i in G`;
* target `K=sum_i k_i`.

It publishes, for every legal local transition,

    T_(i,s) = k_i + r_(i,s) - r_(i+1,tau_i(s)).       (1)

A genuine fixed point gives a closed lifted path and therefore

    sum_i T_(i,s_i) = K.                              (2)

This works for arbitrary local-state radius and requires no participant online
after setup.

### Cover-orbit theorem

Let

    O = (s, pi(s), ..., pi^(h-1)(s))

be a monodromy orbit of length `h`. For each start state in O, follow one whole
n-layer lap and sum its public tokens. Summing those h lap-values gives

    h K.                                               (3)

Proof: every layer share k_i appears exactly h times. At every layer, the h
source pads are the same multiset as the h destination pads because the lifted
transition maps the orbit bijectively to itself. Hence every pad cancels.
Nothing else is used.

This is a complete-public-output identity.

Consequences:

* If multiplication by h is invertible on G, (3) gives K directly.
* In general, observing hK leaves at most a coset of the h-torsion subgroup

      G[h] = {g : h g = 0}.

  For uniform K, the number of compatible keys is exactly `|G[h]|` on an
  observed image point.
* If the false cover has public orbits of lengths h1,...,ht with

      gcd(h1,...,ht)=1,

  then Bezout coefficients `a_j` give

      K = sum_j a_j (h_j K).                           (4)

  This recovers K over **every abelian group**, regardless of characteristic or
  torsion.

No scalar division and no discrete logarithm are required.

## 3. Why exponent-2 / XOR pads do not give generic security

A binary odd-parity cover has a two-cycle monodromy. In an exponent-2 group,
its orbit sum gives `2K=0`, so this *does* block the naive divide-by-two attack.
That motivated the constructive repair.

But use a five-state local alphabet and a false monodromy

    pi = (0 1)(2 3 4).                                (5)

There is no fixed state, hence no global witness. All local transitions are
nevertheless legal.

The two public cover orbits give

    A_2 = 2K,
    A_3 = 3K.

Therefore

    K = A_3 - A_2.                                    (6)

For `G=(Z_2)^lambda`, `A_2=0` and `A_3=K`, so the attempted 2-torsion repair is
especially transparent.

The five-state relation is still a Boolean NP relation after encoding each
state with three bits and checking the fixed local permutation by a constant
size Boolean circuit. It is used here only as a diagnostic false instance for
the transfer architecture; this does not assert hardness of that toy relation.

The same statement applies in multiplicative notation. If

    T_(i,s) = k_i * r_(i,s) / r_(i+1,tau_i(s))

in an abelian multiplicative group, the two cover products are `K^2` and `K^3`,
and

    K = K^3 / K^2.                                    (7)

Again no discrete logarithm is involved.

Thus neither moving from a field to an arbitrary abelian group nor tuning its
torsion fixes this telescoping mechanism.

## 4. Nonabelian conjugacy transfer: constructive attempt

The abelian theorem suggests preserving path order in a noncommutative group.

Let `G` now be a nonabelian group. Setup chooses local frames `R_(i,s)` and
ordered layer factors `K_i`; put

    K = K_0 K_1 ... K_(n-1).

Publish

    C_(i,s)
      = R_(i,s)^(-1) K_i R_(i+1,tau_i(s)).             (8)

For a genuine fixed-point path starting at s,

    product_i C_(i,s_i)
      = R_(0,s)^(-1) K R_(0,s).                        (9)

Thus all valid witnesses recover the same **conjugacy class** of K. Setup can
derive a key from a canonical conjugacy invariant and erase its frames.

This is genuinely nonlinear/nonabelian relative to the preceding affine-flow
table.

### False cover output

For a monodromy orbit of length h, concatenate the h public one-lap products in
orbit order. Adjacent frames cancel and give

    R_(0,s)^(-1) K^h R_(0,s).                          (10)

So the false 2+3 cover exposes the conjugacy classes of `K^2` and `K^3`.

A secure version would need the conjugacy class of K to remain hidden from those
two coprime powers.

## 5. Semisimple matrix groups fail the coprime-power test

Instantiate (8) in `GL_d(F_q)`. Choose K diagonalizable over F_q with distinct
nonzero eigenvalues

    lambda_1,...,lambda_d

whose sixth powers are also distinct. A conjugate of K^2 publicly reveals the
multiset

    A = {lambda_i^2},

and a conjugate of K^3 reveals

    B = {lambda_i^3},

for example by characteristic-polynomial factorization.

For `a in A` and `b in B`, put an edge when

    a^3 = b^2.                                         (11)

If `a=lambda_i^2` and `b=lambda_j^3`, (11) means

    lambda_i^6 = lambda_j^6.

Distinct sixth powers therefore make the matching unique, with j=i. Then

    lambda_i = b / a.                                  (12)

The attacker recovers the eigenvalue multiset of K, hence its conjugacy class
because K is semisimple with distinct eigenvalues.

This attack uses only public matrix multiplication, inversion, characteristic
polynomials / field factorization, and field division. It does **not** use the
earlier public-inner-inverse splice.

The implemented checker extracts eigenvalues by exhaustive field evaluation
because its fields are deliberately tiny algebra fixtures. Polynomial
factorization would replace that step at real dimensions.

This rejects the explicit semisimple matrix/conjugacy repair. It does not prove
that every nonabelian group has efficiently invertible coprime-power conjugacy
data. Treating "hard conjugacy root extraction" as a new assumption would merely
move the missing cryptographic obligation unless independently justified.

## 6. Relation to the preceding flow-table result

`LINEAR_MAC_FLOW_TABLE.md` showed that a one-vertex field table can leak through
an affine flow, including an acyclic DAG example.

The present result is different and stronger in three directions:

1. states may encode arbitrarily large finite local witness windows;
2. the abelian proof does not rely on vector-space linear algebra or fractional
   coefficients;
3. the false attack is a literal public finite cover. Coprime orbit sums recover
   the target over any abelian group.

So "increase local overlap", "switch to XOR pads", and "switch to a
multiplicative abelian group" are all closed within this architecture.

The nonabelian section then tests the most direct order-sensitive escape and
finds a separate coprime-power attack for ordinary semisimple matrix groups.

## 7. What remains open

A surviving construction must leave this architecture in a substantive way. In
particular, it needs at least one of:

* a global consistency mechanism not expressible as finite-cover telescoping;
* a nonabelian/computational state representation where coprime-power public
  cover data provably does not reveal the valid-path key under an independently
  justified PQ assumption;
* a different inner primitive whose arbitrary-QPT key-recovery reduction
  reaches the already established source extractor.

Even if such an inner transfer is found, the required true-instance
`early key recovery -> source witness / independent PQ break` reduction,
malicious-secure ceremony composition, and concrete resource estimates remain
separate obligations.

No completed generic PQ WKEM is claimed here.

## 8. Validation actually executed

`cover_orbit_check.py` is standard-library only. It performs:

* 700 additive trials across moduli 2,4,6,8,12,15,101 on the five-state 2+3
  cover; every trial reconstructs exactly `2K`, `3K`, then K by (6);
* 300 multiplicative trials in F_17^*, F_29^*, F_101^*; every trial reconstructs
  `K^2`, `K^3`, then K by (7);
* 120 nonabelian `GL_2(F_101)` trials with secret random conjugating frames and
  semisimple K having distinct sixth powers; every trial reconstructs public
  conjugates of `K^2` and `K^3`, extracts and uniquely matches their eigenvalues,
  and recovers the canonical eigenvalue key of K;
* explicit checks that the monodromy (5) has no fixed point and that the two
  public orbit lengths are exactly 2 and 3.

These are exact finite-algebra checks of the formulas above. They are not
cryptographic security experiments and do not establish hardness for any
surviving construction.
