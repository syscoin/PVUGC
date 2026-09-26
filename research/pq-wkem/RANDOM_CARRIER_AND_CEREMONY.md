# Random-carrier ideal masking and conditional N-of-N ceremony composition

Starting checkpoint: PR #1 head
`ed58c74e56de5b4738fc114d0e3cd1ae73db66dd`.

This continuation does **not** complete a generic witness KEM.  It records:

1. a fresh constructive attempt that removes the previous public additive target:
   hide the key behind a random witness-evaluable carrier/denominator;
2. an exact complete-public-output quotient attack on that carrier construction,
   including a reference-plus-multi-carrier generalization;
3. a conditional composition theorem for the allowed N-of-N operator roots:
   once an inner WKEM has the required auxiliary-input security/extraction
   property, XOR composition tolerates arbitrary malicious other operators and
   abort, with no participant online after setup;
4. exact finite-field and XOR validation of those claims.

No external literature or web search was used.  Production code is unchanged.

## 1. Constructive attempt: random witness-evaluable carrier

Let `V` be a finite-dimensional vector space over `F_q`, and let `M <= V` be a
public mask subspace.  Every valid witness `w` supplies an efficiently computable
linear evaluation functional

    ell_w : V -> F_q

such that

    ell_w(M)=0.                                           (1)

This is the same public-feature interface available in the explicit polynomial /
moment encodings, but the key is no longer added along a public target vector.

Setup, which knows the statement but no witness, samples:

    K <- F_q,
    A <- carrier distribution on V,
    m0,m1 in M,

and publishes

    D = A + m0,
    N = K A + m1.                                       (2)

A valid witness computes

    Dec_w(D,N) = ell_w(N) / ell_w(D) = K                (3)

whenever `ell_w(A) != 0`.

This is a genuine same-key, witness-restricted public encoding attempt.  The
carrier `A` is fresh and unknown before setup; there is no fixed public vector
whose coefficient is visibly `K`.

### 1.1 Every-witness completeness can be made high in this model

For any fixed valid witness with nonzero `ell_w`, uniform `A in V` has

    Pr[ell_w(A)=0] = 1/q.

If the source relation has at most `W` valid witnesses, a union bound gives

    Pr[all witnesses have nonzero denominator] >= 1-W/q. (4)

For Boolean `n`-bit witnesses, `W <= 2^n`; taking a field with

    q >= 2^(n+lambda)

makes the failure probability at most `2^-lambda`.  The field bit length is only
`O(n+lambda)`.  This observation is only about correctness; the construction is
still broken below.

## 2. Exact complete-public-output break

Let

    pi : V -> V/M

be any public quotient map computed by Gaussian elimination.  Applying it to
(2) gives

    pi(D) = pi(A),
    pi(N) = K pi(A).                                    (5)

If **any** valid witness has `ell_w(D) != 0`, then `pi(D) != 0`: otherwise
`D in M`, contradicting `ell_w(M)=0`.

Therefore on every setup for which honest decryption is defined, an unauthenticated
public algorithm chooses any nonzero quotient coordinate `j` and returns

    K = pi(N)_j / pi(D)_j.                              (6)

No witness search is performed.  The attack is deterministic and polynomial in
the explicit public representation dimension.

The masks may be nonuniform, correlated, or key-dependent; only membership
`m0,m1 in M` is used.  The carrier distribution may also be arbitrary.

### Theorem (masked denominator / common-carrier barrier)

For public `(V,M)`, suppose a ciphertext contains

    D=A+m0,  N=K A+m1,  m0,m1 in M.

If there exists any honest linear decoder `ell` annihilating `M` with
`ell(D) != 0`, then the public quotient recovers `K` exactly by (6).

Thus replacing a public additive key target by an unknown random denominator
does not evade the explicit quotient attack.

## 3. Offset carrier and multi-carrier generalizations

### 3.1 Random offset does not help

Publish three masked elements

    D = A + m0,
    C = B + m2,
    N = K A + B + m1.                                  (7)

A witness computes `(ell(N)-ell(C))/ell(D)=K`.
Publicly,

    pi(N)-pi(C)=K pi(D),                                (8)

so the same quotient ratio recovers `K`.

### 3.2 A reference exposes a whole random carrier basis

Let `U` be an `s`-column matrix over `V`; masks are applied independently to
each column.  Publish

    R = U + M0,
    E = U S_K + M1,                                    (9)

where `S_K` is a public-format `s x s` matrix encoding the key.

Let `Q_R=pi(R)` and `Q_E=pi(E)`.  Then

    Q_E = Q_R S_K.                                     (10)

If `Q_R` has full column rank, a public left inverse gives

    S_K = Q_R^left Q_E.                                (11)

Hence any efficiently invertible key embedding `K -> S_K` is public.  The local
checker uses `S_K=[[1,K],[0,1]]`.

This does not rule out every multi-carrier construction: without a public
reference or another relation determining the carrier basis, (11) need not be
available.  It rejects the natural "publish a masked reference, then hide K in a
random basis" repair.

## 4. False-instance control

The candidate can have perfect hiding on a degenerate false instance, so the
break is not merely "the masks never hid anything."

If the public mask space is the whole feature space, `M=V`, and `m0,m1` are
independent uniform masks, then for every (even adversarially distributed)
carrier `A`,

    (D,N) = (A+m0, K A+m1)

is exactly uniform on `V x V` for every `K`.

The checker exhaustively verifies this distribution over `F_3` in a
two-dimensional feature space.

The problem is the true-instance complete public view: the very nonzero quotient
needed by an honest denominator exposes the scalar relation (5).

## 5. Conditional N-of-N operator composition

The allowed malicious setup ceremony is useful **after** an inner WKEM exists;
it does not repair Sections 1-3.

Assume a base encapsulation for statement `x`

    Encap(pp,x) -> (ct,k),
    Decap(pp,x,w,ct) -> k

has these properties.

1. Every valid source witness recovers `k` with failure at most `eps_c`.
2. For a false statement, one designated honest capsule's key is
   computationally pseudorandom even given arbitrary polynomial public
   auxiliary data `aux` generated by the other operators, including data chosen
   after seeing the honest public capsule but not its hidden key.
3. For the stronger true-instance early-recovery game, any algorithm predicting
   that honest key with nonnegligible advantage yields a source witness or an
   independently justified PQ-assumption break.  The reduction remains valid
   with the same allowed auxiliary data.

Let `N` operators independently produce `(ct_i,k_i)` and define

    K_final = k_1 XOR ... XOR k_N.                      (12)

No `k_i` is published.  Every valid witness decapsulates all capsules and XORs
the recovered shares.

### 5.1 Correctness

A union bound gives

    Pr[final decapsulation failure] <= N eps_c.          (13)

No operator is online after the completed setup.

### 5.2 One honest operator is enough for false-instance hiding

Fix an honest operator `h`.  Reveal all other shares to the adversary; this is a
strictly stronger auxiliary-input game.  Put

    C = XOR_(i != h) k_i,

which may be any efficiently computable function of the allowed public
transcript and malicious operators' secrets.

Then

    K_final = k_h XOR C.                                (14)

XOR by known `C` is a permutation.  Replacing `k_h` by uniform therefore makes
`K_final` uniform with exactly the same distinguishing loss as the base game.

Thus malicious operators may choose their own shares/capsules adaptively from
the public honest capsule.  They gain no extra ability to cancel `k_h` unless
they first learn/predict the hidden honest share, which is precisely the inner
security obligation.

### 5.3 Early-recovery extraction transfers exactly

Given a final-key predictor `A`, a reduction that knows all non-honest shares
computes `C`, runs `A`, and returns

    k_h_guess = K_final_guess XOR C.                    (15)

For every execution,

    [k_h_guess = k_h] iff [K_final_guess = K_final].    (16)

Therefore prediction success and advantage are preserved exactly, not divided by
`N`, in the game where the reduction chooses which honest share carries the
challenge and simulates/reveals all others.

If a deployment insists that several independent honest operators remain
hidden, a standard hybrid may select one challenge position; revealing the
others only strengthens the adversary for this reduction.

### 5.4 Abort and threshold devices

Required participants need not be forced to finish.  Define the ceremony output
as valid only after all required capsule commitments/openings and syntax checks
complete.  Any earlier refusal yields `abort` and **no finalized WKEM
transcript**.  Security is claimed only conditional on completion; this is
security-with-abort, not guaranteed liveness.

`t-of-X` devices inside one operator can realize that operator's `Encap` by an
actively secure threshold MPC and erase their temporary shares afterward.
The theorem above treats the resulting capsule as one honest operator output.
It does not prove a particular MPC protocol, physical erasure mechanism, or
device-corruption threshold.

A critical operational rule is that commitments/reveals must never publish
`k_h`.  If a malicious operator learns an honest raw share before fixing its own
raw share, it can set its share to force any desired XOR.  A hiding commitment
or an MPC that only releases the capsule/public commitment is required.

## 6. Fresh validation executed

`carrier_ceremony_check.py` uses only the Python standard library and performs:

* 2,000 random `F_101` carrier trials for the true Boolean relation `x*y=0`
  in the full four-dimensional multilinear feature space.  On every trial where
  all three valid witnesses have a nonzero denominator, each witness recovers
  the same key and the public quotient attack also recovers it.
* 800 unique-witness trials for `(x,y)=(1,1)`; whenever the honest denominator is
  nonzero, the public quotient recovers the same key.
* exhaustive `F_3`, two-dimensional false-instance enumeration with `M=V`,
  confirming the complete `(D,N)` distribution is identical for all three keys;
* 500 two-carrier `F_101` trials with a four-dimensional quotient and
  `S_K=[[1,K],[0,1]]`; every full-column-rank reference exposes `S_K` and `K`;
* exact XOR identities for one through six operators, enumerating every bit-share
  vector and both possible final guesses, confirming (16);
* an explicit negative control showing that if a malicious participant is given
  the honest raw bit before choosing its own, it forces a two-operator XOR to
  zero on every trial.

The checks validate finite algebra/distributions and composition identities.
They are not cryptographic security experiments and do not establish the missing
inner WKEM.

## 7. Current boundary

Proved here:

* random denominators/common carriers do not evade the public quotient in any
  explicit linear mask space;
* a public carrier reference also exposes finite-dimensional linear basis
  encodings of the key;
* N-of-N XOR composition is a valid malicious-operator wrapper **conditional on**
  one inner capsule satisfying the required auxiliary-input security/extraction
  game, with abort allowed.

Still unresolved:

* the practical generic-NP inner public offline encoder;
* a complete-public-output PQ reduction for that encoder;
* an implementation of the inner malicious-secure threshold MPC/erasure
  ceremony (the composition theorem is interface-level);
* concrete end-to-end parameters/resource estimates.

The stopping condition is therefore not met.
