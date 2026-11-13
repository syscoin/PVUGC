# Layer-randomized branching programs: public intertwiner attack and the WE boundary

Starting checkpoint: PR #1 head
`4a1c13d77c203a3278218474274c72fec931ee1d`.

This continuation does **not** complete a generic witness KEM.  It records:

1. a fresh constructive attempt using an acyclic noncommutative branching-state
   transfer rather than additive quotient masks or cover telescoping;
2. an exact complete-public-output attack that recovers the programmed endpoint
   key from a public linear intertwiner system on every true instance;
3. the same attack after a hidden global conjugation and for pure permutation
   state relabeling;
4. a precise equivalence boundary: the requested public offline same-key
   functionality is already witness-encryption functionality at the privacy
   level, while the requested true-instance source-extraction guarantee is
   strictly stronger.

No external literature or web search was used.  Production code is unchanged.

## 1. Constructive attempt: acyclic noncommutative state transfer

Assume a public targeted layered branching representation over `GL_d(F_q)`:

    A_{i,b} in GL_d(F_q),       i=0,...,L-1, b in {0,1},

with a public target matrix `T` such that a source witness `w` is valid only when

    A(w) := A_{0,w_0} A_{1,w_1} ... A_{L-1,w_{L-1}} = T.     (1)

For this audit it is enough that every valid source witness maps to such a
targeted path.  No claim is made here that this is already a practical generic
NP compiler.

Setup knows the statement and the canonical matrices but no valid witness.
Choose an invertible key carrier `S_K` and random invertible layer frames

    R_0,...,R_{L-1} <- GL_d(F_q),

then program

    R_L = T^{-1} R_0 S_K.                                   (2)

Publish only

    C_{i,b} = R_i^{-1} A_{i,b} R_{i+1}.                     (3)

Erase the `R_i`.

A valid witness multiplies its selected public transitions:

    C(w)
      = C_{0,w_0} ... C_{L-1,w_{L-1}}
      = R_0^{-1} A(w) R_L
      = S_K.                                                (4)

Thus every valid witness recovers the same key carrier.  The construction is:

* acyclic;
* noncommutative;
* public and offline after setup;
* setup-witness-free;
* polynomial size in the supplied branching representation.

It is therefore a genuine different attempt from the rejected additive flow
tables, abelian cover-orbit telescoping, random carriers, and public linear mask
quotients.

## 2. Complete-public-output intertwiner attack

The canonical matrices `A_{i,b}` and the randomized public matrices `C_{i,b}`
satisfy the public homogeneous linear equations

    A_{i,b} X_{i+1} = X_i C_{i,b}                            (5)

in the unknown entries of matrices

    X_0,...,X_L.

The erased setup tuple

    X_i = R_i

is one solution, and all of its matrices are invertible.

Equation (5) is linear in the unknown matrix entries.  It has

    (L+1)d^2

unknown field elements and at most

    2Ld^2

scalar equations for binary branching.

Hence an attacker can compute the full solution space by ordinary Gaussian
elimination.

### 2.1 Efficiently finding an invertible solution tuple

Let `S` be the resulting linear solution space.  The polynomial

    P(X_0,...,X_L) = product_i det(X_i)                     (6)

restricted to `S` is not the zero polynomial, because it is nonzero at the
actual erased tuple `(R_0,...,R_L)`.  Its total degree is

    d(L+1).

Sampling a uniformly random point of `S` therefore produces a tuple with every
`X_i` invertible with probability at least

    1 - d(L+1)/q                                           (7)

by the elementary polynomial-zero bound, whenever the right side is positive.
Thus for `q` polynomially larger than `dL`, the attack finds an invertible tuple
with constant expected repetition.

This is not an assumption about the secret frames.  It is a consequence of the
public linear equations and the existence of one invertible solution.

For very small native fields, equation (7) alone does not prove an efficient
inversion algorithm for every possible matrix-space instance.  Section 4 shows
that simple permutation-state randomization does not gain protection from that:
the public 0/1 matrices can be linearized over a convenient larger field.

### 2.2 Any invertible solution exposes the same accepting endpoint

Let `(X_0,...,X_L)` be **any** invertible solution of (5), not necessarily the
erased setup tuple.

For any valid witness `w`, repeatedly applying (5) gives

    A(w) X_L = X_0 C(w).                                   (8)

Using `A(w)=T` and (4),

    X_0^{-1} T X_L = C(w) = S_K.                           (9)

The attacker does not know `w` and does not need to find one.  It only computes

    S_recovered = X_0^{-1} T X_L                           (10)

from the public target and one publicly reconstructed invertible solution tuple.

Existence of a source witness is used **only in the proof** that (10) equals the
programmed key.  The recovery algorithm itself performs no witness search.

This is exactly the true-instance early-recovery failure that the target WKEM
must exclude.

### Theorem (public branching intertwiner barrier)

For a true targeted branching instance satisfying (1), every endpoint-programmed
layer randomization of the form (2)-(3) over an explicitly represented matrix
algebra is publicly key-recoverable in polynomial time whenever an invertible
solution of (5) can be efficiently sampled from its linear solution space.

For `q > 2d(L+1)`, the elementary random sampling method above succeeds with
probability at least `1/2` per trial.

The attack is full-output and deterministic after the sampled solution.  It is
not a statement that a valid witness was found.

## 3. Why a hidden global conjugation does not repair it

A natural repair is to hide the canonical representation itself behind a secret
global basis `Q`:

    A'_{i,b} = Q^{-1} A_{i,b} Q,
    T'       = Q^{-1} T Q,                                (11)

and then apply the secret layer frames to `A'`.

But define

    X_i = Q R_i.                                          (12)

Then the published transitions still obey

    C_{i,b} = X_i^{-1} A_{i,b} X_{i+1},                   (13)

and the endpoint condition becomes

    X_L = T^{-1} X_0 S_K.                                 (14)

So `Q` is absorbed completely into the unknown layer frames.  The attacker runs
the same public system (5) using the original canonical `(A,T)` and recovers
`S_K` by (10).

Thus a secret **global change of basis** is not a distinct hiding layer.

## 4. Pure permutation/state-label randomization is also inside the attack

Suppose every `A_{i,b}`, every setup frame, and every published `C_{i,b}` is only
a permutation matrix.  This is the most literal hidden state-label relabeling.

All entries are integers in `{0,1}`, so the matrix identities hold over any
field.  An attacker is therefore free to interpret those same public matrices
over a convenient large prime field and solve (5) there.

The finite checker uses width-3 permutation branching programs whose intended
transcript consists entirely of permutation matrices, but solves the public
intertwiner equations over `F_101`.  Multiple distinct invertible solution
tuples occur; every sampled one nevertheless gives exactly the same programmed
key permutation through (10), as required by theorem (9).

Hence choosing a small native permutation group does not avoid the linearized
complete-output attack.

## 5. Relation to the earlier complete-public-view failures

This failure is structurally different from the preceding ones.

* It is not a public quotient of additive masks.
* It is not an affine-flow relaxation using negative coefficients.
* It is not the abelian 2+3 cover-orbit attack.
* It does not require cycling the state graph.
* It does not inspect or recover per-input garbled labels.

The problem is instead that the public canonical semantics and the randomized
semantics are linked by an explicitly linear **intertwiner system**.  Once the
accept target `T` is public, any invertible intertwiner fixes the key endpoint on
a true instance.

A repair must therefore hide more than the layer bases.  In particular, a
candidate that simply says "publish a randomized program equivalent to the
public verifier, but do not reveal the equivalence" needs an independently
justified way to make that equivalence computationally hidden.  Assuming that
the hidden program releases `K` only on valid witnesses would merely assume the
desired primitive.

## 6. Exact functionality boundary: WKEM and witness encryption

It is useful to state explicitly what the requested primitive already implies.

### 6.1 WKEM -> witness encryption

Suppose a public offline WKEM for relation `R(x,w)` provides

    Encap(x) -> (ct,k)
    Decap(x,w,ct) -> k

with the required same-key correctness for every valid witness and false-instance
key hiding.

To witness-encrypt a polynomial-length message `m`:

1. run `Encap(x)` to obtain `(ct,k)`;
2. derive a symmetric key from `k`;
3. encrypt `m` with an authenticated symmetric encryption scheme;
4. output the WKEM capsule and symmetric ciphertext.

Every valid witness decapsulates the same `k` and decrypts `m`.  False-instance
message privacy follows by replacing the WKEM key with uniform and then applying
ordinary symmetric security.

Thus the requested WKEM functionality is already a KEM form of witness
encryption.

### 6.2 Witness encryption -> the privacy part of WKEM

Conversely, given witness encryption for `R`, sample random `k` and publish a
witness encryption of `k` as the capsule.  Any valid witness recovers `k`.

For a false instance, standard message indistinguishability also gives the usual
real-key-versus-independent-key KEM challenge by choosing two independent random
keys `(k_0,k_1)`, using the witness-encryption challenge on those messages, and
presenting `k_0` as the candidate key.

So at the functionality/privacy level these objects are equivalent up to
standard KEM-DEM wrapping.

### 6.3 The user's requested extraction goal is stronger

The current research target additionally requires that on a **true statement**
arbitrary unauthorized early key recovery imply either:

* extraction of a source witness, or
* a break of an independently justified PQ assumption.

Ordinary witness-encryption privacy only speaks about false statements and does
not supply this true-instance knowledge/extraction guarantee.

Therefore the research goal is not weakened by the equivalence above.  The
point is methodological:

> a newly named "witness-restricted public encoder" whose assumed security
> already says that only source witnesses can recover the hidden key is not an
> intermediate assumption.  It is essentially the target WE/WKEM primitive,
> with the requested extraction property still to prove.

This keeps the distinction between **native encryption** and **source-witness
transfer** explicit.

## 7. Fresh validation actually executed

`branching_intertwiner_check.py` is standard-library-only.

It performed:

* 500 independent `GL_2(F_101)` targeted branching fixtures of length 5.
  The public intertwiner solution space had dimension 1 in all 500 fixtures;
  a sampled invertible solution recovered the exact key matrix in all 500.
* 300 additional `GL_2(F_101)` fixtures with a fresh secret global conjugation
  `Q`.  The attack was given only the original canonical `(A,T)` and the
  published randomized transitions.  It recovered the exact key matrix in
  all 300.
* 200 width-3 permutation-only fixtures of length 6.  The public transcript,
  canonical transitions, setup frames, and key carrier were all permutation
  matrices.  The attack linearized them over `F_101`.
* In those permutation fixtures the intertwiner solution-space dimensions were
  2 in 196 fixtures, 3 in 2 fixtures, and 5 in 2 fixtures.
* Eight independently sampled invertible solution tuples were tested per
  permutation fixture: 1,600 total.  Every one recovered the same exact key
  permutation through `X_0^{-1} T X_L`.
* The maximum number of random solution-space samples needed to obtain an
  invertible tuple in any executed fixture was 2.

These are finite-algebra checks of the proved identities.  They are not
cryptographic security experiments, do not validate a generic-NP compiler, and
do not prove an impossibility theorem for nonlinear/computationally hidden
program encodings.

## 8. Current boundary

Proved in this pass:

* acyclic noncommutative layer randomization with public canonical semantics has
  a polynomial public intertwiner attack on true instances;
* hidden global conjugation is absorbed into the layer frames;
* pure permutation/state-label randomization is vulnerable to the same
  linearization;
* the requested public offline same-key primitive is WE-equivalent at the
  functionality/privacy level, while the requested true-instance extraction
  property is stronger.

Still unresolved:

* a practical generic-NP inner encoding whose complete public transcript is not
  related to its public verifier semantics by an efficiently removable quotient,
  flow relaxation, cover relation, or intertwiner system;
* an independently justified PQ hybrid for that inner encoding;
* arbitrary-QPT early-key recovery -> source witness / PQ-break for the complete
  transcript;
* concrete end-to-end resource estimates once such an inner encoding exists.

The conditional N-of-N ceremony composition from the previous checkpoint
remains valid if that inner primitive is obtained.  The stopping condition is
not met.
