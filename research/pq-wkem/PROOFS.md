# Boolean-moment extraction and the missing key-recovery reduction

**Status: a proved semantic compiler component, not a completed witness KEM.**

This note records the prior conversation's moment construction in independently
checked form. `moment_compiler.py` is a separate standard-library implementation.
No literature-priority claim is made. No original third-party paper was fetched
or re-reviewed for this continuation. The theorem below is about the construction
specified here, not an endorsement of other schemes or the repository's Rust code.

## 1. Complete public construction

Fix a field F, Boolean wire variables w_1,...,w_n, and polynomials q_s of degree
at most two representing gates, fixed public inputs, and the accepting output.
For example NAND is `z + xy - 1 = 0`. Reduction by `w_i^2=w_i` is valid on Boolean
assignments. The verifier must include its complete relation; omitting a gate or
public-input constraint changes the language.

Choose D >= 2. Introduce one moment mu_S for every subset S of {1,...,n} with
|S| <= D. Write Lambda_mu(w_S)=mu_S. Form the matrix

    B(mu)[S,0] = mu_S,
    B(mu)[S,j] = mu_(S union {j}),  j=1,...,n,

with rows |S| <= D-1. It contains every moment coordinate, so B(mu)=0 iff mu=0.

Impose the homogeneous linear equations

    Lambda_mu(w_T q_s) = 0   for all s and |T| <= D-2,

where products are squarefree-reduced. Adding `mu_empty=1` gives the affine
slice. Public Gaussian elimination either finds the slice inconsistent or
constructs

    mu = mu^(0) + sum_i sigma_i nu^(i),
    B(mu) = B_0 + sum_i sigma_i B_i.

An empty slice detects an unsatisfiable subcase. A nonempty slice need not have a
satisfying Boolean assignment; see Section 5.

### Completeness

For any satisfying Boolean wire assignment w, set

    mu_S = product_(i in S) w_i.

All localizing equations hold, mu_empty=1, and

    B(mu)[S,j] = w_S (1,w)_j.

The matrix therefore has rank exactly one. Choosing the free moment coordinates
as the affine coefficients makes every honest sigma_i a bit. The extractor does
not assume an adversarial sigma_i is a bit.

## 2. Semantic extraction theorem

**Theorem.** Let mu be a nonzero homogeneous solution. If

    d = rank B(mu) < D,

then it has a decomposition

    mu_S = sum_a alpha_a product_(i in S) w_(a,i),

where every nonzero alpha_a is a field element and every w_a is a Boolean
assignment satisfying every q_s. There are at most 2^(d-1) nonzero atoms. The
following explicit algorithm recovers them.

### Proof

Define the symmetric D-linear form on F^(n+1)

    T(e_(i1),...,e_(iD)) = mu_{nonzero indices among i1,...,iD}.

Its one-coordinate flattening repeats rows of B(mu), and contains all of them.
Its rank is d. Quotient F^(n+1) by its radical. Symmetry makes the radical the same
in every coordinate; T becomes a nondegenerate D-linear form on a d-dimensional
space W.

Let e be the image of e_0 and v_i the image of e_i. Boolean moment indexing gives

    T(v_i,v_i,...) = T(e,v_i,...)                       (1)

for every original coordinate and all remaining arguments.

**e is nonzero.** Otherwise choose d original coordinate images spanning W. Every
D-tuple of those basis vectors repeats a vector because D>d. Equation (1) would
make each such entry zero, and multilinearity would make T identically zero,
contradicting mu != 0. This conclusion concerns the constant *coordinate*, not
only the scalar mu_empty; the latter can be zero for a nonzero homogeneous input.

Complete e to a basis e,u_1,...,u_(d-1), choosing u_j from the original coordinate
images. Equation (1) reduces tensor entries to moments t_S on subsets of these
u_j, padded with e's.

For each a in {0,1}^(d-1), define the linear form l_a by

    l_a(e)=1,  l_a(u_j)=a_j.

Boolean Mobius inversion gives unique weights alpha_a satisfying

    t_S = sum_(a containing S) alpha_a.

Both sides of

    T = sum_a alpha_a l_a^(tensor D)                   (2)

have the same reduced entries and the same repeated-index identities on the
chosen basis, so they agree on all arguments.

Apply (1) to an arbitrary original v_i in (2). This gives

    sum_a alpha_a (l_a(v_i)^2-l_a(v_i))
                      l_a^(tensor (D-2)) = 0.

These latter tensors are linearly independent: to isolate a pattern a, evaluate
on u_j when a_j=1 and e-u_j when a_j=0, padding by e. This uses d-1 <= D-2
arguments and gives the Kronecker delta. Hence every nonzero weight forces

    l_a(v_i)^2 = l_a(v_i).

In a field the only roots are 0 and 1. Set w_(a,i)=l_a(v_i); all atoms are Boolean.

For each atom, form its Boolean selector on the selected original coordinates:

    chi_a(w) = product_(a_j=1) w_(u_j)
               product_(a_j=0) (1-w_(u_j)).

Its degree is d-1 <= D-2. Expanding the selector, the imposed localizing equations
therefore imply

    0 = Lambda_mu(chi_a q_s) = alpha_a q_s(w_a).

The nonzero-weight atoms satisfy every q_s. Equation (2), evaluated on padded
basis tuples, reconstructs every moment coordinate. QED.

### Algorithm and verification

1. Check every localizing equation and `0 < rank B < D`.
2. Choose a column basis of B including column zero.
3. Express every original coordinate column in that basis.
4. Read the 2^(d-1) moments on the selected coordinates and Mobius-invert them.
5. Evaluate each nonzero-weight atom on every original coordinate.
6. Explicitly verify Booleanity, all q_s, and reconstruction of the full mu.

There is no randomness or hidden trapdoor in this algorithm.

### Complexity

The explicit representation has

    m_D = sum_(j=0)^D binom(n,j) moments,
    a_D = sum_(j=0)^(D-1) binom(n,j) matrix rows,
    n+1 matrix columns.

There are at most `number_of_constraints * sum_(j=0)^(D-2) binom(n,j)` localizing
equations, before removing dependencies. For fixed D, the compiler is polynomial
in n. Allowing D to grow can make this representation impractical.

The extractor enumerates at most 2^(d-1) atoms. All subsets of the d-1 selected
coordinates already occur in the explicit moment representation, so
`2^(d-1) <= m_D`. Thus extraction is polynomial in the explicit input size when
field arithmetic is efficient; this does not make the compiler succinct in n.

The mathematical proof works over arbitrary fields. The committed reference
supports only small prime fields with `2 <= p <= 65537`; it does not implement
extension-field arithmetic or propose PQ parameters.

## 3. What the theorem does NOT prove

The proved arrow is

    submitted admissible low-rank moment representation -> valid witness.

The requested missing arrow is

    unauthorized recovery of a fresh encapsulated key
        -> admissible low-rank representation, or a break of a separately
           justified computational assumption.

The theorem in Section 2 receives a matrix/coefficient vector. A key-recovery
algorithm need not provide one. It might operate on the public encoding in some
other way. Neither successful honest decoding nor refusal of an official
invalid-witness API establishes a restriction on such computations.

The preceding conversation's common-factor projection encoders have recorded
public-output failures for some small false instances. They are not imported
here as secure encoders. This directory deliberately provides no `Encap` API.

## 4. Exact outstanding security obligation

To complete a WKEM one must specify a concrete encoder and an actual reduction.
At minimum the statement generator, setup randomness, public transcript, allowed
auxiliary inputs, adversary access, key-recovery event, extraction resources, and
quantitative losses must all be fixed.

For ordinary WE, the reduction must establish indistinguishability on false
statements against QPT processing of the entire classical public output.

For the stronger early-release requirement, define a fresh-challenge experiment:
the adversary is not given the encapsulation key or erased setup secrets, and
receives only explicitly permitted auxiliary data. A reduction using a successful
adversary must produce a witness or solve an independently specified hard problem.
Any quantum rewinding, trapdoor, or simulation access must be justified. No such
reduction is provided by this PR.

A conditional composition is immediate: if a reduction really outputs a nonzero
localizing solution of rank < D with probability epsilon, Section 2 outputs a
valid witness on that event with no additional mathematical failure probability.
Stating the premise is not constructing that reduction.

Do not replace it with a public algorithm extracting w from `(x, header, K)`
alone: the honest encryptor already obtains those values without a witness.
Likewise, permitted side information cannot include the actual key or unrestricted
encapsulation secrets while secrecy is demanded.

A public checker requires a consistent experiment. The distributions
`(header, H(K), K)` and `(header, H(K), U)` with the SAME original checker are
trivially distinguishable. Wrapper hybrids must regenerate downstream data from
their hybrid key, or use an appropriately defined unauthorized-recovery game.

These are proof requirements, not a claim that the desired primitive is
impossible, and not new assumptions being presented as a completed solution.

## 5. Strict-boundary fixture and homogeneous normalization

Over F5, let Boolean x,y satisfy the single proposed constraint `x+y=3`.
No Boolean assignment satisfies it. At D=3 the affine localizing equations give

    (mu_empty, mu_x, mu_y, mu_xy) = (1,4,4,3).

The flattening (rows empty,x,y,xy) is

    [1 4 4]
    [4 4 3]
    [4 3 4]
    [3 3 3].

It has rank exactly 3. The extractor must reject this input because the theorem
requires rank STRICTLY less than D. A nonempty affine slice is not a valid
witness, and weakening `<D` to `<=D` would be false.

Conversely, over F2 the sum of the canonical moments of `(0,0,0)` and `(1,0,0)`
has mu_empty=0 but nonzero rank 2. The homogeneous extractor correctly returns
both weight-one atoms. Rejecting every homogeneous input with mu_empty=0 would
unnecessarily discard inputs covered by the theorem.

## 6. Validation is not the security proof

`tests/test_moment_compiler.py` checks six groups of conditions. `validate.py`
reruns them and records source hashes, exact counts, Python version, and the real
execution interval. Its census repeats the unit-test inputs deliberately and is
not additional distinct coverage. `validation.json` is a captured run.

The tests support the implementation of the above algebra. They neither quantify
cryptographic attack costs nor demonstrate the missing key-recovery reduction.
