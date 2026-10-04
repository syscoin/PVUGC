# Small spectral mass and the inner prover's output range

**Restricted theorem, not a completed inner compiler or WKEM.**

This continuation uses the supplied harmonic-channel note and the PR at
`20fb312eb96d028af92d0019edc65d90043f69e8`. No outside literature was consulted
and no literature-priority claim is made. The result below does not rule out
arbitrary nonlinear compilers, larger spectral mass, or computational WE.

## 1. Spectral packing

For fixed V, y and source noise mu, write

    muhat(a) = E_e chi_a(e),
    Theta_y = sum_(Va=y) |muhat(a)|^2.

Suppose Theta_y <= T. There are at most floor(T/gamma^2) distinct target
preimages pi with Re muhat(pi) >= gamma > 0: every one contributes at least
gamma^2 to the nonnegative sum.

This counts proof vectors, not original witnesses; several witnesses may
produce the same vector. It does not assume that proving is injective.

In particular, T < 2 gamma^2 permits at most one such vector. At gamma=19/20,
the threshold is 361/200 = 1.805. A near-one target-mass bound therefore forces
canonical useful proofs on true instances. A kernel bound transferred to the
target by coset domination is subject to the same condition.

Small spectral mass by itself supplies neither a target preimage nor a prover.

## 2. A Boolean subcube lemma

Over any field, partition Boolean inputs into k nonempty blocks, and fix one
Boolean anchor a_j per block. Let

    U = union_j {u : u_j=a_j}.

A polynomial function of total degree < k that vanishes on U vanishes on the
entire Boolean cube.

Proof. Complement bits where necessary to move the anchors to zero. Reduce
powers using x_i^2=x_i. Multilinear representations on the Boolean cube are
unique over any field, by recursively evaluating a+x_i b at 0 and 1. Setting
block j to zero shows that every coefficient whose monomial misses that block
is zero. Thus a remaining monomial would have to meet all k blocks and have
degree at least k, a contradiction. QED.

The strict bound is necessary: a product of one anchor-vanishing factor per
block has degree k and can be nonzero outside U.

## 3. Few-output range trapping

Let F(u) be a vector of globally evaluable polynomial functions, each of degree
at most d. Suppose F(U) is contained in a finite set S of size at most M.

**Theorem.** If k>dM, then every output of F, including F(0), belongs to S.

Proof. Suppose p=F(u*) is outside S. For each s in S choose a coordinate i_s
with p_i_s != s_i_s. The polynomial

    Q(z) = product_(s in S) (z_i_s - s_i_s)

has degree <=M, vanishes on S, and is nonzero at p. Q(F(u)) has degree <=dM<k
and vanishes on U. Section 2 says it vanishes everywhere, contradicting its
value at u*. QED.

This proof does not require one linear functional that separates every point
simultaneously, and thus also works over small fields. S and the anchors need
not be known to the public evaluator of F.

The bound is sharp at equality. Take k=dM one-bit blocks with anchors 1, over a
field of characteristic greater than M. The polynomial

    F(u) = sum_(j=0)^(M-1) product_(t=0)^(d-1) (1-u_(jd+t))

has range {0,...,M-1} when at least one bit is 1, but F(0)=M.

## 4. Consequence for a specified compiler class

For an underlying relation R(x,w), form

    R_OR(x;w1,...,wk) = OR_j R(x,wj).

If w* is a valid witness, its valid OR inputs include the union of the k
subcubes obtained by fixing one block to w* and leaving all other blocks free.

Suppose that, for a fixed setup and each proving random tape, a public prover
core F(pk,x,u) is globally evaluable and has degree <=d in the actual Boolean
OR-witness inputs. Suppose its valid outputs are accepted proofs within the
knowledge-extraction radius and have source-noise bias at least gamma. If the
actual target spectral mass is <=T, put M=floor(T/gamma^2).

When k>dM, an algorithm can output F(pk,x,0) without an original witness, and
the output is one of those accepted proof vectors. It need not know V or y.
Keeping verification state secret does not remove this implication.

If a uniform efficient inner knowledge extractor turns that accepted-proof
algorithm into an OR witness, applying it to R(x,w)=[f(w)=x] and checking the
returned blocks inverts f. Thus the promises are incompatible with a QPT-hard
one-way f whenever the setup, degree, output-count and extraction premises all
hold on the parameter family being considered. This is conditional on that
one-wayness assumption, not an unconditional complexity separation.

## 5. Probabilistic completeness

Fix the setup and the set S of useful accepted proof vectors. Suppose each
fixed valid OR input maps into S with probability >=1-epsilon over a common
proving-tape distribution. Every fixed tape must still define a globally
evaluable degree-<=d polynomial map.

Put e=dM<k and N equal to the number of actual Boolean prover-input bits. The
space of multilinear degree-<=e functions has dimension

    J = sum_(j=0)^min(e,N) binom(N,j).

By Section 2 its restriction to U is injective, so there exist J points in U
whose evaluations determine every such function. They are used only in the
proof; the evaluator need not know them or w*.

With probability at least 1-J epsilon, a random tape gives useful outputs at
all those points. If F(0) were outside S, Q(F) from Section 3 would vanish on
the determining set and hence identically, a contradiction. Therefore public
accepted-proof generation succeeds with probability at least

    max(0, 1-J epsilon).

A setup-bad probability contributes separately. This is useful only when
J epsilon is small. Fixed d and M make J polynomial in N; arbitrary growing
dM does not.

## 6. Scope limits that cannot be dropped

- The degree premise concerns the complete, publicly evaluable prover core in
  its actual input bits, not the degree of verifier equations alone.
- A formula valid only on satisfying inputs is not sufficient. Removing
  arbitrary proof-generation branches does not establish this premise.
- If a prover computes an auxiliary trace nonlinearly, that computation counts;
  the trace cannot silently be made free input to the same OR relation.
- If d or T depend on compiled instance size, k>dM must hold at that actual
  size. One cannot assume k exceeds an arbitrary polynomial in k.
- High formal degree can have a small circuit. This is not an exponential-size
  lower bound for all nonlinear prover implementations.
- The spectral bound must hold on the true instances in this argument. A bound
  only on false instances, with a different true-instance extraction argument,
  is outside the conclusion.
- Avoiding this theorem does not prove security or instantiate a compiler.

## 7. Exact local validation

The separately saved standard-library checker has 11 groups, zero failures:
9,216 target-packing checks; 36 full-rank subcube restrictions; 5,683 scalar and
1,024 vector polynomial maps; 856 point-set separating products; five strict
range-boundary examples; 512 correlated-random-tape mixtures; and negative
controls for missing completeness, high-degree escape, and noninjective
source-witness mapping. The initial ten-group run and the independent final
replay repeat cases and are not additive coverage.

Checker SHA-256:
`ad041f330f8867a1ae2f607ade85b00423f25d8297bdc618b6bfa9a7e8041756`.

The tests use exact integer, rational and small-prime-field arithmetic. The
proofs above, not finite testing, establish the general claims. No deployed
system, cryptographic-size attack, or quantum computer was tested.

The test sources, full note and captured results are preserved in the current
conversation's `wkem_compiler_contract_audit.zip`; this documentation commit
does not claim those code files have also been committed.

**Uncompleted:** an efficient generic-NP inner compiler satisfying the full
channel contract, its QPT hardness/extraction reduction, secure concrete
parameters, and a complete WKEM. No production code is changed.
