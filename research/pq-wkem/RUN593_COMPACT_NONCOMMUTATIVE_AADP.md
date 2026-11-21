# Run 593 — Compact noncommutative AADP: typed block lift and scalar-quotient test

Date: 2026-10-17. Research-only, one bounded iteration. Starting repository/PR:
`syscoin/PVUGC#1`, branch `research/pq-wkem-validation-20260918`, SHA
`d1d0b0ab5a049d21387d8815269ec8d7ee9cc921`. This is a construction-component
validation and a rejection of one compact representation, NOT secure witness
encryption, a repaired AADP, a quantum-security proof, or a deployment recommendation.

## 1. Purpose and verified literature correction

The user requested work on a compact replacement encoding preserving AADP's
common-capability determinant semantics, while addressing Lev's attacks. This
iteration does not retry global left/right scrambling, public seeds exposing
setup randomness, or arbitrary independent basis changes for each coefficient.

Primary sources read: the May 10 version metadata of ePrint 2026/175; ePrint
2026/1594 metadata; Lev Soukhanov's June 9, 2026 patch explanation; and Patrick
Towa's September 4, 2026 Swiss Crypto Day slides, with rendered pages inspected.
The two ePrint PDFs returned HTTP 403; no full-paper/errata audit is claimed.

Two corrections to earlier discussion: the June patch includes odd
characteristic, not only characteristic two; the September slides describe a
block/QAP direction and an approximately 8 TB example. That slide estimate is
neither a verified 128-bit-QPT implementation nor the same parameter set as the
older hundreds-of-terabytes estimate. Block-lifting is an author-suggested lead;
we claim the exact component proof and tests below, not invention of that lead.

The latest ordinary PR comment, 6067040320, remains the CLZ applicability note.
The live Run 587 file expressly keeps its earlier lattice diagnostic rejected.
No rejected/unpublished packet was republished in preparing this new work.

## 2. A precisely typed block lift preserves source rank

Work over F_q. For a source multiplication constraint ab=cd, keep a,b,c,d as
SCALARS. Replace only the scalar mixing form xi with a bdim-by-bdim matrix X.
Use a different name bdim for the block dimension to avoid confusing it with b:

    G_X = [ a I   c I   -X     0  ]
          [ d I   b I    0     X  ]
          [  0     0   b I   c I ]
          [  0     0   d I   a I ].

X may be fully noncommutative with other mixing blocks. It need not commute with
other X matrices. It commutes with the source scalars, which is what is needed.
One cannot replace all four source scalars by arbitrary noncommuting matrices
and assume the same theorem.

**Rank lemma.** If ab != cd, G_X has rank 4*bdim. If ab=cd and
(a,b,c,d) != (0,0,0,0), it has rank exactly 2*bdim, for EVERY X. If all four source
scalars are zero, its rank is 2*rank(X), so this degenerate case must be tracked.

Proof. Put A=[[a,c],[d,b]], D=[[b,c],[d,a]], J=diag(-1,1). For nonzero determinant,
the two diagonal blocks A tensor I and D tensor I are invertible. For zero
determinant and nonzero source tuple, both A,D have rank one. Since
J adj(D)=A J, the off-diagonal block J tensor X sends ker(D tensor I) into
im(A tensor I). It contributes no additional rank. Hence the block triangular
matrix has rank rank(A tensor I)+rank(D tensor I)=2*bdim. The zero-source case
is immediate. This proof works in characteristic two as well.

For m gates choose N=2*bdim*m+1 and independent uniform field matrices
L_i in F_q^(N x 4*bdim), R_i in F_q^(4*bdim x N). Define

    M(w) = sum_i L_i G_{X_i(w)}(a_i(w),b_i(w),c_i(w),d_i(w)) R_i.

Each X_i(w) is an affine matrix-valued form in the witness coordinates.
For EVERY valid w, rank(M(w)) <= 2*bdim*m=N-1. This yields det M(w)=0, even
though different witnesses yield different matrices. As in the AADP semantics,
publish C(w)=M(w)+k*w_0*E_NN. On the intended affine slice w_0=1, let D(w) be the
bottom-right cofactor. Then

    det(C(w)-t E_NN) = det M(w) + (k-t) D(w).

For a valid witness with D(w) != 0, the unique root is t=k. This retains the
SAME protected capability without canonicalizing the witness or its matrix.

**Completeness scope.** For a fixed valid witness whose every source tuple is
nondegenerate, the block-diagonal gate matrix has rank N-1. Conditional on all
X_i(w), its projected top-left (N-1)-square minor is the product of two
independent uniform square matrices. Thus

    Pr[D(w) != 0] = (product_{j=1}^{N-1} (1-q^(-j)))^2.

The failure probability is <2/(q-1). For a fixed finite witness set W a union
bound gives simultaneous completeness failure <2|W|/(q-1). This may require an
impractically large field. We do NOT silently replace pointwise correctness by
simultaneous/adaptively chosen-witness correctness. Degenerate tuples require
separate bounds. Our small functional test avoids that degeneracy.

## 3. Concrete sparse-source diagnostic: the scalar commutator signal changes

The implemented source is X_i^2=X_0 X_i, i=1,...,m. It is projectively safe:
X_0=0 forces every X_i=0. On X_0=1 its witnesses are all Boolean assignments.
The same gate convention is used for scalar and block versions. Only X_i's
matrix-valued masking coefficients and the necessary dimensions change.

For m=12, q=257, and four deterministic test seeds, compute the public operators
T_2=(M^1)^(-1)M^2 and T_3=(M^1)^(-1)M^3. Results:

- bdim=1: N=25; rank([T_2,T_3])=10 for all four seeds.
- bdim=2: N=49; rank([T_2,T_3])=49 for all four seeds.

This is finite evidence that the specific low-rank commutator signal is removed
in these fixtures. It is NOT a proof against the full published attack, other
normalizations, matrix-algebra/centralizer attacks, NSS-style linearization,
chosen circuits, joint views, or arbitrary QPT attackers. No complete AADP
cryptanalysis implementation was executed.

For m=3, all eight Boolean witnesses in each of eight setups (64 total) were
checked. They all yield det M(w)=0 and recover k=73; no selected cofactor was
zero. The general rank proof, not this census, supplies the correctness lemma.

## 4. A compact carrier that FAILS: group-algebra encoding

A tempting compression is to use the noncommutative algebra A=F_q[S_3]. Each
algebra element requires six field coefficients, whereas its faithful regular
representation is a 6-by-6 matrix requiring 36 explicit entries. This is a 6x
saving relative to THAT expanded block, not a saving relative to scalar AADP.

A non-Abelian carrier is insufficient. Define augmentation

    epsilon(sum_g a_g g) = sum_g a_g.

It is a public, unital, surjective F_q-algebra homomorphism:

    epsilon(a+b)=epsilon(a)+epsilon(b),
    epsilon(ab)=epsilon(a)epsilon(b), epsilon(1_A)=1.

For this candidate the outer dimension is 2m+1 OVER A (regular dimension
6(2m+1)); it is separate from the field-valued dimension choice in Section 2.
Consider an algebra-valued AADP with independently uniform entries of L_i,R_i,
xi_i^j in A, source coefficients embedded centrally, and encrypted scalar k
added as k*1_A to the intended coordinate. Entrywise augmentation gives

    epsilon(C^j) = sum_i epsilon(L_i) U_i^j(epsilon(xi_i^j)) epsilon(R_i)
                   + [j=0] k E_NN.

This is EXACTLY the scalar AADP ciphertext distribution for the same source and
same k: augmentation of each independent uniform algebra element is uniform
in F_q, and all independences are preserved. No hidden basis or secret coins
are needed to compute the projection from this public representation.

**Attack-transfer theorem.** Any classical or QPT scalar-AADP adversary for a
source family gives an adversary against this compressed algebra carrier with
the same success probability, after a deterministic polynomial-time projection.
In particular, this carrier does not remove the already documented scalar
sparse-circuit attack. The reduction is straight-line, with no rewinding,
oracle programming, or copying of advice. It preserves arbitrary auxiliary
inputs when the scalar experiment includes the corresponding projected view;
for a negative result the original attack may simply ignore extra information.

The checker verifies the homomorphism, noncommutativity of S_3, the faithful
regular representation, and exact whole-ciphertext projection: three
coefficient slices and four messages. The *full* scalar message-recovery
algorithm from the paper is not reimplemented; this is exact inheritance of
its attack surface, not an independent end-to-end break claim.

Changing only k's algebra component can remove the augmentation leak, but
other representation components must then be analyzed. In a split semisimple
carrier, every efficiently accessible quotient/representation receiving useful
key material matters. We do not assert a blanket attack on every possible
algebra-valued encoding.

## 5. A genuine design constraint, not a new hiding assumption

The full matrix algebra M_d(F_q), d>1, has no unital F_q-algebra homomorphism to
F_q. Proof: an off-diagonal matrix unit E_ij has square zero, so its scalar
image must be zero. But E_ij E_ji=E_ii, so every diagonal unit maps to zero,
contradicting that their sum is the identity. This blocks the PARTICULAR scalar
quotient above. It does NOT prove matrix-algebra AADP secure.

Thus the surviving component is the small full-matrix-valued mask, rather than
an arbitrary compressed non-Abelian carrier. This is narrower and more testable
than saying 'replace the masks with nonlinear mixing.'

There is currently no size breakthrough. For m=15000, v=m+1 coefficients and
32 bytes per field element, straightforward dense storage is:

- scalar N=30001: 432057602400032 bytes (~432.06 TB);
- 2x2-block N=60001: 1728172804320032 bytes (~1.728 PB).

These are arithmetic illustrations, not chosen security parameters or estimates
for the authors' separate ~8 TB QAP construction. The block lift grows this
unoptimized ciphertext by about 4x. Compressing the private random tape or one
expanded block must not be called compression of the final public ciphertext.

An earlier 'rank-four factors' estimate concerns individual gate contributions.
It is not a rank-four factorization of each aggregate public coefficient matrix;
the matrices M^1 in the diagnostic have full rank. That shortcut stays rejected.

## 6. Explicit model and obligation ledger

Honest algorithms: classical PPT over a specified finite field, with independent
uniform secret setup matrices; finite checker uses seeded non-cryptographic
PRNG values solely for reproducibility. Adversary: arbitrary QPT, classical
public ciphertext/source/context/native checking key, and coherent evaluation
of public algorithms. Quantum advice and auxiliary correlations are not
excluded from the target game; no positive hiding proof for that game is given.

Attack taxonomy: (1) local seams retain exact source-rank algebra, but no
ciphertext-hiding invariant is proved; (2) global algebra representations expose
the group-algebra scalar channel; (3) full commutator rank in eight fixtures is
not a fingerprint-security theorem; (4) all correlated capsules require a joint
proof, not separate marginal tests; (5) the quotient is public and efficiently
computable, no evaluation restrictions help; (6) retaining complete setup
randomness reveals the unencrypted baseline and hence k, so this is not the
optional keyless-setup game; the honest-erasure N-of-N ceremony is still needed
and unimplemented; (7) context binding and independent branch credentials stay
mandatory and cannot repair an inherited same-capsule attack; (8) correlated
native checking keys are in the full game, never a premise that k looks uniform
given its own checker; (9) the inherited classical attack already defeats QPT
security, while the surviving full-matrix mask has no coherent-attack proof.

No Run-259 extraction theorem is invoked. A quotient ciphertext or recovered
capability is not a supplied accepted ORIGINAL representation. False-statement
hiding, unauthorized true-instance recovery -> ORIGINAL evidence or independent
QPT break, and accepted native-forgery composition remain UNPROVED. The original
N-of-N setup/erasure and conditional P2MR-like/native-SLH endpoint are unchanged;
no claims about Bitcoin activation, signature size, or a completed graph.

## 7. Reproducibility and bounded handoff

Run `python run593_compact_block_check.py` with Python 3 and NumPy. Arithmetic is
exact modulo 257; tested matrix dimensions keep dot products within int64.
The committed JSON is exact stdout. Two final executions were byte-identical:
751 assertions, 64 witness cases, 12 whole-ciphertext projection checks, and the
eight normalized-commutator diagnostics above. No cryptographic security is
inferred from passing tests.

Next bounded subproblem: determine whether the typed full-matrix mask admits a
compact public encoding that does not publish the setup factors, introduce a
low-dimensional decodable component, or merely implement the same vulnerable
scalar pencil. Before claiming progress on the full goal, audit centralizers
and the full cryptanalysis, prove a full-public-view QPT reduction, and provide
actual ciphertext/setup/evaluation resource counts. This checkpoint resolves
neither compactness nor security; it validates a specific rank-preserving
component and rules out one apparently convenient compression carrier.

Primary sources:
- https://www.allocinit.xyz/posts/commutator-attack (June 9, 2026)
- https://eprint.iacr.org/2026/175 (metadata revised May 10, 2026)
- https://eprint.iacr.org/2026/1594 (metadata approved August 6, 2026)
- https://swisscryptoday.github.io/assets/2026-09/talks/PatricTowa.pdf
  (September 4, 2026; rendered pages 52,55,59,60,61 inspected, one-based)

No complete practical PQ WKEM. Do not disable the research program based on
this checkpoint. No production changes or PR merge/approval are authorized.
