# Global masked-path transfer and its failed compact exterior repair

**Rejected research candidates, not a completed PQ WKEM or secure compiler.**

This continuation starts from `ae5042e87fd74d2200979168825f064cd85d480c`; the predicate-oracle boundary was subsequently committed at `4bcd98b157459088b2e93ce888fc78d42e95e0d2`. Only supplied context, local calculations and requested GitHub operations were used. No outside literature, priority claim or production-source change is involved.

## 1. Actual public prover

The source instance is a directed graph on N vertices. A witness is a cycle rooted at 0 visiting every vertex exactly once. No general NP-to-graph compiler is claimed here; failure on this relation already rejects the proposed transfer mechanism.

Over a finite field, privately sample split frames L_v in F^(d x r), R_v in F^(r x d), with R_v L_v=I, and commuting r-by-r operators D_v. One explicit frame sampler takes the first r columns of a random invertible S_v and the first r rows of S_v^-1. Diagonal D_v commute and may be singular.

Publish C_uv=L_u D_v R_v for every allowed edge. Setup computes

    T=L_0 (product_v D_v) R_0,
    K=H(Encode(public_header,T)).

It does not need a graph cycle. Multiplying the public edge matrices around any valid cycle gives T: adjacent frames cancel and commuting labels make the full product independent of order. A witness holder hashes that matrix locally, with no returning setup party.

The reference algorithms implement setup, cycle validation, transfer and the same 256-bit hash output. They are NOT secure encryption. Arithmetic storage is O(|E|d^2) field elements; direct evaluation is O(Nd^3). These are not security parameters.

## 2. Singularity does not prevent public splicing

Any public field matrix C has a publicly computable inner inverse G satisfying CGC=C. Choose independent columns J and independent rows I of C[:,J]. Put G[J,I]=C[I,J]^-1 and all other entries zero. Gaussian elimination suffices, including for rectangular or singular matrices.

For the graph with edges {01,10,23,32,12,31}, no full-vertex cycle exists: vertex 0's only predecessor and successor are 1. Nevertheless, for ANY public inner inverse G of C31,

    C01 G C32 C23 C31 C10 = T.

Proof. From C31 G C31=C31, multiply by R3 on the left and L1 on the right:

    D1 R1 G L3 D1=D1.

Expanding the public word gives L0 D1 R1 G L3 D2 D3 D1 D0 R0. Commute D1 past D2,D3 and apply the preceding equality. The result is L0 D1 D2 D3 D0 R0=T. No D_v is assumed invertible.

Thus rectangular frames, singular public edges and singular private labels do not fix this candidate. Tests keep a common nonzero diagonal coordinate when using singular labels, so the target is nonzero; a zero-target control is recorded separately.

For every N>=4, take edges 01,10,12,(N-1)1 and the directed cycle 2->3->...->N-1->2. The same vertex-0 argument proves falsity. The N+2 factor public word

    C01 G_(N-1,1) C_(N-1,2) C23 ... C_(N-2,N-1) C_(N-1,1) C10

again equals T. The implemented recovery routine receives ONLY the public header; private reference values are retained separately by the test harness.

## 3. A literal no-reuse repair has an exponential width requirement

Suppose commuting linear operators A_1,...,A_N have A_i^2=0 and nonzero full product. Then their state space has dimension at least 2^N.

Choose v with (product_i A_i)v!=0. The vectors A_S v for all subsets S are independent: from a nonzero dependence choose a minimum-cardinality S with nonzero coefficient, multiply by A_complement(S), and use square-zero to annihilate every term with an index outside S. Proper subsets have zero coefficients by minimality, leaving a nonzero multiple of the full product, a contradiction. Subset-shift operators attain the bound.

A broader exact-linear recognizer bound does not require commutativity. Suppose a linear-state program outputs 1 on every length-N permutation of N labels and 0 on repeated-label words. At cut k=floor(N/2), index prefixes by size-k subsets and suffixes by size-(N-k) subsets, each in fixed internal order. The acceptance submatrix is a permutation matrix because acceptance occurs exactly for complementary subsets. It factors through the state at the cut. Hence that width is at least binom(N,k), even with position-dependent transitions.

These are LINEAR DIMENSION / exact-output bounds, not bit-complexity lower bounds for implicit encodings, nonlinear final decoding, random nonzero invalid outputs or arbitrary computational WE.

## 4. A compact exterior implementation escapes literal size, but not the attack

Over E=F_(2^m), let W_z be exterior multiplication by z on the exterior algebra of E^N. These operators commute, square to zero, and have nonzero full product when their vectors form a basis. The exterior algebra has dimension 2^N, but a decomposable k-form can be stored as k base vectors.

Choose secret base-space frames F_v in GL_N(E) and a secret basis z_v. With exterior frames Lambda(F_v), an edge is

    C_uv=Lambda(F_u) W_zv Lambda(F_v^-1)=W_a Lambda(M),
    a=F_u z_v, M=F_u F_v^-1.

A valid cycle gives the same top-form coefficient t=det(F0)det(z_0,...,z_(N-1)), which setup knows without a witness. It is nonzero by construction.

We implement a less exposed public edge. Choose a functional f with f(a)=1 and publish only (a,B), where

    B=(I-a f)M.

B has rank N-1 and W_a Lambda(B)=W_a Lambda(M) on every exterior form. Thus there are O(N^2) public field elements per edge, not an explicit exponential matrix. Honest path evaluation preserves a single decomposable form and uses a final determinant, in polynomial time.

However, from (a,B) choose an invertible completion Mtilde=B+a*b, with b nonzero on ker B. Trying coordinate row vectors and testing rank suffices. The public edge equals W_a Lambda(Mtilde).

Define exterior contraction

    i_f(v1 wedge ... wedge vk)=sum_j f(vj) * wedge(all vectors except vj)

in characteristic two. It satisfies W_a i_f W_a=W_a. Therefore

    G=Lambda(Mtilde^-1) i_f

is an efficiently represented public inner inverse: CGC=C.

The exact false-graph splicing word from Section 2 applies unchanged. It uses ONE contraction, creating at most N decomposable terms, followed by polynomially many base-vector transformations and determinants. The public recovery algorithm never materializes the 2^N-dimensional state.

This rejects the implemented compact exterior repair. It does not rule out every implicit/nonlinear representation or an independent cryptographic encoding assumption.

## 5. Actual validation

The combined local package has 26 passing groups, including eight predicate-oracle groups. Selected new counts:

- 480 honest same-key recoveries across 45 complete-graph capsules;
- 108 nonzero-target false recoveries (72 of these with singular public edges);
- 72 separate nonzero-target recoveries with all private D_v singular;
- 36 additional false-family recoveries for N=4,5,8,16,32,64 (12 with singular labels);
- 722 square and 96 rectangular public inner-inverse checks;
- 60 unpublished-edge synthesis checks;
- 191 small commuting square-zero pairs, 3450 subset-shift identities, 21 middle-cut rank checks;
- 252 compact-exterior inner-inverse basis checks, 140 representation identities;
- 96 honest exterior recoveries and 45 nonzero-target false exterior recoveries over F4/F8/F16, through N=12.

Counts overlap; replays repeat coverage. Small fields are algebraic fixtures, not cryptographic security levels, and hashing a tiny-field target to 256 bits does not create 256-bit entropy. General identities follow from the proofs, not from sampled successes. Finite-field checks are exact; the unrelated oracle statevector tests use numerical tolerances and no quantum hardware.

The full sources, validation and longer derivation are in the conversation artifact `wkem_oracle_transfer_audit.zip`. This documentation commit does not assert that those source files are also committed. No malicious-secure MPC, physical erasure, production bridge, secure parameter set, or completed generic-NP witness KEM has been supplied.
