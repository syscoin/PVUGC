# Unmasked minimal-margin spectral candidate: public key-recovery regression

Interactive research checkpoint `unmasked-spectral-central-polynomial-20261022`.
No scheduler run ID was supplied. This responds to the owner's request to prove
or break the ORIGINAL unmasked candidate computationally. It does not use the
later residual-mask cancellation or enlarged-margin flaw.

## 1. Scope and correction

Live repository read: `syscoin/PVUGC#1`, draft/open/unmerged, branch
`research/pq-wkem-validation-20260918`, starting commit
`ef2246af43a567b8baa6863ee7b506cc9a1a5cd1`. Latest substantive ordinary comment read:
`6355253790`.

The target is Run 695's scalar spectral shift applied to Run 593's typed gate:

    C0 = M0 + K I_N,   Cj = Mj (j > 0),   N = 2 b m + 1.

The secret outer factors and the internal b-by-b mixing matrices remain present
and random. There are NO added residual shields, NO extra nullity padding, NO
retained secret coins available to the attack, and NO witness search. The attack
uses three public slices for b=1 and four for b=2. Generating only those slices
samples their exact joint marginal from the complete setup; other public slices
can be generated independently conditional on the same outer factors.

Result: exact encrypted field-capability recovery was executed on a complete,
projectively safe FALSE source family, for b=1 and b=2. This rejects a generic
security claim for this unmasked compiler as presently specified. It is NOT a
claim that every dense/QAP-compiled Syscoin circuit or every larger block size is
broken. There is no claim of breaking standard SLH-DSA or any deployed account.
No native signature was generated in this experiment: recovering the encrypted
field capability is already a failure of the proposed release layer.

Prior scalar commutator cryptanalysis is established literature. The b=2 test
uses a central-polynomial identity instead of assuming that noncommuting blocks
eliminate all usable polynomial identities. No priority claim is made.

## 2. Complete source family; no irrelevant witness variables

Let v=m-3 and homogeneous coordinates be z0,u,x1,...,xv. Use the m constraints

    u*u = z0*z0;
    u*z0 = z0*z0;
    xi*xi = u*xi                 for i=1,...,v;
    (x1+...+xv)*u = (v+1)*u*u.

On z0=1, the second equation forces u=1; all xi are Boolean. Their sum is at
most v as an integer, so over a field of characteristic greater than v+1 the
last equality cannot hold. The source has no affine witness. At z0=0, the first
equation forces u=0, and the Boolean gates force every xi=0. Thus no nonzero
projective witness exists at infinity either. Every xi appears in the final
acceptance constraint, not merely an unused or disconnected gate.

This choice is for an unambiguous false-instance regression. The algebraic attack
uses coefficient sparsity, not the method proving unsatisfiability. Changing the
last constraint to a weighted subset-sum target preserves the relevant sparsity.
That observation is not a hardness proof for any particular subset-sum family.

Each scalar tuple (a,b,c,d) is represented by exactly the typed gate

    G_X = [[a I, c I, -X,   0],
           [d I, b I,  0,   X],
           [  0,   0, b I, c I],
           [  0,   0, d I, a I]].

For every gate, L_i in F_q^(N x 4b), R_i in F_q^(4b x N), and each selected
coefficient X_i^j in Mat_b(F_q) are independently uniform in the honest model.
The tests use deterministic PRNG coins solely to reproduce samples.

## 3. Public attack

Write [A,B]=AB-BA. Select source coefficients for x2,x3,x4 as indices a,c,d;
none is the encrypted constant coefficient. Set

    Q = C_a^(-1),  A = Q C_c,  B = Q C_d,  T(t)=Q(C0-t I).

The attack aborts if a required PUBLIC inverse does not exist.

For b=1 form

    F0 = [Q C0,A],  F1 = [Q,A].

For b=2 form

    H  = [A,B]^2,
    F0 = [H,Q C0],  F1 = [H,Q].

If F1 is invertible, publish/computate the attacker-derived matrix

    Z = F1^(-1) F0.

Whenever F0-K F1 is singular, K is an eigenvalue of Z. Obtain a scalar Krylov
sequence, use Berlekamp--Massey, isolate field roots with gcd(f,T^q-T), and match
candidate roots using the already public exact-capability tag. No enumeration
of F_q or of witnesses is used. This is the same spectral decoding idea used by
the honest construction, now applied to a different PUBLICLY computed matrix.

The native public key can also filter candidates where its API applies; this
experiment uses SHA3-512('unmasked-spectral-test:' || decimal(K)). This is an
ordinary public candidate checker, not an oracle with secret state.

## 4. Structural rank theorem (conservative bound)

Decompose each unencrypted coefficient as

    Mj = U Dj V + Ej,

where U collects the first 2b columns of each L_i, V collects the last 2b rows of
each R_i, and Dj is block diagonal with blocks -X_i^j,+X_i^j. U has N-1 columns
and V has N-1 rows. Ej contains only the public source-scalar contributions.

For the source above, rank(E0)<=8b. For each selected bit coefficient, its Boolean
gate contributes rank 4b and the final linear-sum gate contributes rank 2b, so
rank(Ea),rank(Ec),rank(Ed)<=6b.

Assume U,V have full column/row rank, every X_i^a is invertible, and M_a is
invertible. Complete U,V to invertible matrices P=[U,u*], R=[V;v*], and set

    Mbar_a = P diag(Da,1) R.

Then rank(M_a-Mbar_a)<=6b+1. The inverse-difference identity gives
rank(M_a^(-1)-Mbar_a^(-1))<=6b+1. Define ideal normalized operators

    Tj* = Mbar_a^(-1) U Dj V
        = R^(-1) diag(Da^(-1) Dj,0) R.

Their blocks are X_i^a^(-1) X_i^j, each repeated twice, plus one zero scalar block.
The actual normalized source operators satisfy

    rank(T0-T0*) <= d0 = 14b+1,
    rank(A-A*)  <= dA = 12b+1,
    rank(B-B*)  <= dB = 12b+1,

where T0=Q M0=T(K), NOT Q C0.

### Scalar blocks

For b=1 all ideal operators commute. Thus

    rank([T0,A]) <= 2(d0+dA) = 56.

Consequently, for N>56, F0-KF1 is necessarily singular under these conditions.

### Two-by-two blocks

The commutator of two 2-by-2 matrices has trace zero. Cayley--Hamilton implies
its square is a scalar matrix. Therefore H*=[A*,B*]^2 commutes with T0*.

Put S=[A,B], S*=[A*,B*]. By the exact identity
S-S*=[A-A*,B]+[A*,B-B*],

    rank(S-S*) <= 2(dA+dB).

Since S^2-S*^2=(S-S*)S+S*(S-S*),

    rank(H-H*) <= 4(dA+dB).

Finally

    [H,T0] = [H-H*,T0] + [H*,T0-T0*],

so

    rank(F0-KF1) <= 8(dA+dB)+2d0 = 458    (b=2).

Thus N>458 forces K to be an eigenvalue of Z whenever the PUBLIC F1 is
invertible. This is a sufficient bound, not a claim that the observed rank 88 is
universal. The executed N=513, b=2 small-field cases lie within this bound. The
257-bit N=129 and N=193 cases are smaller and have directly verified rank 88;
the conservative 458 theorem alone does not guarantee success at those sizes.

The result is an explicit polynomial-time attack under stated nondegeneracy
conditions, not a proof of a success probability for every source/block size.
The public inverses and recovered key/tag are directly checked by the code.
Full-rank random-factor conditions have ordinary finite-field bounds. A general
asymptotic bound for all remaining normalized-operator conditions is NOT claimed.

## 5. Why the public denominator is not a secret assumption

There is a useful conditional probability statement. With independently uniform
outer factors, apply a fresh uniform global left change L_i -> J L_i. This leaves
the honest setup distribution unchanged. Every normalized unencrypted Tj is
unchanged, while Q=M_a^(-1) becomes Q J^(-1), uniform in GL_N conditional on the
normalized operators.

If the structural matrix A (b=1) or H (b=2) has distinct eigenvalues over an
algebraic closure, det([H,Q]) (respectively det([Q,A])) is a nonzero degree-N
polynomial in Q. In an eigenbasis choose Q as a cyclic permutation: all the
corresponding eigenvalue differences are nonzero, giving a nonzero determinant.
Schwartz--Zippel and conditioning on Q invertible give a denominator-failure
bound

    N / (q * product_{j=1}^N(1-q^(-j))).

This statement is conditional on the stated simple-spectrum property. Its
probability for every source family/parameter is not proved here. In all three
257-bit tests the structural matrix's scalar minimal polynomial had full degree
N and was squarefree, verifying that property for those sampled matrices.

## 6. Recorded executions

All cases use s=1, full dense secret outer factors, and no residual shields.

Exact candidate modulus: q=2^256+297, as in the prior research parameterization.
GMP's 40-round probable-prime test passed; no new formal primality certificate
was generated in this checkpoint. The algebraic theorem assumes a finite field.

Connected FALSE-source cryptographic-field executions:

| m | b | N | observed rank(F0-KF1) | recovered polynomial degree | field roots | exact tag-selected K |
|---|---|---|---|---|---|---|
|32|1|65|16|17|1|yes|
|32|2|129|88|89|2|yes|
|48|2|193|88|89|2|yes|

The C++ attack function accepts only public coefficient matrices and b. It does
not receive K, L_i, R_i, X_i^j, or an ORIGINAL witness. The Python root extractor
was rerun on a sanitized `*_public.json` containing only q, N, block size,
the public candidate polynomial, structural polynomial, and public tag. It
contains no setup seed, private key, private-factor data or rank-at-K diagnostic. A separate reference file is read
only AFTER recovery to validate the answer. These are synthetic research keys,
not user funds or unrelated third-party credentials.

A separate NumPy/SymPy small-field implementation over F_65537 recovered the exact
key in all 24 deterministic connected-source cases: 12 at b=1,m=32; 8 at
b=2,m=32; 4 at b=2,m=128,N=513. No field enumeration was used.

Larger 257-bit exploratory C++ runs at N=337 and N=385 exceeded the local runtime
limits and are NOT counted as completed cryptographic-field tests. Earlier
exploratory source fixtures were replaced by this connected family and are not
included in the final success totals.

These are direct key-recovery results, not a conclusion inferred merely from
low rank, a high assertion count, or absence of other attacks.

## 7. Reproduction

Python 3 with NumPy and SymPy:

    OPENBLAS_NUM_THREADS=1 python batch_check.py

C++17 with GMP/GMPXX and OpenSSL libcrypto development libraries:

    g++ -O3 -std=c++17 crypto_field_attack.cpp -lgmpxx -lgmp -lcrypto -o check
    ./check 48 2 6 sample
    python extract_roots.py sample.json --output sample_recovery.json

The public root result can be compared with sample_reference.json only in a
separate validation step. The field roots are found algebraically, not by trying
all possible keys. Timings in captured output describe this environment only and
are not forecasts for large compiled circuits.

## 8. Cumulative decision and remaining constructive scope

Computational QPT security would indeed suffice; information-theoretic secrecy
was never necessary. This version instead admits a CLASSICAL public algebraic
attack on the specified source family. It should not be called a secure generic
witness-KEM, even without residual masks or extra padding.

The typed source-rank/correctness lemmas and decoder remain mathematically useful,
but the claim that small noncommutative blocks alone hide the source decomposition
must not be used as a security argument. Lossless package compression cannot
remove this attack because it reconstructs the same three/four coefficient slices.

Dense/QAP-transformed sources, other protected-release mechanisms, and larger
blocks need their own analysis. Merely adding another mask or changing an honest
acceptance guard does not establish the missing arbitrary recovery-to-witness
arrow. No blanket impossibility theorem is asserted, and no new assumption that
restates release security is introduced. The practical PQ WKEM remains unresolved.
Production, PR state and automation are not to be changed by this finding.

## Exact dependencies and primary literature checked

- Run 695: `RUN695_SPECTRAL_COFREE_RELEASE.md`, blob
  `50174666730b93bd20f83bb29ddb2c355ccf1a91`, commit
  `bce27118e804c46f3897048aa14bfdf8df02192b` (connected metadata and full note read).
- Run 593 typed gate: `RUN593_COMPACT_NONCOMMUTATIVE_AADP.md`, blob
  `29b9168bfff6043810284cd1960400579f224e31`, previously live-read at the pinned head;
  its exact formula is reproduced and checked here.
- Latest coefficient audit commit `ef2246af43a567b8baa6863ee7b506cc9a1a5cd1` and
  ordinary comment `6355253790`, read live before this work.
- El Gebali, Rebenko, Schofnegger, Soukhanov, *Breaking ADP-Based Witness
  Encryption*, ePrint 2026/1594. Metadata/abstract inspected; full PDF returned
  HTTP 403. No full-paper proof audit is claimed.
- Patrick Towa, *Implementable Witness Encryption from Arithmetic Affine
  Determinant Programs*, Swiss Crypto Day, 4 September 2026. Rendered PDF pages
  57-59 (one-based) inspected: commutator attack and proposed block/QAP mitigations.
- Authors' AADP challenge specification at allocinit.xyz/posts/challenges read for
  the secret-factor/source-pencilling model and sparse-circuit context.
