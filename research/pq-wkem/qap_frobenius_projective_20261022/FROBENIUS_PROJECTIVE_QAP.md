# Frobenius-quotient QAP: projective normalization with no extra public matrices

Checkpoint `qap-frobenius-projective-20261022`. Interactive continuation; no scheduler run ID was supplied. This is a source-compiler/rank-gadget component, **not a secure PQ witness-KEM**, a recovery-to-witness security reduction, or a deployment recommendation.

## 1. Exact continuation and constructive delta

Connected GitHub reads found syscoin/PVUGC#1 open, draft and unmerged, on `research/pq-wkem-validation-20260918`, at `418e86149dc047835960bfe7fa65f3c7834d1049`. The latest substantive comment was 6357634771. The exact preceding QAP note is blob `f201441801d9ccdcb8a2af35a4a579eae563f7a5`; construction state is `d492be3ce232b2c6bfce384aae65bbff35671f47`; reference implementation is `c52065a432c553705e29ddf792e1403f8e9c7e80`. These files were read at that commit before deriving this component.

That checkpoint left nonzero quotient-only solutions on the homogenizing hyperplane z0=0. This construction removes those solutions algebraically, inside the source equations used by the rank gadget, rather than by an optional public guard. It preserves the number of quotient coordinates, evaluation gates, coefficient matrices, and scalar-block output dimension. Every valid ORIGINAL Boolean witness has one well-defined lift; different witnesses need not have the same intermediate matrix.

Two real changes are required: a characteristic-two source field, and a new alternating 4-by-4 gate instead of the earlier private-affine-X gate. The public ciphertext distribution changes. This is NOT a security-preserving conversion of the old carrier. In particular, its internal affine matrix masks are not retained or silently claimed unnecessary for security. QAP interpolation, Frobenius and the Pfaffian identity are established algebra; no literature-priority claim is made for them.

## 2. Honest model and exact source requirement

Let F=GF(2^kappa) with an explicitly specified irreducible modulus. Honest source compilation, setup, encoding, field arithmetic and decoding are classical. A polynomial-basis implementation gives polynomial-time field arithmetic in kappa. The supplied table-based demonstration backend deliberately accepts only kappa=2..8; it is NOT a cryptographic-size implementation.

Start with a COMPLETE Boolean-circuit R1CS, homogeneous coordinates z=(z0,z1,...,zn), and m>=2 rows

    (A_i z)(B_i z) = z0 (C_i z).

At z0=1 this must encode the actual ORIGINAL relation, including all input and acceptance conditions. Require an explicit Booleanity row z_j^2=z0*z_j for every free wire. This efficiently checkable sufficient prerequisite is enforced by the reference compiler, not merely assumed by its tests. A separately proved projectively safe original source can replace this prerequisite, but is not implemented here.

A circuit already expressed over F2 with Boolean wires retains its Boolean semantics over F. For example NAND is uv=1+w and an accepting output is w=1. One must NOT translate an arbitrary odd-characteristic arithmetic relation to characteristic two by reducing its constants: that can change its language. Original field-arithmetic workloads require a proved Boolean-circuit compilation or another equivalence proof. Actual SYS/BTC parsing, authentication and fork-evidence constraints are not implemented in this fixture.

## 3. Construction: square-root quotient coordinates

Choose distinct gate nodes t_1,...,t_m and L=2m-1 distinct off-domain nodes e_1,...,e_L. Require q>=m+L. Let Z(T)=product_i(T-t_i). Interpolate degree-<m source polynomials A_z(T), B_z(T), C_z(T) from the original rows.

Replace the previous freely homogenized quotient coordinates h_j with rho_j, j=0,...,m-2, and define

    H_rho(T) = sum_j rho_j^2 T^j.

At every off-domain node impose

    A_z(e) B_z(e) + z0 C_z(e) + Z(e) H_rho(e) = 0.       (1)

All equations are homogeneous quadratic in (z,rho). Because squaring is a bijection of a finite field of characteristic two, every possible quotient coefficient has exactly one square root. No possible original quotient is excluded.

Define the PUBLIC linear form

    S_e(rho) = sum_j sqrt(Z(e) e^j) rho_j.

Then S_e(rho)^2 = Z(e) H_rho(e). Computing the coefficients uses the inverse Frobenius map sqrt(a)=a^(2^(kappa-1)). It needs no secret or new oracle. Equation (1) becomes

    a*b + d*c + s^2 = 0,

where a=A_z(e), b=B_z(e), c=C_z(e), d=z0, s=S_e(rho). Each of these five forms is LINEAR in the published source coordinates.

### Encode and supplied-source extraction

Encode(w): produce the complete normalized original wire assignment z=(1,w). Divide A_z B_z+C_z by Z. Reject a nonzero remainder. Its unique quotient has degree at most m-2; set rho_j to the unique square root of each coefficient. This is a witness-preserving deterministic lift, not canonicalization between different ORIGINAL witnesses.

SuppliedSourceExtract(z,rho): check all equations and that the vector is nonzero. The theorem below implies z0!=0. Divide ALL coordinates by z0, project to the original wires, and run the original SOURCE extractor/checker. No bare key or signature is supplied to this extractor, and no key-only extraction claim is made.

## 4. Projective-safety and bijective-lift theorem

**Theorem.** For the complete source above, every nonzero solution of (1) has z0!=0. Normalization yields exactly one Frobenius-quotient lift per accepted original source. Conversely each accepted original source has that lift.

**Proof.** The polynomial

    F(T)=A_z(T)B_z(T)+z0*C_z(T)+Z(T)H_rho(T)

has degree at most 2m-2. Vanishing at L>=2m-1 distinct nodes makes it the zero polynomial. At each gate node, Z=0, so all original homogeneous R1CS rows hold.

If z0=0, every explicit Booleanity row gives z_j^2=0 and hence z_j=0. Thus A_z=B_z=C_z=0. The identity F=0 reduces to Z*H_rho=0. F[T] is an integral domain and Z is nonzero, so H_rho=0. Each rho_j^2=0, hence every rho_j=0. This contradicts the assumed nonzero source vector. Therefore z0!=0.

Divide the vector by z0. All equations are homogeneous quadratic, and H_(rho/z0)=H_rho/z0^2, so the normalized source satisfies the original relation and the same polynomial division identity. Uniqueness of the quotient and bijectivity of squaring give the unique lift. Conversely, polynomial division for any valid original source yields (1). QED.

This removes the exact quotient-only infinity defect in the prior checkpoint. It does not restrict an attacker to producing a source vector or evaluating at a point.

## 5. Constant-size rank gadget and public spectral operator

Use the alternating matrix

    P(a,b,c,d,s) = [[0,a,d,s],
                    [a,0,s,c],
                    [d,s,0,b],
                    [s,c,b,0]].

In characteristic two, direct determinant expansion gives

    det(P) = (ab+dc+s^2)^2.                            (2)

An alternating matrix has even rank, including in characteristic two. A nonzero alternating 4-by-4 matrix therefore has rank 2 when its Pfaffian ab+dc+s^2 is zero, and rank 4 otherwise. The zero tuple has rank 0. Equivalently, pivot on any nonzero off-diagonal entry: the remaining 2-by-2 alternating Schur complement has off-diagonal entry equal to the Pfaffian divided by the pivot. This proves the rank rule without any characteristic-zero assumption.

Every normalized valid source has d=1, so every valid gate is nonzero and has rank EXACTLY 2. The gate is four-by-four, the minimum dimension within alternating gadgets requiring ranks 2 and 4; no global circuit-size or KEM optimality result follows.

For each of the L gates independently sample full uniform outer matrices

    L_e in F^(N x 4), R_e in F^(4 x N), N=2L+1.

Use independent left and right factors, NOT R_e=L_e^T. Congruence-only mixing would make the aggregate alternating; its odd dimension would make it singular for every input, which is not the intended distribution.

Set M(y)=sum_e L_e P_e(y) R_e. Publish its k=n+m coefficient matrices with the capability shift in the z0 slice:

    C0=M0+K I_N, Cj=Mj for j>0.

Also publish the complete relation/context, field definition, compiler/node generator, native verification key and any separately justified exact-key selector. The algebraic fixture uses a synthetic context-bound SHA3-256 selector, not a native signing scheme. Outer factors and their coins remain secret; no keyless construction is claimed.

For every valid normalized witness, rank M(y)<=2L=N-1, so K is an eigenvalue of C(y). Thus the existing field-polynomial spectral recovery interface remains applicable. Different witnesses can give different matrices. The reference performs random scalar Krylov projection, Berlekamp--Massey, gcd(f,T^q-T), and characteristic-two trace splitting, followed by the toy public selector. It does not enumerate all possible field keys to recover the test capability.

The correctness statement is algebraic and holds for every accepted source. The probability of capturing a particular eigenvalue in a random projection is the separate existing decoder condition; no new proof about native-key uniqueness is inferred here.

## 6. Global source coupling is retained at the source-operator level

Let eta be a nonzero coefficient direction, including quotient directions. If eta_0!=0, d is nonzero at all L nodes. If eta_0=0 and the original direction is nonzero, the explicit Booleanity rows make the stacked A_free/B_free map injective. Some A or B polynomial is nonzero of degree at most m-1, so at least L-m+1 gates have a nonzero tuple.

If the original direction vanishes and rho is nonzero, write

    S_e(rho) = sqrt(Z(e)) * sum_j rho_j (sqrt(e))^j.

The sqrt(e) are distinct; the final polynomial is nonzero of degree at most m-2. At least L-m+2 gates have nonzero S_e. Their tuples have a=b=c=d=0, s!=0, and in fact rank 4. In particular, all nonzero directions have block-diagonal source rank at least 2(L-m+1).

The prior random projection lemma consequently gives, for any a>=0,

    Pr[exists eta!=0: rank(sum_e L_e P_e(eta) R_e)
                        < 2(L-m+1)-2a]
      <= min(1,8*(q^(n+m)-1)*q^(-(a+1)^2)).

This is a structural all-direction statement under independent honest factors, inherited from the previously proved random-projection argument. It is NOT a full-output hiding theorem: an adversary need not produce a low-rank source direction. Matrix-valued/nonlinear transforms are not constrained by this scalar-direction property.

## 7. Package accounting and exact limits

For L=2m-1, the scalar-block dense operator has

    k=n+m coefficient matrices,
    N=4m-1,
    k*N^2 field elements,
    k*N^2*kappa bits with fixed-width field packing.

These are EXACTLY the same coefficient count and dimensions as the prior scalar-block QAP checkpoint. There are no extra quotient variables, evaluation gates, or padding. Both the field and the gate distribution changed, so equal payload capacity does not mean identical security.

The executed NAND example has n=3,m=5,L=9,k=8,N=19: 2,888 GF(256) elements, or 2,888 raw payload bytes. Relation metadata, field modulus, native keys, tags, graph data, and setup proofs are excluded from this number and must be counted in a real package.

At a hypothetical 256-bit field, n=29,m=30 gives 26,735,968 raw bytes. The former n=11,000,m=16,000 illustration gives 3,538,833,408,864,000 raw bytes. These are arithmetic counts, NOT practical security parameters or measured large implementations. This fixes a normalization gap without further increasing the already-large QAP representation; it is not a small-package breakthrough or globally optimal encoding.

No security-neutral compression is imported without its own hypotheses. In particular, independent random factors cannot be replaced by exposed seeds; alternating congruence cannot replace independent two-sided mixing.

## 8. Executed validation

The exact two Python files in this directory were compiled and executed twice with byte-identical JSON output. Final result: 2,780 explicit assertions.

- Field moduli for GF(4), GF(8), GF(256) passed deterministic irreducibility checks; a reducible negative control was rejected. Square-root and inverse identities were checked over each full field.
- All 1,024 tuples of five GF(4) source scalars passed the exact rank and determinant rule: 1 rank-zero, 255 rank-two, 768 rank-four.
- Complete normalized and z0=0 censuses: 4,096+4,096 assignments for a true source; 512+512 for a false source. Only the zero vector was accepted at infinity. Normalized true sources were exactly the three ORIGINAL witnesses; the false source had none.
- The matching prior z0*H homogenization has 63 nonzero pure-quotient infinity vectors in each case; the new equations accept zero of them. This is a normalization regression, not a key-recovery attack claim.
- All 32,767 nonzero coefficient directions in the GF(8) true fixture meet the source support/rank bounds. Observed minimum support 4 and block rank 10; proved lower bounds are 3 and 6.
- Three independent GF(256) setups and three valid NAND witnesses per setup: nine successful common-key spectral recoveries, with three distinct witness matrices per setup. Public coefficient evaluation equals direct private assembly on additional arbitrary vectors, including nonnormalized inputs.
- Two old public-pencil templates, two index sets and three setups: 12 key-pencils were full rank. These finite diagnostics do NOT prove resistance, do NOT establish a security level, and are not a matched reproduction against every previously attacked source.

All keys/contexts/coins are synthetic. No deployment, account, native transaction or third-party credential was attacked. Assertion counts are algebraic implementation checks, not cryptographic trials.

## 9. Cumulative construction and attack-surface ledger

Retained proved pieces: complete Boolean SOURCE semantics; QAP interpolation; same-capability rank correctness; public field-polynomial decoder; supplied-source extraction. New proved piece: projectively safe Frobenius quotient lift realized by an equally sized alternating rank gadget. The positive result is source compilation, not a newly assumed release oracle.

The earlier constant-mask and sparse small-block unmasked carriers stay broken in their recorded scope. Their correctness components do not certify this changed ciphertext distribution.

Honest algorithms are classical PPT in the mathematical model. The target attacker remains arbitrary QPT, receiving the COMPLETE classical public array, context, native checking material, all permitted auxiliary input, and polynomially many capsules, with coherent evaluation of public code permitted. None of these attacker powers are removed to make a security claim. No random oracle, rewinding, hidden-extractor oracle, quantum-advice cloning, or hardness assumption is used in the projective/rank theorem.

Attack-family accounting: (1) source seams are constrained by the complete polynomial identity; this is not arbitrary coefficient-processing soundness. (2) global frame/algebra recovery is unproved. (3) distribution fingerprints are not hidden by this theorem. (4) joint related-capsule security is unproved. (5) public arbitrary-input evaluation is fully available; the two fixed-pencil probes are only internal regression checks. (6) retained setup factors reveal the precursor and K; malicious/abort-secure N-of-N setup is not provided. (7) context-tag changes are tested only in the toy selector; no cross-UTXO graph theorem follows. (8) native public-key/tag correlations remain in the target view and require a joint proof. (9) no-attack-found on classical probes is not evidence against coherent quantum attacks.

The decisive missing arrow is STILL arbitrary unauthorized key recovery / accepted native forgery -> ORIGINAL witness or an independently justified QPT break. Projective safety and supplied-source extraction do not imply that arrow. Full-public-output false-instance hiding, hard-true extraction, practical parameters, ceremony and Bitcoin graph remain unproved. The unchanged conditional PQ endpoint does not supply this missing release primitive.

Next exact work item: analyze the full correlated alternating coefficient tensor and its quotient-coordinate subpencil under independent two-sided mixing. In particular, determine whether an alternate public algebraic decomposition recovers K without producing a source; do not treat the normalization repair or the two passing pencil probes as a hardness assumption. Preserve this compiler component even if its first attempted carrier needs replacement. No automation disablement or production change follows from this checkpoint.

## Sources and provenance

- Exact connected GitHub dependency: qap_source_coupling_20261022/QAP_SOURCE_COUPLING.md at 418e86149dc047835960bfe7fa65f3c7834d1049, blob f201441801d9ccdcb8a2af35a4a579eae563f7a5; state and code blobs listed in Section 1.
- Sage primary finite-field implementation documentation, inverse Frobenius / p-th power with negative exponent: https://doc.sagemath.org/html/en/reference/finite_rings/sage/rings/finite_rings/element_pari_ffelt.html . Used only as an implementation reference; the field identity is proved explicitly above.
- The 4-by-4 determinant identity is expanded and exhaustively checked here. No new external RIO, WE, QPT or standard-assumption theorem is imported. No PDF was analyzed in this iteration.
