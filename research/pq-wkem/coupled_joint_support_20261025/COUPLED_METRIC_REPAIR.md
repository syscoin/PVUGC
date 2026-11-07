# Coupled key-metric release: an experimental repair, not a secrecy reduction

**Local research ID:** `offline-coupled-metric-20261025`.

**Result classification:** a new explicit key-placement/evaluation algorithm, an exact repair of the archived separated-projection leakage mechanism, and honest-setup correctness/supplied-pair lemmas. **The arbitrary-recovery-to-ORIGINAL-witness reduction is NOT proved. This is not a secure or practical PQ witness-KEM.**

No Internet or GitHub access was used. This does not represent a scheduled execution or a verified publication. No automation was changed.

## 1. Precise continuation point and limitations

The local dependency is the supplied `PQ_WKEM_JOINT_REDUCTION_CHECKPOINT_20261024.zip`. Its archived arithmetic and quotient normalizer are pinned verbatim. That note analyzes the carrier at `fb1772abab1597cd7821623927b2fb318cb2fa9b` and proves a separated-projection key-list defect. The conversation also contains a later connected read identifying `aa814d446419d84babc294de00b0205d7fe3c636` and comment `6392754218`, which describes an additional joint-view functional defect. That later comment is known context, **not an offline reread of its complete proof or checker**. No claim is made that every certificate in that newer record has been independently checked here or that all of its consequences are repaired.

The failed scalar metric `I_N` is not retained. No additional padding, source-variable canonicalization, common preimage, trusted checker, online authority, or on-chain computation verifier is introduced.

The first contemplated substitution was to place the key on the already-public quotient matrix Q0. It was not promoted: Q0 has rank 2L < N and does not provide the invertible generalized-eigenvalue metric needed for the simple honest recovery proof. Nor does eliminating the old leading-coefficient argument alone prove secrecy. The construction below instead samples an independent local metric in the same hidden factor spaces.

The change is relative to the exact archived carrier. No claim of novelty across all earlier research or external literature is made.

## 2. Exact algorithm

Let E be a characteristic-two finite field of size q; let F be its specified proper subfield. The main illustrative parameters are |E|=2^256 and |F|=2^128. Let L be the number of off-domain QAP checks, N=2L+h, and d=n+m-1 the number of normalized source coordinates over F.

Retain the archived SOURCE encoding and the local affine gate

    G_e(y) = [[c_e(y), a_e(y), s_e(y)],
              [b_e(y), pi_e(y), 0],
              [s_e(y), 0, pi_e(y)]].

Retain independent uniform private U_e in E^(N x 3) and V_e in E^(3 x N), including all existing private source shears and pivots. Write

    M(y) = sum_e U_e G_e(y) V_e.

For each e, sample FIVE independent uniform E-valued scalars and form

    T_e = [[t_c,e, t_a,e, t_s,e],
           [t_b,e, t_pi,e, 0],
           [t_s,e, 0, t_pi,e]].

This is a uniformly random element of the five-dimensional linear space

    H = span_E {E11, E12, E21, E13+E31, E22+E33}.

Sample K independently and uniformly in E. Define the NEW public metric

    B = sum_e U_e T_e V_e,

and publish the coefficient matrices of

    C(y) = z K B + M(y),

together with B, the source/compiler parameters, field encodings, context, and the intended checking-key material. The hidden U_e,V_e,T_e, K and the private source mixing coins are NOT public outputs. In compressed form the quotient family is represented by Q0,Q1 exactly as in the predecessor.

**Public abort:** if rank(B) != N, this trial aborts before any irreversible funding. A retry must restart the complete independent setup trial. The checker does NOT silently condition T on fixed U,V through an unbounded retry loop.

This is the honest-erasure baseline. It is NOT keyless Build: setup computes K. A malicious-secure N-of-N realization is not supplied.

### Encode

For an ORIGINAL witness w, use the unchanged public R1CS/QAP construction: interpolate A_w, B_w, C_w, divide A_w B_w-C_w by Z, and encode the coefficientwise Frobenius square roots of its quotient. The resulting normalized y_w is F-valued. Different valid witnesses need not give the same y_w or M(y_w).

### Recover

Evaluate C(y_w) publicly. Because B is invertible, form B^(-1) C(y_w). Factor its characteristic polynomial over E and examine its E-valued eigenvalues lambda. Retain candidates satisfying

    rank(C(y_w) - lambda B) <= 2L.

The intended K always satisfies this inequality for a valid ORIGINAL witness. The simultaneous wrong-scalar lemma below makes it the unique such scalar, except on its explicitly bounded honest-setup event.

This is a classical randomized polynomial-time algebraic algorithm in the public package size and log(q). The small-field executable enumerates the 256 scalar candidates ONLY after it has checked a valid ORIGINAL witness. It does not implement or benchmark a cryptographic-size characteristic-polynomial factorization. No false-instance key-recovery routine is included.

### Canonical format

The same public two-sided quotient normalization P,Q can be used. Publish P C_i Q and **P B Q**. The former identity metric W=P Q is no longer the key metric and is not needed for this new key placement. The rank test uses

    rank(P C(y) Q - lambda P B Q).

This is pointwise identical to the untransformed test. The generalized-eigenvalue matrix is conjugate by Q to B^(-1) C(y), so its eigenvalues are unchanged.

## 3. What is proved about legitimate recovery

For every normalized input y, pointwise in all setup coins,

    C(y) - K B = M(y).

For every valid ORIGINAL witness, each local G_e(y_w) has rank two in the archived compiler. Therefore

    rank(C(y_w)-K B) <= sum_e rank(G_e(y_w)) = 2L < N.

Thus K is an eigenvalue of B^(-1)C(y_w). This proves **all-valid-witness common-capability correctness**, subject only to public setup abort and the existing SOURCE compiler's correctness. It does not force identical intermediate states.

The correct-key supplied-representation implication is also unchanged pointwise: if the predecessor's theorem extracts an ORIGINAL witness from a normalized F-valued y with rank(M(y)) <= 2L, exactly the same extractor applies to rank(C(y)-K B) <= 2L. This is a transport of the existing input theorem, not a new Run-259 invocation or a proof that a bare K supplies y. Run 259's exact source was not used or restated as a stronger theorem.

## 4. Exact rank distribution of the fresh local metric

For a uniform T in H, the determinant is

    det(T) = pi * (pi*c + a*b + s^2).

The exact counts among q^5 matrices are:

    rank 0: 1
    rank 1: 2 q^2 - q - 1
    rank 2: 2 q^4 - q^3 - 2 q^2 + q
    rank 3: (q-1)^2 q^3.

Proof: for pi != 0, the lower 2x2 pivot is invertible, and exactly one c value makes the determinant vanish for every a,b,s. For pi=0, a rank-at-most-one matrix requires s=0 and ab=0. Count the two coordinate axes in (a,b), then choose c, and separate the zero matrix.

Let D_e=3-rank(T_e). The counts give

    E[q^D_e] = 3 - 1/q - 1/q^2 <= 3.

For independent local metrics,

    Pr[sum_e D_e >= u] <= 3^L q^(-u).

This is an ordinary finite probability calculation, valid for every q=2^s. The checker exhaustively confirms the counts over GF(4); the proof, not that enumeration, supplies the general statement.

## 5. A simultaneous supplied-F-pair wrong-key lemma

This section is **not key hiding**.

Fix a normalized F-valued y and any lambda != K. Set delta=K-lambda. For each e,

    G_e(y) + delta T_e

is uniform in H, independently across e, because H is an E-linear space, G_e(y) belongs to H, and delta is nonzero. The T_e are independent of the source mixing and U,V. This reasoning is for each fixed pair; simultaneous validity is obtained by a union bound, not by pretending that a public-data-dependent pair is independent of the setup.

Let H_y,delta be the block-diagonal matrix of these local gates. If

    rank(H_y,delta) >= 2L+2h = N+h,

then the product with independent uniform U in E^(N x 3L) and V in E^(3L x N) obeys

    Pr[rank(U H_y,delta V) <= 2L | H_y,delta] <= 16(N+1) q^(-h^2).

Here is the counting proof. If the inner rank is rho >= N+h, replace the product by independent uniform A in E^(N x rho) and D in E^(rho x N). Condition on rank(A)=a. The first rank event has probability at most 4 q^(-(N-a)(rho-a)); for a>2L, the second has probability at most 4 q^(-(a-2L)h). Put j=N-a. The sum of exponents is

    h^2 + j(rho-N-h+j) >= h^2.

For a<=2L, the first exponent alone is at least h(rho-2L)>=2h^2. Sum over at most N+1 values of a. The bound uses the usual elementary finite-field subspace count, with the conservative factor four; it does not assume a computational problem is hard.

The inner-rank condition fails only if total deficiency is at least

    u = L-2h+1.

Consequently, for L>=2h and a fixed (y,lambda),

    Pr[rank(C(y)-lambda B) <= 2L]
       <= 3^L q^(-(L-2h+1)) + 16(N+1)q^(-h^2).

There are |F|^d normalized source vectors and at most q wrong candidate scalars. Hence the simultaneous bound is

    epsilon_wrong_F <= |F|^d q *
        [3^L q^(-(L-2h+1)) + 16(N+1)q^(-h^2)].

An arbitrary QPT adversary choosing a CLASSICAL F-valued pair after inspecting all public matrices and checking material cannot evade this pointwise event. This statement does not require rewinding or a random oracle. It gives no claim about recovering K without producing that pair, nor about coherent algorithms that never produce a source vector.

**Scope change explicitly retained:** this new lemma covers normalized F-valued source vectors, not every E-valued source vector. The predecessor's full-E wrong-scalar theorem cannot simply be carried over after changing the key metric. The earlier rank facts for unchanged original/quotient coefficient combinations remain facts about those combinations; they say nothing automatically about combinations that also use the new B.

## 6. Public metric abort probability

Each T_e is invertible with probability (1-1/q)^2, so the union bound gives an inner singularity probability at most 2L/q. Conditioned on all local T_e being invertible, U T is a uniform N-by-3L matrix. Its full-row-rank failure probability is at most

    q^(-(3L-N+1))/(1-1/q).

Conditioned on full row rank, U T V is uniform in E^(N x N). Its singular probability is at most 1/(q-1). Thus a conservative public-abort bound is

    epsilon_abort <= 2L/q + q^(-(L-h+1))/(1-1/q) + 1/(q-1).

All preceding bounds describe one unconditioned honest trial. For the distribution conditioned on non-abort, divide a failure bound by 1-epsilon_abort. Do not silently apply the unconditional bound to a selected capsule.

## 7. Constructive repair of the archived separated-projection mechanism

Use the exact publicly observable quotient normalizer. Each node's exposed columns U_e[:,{1,3}] and rows V_e[{1,3},:] are supported on its own two-coordinate quotient block after normalization.

Let H_A select quotient row blocks in a node set A plus complementary rows, and let Z_B select column blocks in a disjoint node set B plus complementary columns. For EVERY node e, at least one of the following holds:

- H_A U_e has only its hidden middle column potentially nonzero;
- V_e Z_B has only its hidden middle row potentially nonzero.

Therefore, for **every local 3x3 matrix X_e**, not only honest gates,

    rank(H_A U_e X_e V_e Z_B) <= 1.

Summing nodes gives

    rank(H_A B Z_B) <= L,

and, more importantly,

    rank(H_A [C(y)-z lambda B] Z_B) <= L

for EVERY y and EVERY lambda. This latter statement follows because the whole expression is the sum of the same local products with

    X_e = G_e(y) + z(K-lambda) T_e.

It is stronger than merely observing that the projected metric has rank <=L. A low-rank leading coefficient alone would not make every determinant polynomial vanish. Here the entire projected pencil has rank <=L for every scalar, so all (L+1)-minors are **identically zero polynomials**, by the pointwise local factorization over E[T], not by counting a finite set of roots.

Thus the nonzero degree-(L+1) key polynomial used in the archived defect cannot be obtained from these projections of this repaired pencil. This is an exact change to the public release structure, not a new hardness assumption.

A related limited functional observation is also exact. For any supplied linear functional ell that annihilates the entire exposed local-gate space sum_e H_A U_e H V_e Z_B, both the baseline and B vanish under ell. It cannot simultaneously satisfy ell(H_A B Z_B)=1. This is NOT a claim that all possible new public functions or every later certificate must annihilate that space; a certificate proving only ell(M0)=0 need not do so.

**Critical limitation:** neither statement proves full-public-output key secrecy. Original-coordinate matrices, B, C0 and the checking key may jointly expose a different invariant, a smaller affine baseline space, or a factor reconstruction. The newer aa814d full proof was not reread offline; no universal claim that its entire attack family is closed is made.

## 8. Executed validation

The new checker uses the exact archived field and normalizer helpers, plus a complete small R1CS -> interpolation -> QAP quotient -> affine gate -> public matrix pipeline.

Two final executions produced byte-identical validation JSON, with **1,792 direct assertions**. Dependency assertion counts are separately recorded: 471 field/helper assertions and 388 normalizer assertions. There is no independent external review or quantum proof checker.

Checks include:

- exhaustive 1,024-element GF(4) local-metric census and the exact rank counts;
- two true and two false GF(16)-inside-GF(256) source fixtures, with L=9 or 10;
- six honest public recoveries across the three distinct ORIGINAL witnesses per true setup, all recovering the same K within a setup;
- exact current-gate interpolation, Frobenius lifting, and common-key rank identities;
- public quotient normalization and projected per-node rank-at-most-one support identities;
- 240 supplied-secret projected-pencil checks across scalar/source combinations;
- a control showing that the predecessor's projected identity metric has rank >L in each fixture, while the new projected metric and entire shifted pencil stay within rank L;
- exact integer checks of the illustrative simultaneous-pair/abort bounds.

False sources are checked only with retained synthetic setup data to verify identities and ORIGINAL unsatisfiability. No false-source key search, unknown-key factorization, native signing, blockchain access, third-party credential, deployment, or cryptographic-size matrix experiment was performed. The large-parameter certificates are integer arithmetic, not measured secrecy or practicality.

## 9. Concrete parameters and resources

For n=11,000, m=16,000, L=16,374, h=165, N=32,913, q=2^256, |F|=2^128, d=26,999, the wrong-scalar terms are bounded by

    3^16374 / 2^651392 < 2^-625439,
    526624 / 2^3513472 < 2^-3513452.

Their sum is below 2^-625438 for an unconditioned honest trial. The abort probability is below 2^-241. These enormous exponents concern a narrow wrong-scalar rank event; they are **not a security level and not a reduction for K secrecy**. The correct-key ORIGINAL-binding error must still be added at its archived scope.

A dense N-by-N E-matrix takes 34,664,498,208 bytes. Raw two-quotient serialization has 11,004 such matrices, or 381,448,138,280,832 bytes. The canonical format has 11,002 dense matrices, or 381,378,809,284,416 bytes, because P B Q replaces the old metric P Q. This omits metadata, the public source description, checking material and computation overhead, just as the predecessor's dense-matrix estimate did. It is still approximately 381 TB per capsule. No optimality or practicality claim is made.

The new local metric needs five extra private E-scalars per node. These are setup coins, not a new public witness or public matrix per node. Classical dense evaluation, inversion and finite-field factorization remain polynomial but far too expensive at these sizes.

## 10. Complete public-view security ledger

**Proved here:** honest common-key rank correctness for the new encoding; the local metric rank law; the supplied-F-pair wrong-scalar bound; a public-abort bound; exact disappearance of the archived disjoint-support determinant discriminator; correct-key rank identity and canonical-format equivalence.

**Inherited only at its real scope:** an accepted classical normalized source representation at the correct key can be handled by the existing SOURCE/rank extractor. No bare-key extractor has been constructed.

**Not established:** false-instance key hiding; hard-true unauthorized recovery extraction; accepted native-forgery reduction; every-E-source wrong-key exclusion; distributional pseudorandomness of the complete joint tuple; security with malicious/correlated setup coins; selective opening or related capsules; an N-of-N implementation; practical resources.

The honest algorithms are classical randomized polynomial time. The intended attackers are arbitrary QPT with coherent computation over all published classical data; no online evaluation oracle or new QROM is introduced. Quantum advice/auxiliary information must be accounted for by a future game, including public checking-key correlations. No security claim is made in a game that simply excludes the attacker's internal representations. Setup coins and K cannot be handed to the attacker and then called hidden; the stronger retained-builder-coins/keyless variant is not achieved.

For multiple claims, reusing a baseline and metric across different K can reveal key differences. Fresh full setup randomness and context binding are required, but are not asserted to prove composable secrecy. Metadata/domain separation alone does not repair secret-material reuse. No cross-UTXO security theorem is claimed.

Relevant internal checks addressed the old projection seam and global quotient normalization. Statistical gate-rank distributions were derived, not mistaken for pseudorandomness. Multi-view, chosen-evaluation, setup, replay, public-checking-key and genuinely coherent quantum attacks remain part of the unresolved full-view obligation. The test suite is not claimed to cover these cryptographic families exhaustively.

## 11. Exact remaining reduction for this candidate

After fixing the source and private mixing, define the hidden linear map

    Phi(X_1,...,X_L) = sum_e U_e X_e V_e,   X_e in H.

The actual new key-bearing distribution is

    B  = Phi(T_1,...,T_L),
    C0 = Phi(G_1(e0),...,G_L(e0)) + K B,
    Ci = Phi(G_1(ei),...,G_L(ei))  (i != 0),

with quotient markers, the known SOURCE relation, native checking material for K, contexts and correlated external data also available.

Although T is uniform and independent, B is PUBLIC. It is therefore invalid to call K B a hidden one-time pad. Nor may one replace Phi by an ideal random function: it uses the same U,V in every public matrix. No reduction embedding a standard QPT-LWE/SIS challenge into this complete distribution, or extracting an ORIGINAL witness from an arbitrary successful recoverer, has been found.

The next proof must analyze this joint tuple, especially the correlations between the new B and the original-coordinate matrices. It cannot rely only on the separated projection now made uninformative. Merely assuming that this tuple hides K on false statements would rename the missing release-security statement, and is not adopted here.

**Stopping status:** the requested reduction is unresolved. This is an experimental carrier repair with bounded algebraic guarantees, not a claimed secure replacement or completion. All new material remains local; no GitHub publication or scheduler recovery is claimed.
