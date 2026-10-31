# Compact polar SOURCE release — turn 11 (26 October 2026)

**RESTRICTED POSITIVE RESULT; NOT A PRACTICAL OR GENERIC-NP PQ WITNESS-KEM.** Built on the exact published full-public SOURCE Fourier/wiretap example at commit `90aceb4ebda1a90c0a329c53be52e9cb89841689` (parent note: `research/pq-wkem/fullview_theta_wiretap_20261026/README.md`, blob `2951e4b5205b5b204858cd04d2b8c0747b112590`). Independent standard polar-code and leftover-hash theorems are applied to the ACTUAL public quotient channel, not an assumed SourceOpen or an LWE challenge. The existing source has only 2 Boolean variables; hard-true arbitrary-key security remains COMPLETELY OPEN.

## Complete finite classical release

Let C_x be the earlier r×m Boolean one-hot factor SOURCE, whose every valid ORIGINAL witness w maps to a distinct binary v_w with C_x v_w=0, (v_w)_0=1, and wt(v_w)=B=1+n+g. Compute a public basis R∈F₂^{h×m} for ker C_x, h=m−rank(C_x), and b=R e₀. Choose L=2^s, p∈(0,1/2), X←Uniform(F₂^L), independently E_j←Ber(p)^m for each j. Set p_B=[1−(1−2p)^B]/2 and C_h=1−h₂(p_B). Construct a standard polar code G_L=([[1,0],[1,1]])^{⊗s} for BSC(p_B), its information set I and frozen set F with |F|/L→1−C_h; publish the frozen helper W=(XG_L)_F. Independently choose a public binary two-universal Toeplitz H:F₂^L→F₂^k.

**Publish:** (relation identity, x, claim/UTXO, branch, anchors, window, full context, C_x,R,b,p,L,I,W,H,Q,T=K⊕HX,vk(K)), where Q_j=R E_j+b X_j. K is the SAME already-precommitted native capability for every witness. All auxiliary inputs and checking-key correlations must be included in security games. No private SourceOpen oracle, public witness, or NP proof is used at Build.

**Open(original w):** Verify R_x(w)=1 OFF CHAIN. Compute its one-hot v_w, solve α_w R=v_wᵀ publicly, and form Z_{w,j}=α_w Q_j=X_j+v_wᵀE_j. Each valid w sees a *marginal* BSC(p_B) over independent columns, even if distinct witness projections are mutually correlated. Polar successive-cancellation decoding with W recovers Xhat; return Khat=T⊕H Xhat only if it agrees with the native checking key and challenge path. There is no canonical witness or common intermediate representation. Standard polar coding gives classical O(L log L) encoding/decoding and error O(2^{−L^β}) for any β<1/2 at asymptotic information rate <C_h. Union bound gives simultaneous correctness over at most 2^n valid witnesses when L^β exceeds a suitable multiple of n+security parameter. This is PPT in L, but NOT proved PPT in generic x because the gap can shrink exponentially.

## Exact full-public simulation and 82.35% smaller release data for the pinned example

The preceding full public carrier was Y=C_xᵀS+E+e₀Xᵀ with *independent uniform* S. Then Q=RY and ker R=im(C_xᵀ). For every column, conditional on Q_j, X,K,W,H,T,context (all independent of S), the full Y_j is UNIFORM on the affine fiber {y:R y=Q_j}. An exact, classical public simulator chooses any y₀ with R y₀=Q_j and returns y₀+C_xᵀs for a fresh uniform s. Conversely Q=RY is deterministic. Therefore publishing ONLY Q and omitting S is a perfectly two-way publicly simulatable release transformation, including all joint Y coordinate projections and arbitrary QPT postprocessing, subject to the stated non-leakage of S. It is not an unproved marginal LWE hybrid.

For the explicit unsatisfiable four-factor SOURCE from the predecessor (two variables, each of 00,01,10,11 forbidden by one factor), m=17, rank C=14, h=3. The release Q has **3 vs 17 bits per column** (82.35% less release-matrix data); polar helper and hash seed remain extra public overhead. This exact compression may be less effective on general relations.

## Full false-instance information, exact improved rational parameter

This false SOURCE's kernel consists of zero; three nonzero v₀=0 vectors with weights 10,10,12; and four v₀=1 vectors with weight 9. Let ρ=1−2p, D=1+2ρ^{10}+ρ^{12}, t=4ρ^9/D, and J(z)=1−h₂((1+z)/2). Complete quotient Q reveals X only in an even-parity sector of probability D/4; the odd sector there is a BSC of bias t. Thus **exactly**

    I_false(X;Q) = (D/4) J(t)

for the ENTIRE publicly available Q, not a selected pseudowitness. Equivalently for every q∈F₂³,

    P(Q=q | X=x) = 2^−3 Σ_{a∈F₂³} ρ^{wt(a R)} (−1)^{a·q + x (a R)_0}.

In the matching TRUE control (all four factors forbid 00), ORIGINAL witnesses 01,10,11 have weight B=7 and observe BSC bias ρ^7. Choose the rational parameter p=4/25 (ρ=17/25). The executed exact-binary-source calculation gives

    honest capacity C_h           = 0.003262848797040 bits/column
    complete false information I_f = 0.002656702680633 bits/column
    gap g = C_h−I_f                = 0.000606146116407 bits/column.

This strict positivity is independently certified with RATIONAL arithmetic. Use J(z) ln2=Σ_{j≥1}z^{2j}/[(2j)(2j−1)], truncate after j=5 and bound the positive tail by z^12/[132(1−z²)]. Rational lower/upper bounds on (C_h−I_f)ln2 have strictly positive lower endpoint, SHA-256 of the canonical two rational endpoints `ddc5da084b55ceccdcfc2261261ba5c9dbd0eb28e4baf67a69df1897d427f6d5`. Relative to the predecessor's proven conservative rate at p=1/5, this is ~3.95× as much gap; relative to its exact p=1/5 rate, ~2.19×. It is an efficiency improvement solely for this restricted false relation. The theoretical Shannon floor 256/g=422341 columns excludes polar finite-length losses, extractor error, 128-bit margins and setup.

## Explicit polynomial-time reconciliation and full-view false security

For any δ>0 with 3δ<g, use a polynomial-time constructible capacity-achieving polar family for BSC(p_B), publish W=U_F with U=XG_L, |F|≤(1−C_h+δ)L, and use a random public 2-universal Toeplitz H. The joint variables (X_j,Q_j) are genuinely independent across j; there is no SOURCE-opening oracle and no ignored checking-key term. Finite-alphabet AEP gives H_min^ε(X^L|Q^L)≥L(1−I_f−δ), exponentially good in L for constant δ. Because W is |F| public bits,

    H_min^ε(X^L|Q^L,W) ≥ L(g−2δ).

For k<L(g−3δ), leftover hashing makes (Q,W,H,HX) statistically close to (Q,W,H,U_k), with error ε+O(2^{−δL/2}). Therefore replace the actual T=K⊕HX by a fresh uniform T while preserving vk(K), relation/context and any aux independent of hidden X conditional on K/context. The simulator handles the COMPLETE released quotient and public helper correlations. Arbitrary QPT operations cannot increase trace distance for classical outputs with independent quantum advice. Independent fresh related capsules compose by hybrid sum; correlated capsule random coins, malicious setup and selective disclosure of the same native secret are NOT covered.

The polar theorem is a known classical coding result, not a new QPT hardness assumption; its capacity-achieving frozen-set selection has NOT been implemented at finite security size in this run. This is an **asymptotic end-to-end PPT release/recovery/secrecy theorem for the ONE fixed false source and matching easy true control**, not generic witness encryption.

## Actually executed, provenance, and absolute limitations

Offline stdlib-only exact checker: 617 assertions, two byte-identical executions. It constructs the actual false SOURCE, certifies rank/nullspace/kernel weights, exhaustively enumerates all 2^17 Bernoulli noise masks with rational probabilities and compares 16 conditional quotient values to Fourier, verifies three distinct true ORIGINAL witnesses and 128 random compact-release identities, proves the positive rational rate gap, implements polar butterfly+SC decoding and a Toeplitz key mask. At N=4096 with only ONE unfrozen bit, 15/15 seeded honest decoder trials and 15/15 reconstructions of the same precommitted 32-bit toy K passed. **The toy public helper reveals almost all of X; those checks claim NO confidentiality, NO large-code polar performance, and NO native-signature security.**

Checker SHA-256: `2b4ed9fbc59bd3c225e3b1e8eb8144f476ebfda6f8aa632391515e816af8e5a6`. Captured output SHA-256: `e08bda64268bc96da27a25d7fd2e431b8a59c8b7327d7fc78bc616760dde9655`. Complete long derivation, exact executed checker, output, provenance and executable source archive is retained as this run's local artifact (NOT claimed published without exact GitHub byte readback).

**DECISIVE UNSOLVED equation:** For actual hard-true generic x and arbitrary QPT A, prove unauthorized key recovery or accepted native signature forgery on full (x,ctx,C,R,Q,W,H,T,vk,aux,related capsules) implies an **ORIGINAL** witness or an *independently justified* QPT-LWE/SIS/hardness break, without requiring A to supply α, X or any other representation; also prove false-instance security for all generic false x by a justified joint SOURCE simulator. NO SUCH REDUCTION IS ESTABLISHED. Fixed false x is easy to refute and matched true control easy to solve. Generic channel separation, source-coupled QPT-LWE, malicious N-of-N setup, retained builders, full transaction graph, viable concrete 128-bit sizes and quantum native signature deployment remain unresolved.

Only research/pq-wkem/ on existing draft PR #1 is authorized; leave PR open/draft/unmerged, no production/workflow changes. The research automation remains enabled.
