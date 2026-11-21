# R32 MINK-BILINEAR-IDEAL-MIX — nonlinear classical release, broader restricted-FALSE simulator

**Constructive delta (not a generic PQ witness-KEM):** A concrete nonlinear SOURCE release now has a statistical, straight-line, no-SourceOpen simulator for a class of FALSE 3CNFs **strictly exceeding the same-mask degree-zero affine unit-certificate class**. It also keeps every genuine ORIGINAL witness's same-capability correctness. The main arbitrary-FALSE and unauthorized hard-TRUE -> ORIGINAL-witness reductions are still missing.

## Provenance and boundaries

Offline continuity from R31. Verified current syscoin/PVUGC PR #1 open, draft, unmerged, branch research/pq-wkem-validation-20260918, starting head 68a1feae6141e6c75524a4f2b169c8b4986699d4; previous substantive comment 6596491050. Exact R31 RESEARCH.md (blob 5c32afd6e280c547510626309fbeb6c7c76c1157) and CHECKER.py (blob fde166001b5a2c57689e339840e7b6fbd758483a) read at that SHA. No external web/literature. CHECKER.js in this directory is the exact code executed in the V8 isolate; OUTPUT.json records its result. The finite checker cannot prove QPT hardness.

## Algorithms and distributions

Let q be an odd prime. For an ORIGINAL instance x (including relation identity, actual claim/UTXO, branch, anchor/window, context, intended native vk and capability), faithfully compile its verifier to a 3CNF F_x with m clauses. Let A_n=F_q[z_1,...,z_n]/(z_i^2-z_i), represented by squarefree polynomial coefficients. For clause j, f_j(z) is the degree-at-most-three 0/1 failure polynomial; f_j(w)=0 for all genuine valid compiled assignments. Define V=span_Fq{f_1,...,f_m}, with no secret or supplied certificate.

**Honest Build(x,vk,K):** Use an independent native PQ signature KeyGen path to precommit the intended vk and corresponding K or classical secret-key seed; this remains an assumed endpoint, not a Bitcoin deployment. For each capability bit mu of K, independently sample t pairs of uniform coefficient vectors r_i,s_i in F_q^m and bounded coefficient noise e in the squarefree monomial basis of degree at most 6. Form U_i=sum_j r_{ij} f_j, V_i=sum_j s_{ij} f_j. Publish only C_mu=sum_i U_i*V_i + Delta*mu*1+e in A_n, where * is Boolean-quotient multiplication. Destroy r_i,s_i and private noise coins under the honest-erasure setup baseline. Publish x, vk, C, context and a CK defined only by public deterministic operations on these public fields; independent same-base related capsules may use public ideal-element additions B_x u with their derivation metadata. All arithmetic is classically polynomial time for constant degree (output coefficients of degree <= 6, at most M=sum_{j=0}^6 binom(n,j) symbols), but enormous for realistic n. It is NOT an optional keyless Build, and the malicious-builder validity proof is not supplied.

**Lift(x, ORIGINAL w,C):** Locally run the faithful compilation on the ORIGINAL witness w to get an assignment z_w; evaluate each C_mu(z_w) in F_q, and decode nearest to 0 or Delta=(q-1)/2. Every f_j(z_w)=0, hence all U_i(z_w)V_i(z_w)=0. Since a Boolean assignment evaluates a polynomial homomorphically, C_mu(z_w)=Delta*mu+e(z_w). If each coefficient |e_T|<=eta and M*eta<(q-1)/4, every valid ORIGINAL w recovers the SAME precommitted K deterministically. Distinct valid witnesses need not share internal states. No SOURCE-opening oracle or internal representation from the adversary is assumed by honest Lift.

## Proved restricted-FALSE statistical simulator, genuinely with K hidden

Let W=span_Fq{ f_j*f_k : 1<=j,k<=m } in the ambient degree<=6 coefficient space A (dimension M). A FALSE x that satisfies 1 in W has an *algebraically checkable* property; Build and simulator do not require a supplied certificate. For any dual functional a in A*, write T_a=(a(f_j*f_k))_{jk}. For independent uniform vectors r,s in F_q^m and any nontrivial additive character chi of F_q,

E[chi(a((sum r_j f_j)(sum s_k f_k)))] = q^(-rank(T_a)).

Proof: conditional on s, averaging r kills every nonzero row vector T_a s; the surviving fraction of s is q^(-rank T_a). For t independent products the nontrivial additive Fourier coefficient is q^(-t rank T_a). Since 1 is in W, every functional with a(1) != 0 has rank T_a >=1. Parseval and Cauchy-Schwarz applied to the distribution D of the sum of t products and its translate by Delta*1 give the fully finite statistical bound

TV(D, D+Delta*1) <= q^(M/2-t).

Adding independently sampled small coefficient noise e is a convolution and CANNOT increase TV. Consequently, when K has ell bits and S independent base scopes/capsules, with fresh independent mask/noise coins for each bit and base, the entire source-capsule vector distribution for a fixed K is within ell*S*q^(M/2-t) of the distribution made with all capsule plaintext bits ZERO. In particular choose t>=M/2+(lambda+log2(ell*S))/log2(q) for <=2^-lambda statistical distance. Related same-base capsules obtained by deterministic public maps contribute no additional statistical loss. This is a classical distribution coupling; by data processing, arbitrary coherent QPT operations, auxiliary quantum registers, and adaptive *public* selection of derivatives do not increase distinguishing advantage.

**Full-public correlation scope, carefully limited:** The simulator receives the real vk, x, context, and any externally supplied CK/auxiliary/quantum side information whose conditional generation given K is independent of fresh SOURCE mask/noise coins. It samples the zero-plaintext product/noise C and computes all CK and related-capsule fields that are deterministic public functions of (x,vk,C,context). Conditioning on each K value proves the same statistical bound even if vk and side information are correlated with K. The simulator does not know K, does not call SourceOpen, and does not require a refutation certificate. This is NOT a simulator for malicious CK that reveals source coins, secret-dependent postprocessing unavailable from the public inputs, adaptive target private openings, or inconsistent related capsules. Such extra data may reveal K and is excluded explicitly, not silently replaced with a generic full-public theorem.

## Explicit ORIGINAL 3CNF example strictly beyond same-generator affine degree zero

There are four variables z0..z3 and ten authentic 3-literal clauses, written as (ids; violating assignment bad):
(013;010), (012;000), (013;101), (013;011), (023;100), (013;111), (123;011), (023;000), (123;010), (012;111).
Each f_j is the AND of its three literal-violation indicators, so clause satisfaction is f_j=0. All 16 Boolean assignments violate at least one clause (FALSE). Over BOTH F_101 and F_65537, the evaluation matrix of the ten f_j has rank 10 and the unit vector is NOT in their span. The pairwise-product matrix has rank 13 and DOES contain the unit. The exact **integer identity**, verified at every Boolean assignment, is:

1 = f0^2 + f1^2 + f2^2 - f2*f6 + f3^2 + f4^2 + f5^2 - f5*f9 + f6^2 + f8^2 + f9^2.

It is a strict improvement over the same generator set's degree-zero affine shift condition 1 in V, and an explicit instance of 1 in W; no private refutation is inserted into Build.

For the n=4 toy, q=101, M=16, Delta=50, eta=1, t=30, ell=256, S=2, the statistical upper bound is 2^(-137.48) for the stated FALSE class, accounting for all 256 bits and two independent bases. A separate TRUE one-clause fixture has fourteen distinct valid assignments, and all correctly recover each of 256 sampled capability bits; masks vanish at each assignment. The sample deterministic checker RNG is NOT a cryptographic sampler; honest Build requires truly independent uniform samples. This toy is not a certified 128-bit general-purpose WKEM and the asymptotic costs O(n^6) field symbols and O(M) products per bit are unacceptable at large scale.

## Central unproved obligations and tests

1. **Hard TRUE**: If 1 is NOT in W, a publicly computable linear functional annihilates every U_i V_i but evaluates 1 nontrivially. With zero noise it exposes mu exactly. With bounded noise, it exposes Delta*mu+a(e); short pseudo-evaluations may decode K without any ORIGINAL w (R28-style switching remains a live attack). No QPT recovery-to-ORIGINAL-witness or independently justified QPT break is proven. Do not infer it from the FALSE mixing theorem.
2. **Arbitrary FALSE**: Some false F_x have 1 NOT in the bounded-degree product span W. The simulator above gives NO bound there. Higher polynomial degree can make compilation exponential, so this is not arbitrary-NP security.
3. **Malicious setup and full key correlations**: No zero-knowledge proof of honest sampling, no one-honest N-of-N graph/abort composition, no secret-dependent checking-key simulator, no target-base private opening, and no canonical native-vk reduction are established. Source coin retention is outside honest-erasure assumption and can compromise release.
4. **Endpoint**: A native no-EC-key-path Bitcoin-style output and PQ signature are conditional. No Bitcoin NP verification, general proof, on-chain VM, introspection, committee, CAT, adaptor algebra, or changed production code is assumed.

**Exact handoff:** Determine whether an independently justified ordinary-QPT assumption can make bounded-noise, degree-bounded nonlinear product source secure against *arbitrary* recovered-K/accepted-native-forgery attacks on hard TRUE x, without requiring the attacker to furnish a functional or representation. Simultaneously find a classical-PPT generic-NP construction whose FALSE-case public distribution does not require 1 in a bounded-degree product span. If either fails, preserve the finite counterexamples and replace the release mechanism; do not relabel the missing result as an assumption.