# Shared-LWE-key adaptive XOR selective openings (restricted SOURCE)

Record: shared-lwe-key-adaptive-openings-20261028-turn11. OFFLINE. syscoin/PVUGC draft/open/unmerged PR #1, branch research/pq-wkem-validation-20260918, starting SHA 4a6d069424e1545928c00d0cff01ccaeb96e61db. Exact predecessor research/pq-wkem/l1_sphere_lwe_source_20261028/RESEARCH.md blob e7b0cdbd49e512301464768e7c420b5bcb773e03, latest substantive ordinary comment at start 6481632650. No outside literature or web research.

## New constructive composition and scope

A SINGLE (A,b) QPT-decisional-LWE challenge source now instantiates t independently encrypted XOR shares protecting ONE real native signing capability. The adversary may choose up to t-1 share openings ADAPTIVELY, depending on the complete public view and previously opened shares. One full-joint-public hybrid, conditioned on the common A,b, has statistical loss L*delta_h for L=t*ell ciphertexts, and an exact native-EUF-CMA simulator for all allowed opening transcripts. There is NO separate t-factor from guessing an unopened index, no SourceOpen oracle, no requirement that the adversary supply an internal representation, and no quantum rewinding. This improves the predecessor's separately sampled-sibling discussion by instantiating common-source correlations and full adaptive selective opening.

This is ONLY for the ORIGINAL bounded-error LWE public-key relation, not arbitrary NP. Generic-NP compiler, arbitrary fixed-false full-public security, arbitrary hard-true recovery to ORIGINAL W, parameterized 128-bit QPT hardness, malicious setup/abort/graph and Bitcoin source/endpoint are not established. An independently justified QPT decidional-LWE break is the restricted hard-true alternative, not an ORIGINAL witness extractor.

## Exact honest classical PPT Build and same-K Release

Fix odd prime q, m>n, h, kappa, t, with 2h<q. Put g=2h+1, radix B=floor(q/g)>=2, ell=smallest integer with B^ell>=2^kappa. ORIGINAL statement x=(A,b,C), A uniform or arbitrary F_q^(m x n), b in F_q^m. Valid ORIGINAL witness (s,e) satisfies s in F_q^n, e in {-1,0,1}^m, b=As+e, plus the claim/UTXO/branch/anchors/window/context and checking-key bindings specified by C. No generic SYS/BTC relation is implemented.

Define exact LWE game T: sample A uniform, s uniform in F_q^n, e independent uniform ternary, b=As+e; U: sample A,b independently uniform. QPT decisional LWE at THESE exact distributions is an independent assumption. Native KeyGen uses an independent uniformly sampled kappa-bit signing seed K determining a genuine native public checking key pk(K), with QPT EUF-CMA security for the intended challenge path under classical signing queries.

Build given only (A,b,C) samples K and true pk(K), independent U0,Z_1,...,Z_t in {0,1}^kappa, and publishes D=U0 XOR XOR_i Z_i and V=K XOR U0. Each share Z_i is encoded as ell radix-B digits a_ij. Independently sample each r_ij UNIFORMLY from the finite signed integer L1 sphere S(m,h)={r:sum|r_k|=h}, using the exact predecessor polynomial-time combinatorial sampler. Publish for every i,j

    c_ij=A^T r_ij (mod q)
    d_ij=b^T r_ij+g*a_ij (mod q).

The complete public view contains relation/statement, all source-dependent ciphertexts, genuine pk(K), D,V, authenticated intended-path/context fields, permitted auxiliary data and any explicitly modeled independently randomized related capsules. All t shares use the SAME A,b. No source witness, SourceOpen oracle, or signing secret is given to the LWE-challenge simulator.

Public OFF-CHAIN Release first checks the ACTUAL ORIGINAL restricted predicate on (s,e), then computes

    d_ij-s^T c_ij=g*a_ij+e^T r_ij (mod q).

Because |e^T r_ij|<=h<g/2 and cyclic neighboring radix centers have distance at least g, each a_ij and Z_i is uniquely decoded. Return K=V XOR D XOR XOR_i Z_i. EVERY valid ORIGINAL witness, even distinct states (s,e), recovers the SAME precommitted K. Nothing here requires a canonical witness or makes Bitcoin run NP/proof verification.

Security-game Open(i) reveals the SHARE Z_i only, at most t-1 different indices chosen adaptively. It reveals neither r_ij, whole Build coins, ORIGINAL witness, signing seed nor a proof of opening. It is a disclosure experiment, NOT an online release committee or deployed service. Open-all-t is excluded because V XOR D XOR XOR_i Z_i=K. Fresh challenge-path native signatures are never made available by signing queries. Public per-share commitments, source coin disclosure, unreproducible quantum advice and same-K bypass capsules are NOT covered. Context C may bind pk, A,b and ordinary public claim/path/anchors; target-hidden-secret-correlated auxiliary information is disallowed.

## Full-joint ciphertext hybrid under ONE reused challenge H=[A b]

Let N=N(m,h)=sum_{k=1}^{min(m,h)} 2^k*C(m,k)*C(h-1,k-1). For H uniform in F_q^(m x (n+1)) and independent r uniform S(m,h), the difference of distinct r,r' is nonzero modulo q (2h<q), so H^T(r-r') is uniform. Exact collision identity:

    E_H Coll(H^T r|H) = 1/N + (1-1/N)/q^(n+1).

Cauchy-Schwarz/Jensen imply for whole (n+1)-coordinate ciphertexts:

    E_H TV(H^T r|H, U(F_q^(n+1))) <= delta_h
    delta_h = (1/2)*sqrt((q^(n+1)-1)/N).

This is an AVERAGE over random H, NOT a fixed-H statement. Let L=t*ell. Condition on the SHARED H, all seed/share coins (K,U0,Z_i), real pk and legitimate context, thereby fixing all a_ij. Independently sampled r_ij give a conditional product distribution. A product hybrid plus uniform-shift invariance of d_ij yields joint TV at most L*delta_h AFTER averaging H, even though ALL L ciphertexts share H and their public checking key/D/V/contexts are genuinely correlated. Applying any adaptive classical opening/signing procedure and arbitrary coherent QPT postprocessing cannot increase trace distance. No marginal-pad-only security claim is made.

An actual QPT decisional-LWE reduction receives just challenge (A,b), creates the REAL native K/pk, public context and ALL t*ell actual ciphertexts, stores real Z_i, answers adaptive Open(i) by returning Z_i, forwards or simulates permitted classical signing queries, and tests final success. In its T branch this is exact real Build. In its U branch the above joint TV applies; it does not know the challenge s,e and never asks for SourceOpen.

## Exact native simulation after uniform-ciphertext replacement

A separate QPT native-EUF-CMA reduction receives genuine pk(K) but not K. It publishes independent uniform D,V and L independent uniform ciphertext vectors, constructs permitted public context and aux, and on every Open(i) lazily samples a fresh independent uniform Z_i. It forwards allowed classical signing queries to its native challenger.

Proof of EXACT adaptive simulation: for fixed K, ANY proper subset O of shares, any published D,V and Z_O, U0 is forced to V XOR K, while the remaining t-|O| shares have one XOR constraint. There are exactly 2^[kappa*(t-|O|-1)] hidden assignments. Thus (D,V,Z_O) is uniform and independent of K, even conditioned on real pk(K). Revealing the next adaptively selected share remains uniform until the t-th opening, which the experiment forbids. No unopened-index guess and no t multiplicative loss. This identity FAILS for all t opened shares, exactly as expected. It also fails with unmodeled correlations such as a plaintext share commitment or a separate same-K signing bypass.

If the attacker outputs usable K, the reduction signs a fresh permitted challenge-path message; if it outputs an already valid fresh native signature, forward it. Hence under the stated SOURCE distribution/advice/oracle/freshness restrictions:

    Pr_T[unauthorized K recovery or fresh native forgery, <=t-1 openings]
    <= Adv_QPT-DecLWE(q,n,m,chi)
     + Adv_QPT-Native-EUF-CMA
     + (t*ell/2)*sqrt((q^(n+1)-1)/N(m,h)).

All honest algorithms are classical PPT; the attacker can be arbitrary QPT with classical, re-initializable interfaces and challenge-independent efficiently preparable quantum advice. There is no classical-to-QPT rewinding lift or random-oracle extraction. No simulator is claimed for quantum superposition oracle requests or aux entangled with the LWE secret/native seed.

## Exact executed checks / illustrative size

At q=65537,n=128,m=1600,h=696,kappa=256: g=1393, B=47, ell=47. For t=3, L=141 ciphertexts on the SAME (A,b), comprising 18,189 field elements excluding shared public A,b, checking key and metadata. log2(L*delta_h) is approximately -234.382465. At t=256, exact integer arithmetic establishes L^2*(q^(n+1)-1)*2^256 < 4*N(m,h), so statistical loss <2^-128 (approximately 2^-227.967427). These are NOT actual security bits against QPT-LWE attacks and not measured resources for a deployable Bitcoin path.

Independent offline checkers were executed twice each with identical captured JSON. Python verify.py: PASS 20,672 finite assertions, exact all-secret proper-subset opening laws, adaptive opening-policy transcripts, 15,625 random-hash matrix enumeration, 625 shared-H complete joint two-column TV enumerations, exact high-dimensional sphere/bound arithmetic and 12 three-share full 256-bit MOCK same-K/two-witness trials. JavaScript independent_check.js: PASS 4,984 checks, independent adaptive policy, generating-function DP for sphere cardinality, exact bound and all-openings failure boundary. Both are CLASSICAL algebra checks, not native SLH or QPT-security tests. Executed published checker: independent_check.js, output js_output.json. Extended Python code and output retained in local archive.

## Next missing original requirement

Construct a PUBLIC classical PPT witness-FREE compiler Comp(R,x,C)->(A_x,b_x,source) for ARBITRARY ORIGINAL NP, allowing EVERY valid ORIGINAL W to recover the SAME bound capability. Prove full-public security for EVERY false instance, and that arbitrary unauthorized hard-true K recovery / native forgery yields an actual ORIGINAL W or an INDEPENDENT QPT break, without adversary-supplied representation. The present theorem instantiates source and challenge correlations only when ORIGINAL itself is the LWE bounded-error relation. Malicious N-of-N preauthorization/erasure/abort/bypass graph, pre-funding evidence/DA, actual SYS/BTC headers/AuxPoW/tags/ancestor/fork/window checks, censorship inclusion and conditional native PQ-only Bitcoin output remain unproved. The continuing research automation MUST remain enabled.
