# Run 652 — nonlinear local seam pair-profile theorem (scoped)

Date 2026-10-20. New research only, syscoin/PVUGC#1. This is NOT a practical PQ witness-KEM, a QPT-secure public program, or a completed ORIGINAL-witness release.

## Precise ideal experiment

For even b=2m, set V=F_2^b, N=2^b, M=N/2 and nonzero capability K. Let Q_K:V->F_2^(b-1) be linear onto with kernel {0,K}. Sample independent uniformly random hidden permutations T on V and P on F_2^(b-1). Expose complete black-box functions F(s)=P(Q_K(T(s))) and L(s)=Gamma(T(s)), for public finite-label sketch Gamma. The adversary may evaluate both coherently or receive their entire truth tables. Public VK(K) supplies only its own preexisting information about K and is independent of T,P given K. Setup here is an EXPONENTIAL ideal sampler, not classical PPT, and public white-box code or correlated quantum setup advice is outside the result.

For each nonzero K let h_K({u,v}) count unordered K-cosets {z,z+K} of label type {Gamma(z),Gamma(z+K)}, counted once. For any exactly two-to-one public function f and a labeling l on its inputs, let h_{f,l} be the histogram of the unordered label types of f-fibers. Then

Pr[(F,L)=(f,l) | K] = 1[h_{f,l}=h_K] * 2^e * product_t(h_K(t)!)/(N! M!),

where e=sum_u h_K({u,u}). For non-two-to-one f probability is zero. Proof: assign the h_K(t) K-cosets to the matching public fibers in h_K(t)! ways each; for equal-label cosets there are two orientations and for mixed-label cosets exactly one; P is uniquely fixed by the assignments. Denominator counts all N!M! equally likely (T,P). Thus complete-function laws for K and K' are identical IFF their pair-type profiles coincide; if profiles differ, the full-view supports are disjoint. This is stronger than marginal distribution arguments.

## A nonlinear one-bit positive countercase

Write z=(a,d) with m-bit halves, and let g(z)=a·d mod 2. For any K=(p,q) nonzero, its Boolean derivative equals a·q + p·d + p·q, which is nonconstant affine-linear and balanced. Therefore the number of unordered coset label pairs is, independent of nonzero K:

h_K(00)=N/8+2^(m-2),  h_K(11)=N/8-2^(m-2),  h_K(01)=N/4.

By the complete-function theorem, the joint full functions (F,g∘T) give ZERO extra information about K in this ideal model, even against arbitrary coherent quantum-oracle processing. Adding an affine bit does not destroy this property: g_1(z)=g(z) XOR z_0 is also bent and individually has a K-independent full-function law.

## Correlated two-view attack

Publish BOTH L_0(s)=g(T(s)) and L_1(s)=g(T(s)) XOR (T(s))_0. Although each view independently has the exact positive guarantee above, together L_0(s) XOR L_1(s)=(T(s))_0. Obtain any distinct collision F(a)=F(c); since T(a) XOR T(c)=K, the attacker gets

[L_0(a) XOR L_1(a)] XOR [L_0(c) XOR L_1(c)] = K_0.

With b+1 views (g and g XOR each input coordinate) the attacker obtains all coordinates of T(s), hence the complete K from one collision. A classical birthday attack costs O(2^(b/2)) public queries; coherent BHT collision finding gives O(2^(b/3)) query upper bound when the public deterministic evaluator can be run coherently. For b=128 this is approximately 2^42.67 queries; it is not a physical-resource security estimate. The attack finds K without any accepted ORIGINAL witness or Run 259 representation.

## Scope and prior-work boundaries

The one-view positive property is unconditional only for huge uniformly random hidden permutations offered as oracles; publishing pseudorandom-permutation keys, raw reversible gates, or a transparent suffix invalidates its scope. Malicious setup, correlated quantum advice, public-checking-key/setup correlations, and related multi-capsule views are NOT secured. The two-view failure is information-theoretic after a collision and remains relevant to QPT chosen-input adversaries. It does not refute general RIO (Canetti–Chamon–Mucciolo–Ruckenstein, TCC 2024 / ePrint 2024/006) or Canetti–Luo–Zhang's obfuscated controlled-evaluation construction. No full paper/proof/errata audit was performed in this iteration.

Attack taxonomy: (1) joint seam cancellation succeeds with two labels; (2) actual white-box global gauge resistance not shown; (3) full-function pair profile, not just marginal labels; (4) multiple correlated labels break; (5) chosen-input/public coherent collision; (6) honest ideal setup only, malicious setup unproved; (7) no UTXO/branch replay resistance proved; (8) VK independently provides its own information, real correlations unproved; (9) quantum BHT speedup versus classical birthday, no false PQ-security claim.

Run 259, exact live blob c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2, remains a downstream accepted-complete-representation -> ORIGINAL witness theorem under information-theoretic soundness or specified QPT-SIS. No upstream recovery -> accepted z arrow follows. Run 647 exact live blob d1203d5f25b3b60be419add99d5915cefb573532 was read at starting head e09c755074b378aec18fcc3bdcb49788bc78f484.

Exact standard-library checker run652_pr_checker.py was compiled and executed twice with identical output: 1,122,858 assertions testing b=2,4,6,8,10 bent profiles and derivatives, b=2 complete T/P oracle distributions, and finite two-view collision leakage. Its output is run652_pr_validation.json. Checks are not proof of QPT security or concrete parameters.

**Handoff:** The exact pair-profile characterization shows a nonlinear one-bit seam can avoid the previous linear-seam leakage in a fully opaque idealization. Correlated separately safe views still eliminate it. Next require classical-PPT late ORIGINAL-witness admission and a nonseparable public *white-box* release implementation with full-public-output QPT hiding, same K across all valid ORIGINAL witnesses, recovery/native forgery -> accepted complete z or independent QPT break, N-of-N malicious setup/abort, multi-capsule security and measured practical 128-bit resources. None are constructed here. The conditional native-PQ Bitcoin signature/graph endpoint does not resolve these gaps.
