# Run 653 — Two-bit vectorial-bent seam gives a mixed-character fingerprint

2026-10-20; research-only, syscoin/PVUGC#1. Starting branch head: 3032765b859db54ba408ee6bcc865009df367788. Exact preceding note: RUN652_PR_BENT_SEAM_PAIR_PROFILE.md (blob 742c204b56c71d39e88704e608053587c0d41551). This is **not** a PQ witness-KEM, efficient quantum attack, or practical public mixer.

## Ideal experiment and question

Let E=GF(2^m), q=2^m, m>=2. The b=2m-bit protected key/period is K=(p,t) != 0 in E^2. Let Q_K be a binary linear quotient with kernel {0,K}. Uniform independently hidden permutations T:E^2->E^2 and P on the quotient output labels define the public oracles F_K(s)=P(Q_K(T(s))) and L(s)=pi(g(T(s))), where g(a,d)=a*d is field multiplication and pi:E->F_2^r is surjective binary linear. These *uniform hidden permutations* require exponential representation, not classical-PPT software. The attacker can evaluate deterministic public oracles coherently; the theorem below takes the stronger but exponentially costly full truth-table view.

Run 652 proved the complete-function distribution is K-independent for one scalar bent label. Question: does it stay independent for r=2 if **every nonzero component** of pi(g) is bent and each nonzero vector derivative is uniform? **No.**

## Exact results

For any K=(p,t)!=0,

g(a+p,d+t)+g(a,d) = a*t+p*d+p*t.

This affine map E^2->E is surjective with exactly q preimages per value. Every nonzero scalar trace component Tr(alpha*a*d) therefore has balanced derivatives in all nonzero directions and is bent. This remains true for every nonzero linear combination of the two exposed label bits.

Each public F_K output has a fiber {s_y,t_y} of size two. Let chi_u(l)=(-1)^(u dot l). Define the COMPLETE paired statistic

C[u,v] = sum_y (chi_u(L(s_y))*chi_v(L(t_y)) + chi_u(L(t_y))*chi_v(L(s_y))).

Let alpha and beta be the field-trace duals of the output characters u,v. Summing over all internal cosets, independently of T and P, gives

C[u,v] = sum_(a,d in E) (-1)^Tr(alpha*a*d+beta*(a+p)*(d+t)).

Exact character orthogonality gives:

* alpha=beta=0: C=q^2.
* alpha=beta!=0: C=0.
* alpha!=beta: C=q*(-1)^Tr((alpha*beta/(alpha+beta))*p*t).

PROOF: Expand exponent to (alpha+beta)*a*d+beta*t*a+beta*p*d+beta*p*t. If alpha=beta!=0, a nonzero p or t makes the sum of a nontrivial character zero. For alpha!=beta, summing over d forces a=beta*p/(alpha+beta), with q contributions; substitution leaves alpha*beta*p*t/(alpha+beta). This is exact for every choice of hidden T,P.

For ONE output bit, alpha!=beta implies one is zero; all C values are K-independent. For TWO output bits choose distinct nonzero u,v. Then c=alpha*beta/(alpha+beta)!=0 and the entire public paired view determines the trace bit Tr(c*p*t), via the SIGN of C[u,v]. Across keys for which that bit differs, complete-function distributions have disjoint supports. Three pairs of the three nonzero 2-bit characters yield up to three independent trace bits of p*t; the checker obtains rank 2 for m=2 and rank 3 for m=3,4,5.

A separate stronger full-label invariant survives arbitrary **unknown bijective relabeling** of sketch outputs. If pi=id_E, the multiset of multiplicities of same-label F-fibers equals [q/2] for axis shifts (p=0 or t=0) but [1,1,...,1] (q/2 entries) for mixed shifts (p,t nonzero). Proof: axis equality forces a=0 or d=0, giving q/2 zero-labeled cosets; mixed equality forces d=(t/p)*a+t and label (t/p)*(a^2+p*a), where the linearized map a->a^2+p*a has two-element kernel and q/2 distinct images. Merely counting equal-label fibers misses this distinction: there are q/2 in both cases.

## Correct security scope and handoff

This is a complete-public-ORACLE **information-theoretic fingerprint**, not a demonstrated classical-PPT or polynomial-query QPT attack: computing the full statistic naively enumerates 2^(2m) inputs. No physical-resource estimate or native verification-key-conditioned leakage game was proved. Secret permutations in the ideal experiment are not implementable PPT code. No inference is made for RIO, CLZ, Gaussian SOURCE, malicious setup, retained randomness, correlated quantum advice, multiple capsules, replay or practical 128-bit parameters.

The result is a sharp warning against extrapolating Run 652's one-bit bent-label hiding to TWO individually bent bits. Balanced derivative distributions alone do not control the full **mixed-character pair profile**. Attack taxonomy: statistical fingerprint (positive in full oracle), multi-view correlated output bits (positive), public/coherent chosen-input oracles (available but efficient attack unresolved); local seam, global gauge, malicious setup, cross-context replay, public VK correlations and full quantum recovery are not established.

Run 259 (GLOBAL_FINGERPRINT_SOURCE_BINDING_RUN259.md, blob c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2) gives accepted complete representation -> ORIGINAL witness, information-theoretically or conditional on explicit QPT-SIS. It DOES NOT supply unauthorized native signing/capability recovery -> accepted representation. Neither one-bit nor two-bit ideal sketch admits a late ORIGINAL witness and yields the SAME protected native signing capability. False-instance complete-public QPT hiding, early recovery/forgery extraction, N-of-N honest-erasure/malicious setup, and practical parameters remain **UNPROVED**.

Reproduce: python -m py_compile research/pq-wkem/run653_two_bit_pair_fourier_check.py; python research/pq-wkem/run653_two_bit_pair_fourier_check.py. Exact executed standard-library checker passed 8,589 assertions over m=2,3,4,5, and its repeated output was byte-identical. This tests finite algebra, not security. The expanded independent local note contains the same theorems with additional detail. No new full RIO/CLZ primary-proof audit was done.

Next constructive obligation: build a **classical-PPT nonseparable late ORIGINAL-witness admission/release frontier**, checking mixed-character complete-view correlations before any QPT claims, and connect arbitrary key recovery/native forgery -> accepted Run-259 representation. Bitcoin remains only the conditional native-signature/fixed-graph endpoint.