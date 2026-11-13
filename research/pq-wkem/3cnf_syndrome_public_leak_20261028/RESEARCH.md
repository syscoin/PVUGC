# 3CNF-to-ternary-LWE SOURCE: exact ORIGINAL opening, but full-public security BROKEN

**Outcome: NO positive secure witness-KEM advance.** This is a tested disqualification of a natural candidate for the missing witness-free generic-NP compiler. Existing component: restricted shared-key LWE SOURCE, exact predecessor \`research/pq-wkem/shared_lwe_selective_opening_20261028/RESEARCH.md\` (blob 8d7c996046bed561c3f95f022412e15f5ae7935b). Repository syscoin/PVUGC draft/open PR #1, branch research/pq-wkem-validation-20260918, starting e810196c53473fa0ca1dae558006472b49063d48, last substantive ordinary comment 6482734167. No internet/literature research.

## Classical polynomial compiler with ACTUAL ORIGINAL binding

Given arbitrary ORIGINAL NP verifier R(x,W,C), compile its Boolean verifier circuit with intended claim/UTXO, original burn/authorization/output, branch, anchors/window, context and intended native key/path bindings into equisatisfiable Tseitin 3CNF Phi_x. This is a statement-dependent deterministic PPT compiler; every original W extends efficiently with gate values. For n variables and c clauses (pad 1/2-literal clauses by repeating a literal), work over F_q, odd prime q>=7, and form m=2n+c rows:

For each Boolean variable i, add two identical matrix rows A=e_i, with b=0 and b=1 respectively. For each three-slot literal clause add row A=sum positive e_i - sum negative e_i and b=2-(number of negative slots). An accepted SOURCE opening (s,e) satisfies b=As+e mod q and e in {-1,0,1}^m.

The two variable rows imply s_i in {-1,0,1} intersect {0,1,2}={0,1}. Each clause's residual equals 2-L_j(s), where L_j counts true literal slots, and lies in {-1,0,1} iff its clause is TRUE. Hence **every supplied accepted SOURCE opening gives an ACTUAL ORIGINAL witness**, not a moment pseudo-witness. Conversely EVERY valid original W maps to an accepted (s,e), even with distinct extended witness states. This is unconditional algebra, NOT an arbitrary final-key-recovery extractor.

Build reuses the restricted source digit encryption (c,d)=(A^T r,b^T r+g a) mod q, with r uniform signed constant weight h, 2h<q, g=2h+1, B=floor(q/g). For EVERY valid original W, d-s^T c=ga+e^T r, |e^T r|<=h, so every witness decodes the SAME precommitted digit, share and capability off-chain. The genuine checking key, all XOR shares, D,V, C, auxiliary information and related capsules remain visible. Bitcoin is not assigned NP verification.

## Exact full-public catastrophic failure

All public b_i are in {-1,0,1,2}. Condition on the h-element support of r. Its independent signs yield E[exp(t b^T r)|support] <= exp(t² sum b_i²/2) <= exp(2 h t²). Chernoff gives Pr[|b^T r|>=h] <= 2 exp(-h/8). Thus a classical PPT attacker merely rounds **public d=ga+b^T r** to the nearest cyclic radix centre. It learns any digit with probability >=1-2 exp(-h/8), without c, original W, SourceOpen, native forgery, or LWE challenge secret. For L total independently sampled columns it learns **all XOR shares and the final K** with probability >=1-2L exp(-h/8). This applies to every original statement, including FIXED FALSE statements without any valid original witness: the required false full-public security is therefore outright false. Arbitrary QPT attackers can implement the classical attack.

At illustrative q=65537,n=128,m=2000,h=800,t=3, kappa=256, g=1601, B=40, ell=49,L=147, log2 of this **attack's FAILURE upper bound** is -136.069831744. A theoretical uniform-H signed-constant-weight hashing comparison would have N=2^h binom(m,h) and whole L-column TV below 2^-128 (approximately 2^-329.86), but the compiled H=[A b] is NOT uniformly sampled. That assumption substitution is invalid. Neither statistic is a concrete QPT-LWE security certification.

## Attempted repair / retained exact equation

For public invertible column basis U and a secret affine offset z chosen by Build, form A'=AU, b'=b+A'z. All original-valid s extend to s'=U^-1 s+z with the same e. But the first variable rows publicly satisfy A'_0=U and b'_0=Uz, so z=U^-1 b'_0 is publicly solvable, even with dense non-diagonal U and builder erasure. Consequently d'-z^T c'=b^T r+ga and the same attack succeeds. Public affine masking/basis rotation is not a repair.

**Next exact missing equation** is a *secure* classical PPT witness-free Comp(R,x,C)->(A_x,b_x,source), jointly with Open_x(W), in which all valid ORIGINAL W recover one K, EVERY FALSE full public joint view (relation/statement/capsules/real pk/context/aux/related capsules) is QPT-secure, and any arbitrary unauthorized hard-true native-key recovery or intended-path fresh forgery reduces to an ACTUAL ORIGINAL W or independently justified QPT break without adversary-supplied intermediate representations. Any proposed source must first defeat the explicit public-proxy test that d-s0^T c reveals digits for efficiently recoverable s0. The weak algebraic compiler here fails security, so it is not a surviving construction.

## Checks/provenance

Exact \`check.js\` was invoked twice and yielded the byte-identical \`output.json\`. It exhausts field-17 true/false ternary SOURCE openings, checks distinct ORIGINAL witnesses recover an identical mock key, demonstrates direct public d-digit recovery for FALSE, checks a dense public affine offset, and establishes the large-N uniform-H-only inequality by BigInt. A separate extended LOCAL-only Python checker passed 5,501 checks in two identical executions; local initial false small-h assumption was corrected and rerun. No quantum hardness or native SLH proof/implementation was tested. No production changes, reviews, approvals, deployments or merges authorized.
