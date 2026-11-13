# Run 701 — Constructive R1CS source lift composed with spectral key recovery

Research-only checkpoint, 2026-10-22. Source: exact live syscoin/PVUGC#1 draft branch research/pq-wkem-validation-20260918, starting SHA 5e170eba0bce1c4aea5a9bed86ba357625f2ac77. This is a new witness-preserving compilation and an exact pointwise rank lemma, NOT PQ witness-KEM security.

## New constructive capability
Runs 593, 695, 696, 698 and 699 had a typed-gate rank/eigenvalue/recovery pipeline, but the exercised SOURCE relation was only Booleanity. This run connects a COMPLETE 3CNF statement, including clause satisfaction and ORIGINAL extraction, to that unchanged spectral pipeline. The SOURCE states may depend on the chosen valid ORIGINAL witness; the recovered capability does not. A contradictory 3CNF has no accepted SOURCE representation. The compact executed JS checks three distinct valid-original witnesses producing three distinct matrices and the same toy key, and a false 3CNF with no valid-original witness. The extended local Python integration exercises five valid witnesses, Run-699-style dictionary evaluation and Run-696 Krylov/Berlekamp-Massey/Frobenius recovery; its original complete note/checker/results are preserved separately.

## Exact SOURCE compiler and acceptance proof
Over F_q, for a 3CNF with t Boolean variables and c clauses, SOURCE coordinates are z=(z0=1,u1,...,ut,h11,h12,...,hc1,hc2), p=1+t+2c. A positive literal is ui; its negation is z0-ui. Gates are R1CS scalar quadruples (a,b,c,d) requiring ab=cd:
* for each variable ui: (ui,ui,ui,z0);
* for each clause with literals l1,l2,l3 and fresh h1,h2: (l1,l2,l1+l2-h1,z0), (h1,l3,h1+l3-h2,z0), (h2-z0,z0,0,z0).
There are m=t+3c gates. A public Encode maps each valid ORIGINAL Boolean assignment to the unique auxiliary h1=l1 OR l2, h2=h1 OR l3. Public SOURCE acceptance checks z0=1 AND all gates. Any accepted z has ui^2=ui, hence ui in {0,1} in any field, the two OR equations uniquely determine each h, and the output pin forces every clause true. Therefore accepted SOURCE -> valid ORIGINAL witness by reading (u1,...,ut), information-theoretically. Conversely every valid ORIGINAL witness produces an accepted SOURCE. This is not a security theorem about key-only adversaries.

## Exact typed gate, same-key recovery and rank
For block dimension b>=1, retain Run593's scalar-source typed gate

G_i(z) = [ aI  cI  -X(z)  0
           dI  bI   0     X(z)
           0   0    bI    cI
           0   0    dI    aI ].

Here X(z) is an arbitrary public-source-linear b-by-b matrix form with private setup coefficients. On the normalized slice z0=1, every gate has d=1 and is nondegenerate. The exact Run593 lemma yields rank(G_i)=2b when its R1CS constraint holds and rank(G_i)=4b when it fails. Let N=2bm+1 and publish only combined coefficient matrices for C(z)=K*z0*I_N+sum_i L_i G_i(z) R_i, plus bound statement/native verification key. For EVERY accepted source, rank(sum_i L_i G_i(z) R_i) <=2bm=N-1, regardless of setup factors. Hence K is an eigenvalue of every valid witness-dependent C(z), simultaneously, with no canonical witness. Run696's randomized Krylov/Berlekamp-Massey/Frobenius finite-field recovery, followed by genuine native public-key matching in an eventual implementation, applies. This check uses a clearly labelled toy SHA-256 test key selector and small-field exhaustive root scan; it is NOT native Bitcoin or SLH signing.

## NEW exact pointwise invalid-source rank distribution, dense reference only
Fix a normalized z, with k violated gates. Condition on arbitrary fixed X_i(z). With B=diag(G_1,...,G_m), rank B=r=2bm+2bk. For INDEPENDENT UNIFORM DENSE setup L=[L1|...|Lm], R=[R1;...;Rm], M=LBR has the same distribution as U V with independent uniform U in F_q^(N x r), V in F_q^(r x N), by basis changes on the fixed B. If k=0, r=N-1 and M is singular always. If k>=1 then r>=N+(2b-1); the EXACT full-rank probability for this fixed z is

P(rank M=N) = [product_{j=0}^{N-1}(1-q^(j-r))] * [product_{j=0}^{N-1}(1-q^(j-N))].

Proof: U is full row rank with probability the first product; if it is not, UV cannot be invertible. Conditional on U full row rank, independent uniform columns of V map under the surjective linear U to uniform independent columns in F_q^N. Therefore UV is a uniform N x N matrix and nonsingular with probability the second product. This is NOT the square of two rectangular full-rank probabilities. The F_2, N=2,r=3 exhaustive toy check counts exactly 1008 invertible products among 4096, probability 63/256.

Pointwise invalid-source rank is NOT false-instance hiding. z must be fixed before the dense factors are observed. No adaptive/chosen-source, sparse Run697 sampler, multiple-capsule, correlated auxiliary information, public native-key, arbitrary QPT recovery or accepted-forgery security follows. The exact user threat model remains unresolved.

## Cumulative constructive interface
PROVED dependencies: Run593 typed gate blob 29b9168bfff6043810284cd1960400579f224e31; Run695 all-witness eigenvalue blob 50174666730b93bd20f83bb29ddb2c355ccf1a91; Run696 Krylov blob e37f51a69c3ca68d584d0b2e0f18b71e876bf217; Run699 lossless public codec blob f37df98858139d7f78f6c7a6c7d72d58eb5e4b2b; Run259 downstream SOURCE-binding blob c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2 applies ONLY AFTER an accepted complete SOURCE. This checkpoint now provides a genuine 3CNF ORIGINAL -> SOURCE -> spectral same-key correctness chain.

NOT PROVED: full-public-view false-instance QPT hiding; unauthorized hard-true final key recovery/accepted native forgery -> accepted SOURCE or independent QPT break; extension to actual complete SYS/BTC/AuxPoW/coinbase/authorization circuit and exact 3CNF source lifting; malicious and abort-secure one-honest N-of-N setup, retained coins, correlated capsules, cross-UTXO/branch replay, QPT coherent evaluation with checking-key correlations, 128-bit resources or conditional P2MR/native SLH endpoint. Exact pointwise invalid-rank probability is not an adversarial hiding theorem.

Executed compact JS: node --check passed, two runs byte-identical, 988 assertions; 2-variable satisfiable instance: 3 valid witnesses, 3 different matrices, 3 same-key recoveries; contradictory 1-variable instance: 0 valid, 2 invalid. Extended local Python: py_compile and two repeat runs passed, 354 assertions, five valid witnesses/5 different public matrices, five Run696-style Krylov recoveries; checked Run699-style public dictionary on valid and invalid sources. Seeded randomness and tiny q=101 are test fixtures ONLY. Production and draft PR unchanged.

Next mandatory construction: preserve this verified complete SOURCE lift and decoder while obtaining an independently justified compact public operator with full-output arbitrary-QPT hiding and a concrete arbitrary recovery/forgery -> SOURCE or separate QPT-hardness reduction. Do not revert to isolated Booleanity-only security tests, ideal mixers, or compression in place of security.
