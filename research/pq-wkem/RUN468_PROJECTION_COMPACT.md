# Run 468 — nonlinear local output relabeling can preserve a quantum-visible quotient

Live starting PR: syscoin/PVUGC#1, open/draft/unmerged, branch research/pq-wkem-validation-20260918, SHA 99dc382d7ce2b91088de3bb71ecf5d9c7102c698. Last ordinary substantive comment 6067040320. Exact source dependencies inspected: Run 466 (8cea2cc06cbe22361ba3c49d533d006e437e28a1), CLZ applicability (c19d9d9cd515140e3ce62eac960cd548c0add622), Run 259 (c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2). No historical denied run is being republished.

## Conditional interface and theorem

Let n>r. Classical PPT setup chooses efficiently computable n-bit permutation P, secret nonzero Delta, and an efficient possibly nonlinear secret output permutation L. Two deterministic public forward programs implement F0(z)=P(z), F1(z)=L(P(z xor Delta)). Suppose a PUBLIC r-bit projection pi satisfies pi(L(y))=pi(y) for every y. Put f=pi o P and mu=max_{d!=0,e} Pr_z[f(z xor d) xor f(z)=e]<1. This does NOT instantiate an obfuscator hiding P,L,Delta: it attacks any public forward representation with these exact functional promises.

An arbitrary QPT adversary with all public outputs, native checking keys, auxiliary information and multiple capsules can coherently execute these public classical programs; just one vulnerable pair suffices. Remote classical-only black-box access is not the assumed model.

Define G(0,z)=pi(F0(z))=f(z), G(1,z)=pi(F1(z))=f(z xor Delta). The graph S={(b,z,G(b,z))} in F_2^N, N=1+n+r, is invariant under p=(1,Delta,0^r). Prepare the uniform graph superposition by reversible public evaluation and measure all qubits after Hadamards. Every measured Y satisfies <Y,p>=0 exactly.

For any q=(c,d,e), graph autocorrelation is A(q)=Pr_z[f(z xor (d xor c Delta)) xor f(z)=e]. Standard Fourier/graph autocorrelation gives Pr[<Y,q>=0]=(1+A(q))/2. Only q=0 and q=p have A=1; every other q has A<=mu. After M independent coherent queries and Fourier measurements, probability of any false surviving kernel vector is <= (2^N-2)*((1+mu)/2)^M. For M>=ceil((N+kappa+2)/log2(2/(1+mu))), GF(2) elimination recovers p, and thus Delta, with failure below 2^-kappa. If 1-mu is inverse-polynomial and P,L are efficient, this attack is polynomial-time QPT. This is a projected-graph application of established Fourier hidden-translation reasoning, not a new quantum algorithm.

## Why the nonlinear repair fails only in this scope

A genuinely nonlinear triangular relabeling L(hi,lo)=(hi,S_hi(lo)), with different secret permutations S_hi, is not one fixed XOR mask. But it preserves pi(hi,lo)=hi and therefore the exact projected graph shift. If challenge credential K_x is efficiently computed from public context x and Delta, e.g. KDF(x,Delta), recovering Delta recovers K_x without an ORIGINAL witness. If Delta is unrelated to the authorization credential, that implication does not follow. A relabeler destroying the aligned quotient escapes this particular theorem; it is not thereby proved secure.

Attack taxonomy: global synchronization/public output quotient (2), invariant statistical/function fingerprint (3), correlated views (4), coherent chosen-input evaluation (5), public checking-key correlation (8), genuine quantum graph sampling (9). Correct per-UTXO and per-branch KDF separation does not rescue a leaked same-context Delta (7). Mask seams, malicious setup, and signing oracles are unnecessary for this attack. A QPT attacker needs no quantum advice or rewinding.

Run 259 only gives accepted COMPLETE source representation -> ORIGINAL witness, subject to the exact residual/fingerprint or SIS hypotheses. This attack supplies no complete representation and so does not trigger that downstream extractor. No CCMR/RIO/CLZ system is proved to expose the interface attacked here, and no assertion of their insecurity is made. The CLZ/CCMR sources are architectural context, not a full formal-proof/QPT assumption audit (CRYPTO 2026 DOI 10.1007/978-3-032-35367-2_18).

## Evidence and open obligations

The exact executable JavaScript checker calculates exhaustive finite graph autocorrelations, Walsh-Hadamard probabilities, non-affine relabeling checks and GF(2) recovery for n=4 and n=6. Its validation JSON is captured verbatim. A separate extended local Python checker also handles n=8 and public branch-context diagnostics. Toy permutation tables are exponential-size finite fixtures, NOT a classical PPT cryptographic instantiation; quantum measurements were simulated from the exact finite distribution, not run on hardware. No positive security inference from tests.

Still UNPROVED: any independently justified practical local-mixing release, all-valid-ORIGINAL-witness SAME-capability correctness, full-public-output false-instance arbitrary-QPT hiding, unauthorized true-instance capability/native forgery -> accepted complete representation or independent QPT break, malicious N-of-N ceremony/erasure/abort, multi-capsule security, concrete 128-bit resources, and conditional P2MR/native-SLH Bitcoin semantics. Witness privacy remains optional; the Bitcoin endpoint must not verify NP evidence. Keep production unchanged and PR draft/unmerged. The task stopping condition is unmet.
