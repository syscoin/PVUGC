# HPW-R170 checkpoint 01 — hash-only hard-TRUE release -> one-bit passive agreement

**Intermediate proof checkpoint.** This is not a new WKEM, a secure construction, or permission to optimize an invalid carrier. No web/lattice/discrete-log sources. Continue the proof with a real bounded checker; the checker is not yet executed as of this checkpoint.

## Continuity
Start PR syscoin/PVUGC#1, branch `research/pq-wkem-validation-20260918`, HEAD `ee4c9998952e618ba67ac3348a26976ee41c4648` (open/draft/unmerged). Read exact HEAD's `rank_dichotomy_20261109/RESEARCH_AND_CHECKER.md` blob `9b7c63a946062fd4de0a0bae7cb127f6da2e8cd4`, plus the earlier R168 source-disclosure and MDS same-witness checkpoint exact files. Latest bounded issue-comment query returned no comments since 2026-11-09 02:20 UTC. This is NOT another public-affine or exponential-indexed table.

## Exact new step being checked
R166 established: a generic hard-TRUE ORIGINAL-witness-KEM with Build accepting only a statement and a protected random K would instantiate one-way public-key transport on R_y(w)=[H_pre(w)=y]. That implication ALONE did not establish semantic confidentiality or key agreement.

Let sk <- {0,1}^n, pk = H_pre(sk), fresh uniform k-bit K, c = Build(R_y,pk,K); Open(c,sk)=K. Sender chooses r uniform in {0,1}^k and transmits (c,r); its shared bit is b=<r,K> over F_2, receiver recovers b from Open. The extra independent public r does not change the K-recovery game. If QPT Eve predicts b with non-negligible advantage epsilon, a *classical outer oracle algorithm* can run independent copies of Eve on the SAME fixed pk,c and selected r, recovering K via a heavy Fourier coefficient / Goldreich-Levin reconstruction. No classical rewind of Eve's quantum state is presumed.

Write f_T(r)=E_A[(-1)^{A(T,r)}] for fixed public T=(pk,c) and K fixed by the experiment. Its Fourier coefficient at K is
    hat f_T(K) = E_r f_T(r)(-1)^{<r,K>}.
A global bit advantage eps implies E_{T,K}hat f_T(K)=2eps. A non-negligible fraction of experiments have a heavy Fourier coefficient at K. A polynomial number of evaluations of A for chosen r, under standard independent re-invocation and independent auxiliary-advice assumptions, can list all Fourier coefficients of magnitude Omega(eps), including K, using the paired-query prefix energy algorithm. Selecting from the polynomial-size candidate list gives non-negligible full K recovery. By the stipulated hard-TRUE extraction this yields a full ORIGINAL preimage w' with H_pre(w')=pk or an independently specified PQ hash break.

This upgrades the hypothetical primitive's necessary consequence from **one-way transport** to **passive one-bit key agreement**. It still does NOT instantiate the primitive. A proof that black-box random-oracle-only constructions cannot furnish that agreement, especially for classical honest parties against QPT adversaries, requires its own rigorous oracle/query lower bound; do not claim it here from memory alone. Non-black-box assumptions about a specific fixed hash circuit or additional correlated setup could fall outside such a lower bound. The exact adverse oracle theorem is a remaining checkpoint.

## Quantum caveats
1. Eve may be QPT with coherent quantum queries to H; each outer call starts a fresh, independent Eve execution. No direct measurement of Eve's private state required.
2. If Eve has nonuniform quantum advice, the reduction needs polynomial many independent copies of advice. Arbitrary advice correlated with this run's fresh K, source sk, or oracle programming voids the premise.
3. For a fixed transcript, Eve can be randomized and its conditional Fourier coefficient can be negative. Prefix search must retain heavy magnitudes or do signed estimation; the averaging argument ensures useful positive fraction if aggregate advantage is positive.
4. The source preimage relation is the ORIGINAL for this generic-NP instantiation, not a replacement for actual Syscoin source evidence. A Syscoin-only scheme need not satisfy generic-NP and therefore need not instantiate this agreement.
5. This implication is about black-box hash-only generic hard-TRUE release requirements, NOT a claim that SHA-256 is broken or that hash-only witness encryption is impossible.

## Next concrete action this pass
Implement a reproducible paired-query Fourier prefix extractor (not exponential enumeration) that recovers a hidden k-bit K from a randomized public-bit predictor with controlled correlation, verify precision scaling and negative-control independence, and then preserve the complete proof and executable records in this research directory. Independently examine whether public-coin key agreement from this reduction truly triggers a formal black-box RO impossibility; if unproved, record as open, not a theorem. No ordinary PR comment solely for a checkpoint.
