# Run 544 — Noninvertible hash pullbacks admit filtered quantum collision recovery

Live input: draft syscoin/PVUGC#1, branch `research/pq-wkem-validation-20260918`, head `d2db016947e4aa6d7a13ba25bf969a57f0e72e7f`, tree `ed9fe1cb8f91aa2851876975f28dc2dacdee6dcd`. Exact Run 543 proof blob `b2a865cd43f09c15f1db40ad94d1604aab8ebaca` read before work. The latest substantive PR comment was `6067040320`.

## Exact restricted construction and correctness

For k-bit secret K!=0, public independent ideal functions T:{0,1}^n->{0,1}^k (n>=k) and H:{0,1}^k->{0,1}^M, imagine a publicly and coherently evaluable F_K(s)=H(T(s)) XOR H(T(s) XOR K). Such a classical protected evaluator is **not constructed**; literal publication of K would be insecure.

A noninjective T makes raw collision witnesses s!=t and F(s)=F(t) **incorrect**: T(s)=T(t) creates a trivial collision deriving 0, not K. Restrict the toy source relation to F(s)=F(t) AND T(s)!=T(t). Under no accidental distinct XOR-coset output collision, every accepted pair has T(s) XOR T(t)=K, so all accepted pairs recover the same capability while their states differ. This is a toy relation, **not ORIGINAL Syscoin/BTC evidence**. Distinct H-pair cosets have independent uniform M-bit outputs, so the accidental-collision probability is <2^(2k-3-M).

## Attack A: a single public evaluation leaks a hash-preimage target

Let u=T(s). From one F(s) value and public H, calculate Y=F(s) XOR H(u)=H(u XOR K). Quantum preimage search over the k-bit H domain costs O(2^(k/2)) H queries and polynomial working memory, recovering K=u XOR v. This requires only classical access to F once, no inversion of T, and no quantum F oracle. It is exponential, **not a polynomial-time QPT break**.

## Attack B: table plus coherent marked-mate search, even if T is one-way

Sample q inputs with distinct output fibers; save (u_i=T(s_i),v_i=F(s_i)). If two sampled F outputs match and u_i differ, immediately recover K=u_i XOR u_j. Otherwise define a public reversible predicate P(s)=[there exists i: F(s)=v_i AND T(s)!=u_i]. On the good-H event, exactly T(s)=u_i XOR K is marked. Any marked s supplies K.

For ideal random T, conditional on the q sampled fibers, on the remaining L-q inputs (L=2^n) the count Z of marked inputs is Binomial(L-q,q/2^k). Its expectation is mu=(L-q)q/2^k and Pr[Z<mu/2]<=exp(-mu/8). For n>=k and q=o(2^k), a Grover search costs O(sqrt(2^k/q)) coherent F calls, plus q classical sample queries. Taking q=Theta(2^(k/3)) yields **O(2^(k/3)) F-oracle queries and Θ(2^(k/3)) sample memory**. No inverse of T is required. This is a conditional quantum *query upper bound*, **not** a gate/time cost without efficient reversible table membership (naive membership can take O(q) gates per query). k=256 yields about 2^85.3 F queries with huge memory; k>=384 is necessary only to avoid this specific sub-2^128 query ceiling, not sufficient for PQ security. For security parameter k growing linearly, this attack is exponentially costly and is not a QPT distinguisher.

## Reproducibility, narrow scope, and attack ledger

The committed JavaScript checker is the exact function executed in the connected V8 runtime before writing; output JSON is captured verbatim. It enumerates 16 toy SplitMix64 fixtures (k=4..7, n=k+3), checking all equality fibers, 48 one-evaluation hidden hash targets, all marked pair extractions, zero-key trivial collisions, and Grover-amplitude arithmetic. Independent larger Python/SHAKE256 finite checks (20 fixtures, 60 one-evaluation targets) and extended note are preserved locally, not promoted as an executed GitHub checker. Tests do not execute a quantum device or prove a cryptographic assumption.

Attacks: (1) equality/mate seams, not transparent wire-label seams; (2) no public inverse/synchronization required; (3) equal-output fingerprint even with uniform marginals; (4) one capsule, many evaluation views; (5) chosen-input and coherent public evaluation for Attack B; (6) honest classical setup already exposes the attack; (7) context binding cannot remove a within-claim attack; (8) checking key unused (additional correlations unproved); (9) genuine quantum Grover search and distinct memory models. Honest setup is classical PPT in the ideal-oracle specification; the hypothetical protected F implementation remains uninstantiated. Attackers can have arbitrary public keys/context/auxiliary information, but **no arbitrary-QPT full-output hiding or extractor theorem is proved**. Neither toy collision witnesses nor their openings satisfy Run 259's ORIGINAL extraction interface. This does not weaken Run 536's universal-NP=>WE boundary.

**Handoff:** A noninvertible hash input map avoids the *specific polynomial-time inverse-conjugated Simon attack* of Run 543, but neither implements the missing ORIGINAL-source-to-protected-label admission nor eliminates these exponential quantum attacks. Real classical-PPT protected evaluation, every ORIGINAL witness same key, false-instance full-view QPT hiding, unauthorized native-spend-to-ORIGINAL extraction or independent QPT break, malicious N-of-N ceremony, all-capsule binding, concrete time-space parameters, and the conditional Bitcoin native PQ graph remain UNPROVED. No complete WKEM; leave PR draft/unmerged, production unchanged and automation enabled.
