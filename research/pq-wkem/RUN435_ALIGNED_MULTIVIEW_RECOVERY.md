# Run 435 — aligned replicated local-mixing views can erase constant-rate faults

Live starting state: syscoin/PVUGC PR #1, draft branch research/pq-wkem-validation-20260918, SHA 480b064bdd32114da038c1459418917817e62842. Exact Run 434 note blob 1274a94a26350c4719b7eeec0d9e2655b5a7c44c, Run 428 blob a82a5a7efbb852462894fc62ac1d910df0e636f2; latest ordinary substantive comment 6067040320.

## Deterministic three-view theorem

Let F_s:{0,1}^n -> Y satisfy Simon's exact two-to-one promise with nonzero period s. Suppose three deterministic polynomially executable PUBLIC circuits G_0,G_1,G_2 have a COMMON ALIGNED output alphabet, and at least two G_j(x) equal F_s(x) at every x. Then the public pointwise plurality H(x)=plurality_j G_j(x) equals F_s(x) identically. Therefore a QPT adversary with coherent access to the three public circuits recovers s using O(n) Simon queries to H and GF(2) Gaussian elimination. Each joint query is three component evaluations. No frame recovery, random-oracle programming, or source witness is needed.

For example, partition inputs into three efficiently decidable disjoint sets D_0,D_1,D_2 of almost equal size; corrupt G_j only on D_j, using any incorrect value. Each SINGLE capsule is modified at a constant rate about 1/3, beyond Run 434's O(1/n) one-capsule bound. Yet the THREE combined capsules recover F_s perfectly even if each G_j individually loses its exact Simon period. No random noise, independence, or honest-generator seed assumption is needed for the logical two-out-of-three implication. Publicly unusable or mutually unaligned output labels are outside this theorem. If public normalizers bring individually permuted outputs to one common alphabet, the theorem applies after normalization.

## Independent constant-rate extension

For r mutually aligned replicas, suppose for each fixed input x the per-replica indicators of failure to return F_s(x) are independent, each of probability at most p<1/2, allowing arbitrary correlations ACROSS different x and adversarial replacement values. Pointwise plurality is incorrect only if at least half of r replicas err. By Hoeffding its per-input error probability beta is at most exp(-2r(1/2-p)^2). For the static plurality function H_r, E_x,coins[1(H_r(x)!=F_s(x))] <= beta. Markov gives Pr_coins[relative input error delta > delta_star] <= beta/delta_star.

For odd r >= ln(256 n^2)/(2(1/2-p)^2) and delta_star=1/(64n), beta<=1/(256n^2) and setup-bad probability <=1/(4n). With q=4n queries, the exact Run 434 sparse-function theorem gives unconditional period recovery at least

(1-beta/delta_star) * [1-q delta_star-(2^n-2)(1/2+sqrt(2delta_star))^q].

For n>=8 the bracket is >15/16-0.201^n. At n=128 and p=1/4, r=123, q=512, and q*r=62,976 base circuit evaluations give a lower bound >0.935. These are conditional QPT query counts, NOT concrete PQ-security parameters or hardware resource estimates. The single-input cross-replica independence can be realized by classically samplable independent affine hash seeds, even with correlations across inputs; revealing the seeds may make the scheme even easier to attack classically. No secure white-box compiler for secret s is supplied.

## Scope and attack surface

The candidate is a conditional PUBLICLY COHERENTLY EXECUTABLE evaluator family, not an instantiated local-mixing release compiler. There is no claim that a public polynomial classical circuit implementing F_s can keep s concealed against classical white-box inspection. The period must actually encode signing-sufficient capability before this becomes a native-spend attack. The model does not provide an ORIGINAL NP relation, all-valid-witness same-key correctness, or a security reduction. It does not refute CCMR/RIO or solve constant-rate LPN: independent aligned copies are combined BEFORE Simon sampling.

Attack-family assessment: local seam (plurality repairs faults); global gauge (aligned outputs explicitly assumed; unaligned is unknown); statistical fingerprint (per-view noise does not protect common period); multi-capsule (three views enough under deterministic covering); adaptive public evaluation (coherent H computed from G_j); malicious setup (two-of-three theorem deterministic but other malicious setup remains unproved); replay (different keys/unaligned contexts need not combine); public checking keys (cannot re-hide already recovered signing seed); genuinely quantum (Simon Fourier sampling, not classical Grover acceleration). Source extraction from Run 259 applies only to accepted complete representations, not period-derived signatures.

## Exact checker and literature

The committed Node.js standard-library checker is the EXACT executed program; 1,047 assertions passed on exhaustive n=4,...,8 Fourier distributions, pointwise plurality restoration, individual-view period failure, and exact wrong-equation identity. A separate local Python implementation passed 1,640 assertions on 12 n=5,...,8 fixtures, GF(2) rank recovery, and logarithmic replication bounds at n=8,16,64,128,256. Every checker yielded byte-identical repeat outputs. No quantum hardware or PQ signature security testing occurred.

Run 434 is the necessary sparse-patch reduction. May–Schlieper–Schwinger, Noisy Simon Period Finding (arXiv:1910.00802v3) considers quantum measurement noise and LSN/LPN, not this aligned replicated-input correction. Canetti–Chamon–Mucciolo–Ruckenstein, TCC 2024 / ePrint 2024/006, studies local reversible circuit mixing, not the three copied noisy circuits assumed here; its complete proof body was not freshly audited.

Still UNPROVED: a concrete efficient local release, every ORIGINAL witness recovering the same native K, complete-public-output false-instance QPT native-forgery hiding, unauthorized true-instance native forgery -> ORIGINAL or independent QPT break, malicious N-of-N setup and erasure, general multiple-capsule security, 128-bit concrete implementation, and the conditional P2MR/native-SLH endpoint. Production unchanged; no complete PQ witness-KEM.
