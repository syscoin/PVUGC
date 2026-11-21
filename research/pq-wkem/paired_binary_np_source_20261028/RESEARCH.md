# Paired-binary NP SOURCE compiler: exact ORIGINAL binding, insecure public release

**STATUS: NO POSITIVE SECURE WKEM ADVANCE.** This offline bounded iteration completes an exact witness-free ORIGINAL-3CNF to short-preimage source compiler and tests its concrete dual-LWE release. Every accepted short representation projects to an ACTUAL ORIGINAL satisfying witness; every satisfying ORIGINAL witness extends to a distinct permitted representation. Nevertheless a uniform family of FIXED FALSE ORIGINAL instances has a publicly computed, unaccepted pseudo-opening that decrypts the precommitted native-capability seed with overwhelming probability. Do NOT claim an arbitrary-NP WKEM or a generic recovery-to-ORIGINAL reduction.

Provenance: 2026-10-28 23:40 America/Vancouver, scheduled research turn 11, syscoin/PVUGC PR #1 open/draft/unmerged, branch research/pq-wkem-validation-20260918; starting exact HEAD 76bcf5babbac1be3ca930c499aeb703ea1731f17. Exact-version input dual_lwe_short_preimage_20261028/RESEARCH.md blob d702c096ff2bc227629ca7d8f2ee9f5e27199f42 and two_tier_public_proxy_20261028/RESEARCH.md blob 6fca0ecbb6aa733039be88fda3ab315d69fb956a; latest substantive ordinary PR comment 6489272784. No web/external literature used.

## Classical public compiler

First express arbitrary polynomial-time ORIGINAL verification R(x,W) as a polynomial-sized 3CNF F_x using gate-value variables and standard local gate constraints. Any valid ORIGINAL W classically computes its gate-extension values; every satisfying 3CNF assignment projects back to a valid ORIGINAL W. Include exact relation identity, statement, claim/UTXO, branch, anchor/window, context, and intended native capability/checking-key identity in x. This is an algebraic construction ONLY; no deployed chain verifier is assumed.

Let F_x have v Boolean variables and c three-literal clauses (literal repetition permitted). Define N=v+2c, n=N+c=v+3c, m=2N=2v+4c. Choose odd prime q>max(4N+7,7). Create a public sparse matrix A_x of shape n by m and RHS U_x of length n, using N pairs of integer coefficients (w[k,0],w[k,1]). The first v pairs encode truth assignments, the other 2c pairs encode two binary slack bits per clause.

Each pair row enforces w[k,0]+w[k,1]=1 (mod q), with RHS 1. For clause j add one row counting each of its three **satisfied literal occurrences** (selected variable pair entry) plus slack u_j + 2*v_j; set clause RHS to 4. All coefficients and the RHS are PUBLIC and computable in polynomial time without a witness. SOURCE acceptance requires an INTEGER w with A_x w=U_x mod q and ||w||_1 <= h=N. No planted SOURCE preimage is generated or retained.

Completeness: for each ORIGINAL satisfying assignment, each clause has t in {1,2,3} satisfied literal occurrences. Choose the two clause slack bits (u,v) to encode 4-t under weights (1,2): t=1 -> (1,1); t=2 -> (0,1); t=3 -> (1,0). Choose each pair as (1,0) or (0,1). Then A_x w=U_x as an INTEGER equality and ||w||_1=N. All valid ORIGINAL witnesses are supported, with no canonical common preimage.

Exact supplied-representation soundness: suppose integer w satisfies the public congruences and ||w||_1<=N. Since q>N+1, each pair-row congruence equals the integer equality sum=1. Each pair contributes >=1 to L1 norm; with N pairs and total <=N, every pair must be integral nonnegative one-hot. Clause sums lie in [0,6] and q>6, so all clause equalities modulo q are actual integer equalities. A clause with no satisfied literal contributes at most 1+2=3 from slack and cannot reach 4. All clauses are satisfied; projection returns an ORIGINAL W. For FALSE F_x, there are no accepted short SOURCE witnesses. This is NOT a claim that arbitrary native recovery provides an internal accepted representation.

## Instantiated release equation and its fatal public bypass

Using only public A_x,U_x, classical Build generates an independent native signing seed K and its genuine intended checking key, independent XOR shares of K, fresh independent uniform s in F_q^n, ternary e in {-1,0,1}^m and independent ternary eps per encoded digit a. Let h=N, g=2N+3, radix T=floor(q/g)>=2. Publish each complete ciphertext

    c = A_x^T s + e;
    d = U_x^T s + eps + g*a       (mod q).

Also publish the exact relation/statement/context, claim/path, actual native checking key, share-mask metadata, permitted auxiliary data and related capsules. Honest setup and evaluation are classical PPT. For every accepted w from every ORIGINAL witness:

    d-w^T c = g*a + eps-w^T e        (mod q),
    |eps-w^T e| <= 1+||w||_1 <= N+1 < g/2.

Cyclic nearest-center decoding therefore returns each digit and all ORIGINAL witnesses recover exactly the SAME precommitted K, although their source states and residuals differ. Opening stays off-chain; no general verifier, VM or trace dispute is added to Bitcoin. This is ONLY a correctness lemma.

For FALSE instances there is a direct counterexample. Choose any v>=1 and 2v clauses, one repeated-literal clause x_i OR x_i OR x_i and one NOT x_i OR NOT x_i OR NOT x_i for each variable i. Every ORIGINAL assignment fails. No accepted source w exists. But take ANY public assignment and encode every satisfied clause as above. For every failed clause (t=0), choose slack u=2,v=1 with complementary pair values (-1,2) and (0,1). This is NOT Boolean and is NOT an accepted short witness, but it satisfies ALL public equations A_x w*=U_x exactly. If f clauses fail, the attacker constructs w* in public polynomial time with

    ||w*||_1=N+2f > N,
    ||w*||_2^2=N+4f,
    d-(w*)^T c = g*a + eps-(w*)^T e   (mod q).

The secret s is cancelled identically. Random ternary error makes the residual concentrated at scale sqrt(N+4f), while the correctness gap is of order N. By Hoeffding, for L ciphertext columns,

    Pr[any digit wrong] <= 2L exp(-(g/2)^2 /(2*(1+N+4f))).

At q=65537,v=32,c=64,N=160,n=224,m=320,f=32,g=323,T=202, 256-bit capability and 3 XOR shares, L=102. The upper bound on attack failure is 2^-57.429188; thus the public classical attacker recovers the complete native signing capability with probability at least 1-2^-57.429188. This is a bound on the ATTACK FAILING, not a security level. The attack is on a fixed FALSE ORIGINAL relation; it needs no true witness, SourceOpen oracle, internal representation volunteered by the adversary, or native forgery oracle. Because it obtains the native signing seed K, real checking-key correlations or related capsules cannot make K secret again. The given family has exponentially decreasing attack failure as v grows (and q scales to retain radix).

The prior honestly planted dual-LWE statistical lemma and ordinary QPT DecLWE simulator crucially required uniform A and independently hidden planted source. Here A is SPARSE and instance-dependent, U is DETERMINISTIC, and the FALSE-source public pseudo-opening is an explicit break. No LWE or SIS hardness assumption applies to this instance without new justification. Public invertible left changes (A,U) -> (LA,LU) preserve A*w*=U and the attack. Narrowing g enough to spoil public decoding abandons the proved deterministic every-ORIGINAL-witness correctness and is not an independent repair. Verifying the supplied ORIGINAL witness before running a public Release does not prevent a direct public ciphertext computation.

## Executed reproducibility and security scope

The **exact committed JavaScript checker** was run directly inside a V8 JavaScript execution and produced the attached JSON output: PASS 71 assertions. It checks two different ORIGINAL witnesses recovering one same 256-bit mock capability, exhaustive false assignment checks for v=4, the exact v=32 FALSE-instance public pseudo-opening equations, L1 and squared L2 norms, five full mock-seed key recoveries on that FALSE instance, and the exact Hoeffding exponent. The independent local Python checker, preserved in the downloadable archive and NOT claimed as committed, passed 2,362 assertions on each of two byte-identical executions; it additionally exercises eight same-key true trials and twelve complete false-key recoveries. The native checking key in these tests is mock capability equality/hash, NOT a deployed or implemented SLH-like native signature. There is no QPT experiment, concrete 128-bit quantum-hardness certification, native Bitcoin covenant emulation, actual SYS/BTC authentication, malicious N-of-N ceremony, selective opening security, or formal all-auxiliary simulator result for the proposed arbitrary-NP compiler.

**Result is a failed secure compiler.** The exact accepted-SOURCE -> ORIGINAL lemma may be reused, but it cannot be promoted to an unauthorized final-key recovery -> SOURCE representation proof. Next exact challenge: public witness-free Comp(R,x,claim,context,pk) and SOURCE opening Phi(W), simultaneously with a simulator for (R,x,capsule,genuine pk,context,auxiliary data,related capsules) under an independently justified QPT assumption, such that EVERY valid ORIGINAL W recovers the same K, EVERY fixed false x hides K against public noisy pseudo-decryptors, and arbitrary hard-true unauthorized K recovery/native forgery reduces to an ACTUAL ORIGINAL W or a separate QPT break. No hidden SourceOpen oracle, assumed common preimage, general WE/iO primitive relabeling, or adversary-volunteered representation. Graph/ceremony/abort, off-chain source evidence, data availability, BTC PoW/ChainLock assumptions and conditional PQ-only native endpoint remain unresolved. Do not disable the ongoing research automation.
