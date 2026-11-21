# GOIL — global one-hot integral source with a failed quadratic release guard

**Research ID GOIL-2026-11-01-T01. Status: NO POSITIVE SECURE WITNESS-KEM ADVANCE.** This is a restricted representational lemma and an explicit failed public-release repair. It is not ready for merge or deployment.

## Precise starting checkpoint and public distribution

Continues local-only GOLC (Generic ORIGINAL Linear-Constraint Source Lift) and the pinned BASO source-LWE carrier, syscoin/PVUGC#1, research/pq-wkem-validation-20260918 at d85b12d75ca94ab67c589d6a703fb50d600d4ee3; most recent substantive ordinary comment 6554728395. The exact BASO file blob was a79b5f747fc328e2818d534be2b3f7cc04bb0336. Local extended evidence archive: WKEM_GOIL_20261101_EVIDENCE.tar.gz, SHA256 3b2ff1a215b1d1054921c7a8d26bc21c7e4eeae7b2cbb4cae6cf669369a11fef; the full derivation and 455-assertion Python checker are retained there in the execution environment. This GitHub directory instead contains the **exact separately executed small JS regression** and its output.

Fix arbitrary polynomial-size Boolean ORIGINAL NP verifier V_x(W), exact claim/UTXO, branch, relation identity, anchors/window/context, intended native verification key and signed off-chain preauthorization domain. Build is classical PPT and receives NO ORIGINAL witness. For shared input/wire variables z, compile NOT y=1-a; AND y=a*b with Boolean slacks and equations y+s1-a=0, y+s2-b=0, a+b-y+s3=1; pin public inputs and output=1. Let M_x z=b_x have N Boolean coordinates. Every satisfying ORIGINAL W has an extension z_W in {0,1}^N and every binary solution yields an actual ORIGINAL satisfying W; witnesses need not share internal states.

**One-hot lift:** introduce integer p_(i,0),p_(i,1) per z_i with p_(i,0)+p_(i,1)=1 and z_i=p_(i,1). This yields Mtilde_x p=btilde_x on 2N coordinates. Sample B0 uniformly in F_q^(d×(r+N)); publish A=B0*Mtilde, t=B0*btilde, alongside Mtilde, btilde and B0. Source dependent correlations are PUBLIC, not hidden. The full public transcript also contains the original relation and statement, all capsule ciphertexts, real native checking-key correlations, context, actual claim/UTXO, signed P-domain preauthorizations, watcher records, and any adversarial auxiliary input. No independent QPT source simulator exists for this distribution.

A conditional hypothetical native SLH-like key generator supplies authentic sk/vk; protect 512 private bits K=(SK.seed[256],SK.prf[256]) while the public verification fields remain genuinely correlated with the protected key. The JS checker instead uses one toy symbol and no real signature. For each related capsule independently XOR-share the same K across 3 lanes and independently encrypt packed symbols with s uniform in F_q^d, independent errors e in [-E,E]^(2N), e* in [-E,E]:
 beta=A^T s+e mod q; tau=t^T s+e*+g*m mod q; g=floor(q/2^b).
Official public Lift runs V_x(W) OFF-CHAIN, constructs one-hot p_W, checks source and reconstructs the same precommitted K from tau-p_W^T beta for every valid ORIGINAL W. Bitcoin would verify only an ordinary native challenge-path signature at a CONDITIONAL no-EC-keypath PQ endpoint, never ORIGINAL NP/PCP/SNARG/VM/BitVM verification.

## Exact new SHORT-INTEGER representation lemma

**Theorem:** Any integral p with Mtilde p=btilde and ||p||_1<=N extracts an actual ORIGINAL witness. Proof: summing pair equations gives sum_j p_j=N, so N=|sum_j p_j|<=||p||_1<=N. Equality implies every integer p_j is nonnegative; each integer pair sums to 1, hence is (1,0) or (0,1). Then z_i=p_(i,1) is binary and the original GOLC gate equations force an accepted ORIGINAL verifier computation. No canonical witness or common intermediate state is required.

For ||p||_1<=N, all integer row discrepancies of Mtilde p-btilde have magnitude <=2N+1. Select q>2(2N+1), so a nonzero discrepancy stays nonzero in F_q. A fixed invalid p survives independent uniform B0 row masking with exact probability q^-d. Counting at most (2N+1)^(2N) short integer candidates gives
 Pr[invalid short integer p and Ap=t] <= (2N+1)^(2N) / q^d.
Thus d log2(q)>=2N log2(2N+1)+lambda yields at most 2^-lambda representational error. This closes **only** certified/supplied short-INTEGER representation -> ORIGINAL, NOT arbitrary key recovery -> representation or a PQ break.

For any valid W, the one-hot vector has ||p_W||_1=N and Ap_W=t. Its residual is g*m + e* - p_W^T e. Consequently if g>2E(N+1), all valid ORIGINAL witnesses reconstruct the identical precommitted K for every permitted bounded honest error sample and across independently reshared capsules. Honest setup/evaluation are classical PPT, but source columns double and no practical QPT-128 parameters are calibrated.

## Tested nonlinear release and exact fatal bypass

The proposed public quadratic integrality guard changes the official residual to
 rho_guard(p)=tau-p^T beta+sum_j r_j(p_j^2-p_j) mod q,
where all r_j are published. It vanishes for valid Boolean p and randomizes invalid signed openings in the official API. But anyone can subtract this public term and compute tau-p^T beta. **The guard does not cryptographically enforce integrality.**

For FALSE ORIGINAL V(w)=w AND NOT(w) with output pinned to 1, the public signed solution z_fake=(0,1,1,-1,0,1) satisfies every integer gate equation. The associated one-hot p_fake=(1-z_i,z_i) solves Mtilde p=btilde (and Ap=t) for EVERY mask but has ||p_fake||_1=N+2=8 > certified bound N=6. Official Lift rejects; arbitrary public arithmetic cannot be stopped. With q=65537, E=2, b=8, g=256, the false residual error is at most E(1+8)=18<g/2=128. Every encrypted symbol decrypts correctly for EVERY allowed bounded error sample even though there is NO ORIGINAL witness. The exact JS checker verifies 128 separate mock ciphertext decryptions, and the extended local Python checker verifies 48 complete false mock-key/capsule recoveries plus 369,305 enumerated short integral vectors on the FALSE case.

The certified lemma cannot extend automatically to rational source vectors: a separate unsatisfiable four-clause Boolean verifier admits a nonnegative fractional one-hot relaxation at x=y=1/2, nominal l1=N=36. Under modular half-coefficients some noise samples wrap; this proves relaxation unsoundness, not yet a universal full-key attack for those fractions.

The public source also has a publicly computable null vector inherited from Mtilde, making it distinguishable from ordinary uniform A with advantage 1-q^-d for this circuit shape. Therefore the earlier ordinary-QPT-LWE full-public hybrid does not simulate the actual source-dependent output. No SourceOpen oracle is assumed, and the honest native vk, auxiliary data, signing transcripts, related capsules and quantum processing cannot be silently omitted.

## Actual security boundary and next equation

A complete solution still needs classical-PPT witness-free Comp(R_original,x,scope,vk) and public Lift(C,W)=K_precommitted for **every** valid ORIGINAL witness, together with arbitrary nonuniform QPT FALSE/hard-TRUE unauthorized final-key recovery or accepted native forgery -> an **actual ORIGINAL witness** or an **independently justified QPT break**, under all public-checking-key/auxiliary/related-capsule correlations, without attacker-volunteered representation or ideal SourceOpen. Native signature EUF-CMA does not rescue a capsule that reveals its signing key and cannot replace the missing source simulator. Malicious N-of-N ceremony/erasure/abort, watcher DA and timely inclusion, full SYS/BTC fork evidence qualification and the conditional native Bitcoin PQ endpoint remain separate unresolved prerequisites.

This research was carried out offline. No external literature was retrieved, no quantum experiments run and no independent agents invoked. The published JS checker is executable with Node.js 22, standard library only; the extended Python checker is preserved in the local evidence archive. This is intentionally a **negative security checkpoint with a reusable narrow proof**, not successful generic PQ witness encryption.
