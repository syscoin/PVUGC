# Run 470 — a single adjacent matrix-control seam reveals the hidden release target

**Exact scope: conditional negative theorem only.** This is a new explicit, locally masked group-program falsifier; not generic local-mixing impossibility, not an attack on obfuscated CLZ/CCMR/RIO programs, and not a practical PQ WKEM.

Verified live start: syscoin/PVUGC#1 at c7e94437ae08d01dc1ac82b195ea053ac81e9c1e, branch research/pq-wkem-validation-20260918, open/draft/unmerged. Dependencies at that SHA: Run 469 blob 265c6c9a7058e2724f93313faa6f017604970549; Run 259 blob c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2; CLZ assessment blob c19d9d9cd515140e3ce62eac960cd548c0add622. Latest substantive ordinary comment: 6067040320.

## Candidate and exact attack

For public source matrices B_{i,b} in GL_d(F_q), the ORIGINAL toy relation accepts w precisely when prod_i B_{i,w_i}=T. Classical honest setup secretly selects Q_0,...,Q_n and publishes **both** matrix alternatives M_{i,b}=Q_{i-1} B_{i,b} Q_i^{-1}. A late witness publicly selects its binary input path. Every valid w gives the same masked target V_T=Q_0 T Q_n^{-1}, potentially yielding a common K_x=KDF(x,V_T), although its prefix states can differ.

At adjacent stages j,j+1, calculate PUBLIC differences U=M_{j,0}^{-1}M_{j,1}=Q_j A Q_j^{-1} and V=M_{j+1,0}M_{j+1,1}^{-1}=Q_j C Q_j^{-1}, where A=B_{j,0}^{-1}B_{j,1} and C=B_{j+1,0}B_{j+1,1}^{-1} are public. If their simultaneous centralizer inside Mat_d(F_q) is only F_q I, solving linear intertwiners UX=XA, VX=XC gives X=c Q_j, unique up to nonzero scalar.

From this SINGLE internal mask representative, propagate to every endpoint via Qhat_{i-1}=M_{i,0} Qhat_i B_{i,0}^{-1} and Qhat_i=M_{i,0}^{-1} Qhat_{i-1} B_{i,0}. Every Qhat_i=c Q_i with the SAME unknown scalar, which cancels: Qhat_0 T Qhat_n^{-1}=V_T. Field Gaussian elimination runs in polynomial time in n,d,log(q), with no witness, oracle, rewinding or hardness assumption. Any proposed capability KDF(x,V_T) is exposed even for false instances.

## Reproduced concrete fixture

With d=2 and q odd prime, use upper and lower shears A=[[1,1],[0,1]] and C=[[1,0],[1,1]]. Their simultaneous commutant is exactly the scalars. The four source layers are (I,A),(C,I),(I,D),(I,D^-1), D=[[1,2],[0,1]]. Target T_true=AC has two accepted ORIGINAL bitstrings (1,0,0,0) and (1,0,1,1) with distinct stage-three states, yet the SAME final masked target. T_false=[[3,1],[1,1]] has ZERO ORIGINAL bitstrings among all sixteen; nonetheless its masked target is recovered without a witness.

The committed **exact executed** standard JavaScript checker tests 16 independently chosen invertible-mask fixtures over F_7,F_11, solves the two matrix intertwiners, reconstructs all published matrix alternatives, enumerates source witnesses and recovers the target of the false statement. Captured JSON is included. An independent extended local-only standard-library Python checker covers 48 fixtures over F_7,F_11,F_101,F_103 with the same conclusions. Finite checks do not prove PQ security.

## Attack and dependency boundaries

This is a specific local-seam / global-gauge attack (taxonomies 1,2,4,5,8); it is deterministic classical PPT and thus QPT (9). No statistical fingerprint, malicious setup or multi-capsule correlation is needed. Correct x/UTXO/branch separation does not rescue the SAME compromised target. Recovery of V_T compromises signing only if K_x depends on it; an independently hidden capability is not attacked. If protected programs conceal raw matrix alternatives, the theorem does not apply.

Run 259 addresses only an **accepted COMPLETE source representation -> ORIGINAL witness** under its residual/SIS scope. A recovered V_T is not such a representation; the false fixture has none. The missing native-signature/recovery-to-representation arrow is still UNPROVED.

A surviving mixer must prevent these transparent jointly conjugate controls, rather than relying on more random Q_i alone. Remain with late ORIGINAL witness admission into a compact protected region; do not substitute this gauge failure for the constructive WE-like compiler.

**Still unproved:** a real mixer and all-witness same K; false-instance full-public arbitrary-QPT hiding; unauthorized true-instance native authorization -> ORIGINAL witness/QPT break; malicious N-of-N setup, auxiliary input, multi-capsule, practical 128-bit resources; conditional native SLH/P2MR. No production change; PR draft/unmerged. Keep research task enabled.
