# R-source-global-gate: nilpotent noncommutative masks reject local probes but not public splices (NONQUALIFYING)

## Continuity and source
On 2026-11-22, open draft syscoin/PVUGC PR #1, branch research/pq-wkem-validation-20260918, was at fe134f95944a5d508faf6a5aba3859e8d8b72ea5. Read the precise R Sigma-OR note blob 268b7b080a0277077cef8b0080227589d69a2300. Ordinary comments since 2026-11-20: none. No Core/production source read or source-certificate processing in this run. The prior strict-PQ Core constraints, full authenticated source/LC qualification and R316 correction remain in force. This candidate tests a change of algebra to avoid the particular invalid-point fixed-probe and finite-cover scalar leaks of R327/R366, while checking the already known R289 global-splice problem. This note is NOT a WKEM breakthrough.

## Candidate and exact public-algebra screen
For Boolean local conditions c_j(a) define D_j(a)=I on acceptance, and N=[[0,1],[0,0]] with N^2=0 on rejection over F_103. Sample invertible private 2x2 gauges R_0,...,R_(m-1), set R_m=K R_0 for secret nonzero K, and publish the LOCAL transition tables

    L_j(a)=R_j^(-1) D_j(a) R_(j+1).

For any single consistent global assignment w the product telescopes. A satisfying w gives exactly K I, independent of the choice of qualifying w. A rejecting w gives either K R_0^(-1) N R_0 (one failed condition), or zero (two or more failures), so every invalid global output has trace 0, determinant 0 and square 0. This actually removes the simple trace/determinant *fixed invalid global assignment* extraction in the earlier invertible rejecting-gate variant. It is not a security proof.

## Exact generalized local-splice rejection
If every individual clause has some accepting local a_j, an attacker independently chooses each such a_j and publicly multiplies

    product_j L_j(a_j)=R_0^(-1) (product_j I) R_m=K I.

No single global witness need exist. This works for arbitrary noncommuting invertible gauges and arbitrary rejecting matrices, so strengthening nilpotence, the field, gauge dimension, or choice of rejecting algebra cannot repair PUBLIC INDEPENDENT LOCAL ACCEPTANCE. The attacker learns K and then any K-masked frozen S, without a true source certificate, SHA inversion or foreign witness. This is a structural rejection for this family, not a generic impossibility of source-specific hash-only WE.

Adding a public, externally checked global hash or Merkle commitment h=H(w) does NOT bind raw local secret-bearing transitions: an attacker skips that wrapper and splices them directly. Commitments bind honestly verified openings, not arbitrary processing of accessible matrices. An actual repair must make global source-witness consistency cryptographically unavoidable INSIDE a serialized public release operation. The compiler must provide publicly evaluatable transitions for all unknown future w without exposing a key or private oracle; neither side is constructed here.

## Executed synthetic computation
For four bits xyzt and Ch(x,y,z)=(x AND y) OR ((NOT x) AND z), take A: t=Ch(x,y,z); B: t=Ch(x,z,y); C: y!=z. This conjunction is FALSE (the Ch outputs are opposite when y!=z), but each local predicate is nonempty. Python standard-library checker creates complete PUBLIC transition tables, exhaustively checks every one of 16 consistent global assignments yields trace/det/square zero, and constructs a locally valid but globally inconsistent splice that returns K I. Ran two independent process executions, both successful and byte-identical, across 24 deterministic gauge/secret fixtures. Checker SHA256 2e98deeab8934af10d0fc7343eebce2647e76f58d16787e47f7da9977c60c833; both JSON outputs SHA256 875c06126f3937f54d2d3a8c186c743d17a80818af16ec81a9e7184a74462a13. The exact runnable checker and one captured output accompany this note. No native Bitcoin signature, FE, QPT attack, actual AuxPoW, burn relation, or bridge source proof was exercised.

## Source-release stopping point
This cannot supply the required classical-PPT Build_inc(x_W,sigma_cancel)->C and public Open_inc(C,w)=sigma_cancel for EVERY original qualifying witness across the independent OR grounds (greater exact BTC work; finite authenticated particular burn fault; qualified Syscoin history inconsistency/tag fault at required LC depth). The exact claim, activation, outpoint, amount, recipient, network, anchors, source height, windows, reset, native safe transaction/VK and capsule ID must remain bound. The full public view must withstand arbitrary QPT processing, malicious participant/source coins, correlated native VKs, sibling capsules and selective openings. Accepted unauthorized native output must reduce to an actual original certificate or independent justified hash/native break, not a supplied internal representation. N-of-N setup and one qualifying watcher remain distinct, and R225 activation portability still needs a truly claim-bound native spend or an explicit slot-global veto.

**Reject the entire publicly separable local-mask transition family until a real public GLOBAL source-dependent serialized gate and joint public simulator is specified.** Do not count this as an FE implementation, proof of security, material advance, or general no-go theorem. No PR progress comment, user notification, production change, activation, deployment or automation change.
