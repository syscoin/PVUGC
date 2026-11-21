# R236 — independent-branch release-key OR combiner (intermediate, pre-test)

Repository syscoin/PVUGC draft PR #1; observed start fa524a37c842b8caff7db2df531612a94fc012fc, branch research/pq-wkem-validation-20260918. Read exact R235 RESEARCH.md at that head. No external web or other repositories.

Candidate: independent 256-bit branch secrets K1,K2,K3, independent random 256-bit S, E_j=S XOR H(domain,x,j,K_j), D=sigma XOR XOF(domain,x,S,len(sigma)). Every valid ORIGINAL branch-j witness would have to recover K_j from a still-unbuilt branch capsule C_j. Opening any branch then returns the same frozen native cancellation signature sigma. This is a purely algebraic construction of the OR wrapper, NOT a construction of the branch release gates or an ORIGINAL WKEM.

Before tests: assess whether all three E_j together reveal S even if no individual branch key K_j is recovered; compare public partial K_j information and direct XOR. Specify the entire public quantum auxiliary view; do not infer gate secrecy from random oracle or hash assumptions. This checkpoint records a hypothesis, not a successful result.
