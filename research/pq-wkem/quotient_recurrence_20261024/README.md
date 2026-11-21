# Pivot–Schur quotient recurrence (2026-10-24)

**Construction-only continuation of syscoin/PVUGC#1, starting SHA `c8343d87d7ad880dd4aa2deed02d9f681e2c4569`.** No change to the release gate, ORIGINAL relation, N-of-N premises, checking key, or same-K correctness. This is not a QPT key-security proof.

For the exact published Schur/Frobenius gate, on a pure quotient source `(z,w)=(0,0)`, `G_e = s_e(rho)(E13+E31)`, where `s_e(rho)=sqrt(Z(e)) sum_j rho_j sqrt(e)^j`. Therefore the public quotient coefficient matrices factor as `Q_j=A D^j B`, with `D=diag(sqrt(e)*I_2)`, `A` full column rank `2L`, `B` full row rank `2L` except on an honest-setup event of probability at most `2 |E|^(-h-1)/(1-|E|^-1)`.

For **any publicly computed** generalized inverse `G` of `Q_0` satisfying `Q_0 G Q_0=Q_0`, the exact recurrence is
```
Q_j = Q_0 (G Q_1)^j  (j >= 0).
```
Thus the entire public coefficient tensor is recoverable from the original-coordinate matrices `C_0,...,C_n`, only two quotient matrices `Q_0,Q_1`, and the unchanged checking key/context. No hidden per-node factors or additional coins are published. This is a deterministic public classical PPT transformation, hence works as a straight-line simulation for full-public-output QPT attackers, arbitrary correlated auxiliary information and multiple capsules; it adds no hardness assumption.

**Exact honest-setup release equivalence**: BuildCompressed retains `C_0,...,C_n,Q_0,Q_1`; Prepare publicly factors Q0 and computes the generalized inverse; EvalCompressed computes `zC_0+sum_i w_i C_i+A (sum_j rho_j T^j)B`; Encode, Recover and SuppliedPairExtract retain the exact predecessor behavior and all its scope limitations. A separate public CompressVerified path checks omitted matrices for any arbitrary/malicious input, and falls back to the raw representation on rank loss/inconsistency. This is *format* safety, not malicious-N-of-N cryptographic security.

**Concrete storage** (same `n=11000,m=16000,N=32913,E=GF(2^256)`): 27,000 -> **11,003** dense matrices; 935,941,451,616,000 -> **381,413,473,782,624 bytes**, an exact **59.24814815%** reduction. Still approximately **381 TB**, not practical. No security improvement is claimed. The previous <2^-169 supplied-pair semantic bound remains at its original honest-setup scope.

**Executable reproduction**: [complete archive](QUOTIENT_RECURRENCE_BUNDLE.tar.xz) contains the full mathematical derivation, standalone GF(16)⊂GF(256) checker using the exact current gate, captured JSON and SHA-256 provenance. Three independent small-field fixtures with four quotient coordinates passed **1,099 assertions**, in two byte-identical executions. This is not a QPT proof.

**Next exact obligation:** Analyze arbitrary bare-K/native-forgery recovery from the *equivalent reduced joint public family* `(C_0,C_1,...,C_n,Q_0,Q_1,checking key,context,correlated capsules)` and prove ORIGINAL witness extraction or an independently justified QPT break. No such proof exists yet; full-public false-instance secrecy, malicious setup, true practicality and PQ Bitcoin integration remain unproved. Keep PR open/draft/unmerged and the research automation enabled.
