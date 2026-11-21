# Run 434 — sparse static patches do not cure a coherent period leak

Live dependency: syscoin/PVUGC draft PR #1, branch research/pq-wkem-validation-20260918, SHA 054d8c16487face8f7817d936a604ab3078f7684; exact Run 429 note blob 19d8d84b12d9264e068b943f034689cb6b8f5803, exact Run 428 note blob a82a5a7efbb852462894fc62ac1d910df0e636f2; latest substantive comment 6067040320.

**Precise negative result.** Let F:{0,1}^n -> T obey the exact Simon promise F(z)=F(z') iff z'=z or z'=z xor s for some nonzero n-bit protected capability s. A classical PPT setup is *conditionally assumed* to output a polynomial-size publicly executable deterministic classical circuit G with at most delta 2^n changed input values relative to F. The full public circuit, verification key, correlated classical auxiliary views, all contexts, and multiple capsules may be seen by an arbitrary QPT adversary. The public circuit allows coherent quantum evaluation. No compiler with this property and hidden s is constructed.

For |psi_G> = 2^(-n/2) sum_z |z>|G(z)>, Simon Fourier sampling gives the **exact** identity

 Pr[Y dot s = 1] = (1/(2*2^n)) * #{z : G(z) != G(z xor s)} <= delta.

Proof: the projector for Fourier strings nonorthogonal to s is (I-T_s)/2 before Hadamards. Its expectation equals one half the fraction of inputs on which G differs under translation by s. Such a difference requires that z or z xor s was patched; the union has density at most 2 delta.

The pre-Hadamard ideal and patched states have inner product >=1-delta, so the total-variation distance between their measured Fourier distributions is <=sqrt(2delta-delta^2). For every t not in {0,s}, Pr[Y dot t=0] <= 1/2+sqrt(2delta), because the ideal measurement is uniform on s-perp.

Draw q independent coherent samples and compute the F2-kernel of the measured rows. All q samples are orthogonal to s except with probability <=q delta. Conditioned on no such error, rank below n-1 implies some t outside span{s} is orthogonal to every sample. Union bounding these events proves

 Pr[recover s] >= 1-q*delta-(2^n-2)*(1/2+sqrt(2delta))^q.

At n>=8, q=4n and delta<=1/(64n), recovery is >=15/16-(2*(9/16)^4)^n >15/16-0.201^n. This uses polynomial coherent queries and ordinary Gaussian elimination. If s is sufficient to sign for the bound branch, direct capability recovery needs no ORIGINAL witness, breaks false-instance authorization, and cannot be repaired by Run 259 supplied-representation extraction.

**Scope:** Arbitrary static patch positions/outputs are allowed. This theorem does not cover constant-rate corruptions, independently randomized online oracles, a noncoherently accessible external server, or actual CCMR/RIO. Public deterministic randomized algorithms can normally have their public coins fixed by a QPT observer, but no such broader proof is claimed. Classical white-box secrecy of a program implementing G is **not** established. Replacing a uniform secret permutation with a public code may already leak s classically. Nor is all-ORIGINAL-witness SAME-K correctness supplied here.

**Attack families:** (1) local labels still allow period correlation; (2) no global frame synchronization is needed; (3) leakage is a functional Fourier invariant, not a gate spectrum; (4) one capsule suffices; (5) coherent chosen-input calls are essential; (6) honest patches already fail, while malicious setup is not secured; (7) fresh UTXO/branch context cannot cure same-instance period leakage; (8) adding correlated native checking key cannot hide a recovered signing-sufficient seed; (9) this is genuine Hadamard-interference quantum recovery, not classical search with Grover acceleration. No QROM rewinding or extractor is needed for the attack.

**Literature (primary proof-body read):** May–Schlieper–Schwinger, _Noisy Simon Period Finding_, arXiv:1910.00802v3, https://arxiv.org/html/1910.00802v3, Sections 2 and 5–6. Its LSN/LPN equivalence concerns a different, smoothed physical measurement-noise model, especially fixed positive noise. This sparse *function corruption* bound neither solves that LPN problem nor refutes the paper. Run 429 supplied the exact-period candidate; this iteration proves its vulnerability survives O(1/n) sparse public-input patches. Not a new Simon algorithm or an attack on actual CCMR.

**Checker:** run434_compact_check.js, Node.js standard library, directly enumerates finite Fourier spectra and exact integer equation-error identities. The separately executed extended Python checker, retained locally, additionally tests Gaussian elimination on samples from the exact distribution; no actual quantum device. Tests do not imply PQ security. Still missing: any practical local release compiler; all-valid ORIGINAL SAME native capability; full-public-view QPT false-instance signature hiding; unauthorized true-instance forgery -> ORIGINAL or independent QPT break; malicious N-of-N setup/erasure; multi-capsule composition; practical 128-bit resources; conditional Bitcoin P2MR/native-SLH endpoint. No complete WKEM; draft remains unmerged.
