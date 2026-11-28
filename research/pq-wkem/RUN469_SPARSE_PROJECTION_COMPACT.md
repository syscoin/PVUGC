# Run 469 — sparse defects do not repair quantum-visible local release projections

**Conditional negative theorem only.** No secure local-mixing primitive, attack on an actual CCMR/RIO/CLZ implementation, practical post-quantum witness-KEM, or Bitcoin endpoint is claimed.

## Current verified dependencies
Live head on syscoin/PVUGC#1 at starting SHA 3f783bc09426db59b8ec810c2ca4494e392824d6; Run 468 projected-graph theorem blob 69e99fc3b89de39eb5bcb73685b75379c393aabd. CLZ applicability blob c19d9d9cd515140e3ce62eac960cd548c0add622. Run 259 source-binding blob c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2. All files were read at this exact commit. The last substantive ordinary comment is 6067040320.

## New robust projected-graph theorem
Let public classical PPT forward programs implement F0(z)=P(z) and F1(z)=L(P(z xor Delta)) for an efficiently computable n-bit permutation P, unpublished/secret n-bit permutation L, hidden nonzero Delta, and public r-bit projection pi. Put f(z)=pi(P(z)), h(z)=pi(L(P(z))) and eta=Pr_z[f(z)!=h(z)]. Write mu=max_{d!=0,e} Pr_z[f(z xor d) xor f(z)=e] and assume mu+2eta<1.

A quantum attacker can coherently execute these public classical programs and prepare the graph state over S={(b,z,G(b,z))} where G(0,z)=f(z), G(1,z)=h(z xor Delta) and N=1+n+r. The candidate graph translation is p=(1,Delta,0^r). It is NOT necessarily an exact symmetry. Its exact graph autocorrelation is A(p)=1-eta. For every q not in {0,p}, A(q)<=mu+eta.

Proof of the false-correlation bound: for q=(0,d,e) with d!=0, the first branch's differential match probability is <=mu, while the second differs from this match predicate on at most two defect events (<=2eta), so their average is <=mu+eta. For d=0,e!=0 it is zero. For q=(1,d,e), shift variables by Delta: when d xor Delta!=0, comparison with f differs at <=eta points and the differential match is <=mu; when d=Delta and e!=0, matches occur only on the defect set (<=eta). The exceptional nonzero q is p.

Graph Fourier sampling obeys Pr[<Y,q>=0]=(1+A(q))/2. Hence p violates each measured parity with probability eta/2, while every false q survives with probability at most a=(1+mu+eta)/2. After M independent samples, a GF(2) nullspace search recovers span(p) with probability at least

    1 - M*eta/2 - (2^N-2) * a^M.                         (469.1)

This is an exact (possibly vacuous) lower bound. If N is polynomial, 1-mu-eta is inverse polynomial, M is polynomial, and M*eta is sufficiently small to leave constant success, a uniform QPT attacker recovers Delta in polynomial time. If the single-batch lower bound exceeds 1/2 by an inverse polynomial, majority over polynomially many independent batches amplifies success. For larger eta, the noisy-parity problem is NOT solved here; no constant-noise polynomial-time theorem is asserted.

The promised public circuits are evaluated coherently **locally**, not via a remote quantum-query interface. The honest model is classical PPT only for a family with polynomial-size forward circuits; the finite checker uses exponential toy lookup/permutation tables. The attack needs neither quantum advice nor rewinding. A leaked Delta compromises native signing only when K_x is actually publicly derivable from it and the bound x/UTXO/branch, e.g. KDF(x,Delta); an unrelated protected key need not leak. Public native checking keys and multiple capsules are included in the adversary's view, but the negative theorem uses just one vulnerable pair.

## Exact executed checker and scope
The committed JavaScript checker uses finite-field-inversion permutation fixtures with n=7,8,9; a genuinely non-affine L that permutes within pi-fibers and then crosses just two images between fibers. Thus eta=2/2^n is nonzero in every case, unlike Run 468. It constructs graph states, computes exact integer Walsh probabilities, verifies autocorrelation on sampled shifts, simulates measurement outcomes, and solves binary nullspaces. It executed 9513 assertions, yielding 13,18,21 correct recoveries across 24 batches per fixture and zero false one-dimensional candidates. These are finite algebra/algorithm checks, NOT a quantum-hardware demonstration or security proof.

Attack taxonomy: (2) public synchronization via near-invariant projections, (3) function fingerprints, (4) correlated views, (5) coherent public evaluation, (7) context reuse when K depends on Delta, (8) public checking-key correlation, and (9) genuinely quantum graph sampling. No seam or malicious-setup assumption is needed for this specific attack. Run 259 applies only after obtaining an accepted COMPLETE source representation; this attack does not supply that representation.

Literature scope: May–Schlieper–Schwinger, Noisy Simon Period Finding (arXiv:1910.00802), warns that noisy parity decoding can involve LPN; its physical device-noise model differs from deterministic function defects. May–Schlieper, Quantum Period Finding is Compression Robust (arXiv:1905.10074), preserves exact periods. CLZ's CRYPTO 2026 paper (DOI 10.1007/978-3-032-35367-2_18) has not been shown to expose this paired view; its full proof, assumptions, adaptive FE key order, and late-witness-admission interface remain unverified.

**Still missing:** a real minimal release algorithm; all valid ORIGINAL witnesses recover the SAME K_x; false-instance complete-public-output arbitrary-QPT hiding; arbitrary true-instance premature key recovery/accepted native forgery -> accepted COMPLETE representation/ORIGINAL witness or independent QPT break; malicious N-of-N setup/abort/erasure; related-claim composition; 128-bit concrete costs; and the conditional native SLH/P2MR Bitcoin endpoint. All proof/witness material remains OFF CHAIN, native signature and preauthorized graph conditions ON CHAIN. Witness privacy optional. No generic WE/iO-equivalent assumption is accepted as a disguised solution. Leave the research task enabled.
