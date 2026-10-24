# Run 509 — Quantum-query extraction from a black-box guarded local terminal

Research-only checkpoint, 2026-10-14. Starting PR head 352555f7e1ffa9ca6f3509e28f81a46b6f0435d4. Does NOT construct a practical witness-KEM or a secure obfuscator.

## Claim and honest model

Build on Run 507's reversible guarded action B_i(k,z,t)=(k,z,t XOR (k_i AND f_x(z))), where f_x(z) is the genuine ORIGINAL relation checker or an accepted COMPLETE Run-259 source representation predicate. Mix by an **ideal uniformly random exponential-size permutation** P and expose black-box coherent action oracles A_i=P B_i P^{-1}, public seed-preserving loader actions, anchor a=P(K,0,0), statement x, checking key VK(K), and fixed auxiliary input. The adversary is arbitrary QPT, with quantum advice and arbitrary coherent terminal oracle calls, including off-anchor states, but receives **no inspectable implementation/tables or P^{-1}**. The simulator retains ideal P^{-1}; honest setup is NOT classical PPT because ideal P is exponential.

Compare real terminals A_i to null terminals I, keeping x, anchor, VK, loader actions, other public data and quantum advice identical. For any publicly checkable authorization event E (including native verification), let delta=|Pr_real[E]-Pr_null[E]|. The null event probability is not assumed negligible: it includes native-key recovery, pre-signed graph edges, auxiliary checking-key correlations, and possible independent forgery (Run 508).

## Straight-line quantum extraction theorem

Suppose the adversary makes at most q>=1 indexed terminal calls (controlled/superposition queries count). In null-oracle execution, immediately before query j let p_j be its squared query amplitude on (i,y) for which B_i(P^{-1}(y)) differs from P^{-1}(y). Then

    delta <= 2 sum_j sqrt(p_j) <= 2q sqrt((sum_j p_j)/q).

A simulator selects one uniformly random terminal call, runs a single null-oracle prefix, measures that query's (i,y), decodes z from P^{-1}(y), and checks f_x(z). Every changing point satisfies f_x(z)=1, hence

    Pr[extract a complete accepted z] >= delta^2/(4q^2).

**Proof:** Real and null terminal unitaries agree outside the changing-point projector. The norm of their difference applied to the null query state is at most 2sqrt(p_j). Telescope the q-query algorithms with null prefixes and real suffixes. Each suffix is unitary; measurement probability gap is at most final Euclidean state distance. Cauchy–Schwarz gives the inequality. Measuring one uniform null query yields a valid z with at least the indicated probability. The reduction is straight-line, handles coherent queries and fixed identical quantum advice, and uses no rewinding or QROM programming. With polynomial q and nonnegligible *extra* authorization advantage, the extractor is QPT relative to the ideal oracle/frame simulator. If f_x tests folded representations, Run 259's exact zero-residual/statistical-fold or SIS obligation still applies; a short unchecked state is NOT covered.

## Strict limitations and falsification

This upgrades Run 507's *classical observable commutator* result only in the stated **oracle** game. The actual Run 507 proposal publishes complete exponentially large tables. Publishing succinct white-box action circuits instead exposes correlations not captured by this theorem: local seam/holonomy, global gauge recovery, program fingerprints, related capsules, and coherent attacks on the code remain open. The hidden ideal P cannot be sampled/stored by classical PPT setup. A public inverse reveals K from the anchor. Multi-capsule composition, malicious setup/erasure, N-of-N ceremony, Bitcoin graph, native SLH/P2MR endpoint, full-public-output false-instance QPT hiding and arbitrary signature-to-ORIGINAL extraction all remain **UNPROVED**. Preissued native signatures can make the real/null authorization gap zero, as in Run 508.

Full arbitrary chosen-state queries are included; this is not merely the anchor-orbit search bound. A zero seed at the anchor does NOT make the terminal globally the identity on true x, because off-orbit states may carry nonzero latent k. For false x, f_x=0 and real/null terminal oracles coincide everywhere. The exact checker includes both controls.

## Reproducibility, literature and handoff

The exact run509_compact_check.js was executed in the connected JS runtime and independently in Node v22, byte-identical outputs. It checked 544 finite state-vector fixtures (dimensions 8,16,32), 4,449 assertions, 461 nonzero event gaps and no inequality violation. Independent extended Python checker (standard library) ran 9,315 assertions on 512 fixtures, with explicit original-witness query probability and reproducible output. Small quantum simulations validate only formulas, not practical security.

This is an elementary version of the quantum-query hybrid / one-way-to-hiding idea, related to Bennett–Bernstein–Brassard–Vazirani (1997, arXiv quant-ph/9701001) and Ambainis–Hamburg–Unruh (CRYPTO 2019, ePrint 2018/904); not a new general O2H theorem and not a full RIO proof audit.

Core handoff: To use this reduction in the actual bridge, construct a **classical-PPT protected public terminal** and prove that its *entire correlated white-box output* can be replaced by the oracle interface, including checking key, auxiliary inputs and malicious setup, without a WE/iO-equivalent assumption by definition. Only then can Run-259 source binding compose with arbitrary-QPT authorization security. No stop condition is satisfied. Production unchanged; PR stays draft/unmerged.
