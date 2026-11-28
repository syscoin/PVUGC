# R326 — exact SHA-Ch Boolean-ideal projector (NONQUALIFYING)

## Continuity / provenance

Started at PVUGC PR #1 open/draft head `c125bb8e57743208ad855e2909c408d9c8406734` on `research/pq-wkem-validation-20260918`. Read R325 source note at Git blob `a4128ea767ad9299d0689e2296569a396d8512cf` and R324 note at blob `ddbc20c409bd01cf3166b4cfd448af73ba15e5e6`. Core #609 read-only metadata head `c91539de3c34937e57d7f5fda47c7b0502ff33f6`; no Core tests rerun or public activation assumed. PR #1 latest conversation comments were checked; there was no recent completed ORIGINAL-release construction.

This continues R325's exact unfinished issue: incorporate *actual nonlinear SHA multiplication* inside a public source-conditioned release instead of supplying attacker-controlled independent lifted monomials. The approved ORIGINAL relation remains a three-branch OR (qualified strictly greater exact BTC work; finite authenticated specific burn/authorization fault; qualified semantic Syscoin inconsistency or relevant independently outer-authenticated tag fault) with modern contextual AuxPoW and canonical tag rules, claim/UTXO/burn/amount/recipient, anchors, actual h_rel ancestry, LC depth, windows/deadline/reset, capsule, and exact safe native cancellation/VK/activation binding. This exercise instantiates NONE of those original source certificates.

## Explicit attempted construction and exact all-public security analysis

Work in the Boolean quotient `B_n=F2[z_1,...,z_n]/(z_i^2-z_i)`. Translate the source verifier into exact constraints `f_j(z)=0` including the actual SHA bit gate `Ch(x,y,z)=z+xy+xz`. Use a public coefficient basis of dimension d containing constant `1`, and fixed published masks `g_j=a_j(z)f_j(z)`, exactly representable in that basis. Let `V=span_F2{g_j}`.

For each bit i of a setup-frozen secret K, sample independent uniform mask coefficients r_ji, and publicly publish the FULL coefficients of:

`P_i(z)=K_i*1 + sum_j r_ji*g_j(z)`.

Publish `D=S XOR K`, with S the frozen synthetic cancellation bytes. This `Build` is classical polynomial-time in d and the number of mask rows. Public `Open(C,w)` evaluates each `P_i(w)` on the ORIGINAL bits (no independent monomial lifts) and outputs `D XOR (P_i(w))_i`. For every actual satisfying w, each `g_j(w)=0`, hence `P_i(w)=K_i` and ALL such witnesses recover the same S. This proves correctness for the mathematical relation represented by the constraints, not ORIGINAL authenticated history or source release.

**FALSE simulator, restricted to `1 in V`:** uniform masks make the public coefficient vector P uniform in V independently of the secret K, because `V+1=V`. Therefore D is an independent uniform one-time pad even given the complete coefficient vectors, any independently fixed S, native VK and auxiliary data independent of the fresh masks. A simulator samples P uniformly in V and D uniformly. Classical full-public distributions are exactly identical; arbitrary coherent/joint QPT postprocessing cannot distinguish them without an additional correlation or exposure of the setup secrets. Reused coins and correlated sibling capsules are outside this law. This does not rely on QROM programming.

**Fatal hard-TRUE extraction:** If `1 not in V`, public Gaussian elimination finds a linear functional `ell` in the dual coefficient space satisfying `ell(1)=1` and `ell(g_j)=0` for every public mask. Thus `ell(P_i)=K_i` and any public attacker obtains `S=D XOR (ell(P_i))_i` WITHOUT any witness, query log, source representation or native forgery. On EVERY TRUE statement, `1 not in V`, since evaluating a hypothetical equality `1=sum_j alpha_j*g_j` at any satisfying witness would yield `1=0`. If `1 not in V` for a FALSE statement, public leakage also breaks FALSE security. All algorithms are polynomial in the published basis dimension d, which can itself be exponential in source-circuit size if one uses the unrestricted `2^n` Boolean quotient. This is a restricted coefficient-linear obstruction, not a universal no-go theorem for computational hash-only WE.

This fixes R325's invalid-monomial *honest-evaluation semantics* by retaining exact nonlinear SHA functions, but does not fix public release security. Hashing the extracted K is insufficient: `D=S XOR SHA256(domain||K)` leaks once `K_i=ell(P_i)` is read. Hiding the coefficients behind a bare digest removes the specified public evaluator; publishing a plaintext evaluation circuit with coefficients exposes them again. An independently instantiated nonlinear, nonspliceable, source-dependent public encoding is still missing. Do not posit an ideal evaluator, iO, WPRF, or WE as the repair.

## Executed local checker / limitations

A Python3 standard-library checker evaluated **exact** `Ch` truth functionality in four Boolean variables (x,y,z,c), constraints x=y=z=0, `Ch(x,y,z)=c`, with c=0 (one TRUE witness) and c=1 (FALSE). The full 16-dimensional quotient with 80 multiplier rows had rank 15 for TRUE and 16 for FALSE. Public elimination extracted a secret on TRUE; exact mask-tape coupling preserved the public coefficients while toggling K on FALSE. A 256-bit SHA256 postprocessing repair was explicitly tested and still leaked S. Two deterministic runs produced byte-identical JSON outputs, 4,410 assertions each.

Local-only checker SHA256 `d521c07bf9f21893979d8e4942262473d3c20b6ada5ea44b95d245e7b7ba991f`; each JSON SHA256 `d9baf4a61ae5be3b5725bdb8c91cff0762e4413bec3bcaaa62dd9195ee51d0f5`. Derivation, executable code and two outputs are preserved in local reproducibility archive `R326_global_sha_ideal_20261116.tar.gz`, SHA256 `8c94124938abfaec42c51bdb2e53da7c25805269ad4ed5dfa1e33763d66064c0`. Checker outputs are **not** GitHub-published by this note. This did not execute actual SHA256d/AuxPoW admission, original relevant source history, native PQ signatures, QPT experiments, or malicious setup.

## Next mathematical equation

Still require an actual classical-PPT source-specific `Encode_x(K,rho)->E` and PUBLIC `Eval(E,w)=K` for **every** qualifying ORIGINAL certificate, with nonextractability of K (and no native forgery) from complete public E on FALSE and hard-TRUE absent an ORIGINAL witness or independent PQ hash/native break; context/capsule-specific and sibling/selective-opening security must hold with malicious N-of-N setup and source miner retained coins. This is the missing instantiation, not a valid security assumption. No arbitrary-NP theorem required.

**NONQUALIFYING:** closes only the transparent linear-coefficient ideal-masking candidate; no ORIGINAL WKEM or positive source-release foundation, no progress comment, no production/Core change, no automation change.
