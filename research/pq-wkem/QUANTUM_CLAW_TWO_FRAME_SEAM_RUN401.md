# Run 401: coherent quantum claw attack on a two-frame release seam

**Scope:** a conditional, deliberately INSECURE local-release interface. This is **not** a practical WKEM, a RIO break, an impossibility theorem for local mixing generally, or a new quantum collision algorithm. Prior technique: Brassard–Høyer–Tapp (1997/1998). Live starting PR branch `research/pq-wkem-validation-20260918` at `63731c18c137077ced1f2fe9549e85c7c51835ec`, draft/unmerged. Run 400 source `54ddfa5df2c4225e59c535741774cd83194465b4`; Run 259 binding source `c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2`.

## Tested minimal seam

Take independent public quantum-accessible ideal random functions F,G from {0,1}^b to {0,1}^b, N=2^b. A classical honest setup can be polynomial time **relative to these QROM oracles**, but there is **NO classical practical white-box implementation**. Suppose an ideal callable release oracle returns a protected native signing capability K whenever either an ORIGINAL source representation z is valid OR an exposed neighboring-frame compatibility check `F(a)=G(y)` passes. The legitimate source path may preserve distinct states for all valid ORIGINAL witnesses and release the SAME K. The *extra* equality path is the defect. On false statements, no ORIGINAL witnesses exist yet a claw can still release K. This model does not assume security of its defective gate.

## Explicit coherent QPT attack and proof

Query F classically on t distinct inputs and store the distinct output labels S with their input indices. Conditional on D=|S| and an independent random G, among its N possible inputs y the number of markers `G(y) in S` is `M ~ Binomial(N,D/N)`. A quantum algorithm reversibly evaluates G, checks S, flips the marked phase, uncomputes G, and applies ordinary Grover diffusion. With r rounds, exact success probability is

`sin^2((2r+1)*arcsin(sqrt(M/N)))`.

For `t=ceil(N^(1/3))`, F-label collisions cost at most `t(t-1)/(2N)=O(N^(-1/3))` in the random-oracle experiment, so normally D=t. Chernoff concentration gives `M=Theta(t)` except with probability `exp(-Omega(t))`. Grover needs `O(sqrt(N/t))` coherent G queries for a marked y. Retrieve the matching a from the classical table, then call the release program **once classically**. Total query cost

`t+O(sqrt(N/t))=O(N^(1/3))=O(2^(b/3))`

with `O(t*b)` classical table bits (reversible lookup/gate overhead NOT included). Unknown M can be handled by randomized Grover schedules. Any valid claw obtains K and allows the intended native signature without yielding a Run-259 accepted COMPLETE representation or ORIGINAL witness. Classical generic random-claw search takes `Theta(2^(b/2))` birthday queries. This is a genuinely coherent superposition attack on G, not only a classical analysis with an asserted speedup.

**Concrete raw-oracle warning:** b=256 gives birthday exponent 128 but coherent claw exponent **85.33**, while b=384 yields 128 coherent-query exponent with **2^128 classical table entries**. This is a necessary warning *if this exact equality seam releases K*, NOT a practical 128-bit security recommendation; true gate, memory and quantum hardware costs are unmodeled. For b=Theta(lambda), the attack remains exponential in lambda and therefore does not by itself refute asymptotic QPT security for a correctly source-bound primitive.

## Multi-capsule coupling

If L capsules reuse the same public left function F and have independent right functions G_i, a left table of size t can be reused. Model cost is `Q_L(t)=t+O(L*sqrt(N/t))`, optimized at `t=Theta((L^2 N)^(1/3))`, yielding `O(L^(2/3)N^(1/3))` total queries, versus `O(L N^(1/3))` with independent left preparations. Per-context independent F removes only the amortization; it does NOT repair the single-capsule extra equality release path.

## Exact security/attack accounting

Honest model: classical PPT *with public QROM oracles* and a granted ideal protected release, NOT a practical construction. Adversary: arbitrary QPT, with coherent public-oracle access and arbitrary auxiliary input (none needed for this attack), and one classical final release call. Source relation and all native checking keys/branches can be public and context bound; actual native verification key can confirm the obtained key. One honest setup participant or retained coins cannot save an already available equality bypass. For this seam, false-instance QPT hiding and true-instance authorization-to-ORIGINAL extraction both FAIL; source binding Run 259 applies only after a COMPLETE accepted z. A properly source-authenticated mixer which rejects unmatched COMPLETE representations is OUTSIDE this falsifier.

Attack taxonomy: (1) local frame equality seam, (2) public gauge relabeling does not repair equality, (3) individually uniform labels but joint equality, (4) shared-frame multiple-capsule amortization, (5) public chosen/coherent evaluation, (6) honest-random setup already fails, (7) context-bound keys do not repair local bypass, (8) vk does not protect against released K, (9) explicit coherent statevector-tested quantum attack.

## Validation and limits

Exact attached standard-JS checker was evaluated and its complete deterministic output captured. **235 PASS checks**, 36 independent small-statevector fixtures (widths 6,9,12); directly evolves amplitude vectors with phase flips and diffusion, tests norm and exact Grover formula, verifies claw matching and ideal release, checks b/2 and b/3 query exponents, and a 16-capsule shared-table cost model. This is finite quantum-state simulation, NOT a real large-scale quantum attack, concrete 128-bit instantiation, or proof of native SLH/CAT/P2MR deployment.

Core handoff: do NOT allow local frame compatibility alone to be an alternative to an authenticated COMPLETE ORIGINAL representation. Find a real, minimal non-bypassable source-bound release mixer and independently prove full-public false-instance QPT hiding, arbitrary-QPT authorization-to-Run259 representation extraction (or stated break), N-of-N malicious setup/abort/erasure and presigned graph, all-witness SAME-K correctness, cross-claim/capsule security, concrete resources and hypothetical native Bitcoin PQ endpoints. **All remain UNPROVED.** Production unchanged; PR draft/unmerged; stopping condition unmet.

Primary literature: Brassard–Høyer–Tapp, *Quantum Algorithm for the Collision Problem*, arXiv:quant-ph/9705002; *Quantum cryptanalysis of hash and claw-free functions*, LATIN'98, https://doi.org/10.1007/BFb0054319. This note derives its specific random-function bound explicitly, but does NOT claim an exhaustive new proof/errata audit.
