# Run 525 — one opened reference plus public checking key enables quantum recovery

Research-only 2026-10-15, syscoin/PVUGC#1 draft. Exact verified starting head: 5f8fb423cc2d3735f12a8fe44d99f48da08f386d. **Scoped quantum attack, NOT a WKEM construction or general Feistel break.**

## Construction and attack

Let n-bit halves (L,R) be mixed by a shared three-round Feistel frame with independent classical honest-erased a,b,c in F_2^n:

T = L XOR f(R XOR a); U = R XOR g(T XOR b); V = T XOR h(U XOR c).

The public first round f may be ANY efficiently evaluable function, including a nonbijective one. The middle and final rounds g,h must be public efficiently invertible permutations. Public target anchor A_x=(U_x,V_x) encodes (K_x,R_x), where R_x binds the claim, branch and context and K_x determines the intended native signing credential. Public VK_x supplies a polynomial-time test of candidate K_x, e.g. deterministic KeyGen-to-VK equality or checking a valid signature on the bound branch message using fixed valid signing coins.

**Only ONE legitimately opened reference** with complete known (L_1,R_1)->(U_1,V_1) under the same shared frame is needed. For guessed a', calculate:

T_1'=L_1 XOR f(R_1 XOR a')
b'=T_1' XOR g^-1(U_1 XOR R_1)
c'=U_1 XOR h^-1(V_1 XOR T_1').

Invert A_x under (a',b',c') to obtain (K_x',R_x'). Define Q(a')=1 precisely when R_x'=R_x and the public target native-authorization check accepts K_x'. The actual a yields the true b,c, K_x,R_x, hence Q(a)=1. Any marked a' generates a usable target branch credential; recovering actual a,b,c is unnecessary. This works even when the target ORIGINAL relation is false and the reference release was legitimate. One honest erasing setup party does not avert it.

Q is a public deterministic polynomial-time circuit, therefore reversibly and coherently evaluable by a QPT adversary (uncompute work registers). With M>=1 marked candidates, unknown-solution-count BBHT amplitude amplification finds a marked candidate using O(sqrt(2^n/M)) predicate invocations; worst-case O(2^(n/2)). A 128-bit half thus admits about 2^64 *quantum predicate calls*. A half of at least 256 bits is necessary against this attack's exponent alone, NOT sufficient for 128-bit security. Public signing/verification gate cost is an additional polynomial overhead. This is a generic quantum upper bound, not a claim about practical hardware costs.

## Exact limitations and earlier findings

Requires (a) a fully known semantic input/output pair from an opened reference using the same three-round frame, (b) public efficiently reversible g,h, (c) target public anchor and bound public credential checker, and (d) coherent quantum evaluation of these PUBLIC circuits. If opened references hide semantic coordinates, frames are independent, or round structure differs, the proof does not automatically apply. No assumed online oracle, source witness for the false target, claimed general PQ security, or source-side extraction is involved.

Run 524's TWO-reference inverse-first-round algebraic attack was classical polynomial time and remains stronger for that restricted family. Run 525 removes the inverse/low-differential-degree requirement and one of the two reference openings, at the cost of a quantum generic search and target public key testing. Run 519 atomic commutator and Run 259 supplied-complete-representation binding do not prevent direct false-target signing recovery in this conditional frame.

Attack taxonomy: local seams NOT used; shared-frame reconstruction from one legitimate full-state reference; no distributional fingerprint required; static two-capsule view; only public adaptive/coherent evaluation; honest erasure still insufficient for this design; claim/branch binding remains checked; public VK correlation is used by the attack; genuinely coherent quantum search. True-instance arbitrary signature-to-ORIGINAL, full-output false-instance QPT hiding for a surviving implementation, malicious N-of-N setup/abort, multi-capsule composition, concrete 128-bit realization and conditional Bitcoin P2MR/native SLH graph remain UNPROVED.

## Reproducibility and literature

The executed JS checker verifies 96 independent finite instances (including nonbijective first rounds), 8,256 candidate predicate evaluations, and 96 amplitude-vector-versus-closed-form checks; it was rerun byte-identically. Independent local Python checker verified 96 trials, 8,256 candidates and 97 amplitude checks including a 16-candidate equivalent-master control. Toy SHA-256 native-key surrogate is NOT SLH-DSA. Neither checker ran on quantum hardware. Search result uses BBHT: Boyer, Brassard, Hoyer, Tapp, Tight Bounds on Quantum Searching, Fortschritte der Physik 46 (1998), arXiv:quant-ph/9605034. No new complete RIO proof audit. Production unchanged; PR draft/unmerged; stopping condition unmet.
