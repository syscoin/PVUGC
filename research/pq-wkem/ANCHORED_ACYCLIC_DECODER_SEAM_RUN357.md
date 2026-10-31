# Run 357 — Exact decoder-boundary leakage on an acyclic local-mixing path

Live connected-GitHub source: syscoin/PVUGC#1, draft/open/unmerged, research/pq-wkem-validation-20260918, initial SHA 719417e64894c6cf3159ca642754ccee3e789486. Exact source-binding dependency: Run 259 blob c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2; Run 115 blob cf2ec9575948e16b58acbd870208686759f14e44. This is a bounded information-theoretic falsification of an independently framed reversible **open path**, not a general attack on RIO or complete PQ WKEM.

## Exact theorem

Let Omega be finite, G=Sym(Omega), and g_1,...,g_l reversible semantic permutations along one directed path. Each public edge is F_i=pi_i o g_i o pi_(i-1)^(-1). The input frame is publicly fixed pi_0=id; the l-1 interior frames are uniform independent elements of G. For a public output decoder D:Omega->L, sample pi_l uniformly in H={h in G:D o h=D}. Let g=g_l o ... o g_1.

Then F=(F_1,...,F_l) is exactly uniform on the set of tuples whose product P=F_l o ... o F_1 belongs to the coset H g. This set has |H| |G|^(l-1) elements. Given the public tuple, the internal frames are uniquely recoverable for each allowed pi_l; conversely pi_l=P o g^(-1) must belong to H. This proves the uniform support law.

For any two semantic composites g0,g1, their public full-tuple distributions are either **identical** or have **disjoint supports**, with

TV(F|g0,F|g1)=0 iff D o g0=D o g1, and TV=1 otherwise.

Proof: left cosets H g0 and H g1 are identical iff g1 o g0^(-1) lies in H, equivalent to D o g1=D o g0. Otherwise the cosets are disjoint. For every input a, the public gates also satisfy D(P(a))=D(g(a)). If a public computable a has D(g(a)) equal to the protected capability bit, that bit is recovered from one **public off-chain evaluation** without a source witness. Such a useful public input is an additional premise and is NOT guaranteed for a real ORIGINAL-source relation.

For path length >=2, every individual public F_i is exactly uniform over G, even though this complete decoded semantic input/output function is public. No cycles, comparable parallel paths, affine masks, or parity distinguishers are needed.

## Exact counterexample and controls

Take Omega={0,1,2,3}, D=(0,0,1,1), so H=S2 x S2 has order 4 and |G|=24. For a two-edge open path, compare g0=id and g1=(0 2)(1 3), both even. Each individual public edge is perfectly uniform over all 24 permutations. The full public pair lies uniformly in one of 96 possibilities. Yet D(F2(F1(0))) is always 0 for g0 and 1 for g1, so total variation is exactly 1 and the hidden semantic bit is determined. Conversely g2=(0 1) has opposite parity to g0 but the same decoded semantic function; the entire public law is identical (TV 0). An exhaustive checker verified all 24 semantic permutations and 576 ordered pairs: 96 TV-zero pairs, 480 TV-one pairs, plus 3-edge replications.

If the output frame is fully unrestricted uniform G, the full edge tuple is uniformly distributed over G^l; however no nonconstant D can satisfy D o h=D for all h in transitive G. If instead the input frame is uniformly hidden and not exposed, the full edge tuple is also uniformly independent of g, but the model then lacks a public encoding of externally supplied semantic witness states. If both boundary frames are fixed, the semantic composite g is publicly recoverable. These are precise boundary tradeoffs, not general no-go theorems for cryptographic source-dependent embeddings.

## Source and security ledger

Run 259 proves accepted-global-representation -> ORIGINAL witness (information-theoretic global folding or straight-line reduction to the stated QPT-SIS assumption). It does NOT show key recovery/accepted branch signature -> such a representation. The above public decoded-path evaluation does not even present a representation to Run 259. A separate public residual check cannot automatically enforce acceptance before an independently readable capability path.

Attack taxonomy: output seam and global frame cancellation established; full-program semantic fingerprint despite uniform local gates; adaptive/chosen-input evaluation established conditional on a useful input; no multi-capsule replay theorem; malicious setup is unnecessary; native checking key is unused; information-theoretic classical distinguisher also applies against arbitrary QPT attackers. No genuinely coherent quantum algorithm, QROM reduction, full-public-output QPT hiding theorem, or malicious-setup proof is claimed. Honest finite-model sampling/evaluation is classical PPT; no practical representation of a large Sym(Omega) is claimed.

## Literature and remaining obligations

Canetti–Chamon–Mucciolo–Ruckenstein, TCC 2024/ePrint 2024/006, analyzes a much more elaborate functionality-preserving local-mixing/RIO approach under additional assumptions; this simple independent-frame example does not refute it. Gheorghiu–Gupte–Havlíček–Liu, arXiv:2609.40289 (30 September 2026), mentions a quantum extension in its abstract; its full proof was not inspected, and it does not establish the required classical-PPT and arbitrary-QPT source-conditioned release. No circular new assumption is introduced.

Exact deterministic checker: anchored_open_chain_run357_check.py; py_compile and two byte-identical runs passed, with 22926 assertions. These checks validate finite permutation/group arithmetic, not PQ security. A viable compiler must cryptographically protect or source-enforce its boundary while preserving every ORIGINAL witness -> the same K_x, full false-instance QPT hiding, and arbitrary-QPT premature recovery/forgery -> ORIGINAL witness or independently justified break. N-of-N abort/erasure, multiple capsules, native conditional P2MR/SLH signing, and practical 128-bit parameters remain unproved. Practical witness-KEM is UNSOLVED; production unchanged.
