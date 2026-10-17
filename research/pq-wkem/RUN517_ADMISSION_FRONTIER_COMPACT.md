# Run 517 — Public admission-bit frontier: off-orbit boundary and same-sector bypass

Research-only checkpoint. Exact live start 0b57cdef659cfeaefc619f9f38e883e36838214e on draft PR #1, branch research/pq-wkem-validation-20260918. This is a scoped attack against shrinking Run 516's ORIGINAL-guarded terminal to a merely public acceptance bit, NOT an attack on Run 516's ORIGINAL-guarded construction and NOT a practical PQ witness-KEM.

## Exact ideal model

Semantic state (k,d,z,b,t) contains an h-bit native signing seed, immutable complete-context claim sector d, source candidate z, admission bit b, and terminal marker t. A uniform hidden ideal permutation P encodes the state. Target anchor a_x=P(K_x,x,0^n,0,0). Public witness loaders preserve d,k,b. Proposed small terminal:

B^b_{x,i}(k,d,z,b,t)=(k,d,z,b,t XOR ([d=x] AND k_i AND b)).

Publish A_i=P B^b_{x,i} P^-1. A genuinely verified source update could set b with E_x(k,d,z,b,t)=(k,d,z,b XOR ([d=x] AND f_x(z)),t), where f_x checks the ORIGINAL relation or COMPLETE Run-259-accepted representation. For valid z, loaders then E_x then the h fixed-point terminal tests recover the SAME K_x. But E_x itself still embodies the source computation; no compact implementation has been constructed.

## New off-orbit support theorem

For an ORIGINAL-false target, f_x(z)=0 for every z. Nevertheless B^b_{x,i} is nonidentity at semantic states with d=x, b=1, k_i=1. For uniformly sampled public encoded input y,

Pr[A_i(y) != y] = 1/(4|C|),

for EVERY hidden P. A one-query classical distinguisher separates the real terminal from identity, even for a false source relation. This does NOT alone reveal K_x or produce a native signature. It DOES invalidate direct transfer of Run 509's quantum oracle hybrid: a query at which the real and null oracles differ reveals only b=1, NOT an ORIGINAL witness or complete accepted representation. The source-extraction obligation is support of the real-minus-null terminal contained in globally accepted complete source states, not merely an honest-orbit promise.

## New same-sector key-recovery falsifier

If a public instruction F_x:(k,d,z,b,t)->(k,d,z,b XOR [d=x],t) is exposed, or can be synthesized from other public operations, compute y=P F_x P^-1(a_x)=P(K_x,x,0^n,1,0). Then K_{x,i} = 1[A_i(y) != y] for each bit. This recovers the ENTIRE native signing seed in h+1 action calls even when NO ORIGINAL witness exists. No cross-claim sector switch, permutation inversion, lattice attack, quantum attack, or malicious setup is necessary. A public encoder that accepts an unauthenticated externally supplied b=1 has the equivalent flaw. The branch-bound native signature can then be created by the recovered seed, assuming the conditional endpoint actually exists.

The theorem applies ONLY when this public admission edit is available. It does not assert that all honest, source-gated encoders admit such an edit.

## Restricted positive ideal-view theorem

Do not confuse global terminal distinguishability with seed distinguishability. If false target x has E_x=identity, all publicly available loaders preserve b, all reference actions are confined to disjoint claim sectors, and NO action connects target b=0 to b=1, then for any target seeds K0,K1 define Delta=K0 XOR K1. The permutation T_Delta XORs Delta into k ONLY in sector d=x,b=0. T commutes with all allowed actions, including the target terminal (which acts only in b=1), leaving complete mixed-action tables identical under P and P composed with T. It exchanges target anchors for K0 and K1 and leaves all reference anchors unchanged. Uniform P gives EXACT same ideal public-view law conditional on either seed, even with arbitrarily many independent reference capsules. Equality survives quantum coherent postprocessing of those ideal actions. Editor F_x does NOT commute with T and destroys the coupling. External native VK and correlated auxiliaries must be modeled separately: no claim is made that VK(K0) and VK(K1) are indistinguishable as public keys.

## Minimal frontier and QPT ledger

TWO separate requirements emerge. (1) Reachability-source binding: every accepting frontier state reachable from the real anchor through public instructions must supply COMPLETE ORIGINAL-source evidence or an independently justified break. F_x fails this. (2) Full-oracle source support: to use Run 509's arbitrary coherent-query extraction, every input in the real-vs-null oracle difference support must source-bind to ORIGINAL, not merely have b=1. The bare-bit terminal fails this even when F_x is withheld.

A small protected checker of a succinct source certificate could be explored, but its arbitrary-QPT extraction to COMPLETE Run-259 evidence, setup/CRS security, native checking-key correlations, and full white-box composition must be proved. Merely trusting a public Boolean verifier output is insufficient. This note introduces NO WE/iO/RIO-equivalent assumption or claimed PQ SNARG.

Attack taxonomy: (1) same-sector admission seam; (2) b=0-local gauge coupling only without cross-admission; (3) false-instance off-orbit action fingerprint 1/(4|C|); (4) independent reference views only in restricted coupling; (5) adaptive chosen-input edit yields key; (6) malicious setup/retained frame unproved; (7) claim/UTXO binding still mandatory but not sufficient; (8) public native VK correlations separate; (9) classical attacks carry to QPT; no new coherent quantum break or practical QPT proof.

Honest algorithms are classical, but uniform P is exponential-size, so classical-PPT setup is NOT established. Adversary has arbitrary public action evaluation, including coherent access to the same actions where stated, no secret P. No rewinding, QROM, or new algebraic hardness is invoked. Restricted positive theorem permits P-independent auxiliaries shared identically across games, not P-dependent auxiliary leakage. Native-signature extraction remains unproved outside explicit edit attack.

## Reproducibility, literature, handoff

EXACT committed JavaScript checker runs over all 40,320 permutations of eight states and deterministic sampled 16-state two-claim and true-source fixtures, checking key recovery, noncommutation, exact nonfixing counts, honest SAME-capability recovery, and restricted coupling. An independent extended local Python checker exhausts S8 and uses seeded S16/S32 fixtures; its two captures matched byte for byte. These checks verify finite algebra, not PQ security.

No new RIO/Canetti-Luo-Zhang paper proof was audited; random reversible-circuit results do not authenticate a public admission bit. Run 259 only binds a genuinely COMPLETE accepted representation. Conditional Bitcoin endpoint remains P2MR-like no-EC-key-path plus native SLH-DSA-like signature verification; no on-chain NP proof, CAT, or proven payout graph assumed. Full-public-output QPT hiding, arbitrary authorization-to-ORIGINAL extraction, compact protected source admission, malicious N-of-N setup/erasure, multi-capsule security, and practical 128-bit resources remain UNPROVED. Production unchanged; PR draft/unmerged; stop condition unmet.
