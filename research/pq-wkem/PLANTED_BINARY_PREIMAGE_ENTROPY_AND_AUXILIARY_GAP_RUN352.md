# Run 352 — Planted binary-preimage density and auxiliary-input boundary

Live PR start: syscoin/PVUGC#1, draft/open/unmerged, branch research/pq-wkem-validation-20260918, SHA a4e17a16e9c34f0754dca8e5af4d5b93bb272cb8. Exact current-head dependencies: Run 259 blob c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2 and Run 115 blob cf2ec9575948e16b58acbd870208686759f14e44. Run 350/351 claims were provided in the task conversation, not claimed published on branch.

## Theorem 1 — planted binary target has many ambient preimages
Let q be an odd prime, A uniform in F_q^{n x m}, u0 uniform in {0,1}^m independent of A, t=A u0, and X=#{v in {0,1}^m: A v=t}. For each fixed u0, X=1+sum_{v != u0} [A(v-u0)=0]. Every nonzero difference is uniform under A. Two distinct planted differences are linearly independent: at each coordinate their possible nonzero sign is fixed by the planted bit. Therefore the indicators are pairwise independent:

E[X]=1+(2^m-1)/q^n,
Var[X]=(2^m-1) q^{-n}(1-q^{-n}).

Writing mu=(2^m-1)/q^n, Chebyshev gives Pr[X < 1+mu/2] <= 4/mu.

For the leftover-hash benchmark,
TV((A,Au0),(A,U_{F_q^n})) <= (1/2)sqrt(q^n/2^m).
The sufficient requirement that this upper bound be <=2^{-kappa} forces 2^m/q^n >=2^{2 kappa-2}. At kappa=128, the expected binary-preimage multiplicity is about 2^254; this is a capacity fact, NOT an efficient search attack or concrete LWE parameter claim.

## Theorem 2 — all short ambient preimages decrypt, regardless of source
In the Run-115 HPS wrapper, publish h=A^T s+e and d=c_K-s^Tt modulo q. Every binary v satisfying Av=t computes h^T v+d = c_K+e^T v. When ||e||_infty m < (q-1)/4, ALL binary preimages decode K. For a false ORIGINAL statement none is an ORIGINAL witness, yet they still decrypt. Run 259's SIS hash verifies the source residual of an ACCEPTED representation z; it cannot be automatically appended after HPS decryption to turn every ambient v into an accepted z. The missing recovery-to-accepted-representation arrow remains a separate cryptographic obligation.

## Theorem 3 — disclosing setup preimage destroys target independence
The exact statistical distance is
TV((A,u0,Au0),(A,u0,U_{F_q^n})) = 1-q^{-n}.
Condition on any (A,u0): a point mass and a uniform target have TV 1-1/q^n. More strongly, a builder retaining u0 computes h^T u0+d and recovers K with ordinary correctness. Thus this benchmark fails the optional *keyless builder retaining all coins* game unconditionally. It does not automatically break the separate one-honest-party N-of-N erasure model, which requires an actual secrecy/abort ceremony proof.

If l designated coordinates of u0 are revealed, the remaining uniform source has entropy m-l, giving the conditional sufficient LHL bound
TV <= (1/2)sqrt(q^n/2^{m-l}).
This bound applies to fixed coordinate leakage, not arbitrary correlated leakage or adversarial positions selected after seeing A. Maliciously setting A after learning u0 to make Au0=0 produces t=0 and d=c_K, an immediate public release.

## Attack taxonomy and exact scope
Local seam: public HPS readout bypasses source check. Gauge: disclosed u0 ties t exactly to A. Fingerprint: binary norm is source-blind. Multi-view: reused planted coins create related-capsule exposure. Adaptive evaluation: input u0 itself decrypts. Malicious setup: retained coins/biased A. Replay: claim hashes do not change algebra unless cryptographically enforced before release. Native PK(K): offers no defense against direct u0 recovery. Quantum: all listed negative results are unconditional, hence QPT; efficient public-only binary-preimage search is NOT proved.

Honest algorithms analyzed are classical PPT. Arbitrary-QPT attackers may run coherent public evaluation, receive public checking keys and related capsules. No new WE/RIO/iO/WPRF assumption, oracle programming or quantum rewinding is invoked. The previous fixed-target QPT-LWE argument is not disputed for its exact independent/public-only distribution; it cannot be promoted to auxiliaries revealing planted u0.

## Remaining obligations
Construct a genuinely compact source-bound certificate release gate that enforces the ORIGINAL relation BEFORE all key-bearing short preimages become usable. Every valid ORIGINAL witness must recover the same branch K, while false-instance public view hides it and unauthorized recovery/accepted forgery reduces to ORIGINAL extraction or an independently justified arbitrary-QPT break. Run 259 supplies only the downstream acceptance-to-source arrow. Real N-of-N setup, abort safety, multiple capsules, native PQ endpoint and practical 128-bit parameters remain unproved.

Checker: planted_binary_preimage_run352_check.py (deterministic standard Python). It exhaustively enumerates exact small-field moments and LHL distances, pairwise planted-difference independence, and HPS recovery for public binary preimages. py_compile passed; two executions were byte-identical; 531394 assertions. This does not certify LWE/SIS hardness.
