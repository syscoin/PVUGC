# Run 696 — Black-box all-witness spectral release decoder

Constructive integration on the live Run 695 cofactor-free spectral release. Status: a classical randomized **correctness and implementation** improvement, NOT a practical PQ witness-KEM or a QPT-security proof. Starting PR head: bce27118e804c46f3897048aa14bfdf8df02192b, open/draft/unmerged, branch research/pq-wkem-validation-20260918.

## Existing construction and new algorithm

Run 593 supplies a source matrix pencil M_x(z) with rank < n for every valid complete SOURCE representation z=Encode(x,w). Run 695 publishes a masked pencil C(z)=M_x(z)+K E for z_0=1, E publicly invertible. For every valid ORIGINAL witness w, det(C(z)-K E)=det M_x(z)=0. It obtains K by factoring a dense degree-n characteristic polynomial; no last-cofactor assumption is required. Different valid witnesses retain different matrices, but they contain the SAME intended K.

This run replaces dense characteristic-polynomial construction by an explicitly executable **black-box recovery interface**. Setup/Encode and the published matrices remain the same; no new capsule, trusted signer, release oracle, or secret generator is introduced.

Recover(P_x,z): define A_z(v)=Solve(E,C(z)v), using the already-public operator. Draw fresh independent uniform u,v in F_q^n AFTER receiving z. Compute s_i=u^T A_z^i v for i=0,...,2n-1, using 2n-1 applications of A_z. Apply Berlekamp-Massey to the scalar Krylov sequence to obtain its monic minimal recurrence f(T), degree <=n. Compute g(T)=gcd(f(T),T^q-T): modular exponentiation of T^q mod f requires O(log q) polynomial modular multiplications, and g contains precisely the distinct F_q roots of f, discarding all extension-field factors and repeated factors. Split only g into its field-linear factors by a polynomial-time randomized root-finder. Filter each root through the exact canonical native signing-seed domain, the FULL public native verification key and context binding. Return exactly one matching K or retry with fresh u,v. All signing is off chain; conditional native-PQ Bitcoin validation only sees an ordinary branch signature and the already planned fixed graph conditions.

## Precise completeness theorem

Fix ANY classical setup and ANY z for which M_x(z) is singular; assume z_0=1. Then A_z=E^-1 M_x(z)+KI has eigenvalue K, including for defective Jordan blocks and any corank. Let P_K be its polynomial spectral projector onto the nonzero K-primary space over F_q, of rank r>=1. For independent uniformly sampled v, Pr[P_K v!=0]=1-q^-r. Conditional on this, independent uniform u satisfies u^T P_K v!=0 with probability 1-q^-1.

The condition u^T P_K v!=0 ensures a nonzero K-primary component in s_i. Distinct primary components cannot cancel. For K!=0 the scalar generating function has a nonzero pole at 1/K; for K=0 it has a nonzero finite-support nilpotent-primary contribution. Thus the minimal scalar recurrence f(T) contains T-K. Berlekamp-Massey recovers that recurrence from the first 2n terms. Frobenius root isolation leaves K in g(T).

One attempt includes the correct key with probability >=(1-q^-r)(1-q^-1)>=(1-1/q)^2. With t independent retries the failure is at most (2/q-1/q^2)^t. The quantifier order is FOR EVERY fixed setup and every (possibly adaptively selected) valid ORIGINAL witness, probability over fresh private Recover coins. This is NOT a claim that a public fixed projection works for all witnesses. The same K is returned under the additional explicit condition that the native checking key uniquely identifies the intended signing seed in the candidate domain. Public checking-key uniqueness, and QPT security of that key, remain separate.

## Costs and exact limitation

Each attempt takes 2n-1 operator calls, O(n^2) naive Berlekamp-Massey arithmetic, modular Frobenius/gcd, and randomized splitting of only the field-linear component. Additional working memory is O(n) field elements apart from the **preexisting public operator representation**. If applying A costs T_mv operations, the Krylov phase costs O(n*T_mv+n^2). For a future *cryptographically sound sparse operator* T_mv=O(n), the dense n-by-n matrix and characteristic polynomial are unnecessary. For a dense operator T_mv=O(n^2), this approach can instead be O(n^3) and is not necessarily faster than optimized dense algebra.

This DOES NOT compress the present dense ciphertext; the Run 593/695 illustrative n=30001, m=v=15000, 32-byte field encodings still require roughly 432 TB for coefficient matrices. It DOES NOT repair AADP's inherited security attacks or prove false-instance QPT key hiding, true-instance recovery/forgery -> accepted complete SOURCE representation, malicious N-of-N setup/abort security, multi-capsule composition, or practical Bitcoin PQ endpoint activation.

The Run 259 SIS/fingerprint extractor remains a downstream theorem ONLY for a supplied accepted complete SOURCE z. An arbitrary attacker can evaluate C(z) directly: a public SISAccept check in honest Recover cannot force them to supply z. The upstream arbitrary-capability recovery -> accepted z implication is UNPROVED. Witness privacy is optional, not a hidden assumption.

## Executed evidence and construction handoff

A standard-library Python checker preserved locally implements the actual small Run-593-style source pencil and this decoder. It passed 653 assertions, including 160 recoveries for 40 setups x four distinct valid Boolean witnesses, zero-last-cofactor source cases, nonsemisimple eigenvalues, random-projection retries, and an irreducible quadratic filtered by gcd(f,T^q-T). The exact local proof/checker/output SHA-256 values appear in the provenance. The short executable JS checker committed here tests the finite decoder independently; its public-key toy map is intentionally invertible, so no hiding claim follows.

Keep Setup/Encode/Recover v0.1 as one cumulative candidate. Next construct and independently secure a compact opaque publicly evaluable operator Apply_x(z,v), then prove BOTH full-output false-instance QPT hiding AND arbitrary true-instance unauthorized final capability/signature -> an accepted complete SOURCE z or an independent QPT-standard hardness break. Reuse Run 259 only once that arrow exists. This is a recoverability/efficiency advance, not completion.

Dependencies: Run 695 blob 50174666730b93bd20f83bb29ddb2c355ccf1a91; Run 593 blob 29b9168bfff6043810284cd1960400579f224e31; Run 259 blob c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2. Classical method: Wiedemann (IEEE TIT 1986, DOI 10.1109/TIT.1986.1057137); randomized minimal polynomial analysis DOI 10.1016/j.jsc.2015.06.005. No novelty claim for Wiedemann itself.

Stopping condition unmet; no production modifications.
