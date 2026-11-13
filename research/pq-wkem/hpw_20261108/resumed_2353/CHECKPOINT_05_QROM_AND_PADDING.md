# HPW-20261108: Exact hash-only exponential reference, quantum-query extraction, and the per-witness pad boundary

**Status: an actual conditional foundational proof opportunity, not a secure practical generic witness-KEM.** The first construction implements R_ORIGINAL-dependent public release for arbitrary fixed NP relation by exhausting all witnesses. The second result proves an elementary but exact impossibility for making THIS per-witness random-pad lookup classical-PPT without changing its correlation mechanism. Neither theorem rules out hash-based WE or general PoW constructions. No lattice, group or performance optimization.

## Exact full-public reference distribution

Fix security parameter kappa, a classical-PPT ORIGINAL verifier R(x,w), and a fixed l-bit witness encoding with set S_x={w:R(x,w)=1}. Hash domains T,F,C,P are independent quantum-accessible random functions with injective length-delimited encodings and context including relation, claim/UTXO, branch, anchor/window, intended native VK/message, and capsule ID. F/C are kappa-bit, P has native-signature length, and the T tag length can be 2l+kappa to make all S_x tag collisions negligible (or Open tests all collisions using C).

Build, using honest N-of-N preauthorization and later mandatory erasure as a separate assumption, samples K<-U({0,1}^kappa), freezes an intended ordinary native sigma=Sign(sk_native,M) and publishes x, context, VK, M, and the records for ALL w in S_x:

    (T(ctx,w), E_w = K xor F(ctx,w)).

It also publishes CK=C(ctx,K), Dsig=sigma xor P(ctx,K), and any public acyclic checking manifest/hash/Aux that is computable from these actual bytes. Sibling capsules have independent K and distinct M; revealing one for the SAME M must count as already authorized release, not a fresh target forgery. Build does not publish w, but tags and records are all public. It samples x/statement without any satisfying witness, yet checks R(x,w) while exhaustively enumerating w. Hence it has O(2^l poly(lambda,|x|)) runtime and output. It is **not** classical PPT for generic NP, which is an explicit unclosed requirement.

Public Open(x,capsule,w) uses the actual ORIGINAL w to compute tag T, tries matching E_w, obtains K=E_w xor F(ctx,w), checks CK, unmasks sigma, verifies the frozen native message under VK. Every ORIGINAL valid w returns the same precommitted signature. No SourceOpen oracle, canonical witness, additional native Bitcoin NP verifier or new opcode.

## Quantum-query extraction, conditional on this inefficient Build and an ideal QROM

This is a formal argument under an independent random-oracle model, not a claim for real SHA256 or a generic QPT reduction with PPT setup.

Couple two experiments conditional on x, native VK/M and independent native signing coins. Sample K uniformly. For all w in S_x choose T_w using actual independent T oracle; choose E_w independently uniformly; choose CK and Dsig independently uniformly. This is the exact public marginal of the REAL distribution because F(w) is uniform independent per distinct accepted w, C(K) is independent uniform, and P(K) is independent uniform; XOR by K or sigma preserves uniformity. In REAL, program F(ctx,w)=E_w xor K for all w in S_x, C(ctx,K)=CK, and P(ctx,K)=Dsig xor sigma. Every programmed value is independently uniform (conditionally on K,sigma), so the resulting marginal oracle is a genuine random oracle with exactly the desired public correlations.

In REF, leave F,C,P unprogrammed at those hidden points, with identical public records. REF K is perfectly independent of the adversary's entire public/oracle transcript, so for any QPT adversary A, Pr[A outputs K in REF]=2^(-kappa). (A may have quantum advice independent of the fresh K, random oracles, and honest signing secrets; advice correlated with them is outside this bound.) The T oracle does not differ between the games; public tags may be queried coherently. No selective opening of the target K or its pads is permitted; reveal of genuine ORIGINAL w is qualified release, not unauthorized recovery.

For a fixed adversary making Q total coherent oracle calls to F/C/P/T, let |psi_j> be its state just before query j in REF, and define p_j^S as the probability that the query address belongs to the F-domain on an accepting ORIGINAL w in S_x. Domain separation ensures the real/ref differences occur only on these addresses and two single secret-key domains (C,K),(P,K). For a uniform fresh K independent of the REF query state, each of the latter addresses contributes expectation at most 2^(-kappa). The standard unitary telescoping inequality (direct proof: |(U_real-U_ref)psi|<=2||Pi_diff psi||, triangle inequality, Cauchy-Schwarz) yields for the difference epsilon in any fixed final output event:

    epsilon <= 2 sqrt(Q * sum_j E[p_j^S]) + 2 Q sqrt(2 / 2^kappa).

If the event is exact native-capability key recovery, REF event probability is 2^(-kappa). Rearranging, a randomly selected pre-query measurement of the F-domain input in the reference execution outputs an ACTUAL ORIGINAL witness with probability at least

    [ max(0, epsilon - 2Q sqrt(2 / 2^kappa)) ]^2 / (4 Q^2).

The extractor verifies R(x,w) itself, off chain; it never asks the adversary to volunteer a representation or its query log, and quantum superposition queries are explicitly included. The exact sampled REAL/REF oracle coupling is the justification for applying the hybrid—not an assumed classical rewinding argument. If x is FALSE then S_x is empty and this gives a conservative QROM key-recovery bound 2^-kappa + 2Q sqrt(2/2^kappa). A tight Grover-style square bound is not claimed.

For a fresh native signature rather than K, in REF Dsig is an independent uniform string. A native QPT-EUF-CMA challenger supplies VK and may sign only *distinct* off-target M. Any accepted target signature output by A in REF is a native forgery. The same real/ref distance bounds the change in the accepted-forgery event. This is conditional on appropriately domain-separated hash uses and independent publicly simulatable J/CK/Aux/related capsule fields. Arbitrary malicious-correlated setup, direct signing-key retention, and source-selected K are not proved. No generic polynomial-time extractor is established because the REF simulator itself must enumerate all accepted witnesses to form the public records.

### Exact mathematical limitation of the pad-lookup normal form

Restrict the construction class explicitly as follows. Each accepting witness w needs a public lookup value E_w=K xor F(ctx,w), determined by Build's public transcript independently of any future oracle evaluation at F(ctx,w). Setup is classical and makes q distinct queries to F. Assume independent uniform F outputs per new witness. For an unqueried valid w, conditional on the entire setup transcript, F(ctx,w) is uniform and independent of K and E_w, hence

    Pr[ E_w = K xor F(ctx,w) | setup transcript ] = 2^-kappa.

For r distinct unqueried accepting witnesses these events are jointly independent, so the probability all of them have the required exact release identity is 2^(-kappa*r). Thus a Build with overwhelming every-witness correctness in this **per-witness independent-pad normal form** must query almost every accepting w. If |S_x| is exponential, classical-PPT Build cannot instantiate this architecture.

This does NOT cover an evaluator that uses a genuinely new correlated source, a compact secret-function obfuscation, a nonlocal hash relation, or other cryptographic release mechanism. It also does not prove that no polynomial hash-only witness encryption exists. It precisely identifies what must change: the setup must create **computationally protected cross-witness correlations**, not just compress independently random witness pads or include a root commitment in PoW. Merkle roots cannot by themselves reconstruct omitted random encrypted leaves without separate opening information.

## Actual bounded tests

1. source_indexed_reference.py: deterministic toy 14-bit parent-work witness space with two source child outcomes, actual SHA256/Shake256 full-evidence tags, 104 accepted toy certificates, identical recovered frozen 96-byte capability, and eight fake-anchor/child certificates rejected even by raw release. A deliberately invalid **folding by semantic child** variant recovers K from a fake certificate without its work proof. 124 checks, exact byte-identical rerun. Valid toy PoW is privately mineable before network publication and does **not** establish canonical BTC membership, temporal source safety, or practical security.
2. garbling_closure.py: SHA256-keyed NOT, identity and AND garbled gates with both input labels public. On the original FALSE relation x AND NOT x, two honest paths both output false; public input labels expose both intermediate labels and permit inconsistent (true,true) gate evaluation, revealing a frozen key anyway. 448 checks across 64 fixtures; byte-identical rerun. This shows why a local hash-garbling fold does not solve the global consistency/size problem. It is not a general impossibility proof.
3. ideal_qrom_distribution.py: exact enumeration of uniform two/three-domain public records conditioned on fixed K, for (kappa,s)=(1,3),(2,2),(3,1). All joint public record/CK/Dsig distributions match for every K. This checks the finite public-marginal algebra, **not** the quantum hybrid, hash security or a real native signature.
4. prefix_gate_checker.py: 60 checks over 12 fixtures, reproducing the earlier R7 result that a raw SHA puzzle can be solved using an INVALID anchored source string and unlock even when honest Open rejects it. No new attack credit claimed.

Exact executed local sources and byte-identical captured outputs are preserved with this checkpoint as separate files in the run archive. Source/file SHA256 are recorded in MANIFEST.json. No independent agent was invoked.

## Source-specific next task: accepted-work correlation

A PolyPPT Build_hash(x,sigma) must avoid the per-witness table. It must set up source-dependent pads whose release preimages can be generated from **complete, authenticated** Syscoin/AuxPoW evidence, not just a child header, a public semantic outcome label, or a fake hash search. OutcomeID and WorkID must stay distinct. Genuine coinbase tag/ancestor/interval/lag and qualified inclusion/censorship assumptions remain indispensable. A static toy PoW predicate may be satisfied by PRIVATE mining before any public event; only an actual admissible ORIGINAL statement suffices as source authority. The source compiler and full-public QPT simulator must be instantiated together.

The exact missing equations remain

    Build_hash(R_original,x,sigma) -> capsule in poly(lambda, |x|) time,
    Open_hash(capsule,w) = SAME sigma  for every R_original(x,w)=1,
    A_QPT recovers sigma / forges target without qualified w
       -> extract a FULL ORIGINAL witness OR independently justified PQ hash break.

No online release issuer, lattice wrapper, public suffix verifier on Bitcoin, new opcode, unexplained keyless Build, or production deployment is introduced. N-of-N honest-erasure/abort, pre-funding DA, source observation windows, and native SLH-like P2MR endpoint remain open.
