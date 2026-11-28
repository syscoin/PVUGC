# Paired-instance witness lifting with globally correlated permutation constraints — 2026-11-27 UTC

Nonqualifying construction/repair iteration; no secure WKEM or deployment claim.

## Continuity and selection

Actual start PR #1 head cd089aa71a87fd3a13fa28dfc6aa57ced0e2a323, syscoin/PVUGC, branch research/pq-wkem-validation-20260918, open/draft/unmerged. Read PR metadata, recent substantive comments through R225, the exact head commit's changed-file name (not a PR diff), and SOURCE_ADAPTIVE_CYCLE_PROOF_TRANSPORTER_20261127.md at that head (blob 21ba796db06c919418d319985086517b723ad380), plus the exact MPC view completion and layered irreversible interval jump notes at that head. Duplicate path read returned NOT_FOUND/404. No new Core-source assertion.

Missing operation: a witnessless offline classical-PPT serialized Build(x,sigma_cancel), whose public Open from ANY qualifying ORIGINAL certificate yields the identical frozen safe native capability, with full-public FALSE/hard-TRUE QPT recovery and native forgery security.

Selection: **encode secret bits in the hidden ordering of a pair of witness-liftable constraint instances**, not in a secret transporter's identity, intermediate wire labels, additive private coefficients, or a hidden terminal correction. A correct source witness lifts to a solution of exactly one instance of each pair. To avoid trivially exposing the bit in one clause or output gate, use a globally correlated cycle of individually satisfiable nonlinear permutation constraints; every proper subset of the permutation records has the same distribution in both modes. The payload-bearing operation is recognition of which complete paired constraint instance admits a lift, not a hash of varying valid source witnesses. Test the joint public distribution before any packing or scaling. This differs from the last head's n-element secret-transporter enumeration: there is no secret transporter to enumerate and no secret permutation is selected by Open. The key is an ordering of publicly represented NP instances.

Let V_x denote the complete claim-bound original verifier with all three OR grounds, including authentic relevance and maturity. Use an ordinary Tseitin gate-equivalence reduction to a CNF F_x with output asserted; every original witness w yields a satisfying assignment u by evaluating all gates, and any satisfying u contains an original witness. This is an abstract polynomial verifier compilation, not a new implementation or audit of Core. The paired-instance candidate is evaluated even granting this complete compiler.

## 1. Actual paired Build and Open

Choose q>=3, a polynomial alphabet size, and m>=3 polynomial cycle length. Write Q={0,...,q-1}. Choose a fixed derangement delta(a)=a+1 mod q. Let branch type good have target product g=id and branch type bad have g=delta. In either type, sample independent uniform permutations P_1,...,P_(m-1) on Q and set

    P_m = g composed with (P_(m-1) composed with ... composed with P_1)^(-1).

Add to F_x the cycle of constraints

    a_(j+1)=P_j(a_j) for j=1,...,m,
    a_(m+1)=a_1.

All individual constraints are satisfiable, all have identical shape and exactly q accepting pairs. Permutations can be serialized as literal lookup tables. For the intended hash-only presentation, instead publish, for each relation and each a, a domain-separated salted commitment to its unique accepting pair (a,P_j(a)), in random order with salts included. Public verification of a candidate pair enumerates the q records and computes H(ctx,pair_index,branch_index,j,salt,a,b), using canonical injective encoding and independent domains. The relation is accepted iff at least one matches. Build knows every pair and generates these records without an original witness. As with any such hash-tag table, exact verification additionally needs absence of accidental collisions over the enumerated q^2 possible pairs; Build can check this by polynomial enumeration and abort before funding. Alternatively use literal tables for exact combinatorial correctness. No collision-resistance theorem for an actual hash is needed for the attack.

Build samples a uniform lambda-bit K. For each i, put a freshly sampled good cycle with F_x at index K_i, and a freshly sampled bad cycle with F_x at index 1-K_i. Serialize the two packages, the original compiler/public statement, and the full context, and output

    E = sigma_cancel XOR H_final(ctx,K; length).

Here final expansion has an independent domain and ctx includes the original claim/native endpoint/capsule bindings. No actual native signature implementation is claimed. Complexity is polynomial in verifier size, m, q, lambda; no oracle evaluator or setup witness is required.

Lift(x,w,D): evaluate the full original verifier and its CNF extension u from w, then start at a_1=0 and traverse the m local constraints using the tables (or find the unique allowed successor by enumeration in the hash-tag representation). It yields a complete assignment of the package exactly when the cycle returns to 0. Public Open verifies the complete original source certificate and invokes Lift for each package; for each pair, exactly one returns a valid full assignment. Set K_i to its index, then unmask E. For every qualifying original witness, good accepts and bad cannot close, since delta has no fixed point. Different original u need not share a canonical witness or a common preimage. The full original verification genuinely appears in the lifted NP instance. This does not yet mean it cryptographically controls access to E.

## 2. Joint law: the local hiding is exact but irrelevant

For any prescribed product g, the distribution is uniform over the (q!)^(m-1) tuples with ordered product g. Indeed specifying m-1 factors determines the remaining one uniquely. More generally, if factor P_k is omitted, write L=P_m composed with ... composed with P_(k+1), R=P_(k-1) composed with ... composed with P_1; then P_k=L^(-1) composed with g composed with R^(-1). Thus for EVERY proper subset of factor indices, its joint marginal is independent uniform over that many permutations, in both good and bad distributions. This also holds after independently salting/shuffling the tables in those records. There is no per-factor or even m-1-factor statistical classifier for the branch. This is exact arithmetic in a finite combinatorial group, not a discrete-log or group-hardness assumption.

A witnessless sampler can therefore perfectly simulate any such restricted view. But simulating the COMPLETE public capsule with a hidden order would be the actual security obligation, and does not follow from those exact marginals.

## 3. Full-public recovery, without original evidence or forged local labels

For each pair, ignore F_x altogether and traverse each cycle from 0 using its public relation records. For the literal-table representation this is m lookups. For the salted hash-tag representation, enumerate candidate successors and records to reconstruct the unique successor at each stage (at most O(m q^2) hash evaluations per cycle). In a successfully built capsule this returns 0 exactly for the good branch and delta(0) for the other. Thus the same public procedure obtains all K_i and unmasks the exact sigma_cancel without ANY original certificate. It works unchanged on FALSE and unauthorized hard-TRUE original statements, including when no satisfying u exists, and does not make a fake source witness pass V_x. It does not require mixed labels from incompatible witnesses, guessing a hidden permutation, a native forgery oracle, or inversion of a hash. It is classical PPT, hence defeats the requested QPT security. The real full public distribution allows deterministic classification of the good order; replacing that order by an independent hidden bit in the intended simulator fails on this same classifier.

This is the specific new failure of the paired-instance route: the source-witness-dependent *complete lifting* operation is genuine, but the smaller branch-selection operation is publicly executable independently of the source. Certifying the complete lifted assignment in honest Open cannot repair it. In particular, it is not enough to hide the order of two instances with local marginal symmetry if their joint globally correlated constraint systems expose the order on a source-free projection.

## 4. Specific repair preflight and outstanding operation

A proposed repair is to make the branch distinguishing test occur only on a starting state supplied by the entire ORIGINAL witness. In precise terms one needs two serialized public transition systems, with a lift L(x,w) providing a starting state, so that for every original valid w:

    fixedpoint_test(D_(K_i),L(x,w))=1,
    fixedpoint_test(D_(1-K_i),L(x,w))=0,

but no arbitrary unauthorized algorithm on the full view can recover the order unless it produces an original certificate or an independent justified QPT hash break. The new requirement is not that every fixed point be an original witness (which would be an additional semantic choice); it is that the observable mode difference be cryptographically inaccessible without original evidence.

The current identity/derangement pair cannot accomplish this merely by changing the starting-state encoding: every starting state distinguishes the modes. Even if q is exponentially large and the tables are replaced by compact *publicly evaluable* nonlinear permutations, the same attack uses one arbitrary public state and only m evaluations, so it does not depend on the ability to enumerate all transitions. Increasing q, salting more records or hiding only the permutation table entries is not a repair. This is an analytic rejection, not another parameter sweep.

One can write a source-dependent semantic permutation on (w,t), where t is a bit: apply t -> t XOR (b AND V_x(w)), preserving w. In the b=0 mode it is identity; in the b=1 mode exactly the qualifying original witnesses distinguish it by one application. Invalid w gives the same result in both modes. This is the correct *black-box* behavior for a branch selector, not a serialized secure construction: the straightforward circuit exposes b, and splitting it into independently masked reversible frames would invoke the already-recorded frame/output and label-switch regressions. We reject that variant before implementation. Merely naming a hidden source-conditioned permutation evaluator changes the missing operation into an assumption. Even a perfect black-box oracle argument would not prove concrete full-public security for its actual serialized description.

A future paired-instance approach needs an actual hash-only randomized sampler of descriptions where the source-guided branch-lifting mode is not independently recognizable from the full description. This means proving joint indistinguishability of the two orderings for FALSE, and an original-certificate-producing reduction (or justified independent QPT break) for arbitrary hard-TRUE recovery, including malicious source-coin retention and related capsules. It must be a concrete algorithm that jointly generates both descriptions and the payload relation before the original witnesses exist. Neither equality of restricted marginals, computational hiding of individual commitments, nor an abstract NP witness-lifting compiler supplies that sampler. We have not implemented it. This paired-instance preflight is not a general impossibility result against a source-specific computational construction.

## Scope

All three independent original grounds, complete source authentication and relevance, R225 endpoint choice, R316 correction, one-honest N-of-N setup/capsule correctness before funding, full QPT auxiliary/sibling composition, exact native recovery versus accepted forgery, and timely admissibility/inclusion obligations remain unchanged. No new Core consensus facts, no deployment claim, no code/checker/subagent/external literature/web used. Static exact construction and joint-distribution/recovery derivation only. No ordinary PR progress comment. Do not continue by enlarging this independent cycle, changing its finite permutation alphabet, or testing another local encoding. A different source-conditioned public correlation and its simulator are still required.
