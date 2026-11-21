# R183 — Independent-key OR release combiner for ORIGINAL bridge challenges

**Status: conditional compositional theorem, NOT an implemented hash-only witness-KEM, secure original-source compiler, native PQ signature, or deployment recommendation.** This narrows the cross-branch correlation obligation; it does not instantiate even one branch's release algorithm. No outside web/literature, lattice, public DLog group or online release authority.

## Continuity and provenance

Repository syscoin/PVUGC PR #1, open/draft existing branch research/pq-wkem-validation-20260918. Starting observed head ac473d38c97f9450d3a0de00fc524be42f8b0320 (R182 activated-annex source-binding); read R182 blob 01e84752f74f9baa243f19ea25f10381d7ff5256 and targeted R181 at that actual ref, plus latest relevant R176/R177 ordinary PR comments. No full PR diff or old-archive reconstruction. CHECKPOINT_01.md was saved locally before checker execution. Standard-library checker.py was executed twice with byte-identical captured.json. Source SHA256 9f8c5acfcf64ff30f60bc8e8b0a1cd755d73726aa563161520925994fea9515a; output SHA256 57c8cf86f75b1cde62191b2845a13aaae36be49f6a7915a8d788242c6b765f4a. Exact source/output blobs and checkpoint are included in this research directory. No independent agent, quantum program, real native signature or production source verifier was invoked.

## Original relation and exact delta

One notary can initiate a constrained withdrawal, one of three qualifying ORIGINAL evidence families can trigger the safe challenge, and N-of-N preauthorization constrains the Bitcoin transaction graph independently of the online notary and permissionless challenger.

R1 is a relevant, authenticated competing Bitcoin history with more exact cumulative target-derived work, excluding mere extensions or unrelated chains. R2 is a finite refutation of the *actual bound* PoB claim, not a global assertion that no burn exists anywhere; state nonmembership requires a consensus-authenticated map root or bounded complete authenticated history. R3 is an authenticated, sufficiently deep Syscoin/AuxPoW tag/ancestry incompatibility (or explicitly authorized tag fault), with actual BTC source anchoring and source-window qualification, not two parent work certificates for the same child.

The original release specification requires every qualifying witness under R1 OR R2 OR R3 to recover the SAME frozen, claim/path-scoped native cancellation capability. That does **not** require the three branches to recover the SAME symmetric intermediate key. This matters because each branch has structurally different source evidence and different hash inputs; trying to force a single K to be the raw hash-derived output of all three was an unnecessary extra correctness constraint.

## Explicit combiner (conditional on separate real source-bound leaf encapsulations)

For one honest setup participant i, freeze the exact native cancellation message M and a valid ordinary native signature sigma_i on M. Let native VK_i be public. For each j in {1,2,3}, independently generate a kappa-bit key K_{i,j} using a classical PPT branch-specific leaf construction:

    (C_{i,j},K_{i,j}) <- Encap_j(R_j,x_slot ; fresh coins).

The source-bound leaf algorithm must already ensure that every ORIGINAL witness w satisfying R_j(x_slot,w) publicly obtains precisely K_{i,j} through Decap_j(C_{i,j},w). This algorithm is COMPLETELY UNINSTANTIATED for all three source relations, and calling it Encap does not solve it.

Choose a dedicated quantum-accessible random-oracle domain H_pad with L-bit outputs, where L is the native frozen signature length. Its input includes protocol version, slot/claim ID, native signer ID, branch ID and the fresh key. This domain is independent of every hash domain used for leaf construction, checking keys, native signing, source commitment, capsule manifests and all related claims. Publish independently masked copies of the SAME sigma_i:

    D_{i,j} = sigma_i XOR H_pad(context, i, j, K_{i,j})
    Capsule_i = (x_slot, VK_i, M, C_{i,1..3}, D_{i,1..3}, audit data).

Public Open_i(j,w) uses the ORIGINAL source witness (not a fabricated verifier result) to recover K_{i,j} from C_{i,j}, unmasks D_{i,j}, checks the ordinary native signature against VK_i and M, and returns sigma_i. Every accepted witness from any branch therefore yields the same frozen sigma_i, even when the branches' intermediate K values are distinct. It is efficient if the missing leaf algorithms are efficient.

For the existing N-of-N graph, independently repeat for each participant i. Any one valid ORIGINAL challenge must open every required honest participant's contribution to the SAME bounded cancellation transaction. The resulting Boolean structure is AND over participant signatures of OR over challenge grounds, not AND over the grounds. This does not assume threshold signature aggregation, Bitcoin verification of NP statements or online release. One honest participant can block premature full cancellation if its own signature remains concealed, but malicious capsule liveness and pre-funding correctness auditing remain separate open obligations.

## Exact joint-public QROM coupling (proved only for this conditional combiner)

Assume the entire actual sampled joint distribution of branch public capsules C_j, keys K_j, native VK/M, source commitments, manifests and quantum auxiliary state is independent of the newly chosen *dedicated* H_pad oracle and of its pad values. The branch source construction may depend on complex SHA/AuxPoW fields and correlate K_j with C_j; that correlation is retained, not replaced by independent ideal source tokens. The leaf builder never queries the H_pad domain and there is no circular dependency from source/manifest into pad values except through the explicitly published D_j. Oracle preprocessing by the attacker must be counted in query budget Q; freely supplied quantum advice dependent on freshly chosen H_pad is not covered. Native target-signature-dependent audit fields must be simulatable in REF without sigma_i.

REAL: sample honest native sigma_i and branch (C_j,K_j), supply independent random H_pad quantum oracles, and publish D_j=sigma_i XOR H_pad(j,K_j). All other allowed public fields are sampled by the ACTUAL protocol.

REF: retain the SAME sampled C_j,K_j, public VK/M and source/auxiliary fields, but publish three independent uniform D_j and supply independent uniform H_pad oracle tables.

Given any fixed C_j,K_j and sigma_i, each REAL D_j is uniform and independent of the others. Couple both worlds by first sampling D_j uniformly. In REAL impose the oracle values H_pad(j,K_j)=D_j XOR sigma_i, while all other oracle inputs are independently uniform. Because these imposed values are independently uniform, the complete marginal REAL oracle distribution is correct; the REAL public D and oracle retain their exact required correlation. In REF leave the H_pad(j,K_j) values independently random. Thus under the stipulated source/auxiliary independence the public marginal distributions match exactly, and the two quantum oracles differ ONLY at the three secret addresses S={(j,K_j):j=1,2,3}. This is a proof coupling, not an implementable release oracle or an assumption about SHA standard-model security.

For any Q-query arbitrary QPT adversary A and classical final event E, write psi_t for the reference execution's pre-query quantum state and p_t for its query-address squared amplitude on the actual S, averaged over the full coupled distribution. A quantum XOR-oracle call's unitary difference on any state has norm at most 2 sqrt(p_t). Hybrid telescoping, triangle inequality and Cauchy-Schwarz give

    delta = |Pr_REAL[E]-Pr_REF[E]|
         <= 2 sum_{t=1}^Q sqrt(E[p_t])
         <= 2 sqrt(Q * sum_{t=1}^Q E[p_t]).

Hence select t uniformly, run the REF algorithm up to that query, measure the input-address register, and return its branch/key candidate. The chance to output the ACTUAL (j,K_j) for some j is at least

    delta^2 / (4 Q^2), for Q>=1.

For Q=0 the two worlds are identical and delta=0. This extractor requires neither classical rewinding nor adversarial disclosure of its query log, supplied representation or private witness. Guessing one fixed j rather than accepting a tagged branch result costs at most a factor 3.

Let E be an accepted native cancellation authorization under an honest native VK on the protected M. In REF, masks D_j are uniform and independent of sigma_i and can be simulated with a public VK from a QPT-EUF signing challenger (and allowed off-target signing oracle). Thus REF acceptance is an ordinary native forgery, PROVIDED no unmodeled direct H(sigma_i), target-signature opening, retained honest sk, or unsimulatable audit field is in the public view. If REAL acceptance exceeds native REF forging probability by epsilon, the random-query measurement recovers SOME genuine branch K_j with probability at least epsilon^2/(4Q^2), or one already has a native PQ signature break.

To finish an ORIGINAL-witness reduction, EACH actual branch leaf must additionally guarantee that any arbitrary QPT recovery of its K_j, including this query-measurement algorithm and all other branch capsules/auxiliary/source coins, produces an ACTUAL branch-j ORIGINAL witness or independent PQ primitive break. This is the remaining hard premise; it is not proved by the joint-public QROM calculation above. The source chooser retaining K_j or getting an online hidden label would invalidate the premise. Consequently this conditional theorem must not be called a completed source WKEM.

## Explicit regressions, malicious setup, source and endpoint limits

- Reusing H_pad for a public K-check tag CK_j=H_pad(j,K_j) exposes sigma_i=D_j XOR CK_j instantly. A completely separate hash domain is mandatory; the executed checker illustrates this exact disclosure.
- Reusing a key or pad address between claims, branch IDs, native signer IDs or related capsules may allow selective opening of one claim to disclose another. Fresh keys, domain-separated inputs, and an explicit same-message-authorization rule are mandatory; sibling cases with shared source data need genuine joint simulation.
- A source validity check performed after a public raw pad opening cannot repair a leaf gate. It must be the complete authenticated Bitcoin/Syscoin ORIGINAL source that cryptographically enables Decap_j, including actual activated BTC wtxid/annex and source window, PoB authorization, AuxPoW parent work/coinbase tags and correctly qualified branch ancestry.
- If the native cancellation message M signs a capsule root which itself contains D_j containing that signature, a circular fixed-point dependency arises. Freeze the preauthorized graph/M first, generate sealed signatures second, then authenticate the capsule root in an acyclic setup manifest checked before funding. Native endpoint and no-EC-key-path P2MR-like behavior remain conditional, not deployed assertions.
- N-of-N gives a safety veto from one honest non-bypass signing participant only if its secret is protected/erased. It does NOT guarantee usable cancellation when corrupt participants issue malformed/unopenable capsules. Full pre-funding data availability and verifiable correct sealing are separate prerequisites.
- Native signatures and a possibly transparent off-chain ZK/argument verifier do not automatically implement release. If any proof system is used, the native endpoint still verifies an ordinary authorization, not the original NP circuit, and any hard-TRUE extraction needs QPT ORIGINAL evidence extraction, not mere inner proof acceptance.
- The theorem is in a dedicated ideal quantum-random-oracle model and uses an uninstantiated real-source branch key-recovery premise. It does not prove an IND KEM, arbitrary oracle-dependent quantum advice security, standard-model SHA security, malicious setup or full active multi-capsule composition. It does not show the branch leaf algorithms exist.

## Executed bounded checker and next work

Python 3 standard-library checker.py was actually executed twice with byte-identical captured.json. It exhaustively enumerates three independent toy pad domains (kappa=1,2,3), tests exact joint uniform mask marginals and same frozen output for all three branches, and tests the direct public check-domain reuse leak. Its 6,350,888 assertions are *algebraic functional checks*, NOT proof of QROM or branch-KEM hardness.

**Exact next problem (still unsolved):** For each j=1,2,3, construct a classical-PPT hash/SHA/source-dependent Encap_j before the activated assertion is known and a public Decap_j(C_j,w) that gives the SAME K_j for EVERY ORIGINAL valid BTC-work, PoB-fault or qualified SYS AuxPoW challenge witness of that branch; from any arbitrary QPT unauthorized K_j recovery, extract ACTUAL original authenticated evidence or an independently justified hash break. All native checking, malicious source coins and full related-capsule auxiliary view must be simulated. This composes only after the source-dependent leaf release exists. Do not optimize this combiner or treat a synthetic PoW fixture as deployed source evidence.

No ordinary PR progress comment was posted or warranted merely for this conditional composition checkpoint.
