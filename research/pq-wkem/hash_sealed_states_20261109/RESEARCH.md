# HPW-HSS-20261109 — Hash-sealed complete verifier states

**Outcome: no breakthrough and no secure generic witness-KEM.** This pass directly attempted the missing polynomial-time ORIGINAL-dependent compiler, not an optimization. Complete verifier-state labels repair the previously demonstrated contradictory-input mixing at the level of permitted transitions. The explicit implementation then encounters an exponential state requirement for a specified verifier family. The two attempted polynomial replacements respectively restore false-source release or lose every-witness SAME-capability correctness. These are supporting research findings, not a reportable generic construction advance.

## 1. Exact continuity and changes

Repository `syscoin/PVUGC`, PR #1, branch `research/pq-wkem-validation-20260918`; observed start SHA `21ef9abc289e40c02bb119121978d813d222c60a`, open/draft/unmerged. Read the current R166 delta (one-way transport implication, not a construction), and exact `hpw_20261108/resumed_2353/CHECKPOINT_05_QROM_AND_PADDING.md`. A bounded recent-comment query returned no newer comments. No full PR diff or historical archive reconstruction was used.

An intermediate checkpoint was committed during this pass at `b93b597941e23cfe2e4eff4fcf58ac492f953cdb`, tree `62530dba3d5561e32c745f088ea68fbbb9ac9c21`, with parent equal to the starting SHA. Its exact file readback has blob `c7fa760ba55331c57de591358511b73fdc59ca13`. The non-force branch update used the expected head. This preservation is not mathematical progress.

The change from the earlier wire-label garbling is explicit: one secret hash label represents a whole configuration, including every previously read witness value that can be read again. A raw evaluator cannot independently select inconsistent bit labels while remaining on a permitted full-state path. The tests do not rely on an honest Open API rechecking the original relation after decrypting the capability.

## 2. Concrete classical construction and distribution

Let V_x be a fixed deterministic ORIGINAL verifier. A configuration s contains its program location, work registers, and the values of still-live witness cells. A cell remains live from its first query through its last query under the specified execution order. A graph transition reads witness position i and value b. A second read of i must agree with its remembered value; otherwise that transition is absent. Rejecting transitions are absent. All accepting executions end at a common terminal A. Distinct valid witnesses can have different intermediate states and paths; neither a canonical witness nor a common witness preimage is required.

Build enumerates the reachable configuration graph. For each ordinary configuration s and the terminal A, sample independent secret lambda-bit labels L_s,L_A. Detect and reject label/tag collisions during setup. Let ctx injectively encode the original relation and statement, claim/UTXO, branch/path, anchors/window, capsule identity, intended native VK and message description. It must not include a circular hash of its own future ciphertext.

Use independent, domain-separated hash domains H_tag, H_edge, H_end and H_release. For every permitted transition s --(i,b)--> s', publish:

    tag_s = H_tag(ctx,L_s),
    row(tag_s) = (i, { b : L_s' XOR H_edge(ctx,L_s,i,b) }).

Publish L_start, terminal check H_end(ctx,L_A), and

    Dsig = sigma XOR H_release(ctx,L_A),

where sigma is the SAME already frozen native signature on the intended message. H_release supplies exactly the signature length. The complete capsule contains these rows, ctx, VK and any acyclic public checking/manifest fields. Secret labels and native signing secrets are not public. This is an honest-erasure setup baseline, not a keyless or malicious-secure distributed ceremony.

Open follows the witness's requested read bit at each row, decrypts its next label, and uses the terminal hash check to recognize the final state. It unmasks sigma and checks native verification. The checker implements actual SHAKE256 domain-separated operations and an actual Lamport one-time-signature fixture. It does not claim Lamport is a deployed native Bitcoin endpoint. Fixture labels/signing secrets are generated deterministically from public test seeds for reproduction; the intended distribution above is independent secret randomness, not the insecure deterministic fixture.

This is polynomial in the explicitly enumerated graph size S. It has NOT been shown polynomial in the ORIGINAL input/security parameters; in the experiments below S is exponential for one simple fixed-order verifier family.

## 3. What retaining memory really repairs

Induct along any graph path. On the first read of a witness cell, record the selected bit. Before the cell's last read, all subsequent transitions require that same bit. After its last read, discarding it cannot affect any future query. Consequently every complete path has a globally consistent assignment, reconstructible from its edge labels. The deterministic verifier state updates then imply that an accepting path yields an ACTUAL satisfying assignment of the original CNF relation. Conversely, every satisfying assignment follows a valid path and reaches A. This is a proof about exact graph paths, not a proof that an arbitrary quantum key-recovery algorithm supplies such a path.

For the full-state graph, the executed raw search receives only the public capsule. It is NOT passed private labels, an original satisfying assignment, a token issuer, or Build's private graph states. It computes row hashes and decrypts outgoing transitions. On all 42 CNF fixtures, its accepted paths match original satisfiability. Its reconstructed witnesses satisfy the original clauses.

The proposed small quotient keeps only the program location and local clause accumulator, dropping repeated-input memory. It uses the SAME state-specific cryptographic row construction, not plaintext edges. This quotient still admits reading x=1 in the positive clause and x=0 in the negative clause. For both false CNF fixtures, raw public traversal recovers the actual frozen Lamport signature, while no consistent ORIGINAL witness exists. Hashing local state does not recreate the omitted dependency.

## 4. Why the explicit full-state repair is not a generic polynomial compiler

Use a verifier reading a_1,...,a_n and then b_1,...,b_n, accepting iff the two n-bit strings are equal. At the midpoint, each first string a defines a different necessary residual acceptance condition: suffix b=a must be accepted, and for a' != a it must be rejected. Merging these midpoint states while retaining this read order therefore violates correctness or source soundness. There are 2^n such states, regardless of whether their names are long descriptions or lambda-bit hashes.

For the implemented verifier, the exact number of nonterminal states is

    sum_{j=0}^{n-1} 2^j + sum_{j=1}^{n} 2^j = 3*2^n - 3,

and the edge count is 4*2^n - 4. The checker verifies these counts for n=1,...,10, including 3,069 nonterminal states and 4,092 edges at n=10. This is a lower bound for this specified read-order model, NOT a lower bound for every verifier, every hash construction or witness encryption. Reading equality bits in a different order changes this example; no general impossibility is inferred from it.

There is another decisive issue for the entire explicit publicly navigable graph architecture. Once a label is known, both available outgoing ciphertexts can be decrypted. A public breadth-first search visits each reachable label once and either finds the terminal with a complete ORIGINAL witness or exhausts the graph. Its cost is O(S) graph/hash work plus output verification. Thus a compact, uniformly constructible exact graph for arbitrary hard source relations would make their witness search efficient. For a deterministic exact generic compiler this gives the corresponding polynomial search/decision consequence; with a bounded-error randomized compiler the consequence is randomized. This is a scoped observation about THIS explicit architecture, not an impossibility of hash-only witness encryption.

Neither encrypting the rows nor obscuring semantic state names prevents this traversal: the root label and both branch-opening procedures are public. A useful replacement must change the public evaluation structure, not just shorten node tags.

## 5. Attempted generative repair and result

To avoid stored state rows, replace transitions with the concrete public rule

    L_next = H_chain(ctx,L_current,step,read_bit).

A witness can compute this in polynomial time and Build need not precompute every prefix. But distinct accepted histories now produce distinct terminal labels rather than L_A. Freezing Dsig against one such label opens for that witness and not the others. In the executed source fixture, four distinct valid certificates produce four distinct terminal labels; a single frozen mask releases the signature for only one.

This is not a claim that honest output states must be identical. Different states are allowed, but each must have an actual public recovery operation yielding the SAME precommitted capability. This replacement supplies none. A separate encrypted correction for each terminal reintroduces the enumerated-table obligation. A secret-seeded public correction evaluator would require another concrete protected evaluation primitive; no such primitive is assumed here. Increasing hash width cannot establish the missing correlation.

## 6. Source/PoW binding test and limits

The synthetic source statement fixes a claim, a slot, an anchor and a baseline child outcome of zero. Its nine-bit witness is an alternative child bit, an anchor selector, and a seven-bit parent nonce. Work is actual SHA256d of the complete synthetic context/certificate; the fixture accepts a leading-four-zero-bit target. The ORIGINAL toy challenge predicate additionally requires the correct anchor and a different child outcome.

The full-state compiler enumerates this small source domain. All four accepted certificates recover the same frozen native signature. Nineteen certificates with actual toy work but the wrong anchor and nine work certificates supporting the baseline child do not release even through the raw hash-row algorithm. This shows the SOURCE dependency is actually in the compiled rows for this finite experiment, not only in an honest post-hoc verifier. The cost is the enumerated 511-node graph over 512 possible witnesses; no polynomial generic source compiler follows.

The fixture is NOT a Bitcoin/Syscoin parser, best-chain proof, ChainLock system, live interval/lag checker, or deployed endpoint. Its valid low-difficulty work can be privately mined. Authentic AuxPoW, parent-chain membership, coinbase/Merkle tags, cross-height ancestry, observation windows, DA, reorg/censorship and timing constraints remain required in the actual ORIGINAL relation. Neither a second parent nonce nor a root commitment alone establishes a conflicting source outcome.

## 7. QPT and joint-public security status

No full-joint QPT security theorem is claimed for this candidate. A graph-path extraction invariant is not arbitrary capability-recovery extraction. No adversary is required to volunteer a representation or query log. An explicit graph permits the separate public traversal above, with its runtime measured in graph size; that is not an efficient generic-original-input extractor when Build is exponential.

For a false instance with no accepting transitions, L_A appears only through its terminal commitment and signature mask, while ordinary reachable labels are independent. One can investigate a domain-separated QROM hidden-point/native-forgery hybrid for that special public distribution. That does not repair the compiler, imply a concrete SHA theorem, or establish malicious setup, cross-capsule correlations, quantum auxiliary leakage or adaptive selective openings. Those remain unproved here. No statistical false-hiding target is silently imposed.

The required full view still includes R,x, capsule, native VK, checking key, context, source commitments, Aux, related capsules and allowed disclosures. No online release authority, discrete-log group, lattice fallback, generic verifier on Bitcoin or new opcode is introduced. N-of-N setup with one honest participant, erasure, abort safety and pre-funding DA are not implemented by the one-builder fixture.

## 8. Actually executed checks and provenance

The single Python-standard-library checker `checker.py` was executed locally, then re-executed with byte-identical stdout. The final code passed 1,432 assertions. It covers 306 original assignments over 42 CNF fixtures, 40 true and two false formulas, both quotient leaks, exact fixed-order state counts, native-VK/context binding, actual Lamport verification, and all 512 synthetic source witnesses. No independent agent or second independently developed implementation was used. A preliminary successful version was reviewed and strengthened to bind the native VK into ctx before the final two executions; no failed check is counted as passed.

Final source SHA-256: `1d67c9c32ea4666e04ddbb7ea1532961fc1b7f8a1c256bd80384529da981ab31`.
Captured stdout SHA-256: `599d291f51e249d01b384c76cbd3f64fa067bc1313360d722ac2a9f8ffc2ab5b`.

The algebra and tests do not establish quantum hardness, parameter calibration or a practical generic construction. No test count is being promoted to a breakthrough.

## 9. Exact handoff

The sought compiler must permit every ORIGINAL valid witness to recover the same precommitted capability while preventing public inconsistent evaluation, WITHOUT either enumerating all consistent states/witnesses or handing out an ordinary compact publicly traversable acceptance graph. The concrete missing operation is a polynomial-size hash-based correlation/evaluation mechanism preserving full witness consistency across repeated source checks and supporting common-capability convergence. Its source-dependent setup and full-public QPT simulator must be instantiated together. A secret correction evaluator, programmable validity gate, witness issuer, or renamed WE/obfuscator is not an implementation.

Do not optimize these rejected/reference state tables. Keep the source-specific work and common-capability requirements; do not call this an end-to-end solution or a reason to disable the research task.
