# Hash-only enumerated semantic-state release — exact restricted component, NOT ORIGINAL bridge WKEM

**NONQUALIFYING. Do not notify.** This is a bounded constructive check that replaces public additive/tensor masks with nonlinear per-state hash locks. The underlying full-state approach is historically known to be exponential on unrestricted SHA histories. The precise missing original-source cryptographic step remains unconstructed. It must not be advertised as a general WE result, feasible source gate, or hard-TRUE security theorem.

## Provenance and target

On 2026-11-23 the open/draft PVUGC PR #1 was inspected at head \`67dea8d5cb19b083e4f29cfa86bf2a306359107a\` on \`research/pq-wkem-validation-20260918\`. Exact preceding note blob \`96098b9dde31b77f7e6a3cfc8c487bc4e3b45ee2\` and prior SHA-diamond note blob \`4cf6313ef38fd310bf64ab80ef7e2b6e49a1f812\` were read. Top-level PR comments since 2026-11-21 were empty. A concurrent *different* Praxis review reached PR head \`32ad428ae15a6ebb0f704425a50f7bf291cca007\` while this iteration was being prepared; this note does not edit or supersede that review. No web, Core, source networks, real witnesses, FE, ZK, native signature, or quantum tests were run here.

This candidate attempts the exact missing protected transition operation by using independently random hidden state labels and SHA one-time-pad transitions **instead of raw source-derived pads**. Only a public transition ciphertext exists for each enumerated semantic state; no hidden source signer or ideal evaluator is postulated.

## Actually serialized restricted Build/Open

Fix a PUBLIC deterministic layered automaton with L layers, state sets Q_i of width at most W, alphabet Σ, transition δ_i(q,b), start q0 and accepting terminal set A. Build samples independently uniform λ-bit labels s_{i,q} for every state, publishes s_{0,q0}, and publishes for every enumerated state/letter:

    E_{i,q,b}=s_{i+1,δ_i(q,b)} XOR H("edge"||i||q||b||s_{i,q}).

For each q∈A it also publishes D_q=S XOR H("final"||s_{L,q}). The public capsule C contains all δ, A, E, D, the start label and exact policy context (the checker uses fixed domains; deployment would require the context inside each domain). Build costs O(L W |Σ|) SHA calls and O(λ L W |Σ|) bits of public output.

Open on input w=(b_0,...,b_{L-1}) starts from (q0,s0), decrypts one E transition at each step, updates the semantic state with δ, and if the final state q∈A returns D_q XOR H("final"||s_{L,q}); otherwise returns ⊥.

**Exact all-witness correctness:** Induction shows that any actual transition recovers exactly the compiler's label at the next state. Every accepted sequence, even if it follows unrelated intermediate labels or a different accepted terminal state, returns the SAME S. No forced shared preimage. Unlike public R366 tensor readouts, paths are not algebraically combineable by a low-degree public cancellation identity: a wrong-source state lacks the corresponding keyed SHA pad. This statement addresses that *specific* attack shape, not arbitrary circuit attacks.

## Full-public FALSE security: limited classical-ROM statement

For an automaton with no reachable accepting state, all accepted-terminal labels are outside the reachable directed graph from q0. Public path traversal discloses every reachable label, but no unreachable label. In a **classical random oracle** model with independent honest Build labels, every ciphertext from an unreachable source is one-time-padded by a fresh oracle value keyed at an unknown input; even two incoming edges for the same child receive independent pads. A hybrid replaces those ciphertexts with independent uniform bytes and replaces each accepted-terminal D_q with a uniform string. Up to guesses/queries hitting any hidden state label, the entire public view is thus independent of S. A coarse loss is O(Q_H (L+1)W/2^λ + ((L+1)W)^2/2^λ), with Q_H classical oracle queries, no correlated auxiliary labels, and honest setup. This is **not a proved QROM statement**; coherent queries, sibling/adaptive capsules, malicious setup and source-retained coins require separate work. Concrete SHA security cannot be inferred from ideal-oracle proof.

## The fundamental honest-practical ORIGINAL obstruction

A public layered DFA with polynomial W and alphabet size has polynomial-time reachability and accepted-witness extraction in O(LW|Σ|), using predecessor pointers. It therefore does NOT provide hard-TRUE source work even if its FALSE security holds.

The actual Bitcoin/Syscoin certificate verifier must retain a 256-bit predecessor hash to compare with the following header's prev-hash, plus contextual difficulty, AuxPoW canonical modern ID and exact tag, Merkle binding, actual ancestry, LC depth and claim qualifiers. For the simple abstract streaming equality language L_eq={(h,h):h∈{0,1}^256}, every deterministic one-pass finite-state machine needs at least 2^256 states between h and its continuation: two different prefixes h≠h' cannot share one state because appending h distinguishes them. This is a precise distinguishability bound **only** for that abstract language, not proof that all 2^256 digests occur on real PoW chains or that a different succinct compiler is impossible.

Listing semantic hash states is exponential. Avoiding listing them by replacing the transition label with public SHA(state) recreates public probing/leakage; an imagined private or ideal "authenticated state transition" is just the missing FE/iO/source-release gate renamed. The *new necessary equation* is a succinct public transition encoding (polynomial in SHA circuit size, not 2^256) that delivers a hidden per-state next label on a genuinely authenticated source transition, prevents off-path composition and raw invalid-trace evaluation, and supports joint-public FALSE and hard-TRUE arbitrary QPT recovery to an ACTUAL ORIGINAL OR-certificate. No such encoding is constructed here.

The three approved OR grounds are unchanged: competing same-anchor Bitcoin history with strictly greater exact work; finite authenticated specific-burn fault; qualified Syscoin history inconsistency/tag fault at actual LC depth (no greater Syscoin work or winning-chain selection). The R316 stale tag-reference example is not a strict-tag vulnerability. One honest N-of-N setup, safe activation-bound native spend and all other original source/endpoint obligations remain open.

## Executed bounded check

The committed Python checker is standard library SHA256, seeded independent hidden per-state 256-bit labels, alphabet {0,1}, L=5 and W=4. TRUE fixture accepts eight of the 32 bit sequences; **every accepted path** recovers the identical S, and every rejected path returns ⊥. FALSE fixture has an unreachable accepting state and all 32 candidate paths return ⊥. Two actual executions returned exit status zero and byte-identical JSON output. Checker SHA256: \`3245c05b71771a9dffc3f8361b6150213ef855b81d8be12b9a52a375ec0a02f5\`; both output files SHA256: \`a7816a85c3c5a4bb23e73464002ad74a83395c642fd307c72e3655ab160ace29\`. Do not infer security from the tests.

**Stop point:** This restricted hash-state compiler is an executable positive subcomponent in a tractable regular language, but provides no polynomial ORIGINAL Build/Open, no hard-TRUE or QPT reduction, and no malicious setup/auxiliary/capsule proof. The exponential-state approach is not a viable optimization target without a qualitatively new *succinct protected transition*. Do not continue this family by mere parameter growth or hash-domain relabeling. No user or PR progress comment, Core/production edit, deployment, transfer or automation change.
