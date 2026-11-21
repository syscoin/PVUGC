# PSTC — public semantic-state transition capsule: constructive graph compiler and ORIGINAL-witness extraction

## Provenance and scope (nonqualifying)
At the observed open/draft PVUGC PR #1 head `bae3dfcd94a84939d1c6d1d794ffc08d1f2eda5b`, branch `research/pq-wkem-validation-20260918`, read `research/pq-wkem/hsa_prefix_state_preflight_20261120/RESEARCH.md` at blob `d34335e127a88a2c0799b0fd2e6e6bc3d4df870b`; also read its R403 predecessor `research/pq-wkem/r403_global_digest_label_20261120/RESEARCH.md` at `3d13cabb272634ca127bd9567fe55694f1dc20db`. An issue-comment GET since 2026-11-18T19:24:00Z returned []. This pass does not assert any changed Core #609 source or deployed PQ rules, and does not rerun Core tests. No web or outside literature, independent agents, local tests or source witnesses were used.

The unresolved HSA equation is a polynomial-time PUBLIC terminal map `Decode_C(q_L(w))=S` for every qualifying original witness, with no early recovery. HSA kept a separate hash label for each prefix, so directly encoding all accepting terminals is exponential. This pass tests a genuinely different *compression* change before implementing a large system: **merge prefixes by the actual verifier semantic state**, not their digest or SHA label. It is a preflight of a specific public Build/Open class, not a substitute generic-WE claim.

## Candidate PSTC: share one secret state label per semantic verifier state

Assume a layered deterministic verifier with public states `Q_j`, start `q_0`, transitions `delta_j(q,b)`, input length `L`, and public accepting states `F`. The verifier is claimed to recognize the ORIGINAL relation: the input string is a full canonical encoding of an authenticated qualifying BTC-better-work certificate, particular-claim burn refutation, or qualified strict-contextual Syscoin inconsistency/tag-fault certificate. The predicate includes actual ancestry, claim binding, valid source-carrier authentication, LC depth, deadlines, reset, native cancellation and VK as required. This is a *conditional automaton representation*, not a claim that such a small automaton exists for SHA/AuxPoW.

Try to compile the fixed cancellation authorization `S` with random independent `lambda`-bit labels `ell_(j,q)` for every state. Publish `ell_(0,q0)` and for every enumerated edge `e=(j,q,b,q')` an encrypted transition

`E_e = ell_(j+1,q') XOR H("PSTC/edge" || sid || e || ell_(j,q))`

and authenticated edge selectors/identifiers sufficient for a public evaluator to find the applicable edge. For accepting terminal q publish

`D_q = S XOR H("PSTC/accept" || sid || q || ell_(L,q))`.

The prescribed `Open(C,w)` follows only the symbols of w, decrypts each selected edge with its current label, then uses `D_q` to recover the SAME S if its terminal state is accepting. This is a classical polynomial-time Build/Open **only if the explicit total state/edge count is polynomial**. It has no online signer, no foreign lattice/group primitive and no unique-witness restriction. It is also NOT secure.

## Original-witness extraction lemma (exact, not a generic impossibility result)

Let `G_x` be an explicitly enumerable, publicly navigable acyclic graph of `V` states and `E` edges representing the accepted paths of a fixed instance `x`. Assume:

1. Honest completeness: if a qualifying ORIGINAL `w` exists, some accepted path has label `Encode(x,w)`.
2. Soundness of the *whole graph*: every accepted path's decoded label yields an ACTUAL qualifying ORIGINAL certificate `w`, rather than just a local gate assignment, fabricated carrier, or unrelated PoW.
3. The public capsule identifies the start, each graph transition and its successor semantic state, and terminal acceptance in time `poly(lambda,|G_x|)`. Public label ciphertexts may conceal `S`, but not those structural facts.
4. The original witness has bounded polynomial length; the graph is layered by that length, or has polynomial paths with cycles excluded by a bound.

Then the algorithm `E(C)` runs breadth-first search from the public start to a reachable accepting state, records predecessor edges, emits the concatenated input bits, and canonical-decodes them. If any valid witness exists, it succeeds and outputs an **ACTUAL ORIGINAL qualifying certificate**. Its time is `O(V+E+L+T_decode)` after public graph construction and its memory is `O(V+L)`; it need not know `S`, a hidden FE key, private source coins, or private builder randomness. If a builder's public graph includes all allowed transition ciphertexts, another extractor can simply copy the revealed starting label, follow both edges at every reachable state, deduplicate by the public state identifiers, and recover the terminal pad. In particular the standard honest one-path evaluation is insufficient to confine adversaries to one input path.

For an efficiently samplable *hard-TRUE source distribution* over fully specified bridge setup instances with signing key material available to the honest builder and no already accessible original certificate, a classical-PPT compiler that always outputs an exact polynomial-size PUBLIC graph with both properties above would imply a polynomial-time original-certificate finder: sample the builder input S as in the honest ceremony, run Build, then BFS. This is an unconditional reduction **conditional on that precise graph interface and input distribution**, not a statement that finding any fork is hard in all network states. The computation of Build is charged; if it mines an ORIGINAL certificate in advance, that is source work shifted to setup. If a true certificate is already public, the hard-TRUE premise does not hold and copying it is legitimate.

This lemma is independent of whether the edge encryptions use SHA, AES, random labels, or perfectly opaque masks. It immediately includes classical adversaries within the requested QPT class. It is **not** a full-public FALSE/QPT confidentiality result for other encodings and does not imply NP-WE impossibility.

## Attempted repair of HSA through semantic-state merging

For a verifier holding a SHA256 chaining value, parent-header and coinbase bytes, chain ID, exact depth/lag, relevant ancestry and ongoing work, a semantic state may require Omega(lambda) bits even if the transition procedure is polynomial-time. Enumerating 2^lambda states is not a practical classical-PPT Build. Unlike the R403 prefix-hash method, merging *semantic* states can reduce the count on some simple predicates, but in precisely the cases where that yields an explicitly public polynomial-size transition graph, the BFS extractor above can find a source witness without waiting for the intended source generation.

Could conceal state IDs? A copied classical label can still be advanced on both next symbols. If each public state label permits identifying which of polynomially many public transition rows applies and deduplicating a repeated state, the same BFS applies. Hiding state equality or making transitions depend on unavailable path-correlated source secrets escapes this restricted lemma, **but that requires a new serialized, public evaluator** that can open every actual original witness and whose total public distribution resists arbitrary path processing. Randomly renaming states is not such a mechanism.

Could encrypt each edge under `H(full authenticated source certificate)`? That value is unknown to the builder before the future evidence. Enumerating all source-hash keys reverts to HSA's exponential terminal table; publishing a public edge-key generator lets an attacker invoke it on fabricated inputs unless source authentication is cryptographically enforced inside it. A separately called `VerifyOriginal(w)` is bypassable. Therefore this repair has **not** created the missing source-conditioned release functionality.

## Output security check; no claims beyond the proved class

FALSE: if graph soundness implies there is no accepting path, the graph-BFS attack does not output S. That observation is not a FALSE simulator for the entire published ciphertexts, whose correlations may leak S in other ways. No FALSE theorem is claimed.

Hard TRUE: in the explicitly enumerable class, public BFS itself is an unauthorized early ORIGINAL certificate finder (or shows Build did the original work). The native cancellation authorization can then legitimately be opened; this does not violate a hypothetical reduction to finding the original witness, but **destroys any claimed independent source-work hardness under this graph representation**.

Joint QPT: public classical graph scanning is an allowed QPT strategy. This result does not need rewinding, query logs or oracle programming, so there is no spurious quantum lift. There is no security analysis for a concealed-topology capsule, sibling selective openings, malicious setup coins or coherent SHA interfaces.

## Decision and exact handoff

**Rejected as an ORIGINAL release candidate at symbolic preflight**, before pointless toy benchmarking. The positive compositional fact is exact same-S correctness with polynomial Build/Open for explicit polynomial-state verifiers; the actual ORIGINAL-source qualification cannot be combined with publicly navigable polynomial-state compression without giving an early polynomial-time original witness finder. This formalizes a useful candidate filter: any proposed "semantic-state folding" must first establish that its public representation prevents copying/forking and graph exploration without assuming an unimplemented secret evaluator, while retaining every-original-witness correctness.

The next equation is still the missing source-conditioned, serialized polynomial-time operation

`C=Build_inc(x_W,S;rho), Open_inc(C,w)=S for every R_original(x_W,w)=1`

with complete-public FALSE and hard-TRUE QPT recovery/native forgery reduced to actual original evidence or justified independent breaks. The graph lemma has not instantiated it and is **not a breakthrough**. No Core, Bitcoin network, native signature, hash-work measurement, local checker, PR comment, deployment, transfer, production/workflow or automation changes were performed. Preserve the task enabled under the specified completion gate.
