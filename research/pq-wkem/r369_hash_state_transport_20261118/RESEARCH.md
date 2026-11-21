# R369 — Global hash-locked state transport: an anti-splice restricted compiler, not ORIGINAL release

**NONQUALIFYING research checkpoint.** No notification or PR progress comment is justified. One bounded local construction/reproducibility iteration was performed; no actual Bitcoin/Syscoin certificate, real Bitcoin script admission, quantum proof, or source-dependent public release was constructed.

## Source continuity

Started from the open/draft syscoin/PVUGC PR #1, branch research/pq-wkem-validation-20260918, SHA 11ab1e6facba7311efda02d1f5e37660b2a1fb23 (R368). R368 research file blob 40ffcf726ed151308961c3ed1e7190d346c6bb41 and R367 file blob de8839deb0be1f813eb8dba2ca81cf7097bd35df were read. PR issue comments since 2026-11-18T18:27:00Z were empty. The latest Core #609 source was not reread and no Core test was run. The prior conditional FE design remains unimplemented.

R368 public matrix layers permit independent local choice for each repeated variable occurrence, allowing a product with inconsistent occurrences to recover the target even for a FALSE relation. The *new mathematical change tested here* is to publish a global directed state graph with edge encryption keyed by the immediately preceding state's hidden label. No arbitrary local clause readouts or independently addressable occurrence labels exist. This is a change in the splice premise, not a claim of cryptographic security.

## Exact Build/Open for an explicit state graph

Fix a finite directed, layered, explicitly represented automaton G_x=(V,E) with root r, accepting set A, edges e=(u,b,v), and the promise that paths from r into A correspond exactly to witness strings accepted by its (restricted regular) relation R_x. Build samples independent 256-bit labels k_v and publishes root label k_r. For every edge, publish

    c_e = k_v XOR SHA256(enc("EDGE-v1",k_u,id_e)).

For every accepting vertex a, publish

    d_a = S XOR SHA256(enc("OUT-v1",k_a,id_a)).

The capsule is the graph, its labeled ciphertext edges and accepting outputs, the known root label and their canonical domain encoding. Builder work and size are O(lambda*(|V|+|E|)). A public opener follows one complete witness walk, deriving the state label at each step from the correct edge and previous label. At any accepting vertex a it decrypts d_a and returns S. All accepting paths, including different paths merging in states and different accepting vertices, return the **same** frozen S, without requiring a common witness preimage or canonical future source history.

This is cryptographically global in one narrow sense: combining an edge ciphertext with a label for the wrong predecessor does not give its advertised next label, except through a keyed-hash collision or lucky guess. It does not prove unrestricted security from the whole public representation.

## Public FALSE and hard-TRUE examination

If no accepting vertex is reachable, all accepting output masks use hidden state labels. In a classical lazy-random-oracle experiment, assuming every such key remains unqueried, the pads at accepting vertices can be coupled to independent uniform 256-bit outputs. Then the entire false-instance public view is independent of the frozen S up to hidden-label discovery. This is a **conditional classical ROM argument**. Concrete SHA security, arbitrary advice, coherent QPT oracle access, auxiliary native-VK correlations, sibling capsules and malicious setup are NOT proved. The checker only verifies functionality; not this indistinguishability theorem.

For any *explicit* graph with polynomially many vertices/edges, however, an attacker runs ordinary public breadth-first graph search, ignoring ciphertexts, and extracts an accepting path in O(|V|+|E|) whenever one exists. The graph already gives a polynomial witness finder. The checker finds an accepting 6-bit witness by BFS without mining or decoding the secret. Consequently this cannot express the intended **hard-TRUE original source acquisition bound**, unless the original relation has an unexpectedly efficient witness finder. This is not a generic impossibility of source-specific witness encryption.

A source verifier expressed as a polynomial-size Boolean circuit is NOT thereby an explicitly enumerated polynomial-state graph. The original SHA256d/AuxPoW verifier has hundreds of bits of intermediate state and arbitrary unknown future header inputs; enumerating all states and transitions can be exponential. We assert no blanket lower bound for SHA circuits or for arbitrary variable ordering. The graph construction remains restricted and is not a practical original Build.

## Constructive attempted repair and exact remaining equation

To support arbitrary future headers without enumerating all state/input transitions one needs a public compact key-transport evaluation

    T_C(xi,h) = k_delta(xi,h) XOR SHA256(enc("edge",k_xi,xi,h))

which provides a path-independent label at the resulting logical state for **every** relevant authenticated original transition, but does not expose accepting labels through other public computations.

Sampling labels as PRF_t(xi) under a secret builder seed only lets the builder generate transition entries; it does not publish a public on-demand transition algorithm. Publishing t exposes the accepting masks and S. Publishing an opaque evaluator that hides t would itself require the missing protected FE/release construction and is not a repair. Conversely the simple publicly computable update k_next=H(k_current,xi,h) makes labels path-specific: distinct valid histories merging at a logical state generally have distinct keys, so a single frozen output mask cannot be precommitted to all of them. A correction for each possible incoming edge returns to the unenumerable table.

Therefore **no practical, serialized classical-PPT ORIGINAL Build/Open, no full-public FALSE/hard-TRUE QPT reduction, and no PoW cost theorem** were achieved. The exact next equation is a succinct global source-conditioned public key transport compiler, with a full public simulator, which neither leaks accepting labels nor permits paths inconsistent with the ORIGINAL verifier. Simply *assuming* such a compiler is assuming the missing FE-like functionality.

The ORIGINAL relation is unchanged: qualified strictly greater Bitcoin work, OR finite authenticated claim-specific burn fault, OR qualified actual Syscoin history inconsistency / independently authenticated tag fault at required LC depth. Modern strict contextual chain ID/tag/AuxPoW binding, all anchors/windows/claim/UTXO/amount/recipient/deadline/reset/safe-message/VK/capsule binding, and the correct outer-carrier fault type remain required. Distinct valid parents for one child are not a fork; identical stale tags alone do not disprove history consistency. The work bound concerns obtaining original evidence, not each canceller individually mining. There is no extra Syscoin-work threshold or online second notary.

## Executed checker and limitations

Two separate local Python3 executions completed successfully and produced byte-identical JSON. Local checker SHA256 ef2a7b602df178f69276ee461cb1a0f5526409e58e6ca1cf46b0b50af2559d4c; both JSON SHA256 ba9f084b071a65df2c342b3740b613f232f7250fc53cd46a47eae79833e4f686. In the synthetic six-bit, 13-state, 22-edge automaton, all 32 accepted paths yield identical S; the FALSE instance has zero accepted paths. BFS finds accepted word 100000 on TRUE and none on FALSE. Two FALSE capsules with different payloads and identical random coins have identical edges and roots but different accepting ciphertexts. This is NOT a security experiment or a source authenticity test.

The exact executed checker and captured outputs are in the adjacent files. No real AuxPoW source, Bitcoin VM, native signer, quantum attack/extractor, malicious setup, or deployed network property was tested. No ordinary PR comment, Core edit, production edit, deployment, fund transfer, or automation change.

**Do not repeat this run with bigger explicit state graphs.** Further work is justified only by actually compiling the succinct ORIGINAL source-dependent transport together with independent complete-public security, or by a mathematically new mechanism that avoids this missing operation.