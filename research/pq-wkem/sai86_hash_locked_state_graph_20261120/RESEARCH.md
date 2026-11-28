# SAI86: hash-locked global-state release (NONQUALIFYING)

## Continuity, candidate-selection test

Read open draft PVUGC PR #1 at 952cb6a10644dcfd8c8b1fdd279602d256a0ec0a, branch research/pq-wkem-validation-20260918; exact SAI85 note blob 7b141fa2ca91f06d0fbe87d3c53c7acfe4b64f8f. Issue comments since 2026-11-20T22:49:00Z returned no new entries. This run did not use web/external literature, read Core #609 source, rerun Core tests or inspect an actual source certificate. The original strict post-PQ AuxPoW relation remains unchanged.

SAI85 precomputed a table for every accepted witness, requiring exponential enumeration. THIS attempt instead makes the nontrivial structural change of using one secret label PER GLOBAL VERIFIER STATE, shared by all different prefixes reaching that same state. This enforces the same-key property globally and does not expose per-clause outputs to splice. Its exact unfinished repair is succinct state merging on actual SHA/AuxPoW traces, not another hash-prefix, affine polynomial or independent puzzle.

## Classical explicit Build_A / Open_A for a layered deterministic automaton

Input: an explicit public length-n layered deterministic automaton A_x, layers Q_0,...,Q_n, initial state q0, transitions delta_i(q,b), accepting terminal set F_x subset Q_n, with R_x(w)=1 iff the SINGLE complete run on w ends in F_x. This is a restricted relation unless a practical authentic original-source compiler is supplied.

Build_A(x,S), security parameter k=256, public domain-separated SHA256 calls (modeled as independent random oracles only in the stated ideal argument):

- Sample independent hidden random labels L_(i,q) in {0,1}^k for EVERY layer/state. In particular, different paths merging into state q receive the IDENTICAL successor label L_(i,q).
- Publish the initial label L_(0,q0). For each nonterminal state publish a lookup record addressed by T_(i,q)=H_tag(sid,i,L_(i,q)) with two ciphertexts:

    E_(i,q,b) = L_(i+1,delta_i(q,b)) XOR H_pad(sid,i,b,L_(i,q)).

- For each accepting terminal q publish an entry addressed by U_q=H_endtag(sid,n,L_(n,q)) with D_q=S XOR H_out(sid,L_(n,q)).
- The public C comprises sid, n, initial label, unordered transition table {T:(E0,E1)}, unordered output table {U:D}, public x and manifest. No private evaluator or external source signer is used in this restricted algorithm.

Open_A(C,w): Start with the initial label. For every input bit b_i, look up H_tag(sid,i,L_i) and decrypt E_b with H_pad(sid,i,b_i,L_i). At depth n, look up H_endtag(sid,n,L_n); if an output ciphertext exists, XOR it with H_out(sid,L_n) and return the resulting S; otherwise bottom.

Correctness follows by induction on the deterministic transitions. Every accepted global w, including different w merging into a state or ending in different accepting states, opens the SAME frozen S. This is an actual serialized hash-only, classical builder/evaluator for the EXPLICIT finite-state relation. Build uses O(sum_i |Q_i|) labels/edges and Open uses O(n) hashes. The semantic source relation, not an optional post-output if-check, determines which output label is reachable.

## Honesty and security scope, not a full theorem

For an honestly generated FALSE explicit graph, accepting terminal states may still exist but are all UNREACHABLE from the released start label. Their labels are fresh and hidden behind independent RO pads on all incoming unreachable-parent edges; their output ciphertexts mask S by H_out at inaccessible labels. In the classical domain-separated ROM, condition on no adversary RO query guessing any inaccessible label and no tag/pad collisions. Then the full public ciphertext transcript and all reachable-state oracle values are independent of S. For N hidden labels and q classical oracle queries, brute-force and collision terms scale with q*N/2^k and N^2/2^k, with no sharp constant or full joint proof claimed. This is not an unconditional claim for SHA, and not a QPT/ROM-programming, native verification-key-correlated, sibling-capsule, source-generated-secret or malicious-setup theorem.

The public graph has a stronger property that blocks a misleading "hard-TRUE" claim: BFS from the initial state over the EXPLICIT transition graph finds an accepting complete input in O(sum_i |Q_i|) operations if one exists. The public hash-locked table itself can be traversed by decrypting BOTH bits at each reachable state label and storing a representative full prefix; this yields a satisfying input and S. No hidden query-log extraction from the adversary is needed for this SEARCH. Consequently, a hard PoW search language cannot have a practical, polynomially explicit verifier-state graph that the builder can construct before future history exists, unless an accepted certificate was already efficiently obtainable. This is a cost limitation of this particular construction, NOT a general hash-only impossibility theorem.

For original Bitcoin/Syscoin claims, the graph would need to represent the ACTUAL original authenticated history predicate: all relevant contextual retarget rules, exact AuxPoW parent/child Merkle and canonical tags, same-anchor BTC chainwork, ancestor-height and LC-depth checks, claim/UTXO/burn/amount/recipient, windows and resets, as well as future chain membership. Nothing here constructs that graph efficiently or authenticates real Bitcoin best-chain status. A simple SHA target below does not qualify as an ORIGINAL witness.

## Precise failed repair: compact SHA state chaining

Replacing the O(number of edges) stored transition table with the compact public recurrence L_(i+1)=H(sid,i,L_i,b_i) eliminates the vital convergence. Distinct path prefixes produce independent random oracle inputs and, absent collisions, distinct next labels. For M distinct generated RO outputs the probability of any merge is bounded by M(M-1)/2^(k+1). Therefore this compact raw-hash rule gives 2^n distinct terminal labels for n binary choices, even if the public verifier has many semantically merged states. That is not a secure common-value release. Publishing L_(i,q)=H(q) instead permits arbitrary STATE INJECTION: an attacker supplies a guessed accepting state description to obtain its token without a corresponding original certificate. A PRF with hidden seed in an executable public transition program is still an uninstantiated secret circuit. Neither variant is a repair.

The indispensable missing equation is a practical, AUTHENTIC SOURCE-CONDITIONED NONSPLICEABLE, secret-many-to-one transition map:

    SuccinctMerge_x(C, L_(i,q), b) = L_(i+1,delta_i(q,b))

with independent fixed destination labels despite exponentially many possible authenticated SHA/AuxPoW predecessors, without revealing injectable terminal labels, a secret-logic program, an explicit exponential table, an independent puzzle, or a new nonhash assumption. Build/Open and its complete-public simulator must be developed TOGETHER; naming this interface FE or obfuscation does not instantiate it.

## Executed local computation (strictly toy)

The standard-library Python checker was run twice with independent fresh secrets.token_bytes(32) labels and S. Its redacted semantic JSON outputs were byte-identical. Exhaustive validation: 512 nine-bit strings on a mod-7 merged-state graph, TRUE target 3 accepted 84 inputs, and FALSE target 8 accepted none while an actual unreachable terminal ciphertext was still in the public capsule. There were 162 public transitions per mod-7 case; BFS explored 84 reachable edges. A separate fabricated 80-byte-header-shaped SHA256d puzzle with 12 nonce bits used an EXPLICIT prefix trie (8190 public transitions) and accepted 34 out of 4096 inputs. Every accepted word returned exactly the same synthetic 32-byte S; invalid words returned bottom. BFS returned accepted paths. This is NO actual Bitcoin/Syscoin block, no AuxPoW/claim authentication, native ECDSA, ZK/FE, full quantum attack, or practical construction for the original relation.

Local archive /mnt/data/SAI86_hash_locked_state_graph_20261120.tar.gz SHA256 f7d563d2ad76d12edcfd5582a956378f631a84d6dfaf32bbe96b661a806857af. Checker SHA256 0e48f706e8875199d4325b3be6a8b962413af0604530e63f6b0945bb93d73066; output1/output2 SHA256 f56240062e1ba3a9f4bc451292323b704eee4a768434d03ff290b142bd87cdee. These exact bytes were executed locally. The checker/output are only in the local archive unless separately published; the GitHub research note is a precise handoff.

## Required continuation and disposition

NONQUALIFYING. The construction is correct for an EXPLICIT automaton but has no classical practical PPT Build_orig(x_W,S) or Open_orig(C,w)=S for every qualifying ORIGINAL strict-PQ source certificate, no complete-public FALSE/hard-TRUE QPT recovery/native-forgery reduction, no malicious setup/capsule checking proof, and no practical proof of obtaining original source evidence within the work budget. Do not notify, publish progress comments, or claim release readiness. The conditional one-honest independent participant setup and first-release native ECDSA message binding from the earlier FE study do not repair the missing source gate. No Core, production, deployment, automation or other-repo change.
