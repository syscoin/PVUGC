# Public-frontier hash-garbled verifier — NONQUALIFYING research

Start: syscoin/PVUGC PR #1, branch research/pq-wkem-validation-20260918, head d7c442e64dedbd682b25f04eb55f08152f2f00ea, tree 41a265e4ba042c0557317e8c67a7d5727940fe08. Read latest constrained-prf note blob b5ddef2a05c69fc05b1c82add11023aa0577d999 and preceding hash-braiding blob 471daa3490a7de924dc84dd80c9860f93323cde9. Issue comments since Nov 18 19:24 UTC returned empty. Read Core #609 PR metadata (head b3b4f643383a2149807a25fe38d26b5f058daa60), not its source; no Core tests or source-network data, no web/literature.

## Distinct algorithmic change
The last GGM puncture gave a public pad on invented indices and failed universal witness convergence. The braid gave a different pad for different qualified witnesses. The present construction is an ACTUALLY SERIALIZED, classical-PPT *globally linked hash-garbled deterministic finite automaton*, designed to prevent prescribed evaluation from mixing independent local SHA constraints. This is not a reparametrized public polynomial mask.

Let A_x=(Q,q0,delta,F) exactly decide a fixed-length binary relation, with witness length n and W=|Q|. Build samples independent random 256-bit labels L[i,q] for 0<=i<=n, q in Q. Publish the initial L[0,q0]. At each i,q publish a row identified by tag=SHA256("TAG"||i||L[i,q]) and two entries:

    E[i,q,b] = L[i+1,delta(q,b)] XOR SHA256("PAD"||i||b||L[i,q]).

At the terminal layer, for each q in F publish endtag=SHA256("ENDTAG"||L[n,q]) and D_q=S XOR SHA256("ENDPAD"||L[n,q]). Open starts with the one initial label, selects the corresponding row and supplied bit for each position, and decrypts the next token. It returns D_q XOR final pad if a matching terminal endtag exists, else bottom. All public rows are explicitly serialized; no evaluator authority or private program is assumed. Real Build would use independent secret randomness; the checker uses PUBLIC deterministic test randomness, never claimed cryptographic.

## Correctness and the obstruction
By induction, Open's label after the first i witness bits equals L[i, delta*(q0,w[0:i])]. Every accepting witness, including ones reaching different accepting states, therefore recovers exactly the SAME frozen S. A rejecting witness under the prescribed algorithm fails terminal lookup (except negligible random tag collision). This is actual classical polynomial Build/Open only IF n and W are polynomial.

But all rows and the initial label are PUBLIC. A separate attacker explores both b=0 and b=1 from every currently reachable label, deduplicating repeated next-state labels and carrying one representative prefix. Each layer contains at most W reached labels, hence O(nW*2) public row/hash operations reveal an accepted witness and the frozen S whenever one exists. This is a full-public frontier computation, not an external verifier bypass. It defeats an intended *large work-cost* claim if this small-width public automaton supposedly implements the hard ORIGINAL source relation. Importantly it outputs an actual valid witness, not a forged or invented index. It does not show unauthorized secret recovery without a witness. The published automaton may itself precompute/encode expensive source search, which must count toward the resource-bound experiment. A compact explicit state machine for a genuinely hard-TRUE relation cannot automatically be assumed.

Attempted repair: give each separate path a fresh nonmerging hash-token chain. The public frontier no longer merges, but a source-oblivious Build would need to create up to 2^n path-specific transitions. An algorithmically compressed replacement must implement

    HiddenNext(C,L[i,q],b) = L[i+1,delta_x(q,b)]

for the complete ORIGINAL SHA/AuxPoW verifier using polynomial publicly readable ciphertext bytes, while not revealing a publicly searchable polynomial state graph, arbitrary invalid-trace pads, or mixed local labels. A compact public algorithm for that operation was NOT constructed. Merely naming an implicit SHA delta or encrypted transition is a renamed FE/obfuscation assumption, not a solution. No exponential minimum DFA width for actual SHA is claimed as proved here.

FALSE semantics: the synthetic false instance has no reachable endtag; this proves reachability failure for prescribed Open and frontier BFS only. Full-public FALSE hiding, QROM security, coherent QPT adversaries, maliciously correlated keys, joint auxiliary/native VK, sibling selective opening and extraction are NOT proved. There is no simulator for the complete serialized public view.

## Invoked checker and outcome
Executed Python3 standard-library checker locally at /mnt/data/research/pq-wkem/public_frontier_gate_20261122/check.py, exit 0. It exhaustively checked 2^10 strings of a 4-state verifier: 1,023 accepting strings return the same synthetic S, the one rejecting string returns bottom. It built a 24-bit, 4-state automaton with 96 public rows; public BFS found the accepted 24-bit string 000000000000000000000001 and recovered S while visiting a total 72 frontier labels (max 3 per layer), rather than enumerating 2^24 inputs. An unreachable-accept-state FALSE fixture yielded no path under BFS; NOT a secrecy test.

Local executed checker SHA256 b1d2ef481ab1ed115e9d6d6b329f4164b56160f084486c2254b96013704fa8c4; captured output SHA256 eaca76f89d61659a10f63990991e85e321e0ff2792bb6dd71df56ade6e31e226. These are synthetic fixtures only: no source certificate, Bitcoin Script/VM, native signing, original verification, quantum test or setup proof. The code and output are preserved alongside this note.

## ORIGINAL status
The approved ORIGINAL source remains a disjunction: (1) qualified strictly greater exact Bitcoin work from the same anchor; (2) finite authenticated specific withdrawal burn refutation/nonmembership/complete bounded execution; (3) qualified incompatible Syscoin histories or independently authenticated relevant tag fault at required LC depth, WITHOUT extra Syscoin-work or winning-branch conditions. Binding includes exact claim/UTXO/amount/recipient/burn/replay, baseline/anchors/windows/reset/deadline, contextual strict post-PQ child chain ID/canonical parent tag, actual ancestor consistency, safe cancel message, native VK and capsule ID. R316 equal stale reference tags are no LC-detection defect. Different valid parents for the same child alone are no fork.

The 4-state DFA is an EASIER relation, not actual original Build/Open. No classical practical source-conditioned common-secret release for all authentic future original certificates, no full-public FALSE/hard-TRUE QPT recovery-to-ORIGINAL/native-forgery reduction, no one-honest malicious setup, R225 endpoint composition, or multi-capsule proof was found. Next exact constructive operation is a truly secure polynomial-size HiddenNext for the real source verifier, with a jointly simulated public capsule, or a different independently instantiated source-conditioned release mechanism. Repeated toy width increases are not progress.

NONQUALIFYING; no PR comment or user breakthrough announcement, no production/Core write, deployment or automation change.
