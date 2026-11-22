# SAI107 — Confluent hidden SHA-state transducer (NONQUALIFYING)

## Source / exact unfinished step
Read live draft syscoin/PVUGC PR #1, branch `research/pq-wkem-validation-20260918`, head `607defdc8ca4b1349a6c7df05263ba9a90fe9529`, and SAI106 RESEARCH.md blob `303295f77263ac010fcf196ec6e756f93e91fca4`. Recent scoped issue comments since 2026-11-18 19:24 UTC were empty. Read Core #609 PR metadata only; did not inspect current source/test or run Bitcoin/Core/FE. No external browsing. Earlier SAI103, SAI105 and SAI106 were read narrowly to distinguish this from another input-label or prefix seed test.

SAI106 failed because both garbled input bit labels are public, permitting inconsistent gate-label splicing. This candidate changes the cryptographic state: attach each secret label to the *whole semantic verifier state*, so a permitted next label represents one coherent input prefix. The new question is whether such state labels can be computed implicitly for SHA/AuxPoW without an exponential transition table, secret online issuer, or public release of the accepted-state key.

## Exact candidate and Build/Open over explicit finite-state machine
Let a fully bound deterministic streaming verifier for original relation R_x be q[t+1]=delta_x(t,q[t],b[t]), with start q0 and acceptance a. Its state must encode complete exact claim/UTXO/burn/amount/recipient, source anchors/windows, header/target/AuxPoW/tag/ancestry/maturity, and the three original OR grounds. This source transducer is a *specification*, not implemented.

Build chooses random 256-bit k[t,q] for every explicitly enumerated state at each layer, fixes common terminal K for accepting states, and publishes
    C[t,q,b] = k[t+1,delta_x(t,q,b)] XOR SHA256(encode(domain,x,t,q,b,k[t,q]))
alongside start key k[0,q0] and D=S XOR SHA256(encode(terminal,K)).
A public Open that follows exactly one whole input and its deterministic state transitions inductively recovers each next state key and S on acceptance. Different satisfying inputs converge to the same K. Unlike SAI106, arbitrary selection of bits across steps still describes *one actual input prefix*; unrelated internal labels cannot be selected without obtaining their corresponding state key.

This is classical Build/Open only in the size of the EXPLICIT graph: O(lambda*sum_t |W_t|) secret labels and O(lambda*sum_t 2|W_t|) public bytes. This repeats the SAI103 explicit-DAG limitation in a different, semantic state-machine encoding. If the graph is polynomial-size and every accepting path decodes into an original certificate, BFS finds that certificate in polynomial time. It is not a bridge-strength hard-TRUE release compiler.

## Implicit construction/repair attempt
(1) Public GGM/SHA forward state: k(prefix||b)=SHA256("deleg"||k(prefix)||b) is compact and allows all input prefixes. However two paths p and r that reach the SAME semantic verifier state q generally have different labels, k(p)!=k(r), and their suffix decryptions do not converge on one terminal K. This is a new *confluence* requirement, not just local label availability.

(2) Canonical public semantic label: k[t,q]=SHA256("state"||t||q) makes all paths entering q agree, but the accepted terminal key is immediately public and D reveals S without a source certificate. This is a direct full-public violation.

(3) Secret semantic labels with public corrections: put k[t,q]=SHA256(s||t||q) for independent secret setup salt s. One ideal correction equation is
    Delta[t,q,b] = SHA256(s||t+1||delta_x(t,q,b)) XOR SHA256("deleg"||SHA256(s||t||q)||b).
Then a holder of k[t,q] can derive the successor's canonical label via SHA256("deleg"||k[t,q]||b) XOR Delta[t,q,b]. This is correct for all witnesses and avoids independent input-label splicing *if* correct Delta values are provided. Build must know s and enumerate each possible q to publish Delta. Publishing s reveals the terminal label. Replacing the table by a public short keyed-Correct program without exposing s and without permitting off-path forgery is the absent cryptographic primitive, not an implementation supplied here. An ordinary ZK/SHA verifier outside Correct or a Merkle commitment to unseen tokens does not make it secure.

The genuine missing equation is a polynomial-time serialized public mechanism satisfying
    PubDelegate(x,t,q,b,k[t,q],C) = k[t+1,delta_x(t,q,b)]
for source-consistent states/transitions and the SAME frozen S for every ORIGINAL qualifying witness, with complete-public FALSE and hard-TRUE QPT security and a reduction to ORIGINAL certificates or independently justified hash/native breaks. Arbitrary public processing (not just prescribed traversal), auxiliary data, sibling capsules, malicious retained source coins, one-honest N-of-N setup, and native claim binding must be covered. No such Build, simulator or QPT proof exists here. The current first-release ECDSA Bitcoin endpoint does not itself have native QPT unforgeability.

## Executed bounded falsification / provenance
Executed a Python3 SHA256 checker twice, byte-identical output: a deliberately truncated 8-bit SHA semantic-state machine with 10 input bits. Paths 0000001101 and 0000010111 map to the same semantic state 0x5a, while their iterative hidden labels differ. Canonical *public* label recovers test-only S without any path. This models confluence only; it does not demonstrate a Bitcoin/Syscoin SHA hash collision, original challenge, FE, native signing, source admission or QPT security.

Checker SHA256 25e9358aae11e2f0a87c32ee4a1de571408dc84e458006ba376b509da177abfd.
Both captured JSON outputs SHA256 3ef8c81d7833368b0e011e59f34bff22089b9be79254d59587d30fe020f9308b.
Full local derivation/checker/output archive SHA256 8482a03598e044ae875bac337bbf58c914aec87d8016f6b2be04fb8331cbb5cc.
This is not a construction advance, so no top-level comment or user notification is warranted. Do not retry an equivalent GGM/public-label/correction-table variant absent a new non-circular source-dependent public computation.
