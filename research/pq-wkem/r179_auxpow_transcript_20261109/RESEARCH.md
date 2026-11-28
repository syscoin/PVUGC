# R179 — Byte-tethered SHA/AuxPoW source transition and unsolved challenge-key release

**STATUS:** An implemented *partial authenticated-source verifier* for a synthetic Bitcoin/Syscoin AuxPoW pair, plus a demonstrably broken key-release attempt. **Not a witness-KEM, not an authenticated Bitcoin-mainnet inclusion proof, not QPT secure, and not a cryptographic breakthrough.** The user's one-of-N withdrawal / anyone-can-challenge / N-of-N preauthorization model is unchanged.

## Continuity and exact executed evidence

- \`syscoin/PVUGC#1\` on \`research/pq-wkem-validation-20260918\`. Actual starting head \`d08a082c0dbb68c1398a0d295724d907bd4267c8\`; intermediate in-progress checkpoint \`025e81a6ad02491e89a9463fbdd8e83233c7ce38\` was published *before* execution. No previous-run replay or full PR diff was read.
- Read exact R178 research blob \`ad1d0d1120f57b0de625952ebb73e10e1dbf5b2d\`; it already rejected public digest buckets, fixed-anchor pads and miner tickets. The new pass focuses on the byte-originating SHA/AuxPoW authentication transition.
- Read only the user's pinned source \`syscoin/syscoin@1180dad257fb3cda797187f51ccc519b684e148d\`: \`src/validation.cpp\`, \`src/auxpow.cpp\`, and relevant \`src/auxpow.h\` constants (\`sys\` and \`fabe6d6d\`). No external web/literature or independent agents.
- **Exact executed source, stdout and run manifest** in \`EXECUTED.tar.xz\` (xz-compressed tar; extract with \`tar -xJf EXECUTED.tar.xz\`). This is an exact binary archive, Git blob \`551cabe48389ed50002d8eb616c9293c8bdcb5fa\`, matched to local git-object SHA before publishing. Its \`checker.py\` SHA256 is \`85db94c675ccc1444e784aef30afb92e82ca05620cb3799c770531a83ce39b5f\`; \`captured.json\` SHA256 is \`40f7a63f247ccae5ccf5e56257ac786c00c2c4ecb037c1016448b0e8e0435310\`. Executed twice, byte-identical output. \`402\` functional assertions, no QPT experiments.

## Original challenge semantics and source-authentication component

Target a fixed, immutable withdrawal context \`x_W\` binding vault/UTXO, amount, claim/burn, recipient, asserted source, anchors/window, source height, challenge deadline, native cancellation message/VK, and capsule ID. A one-of-N notary may initiate the withdrawal within the covenant graph; **any** qualifying original source witness for BTC higher conflicting chainwork, invalid/absent bound burn, or qualified Syscoin fork/tag fault must release the **same** claim-scoped cancellation package without online permission. An N-of-N graph does not itself enforce any of these predicates. This run analyzes the fork/tag branch only, not the other two release branches.

For active Nexus AuxPoW child at height \`n\`, pinned \`CheckContextualAuxPowTag\` uses the candidate chain's own ancestor at

    h_ref(n)=10*floor((n-6)/10)

and expects its 32-byte hash plus little-endian uint32 height in the parent coinbase's unspendable output **after** the first \`sys\` marker in that output. The source's parser is *not* a strict adjacent-tuple decoder, and duplicate marker-bearing **outputs**, not every repeated \`sys\` within one output, trigger its displayed multiple-tag check.

The new offline checker includes a real byte-format SHA256d implementation through Python hashlib of 80-byte parent headers, compact-target evaluation for deliberately easy regtest-like bits \`0x207fffff\`, canonical CompactSize for synthetic non-witness single-input coinbases, SHA256d coinbase txid/parent-Merkle linkage, empty AuxPoW chain-Merkle branch and deterministic index zero, pure child-header SHA256d identity and previous-child links, and the pinned contextual tag behavior. A separate partial predicate consumes caller-supplied child history and a **bound** height-100 source hash; it does not trust a private fixture oracle.

### Conditional source-certificate lemma, not key release

Given a *complete and correctly authenticated* \`Q_x(P)\` including the real Bitcoin/source anchors and original history rules, two qualified candidate histories with the same referenced height h but unequal correctly parsed tagged ancestor hashes certify incompatible Syscoin histories at h (up to SHA child-header identity failure). At different referenced heights one must positively authenticate the higher one's ancestor down to the lower height. Multiple parent work certificates for one pure Syscoin child do NOT constitute a fork. No chain-selection comparison is necessary for the qualified inconsistency predicate.

This is a source-verifier lemma conditional on the **missing full \`Q_x\`**, not evidence-conditioned key recovery.

### Actual synthetic tests

A common synthetic child prefix at heights 90–100 branches into two conflicting histories at height 101, each continuing to 116. \`32\` synthetically mined Bitcoin 80-byte parents (total \`66\` SHA candidate trials counting an alternate certificate) are linked in **one** easy-work test chain and contain coinbase commitments to the two Syscoin branch tips. At n=101..115, tags reference shared ancestors 90 or 100, while at n=116 both correctly reference height 110 with *different* hashes. This verifies the pinned 7–16 child-block visibility timing for this synthetic divergence but is NOT evidence of BTC main-chain inclusion.

Mutation tests reject altered child hash, coinbase, parent Merkle root, ancestor, source-history intermediate header and claim anchor; verify a second work certificate for the same child remains the same outcome; distinguish tag-fault outer authentication from a failed contextual tag. They also confirm **same-output duplicate marker acceptance**: a parent coinbase containing \`OP_RETURN || sys || expected || sys || wrong\`, or \`sys || wrong || sys || expected\`, can pass the pinned marker/expected-byte search. A bridge that labels those encodings tag faults when Core accepts them risks an unjustified cancellation. Missing required-tag faults must prove the complete relevant authenticated coinbase, not rely on partial bytes.

**Explicit missing source authentication:** Bitcoin best-chain/terminal anchor admission and full DAA, actual mainnet PoW/difficulty, full Syscoin state/auxpow and relevant interval tags, source-history and burn validity, lag/window/DA/censorship policy, and integration with the exact withdrawal transaction are not implemented. This synthetic local verifier can accept a private locally mined low-difficulty fork, which is **not an ORIGINAL qualified witness**. Its testbed is a future input-validation component only.

## Actual hash-only release attempt and raw break

Take an openly source-derived baseline ancestor \`a(x_W)\`. Let \`sigma\` denote a frozen **fixture** capability (not a native signature), and publish

    p = SHA256("baseline-pad" || context || a(x_W))
    E = sigma XOR p.

An honest \`Open\` that first checks both source transcripts and a tag contradiction returns \`E XOR p = sigma\` on true fixtures and rejects early/same-child cases. But an arbitrary adversary simply computes \`p\` and \`E XOR p\` from the **full public capsule** without supplying a witness or calling the verifier. This exact attack passed in the checker and immediately violates FALSE and hard-TRUE key-release security, independently of SHA preimage resistance or Grover speedup.

The natural repair \`p=H(future authenticated transcript)\` makes \`p\` unknown at Build, and different valid original transcripts produce different values. Setup cannot precommit an arbitrary fixed native signature's encryption under all such future pads without a **new cryptographic source-to-common-value correlation**. Selecting one future work digest violates every-ORIGINAL-witness completeness; inserting a secret label from a source actor adds signer retention/online issuance and is not in current consensus. R178 already rejected these direct patches. A byte-faithful source verifier is **not** that missing gate.

## The precise next construction obligation

Build a classical-PPT \`Build_hash(x_W,sigma_cancel)\` with public \`Open_hash(C,w)=same sigma_cancel\` for every fully qualified ORIGINAL challenge witness (all three OR branches), with authentication **inside the cryptographic release**, and demonstrate arbitrary full-public QPT recovery/native forgery => an ACTUAL original evidence witness or independently justified PQ break. Cover malicious N-of-N setup, auxiliary source-coin dependence, sibling capsules and selective openings. The single explicit failure today is the missing nonlocal correlated hidden terminal value; parser conformance and proof compression cannot substitute for it. Bitcoin should verify only an ordinary native cancellation path, no source NP/VM verifier or trace dispute.

No ordinary PR comment is warranted; the recurring research task must remain enabled.