# R301 — SHA256d parent-prefix states do not issue a source-earned key (NONQUALIFYING)

## Source and execution provenance

Continues R300 exact unresolved `SourceEarnedKey` at blob `8700adc2d90a2645ab453d744288b2a07189c45b`. Starting syscoin/PVUGC PR #1 head `1a22e0095a0f7e8fc90c5f0b42fdd3cc96d64dbb`, open/draft, branch `research/pq-wkem-validation-20260918`. Core PR #609 read-only metadata still `c91539de3c34937e57d7f5fda47c7b0502ff33f6` (not evidence of activation, no Core test run). Last substantive PVUGC ordinary PR comment read: R225 #6796383617, concerning separate native-signature activation leakage. No external literature/web.

Original three independent OR challenge grounds, exact semantic h_rel ancestor, claim/UTXO/burn/amount/recipient/source-anchors/window, modern contextual AuxPoW and exact 41-byte SYS tag, child-merkle root, certified faulty-parent provenance, depth, deadline/reset, capsule ID and safe native cancel message/VK stay unchanged. One notary initiates; anybody with ORIGINAL proof challenges. N-of-N preauthorizes offline. The toy fixture below implements **none** of the ORIGINAL admission, Bitcoin membership, LC-depth or native signature conditions.

## Concrete release construction and two repairs

The purpose was to test whether a SHA256 compression state common to competing parent-header candidates can give the missing setup-to-future-witness hidden-key bridge. Let `hdr_n=prefix76 || uint32_le(n)`, 80 bytes, and `p=SHA256_Compress(IV,hdr_n[0:64])`.

Candidate A, prefix-derived common key:

```
Build_prefix(x,S): E = S XOR SHA256("R301-prefix-pad" || p); publish (prefix76,E)
Open_prefix(C,w): after proposed source qualification, output E XOR SHA256("R301-prefix-pad" || p)
```

The first 64 bytes of every candidate parent are identical, so SHA's public compression state p is identical, and **publicly calculable**. The complete public package reveals S *before* any source evidence. This is deterministic FALSE recovery even in an ideal SHA model. No post-release `VerifySource` restores secrecy. The fact that p is a common value is NOT a hidden credential.

Candidate B, suffix-dependent pad: let `d_n=SHA256(SHA256(hdr_n))`; publish `E_0=S XOR SHA256("R301-suffix-pad"||d_n0)` for one known valid candidate n0. `Open(C,n)=E_0 XOR SHA256("R301-suffix-pad"||d_n)` opens correctly only when the keys match. An independently generated future qualifying parent generally has a different SHA256d digest. The setup cannot publish an `E_n` for *all* unseen future n with this single static pad. A public dynamic correction derived only from publicly available header data would also need to enforce ORIGINAL-source authentication *inside* secret release; a privately keyed correction cannot simply be invoked by a public noninteractive opener. No such issuer was implemented.

This is a restricted information-flow lemma about **this pair of hash-pad carriers**, not a lower bound for WE, garbling, obfuscation, random oracles, or concrete SHA security. Real competing parent headers can differ in Merkle root/coinbase, not just nonce; they need not share even the first block midstate.

## Exact bounded execution and proof boundary

`checker.py` implements SHA256 compression (including 80-byte padding), independently compares it with `hashlib.sha256` on 10 boundary sizes and 8,192 distinct 80-byte headers, then evaluates toy SHA256d work `digest[0]==0`. There were 38 qualified **toy** nonces. All shared exact prefix midstate `ab4a813ef8cf6d736e61a5e3a56cabd2ec4e09edb5633ec8a7b78815f8023934`, with 38 distinct final SHA256d hashes in this sample. The prefix-key ciphertext leaked S without evidence; a suffix-key ciphertext for the first qualified candidate failed to reproduce S for all other 37. Two executions: 16,437 assertions each, byte-identical JSON outputs. These measurements are regression tests, not evidence of a QPT theorem or consensus admission.

Full LOCAL reproducible archive: `/mnt/data/R301_sha_state_binding_20261115.tar.gz`, SHA256 `daf07c96836f6675a4ddeaab7dea9fde97c758d8751f7b716fdfa962c6475bb1`. This archive is a conversation-local artifact, not a GitHub source file. Its `checker.py` SHA256 is `735a039dbafe6a1e40d029da45ccce6a8ac3c8553f33f83980635909ab84802f`; `run1.json` and `run2.json` SHA256 each `c54d7bc6e2a5a9f40531dec9f497f23b1ca9f8688746a8e773e7ed3015736c9e`. Local archive also includes detailed derivation, provenance, and checker. This repository note does not claim to have committed the executable.

## Exact unresolved ORIGINAL-source obligation

Construct genuine classical PPT `Build_inc(x_W,sigma_cancel)`, public `Open_inc(C,w)`, such that every fully authenticated ORIGINAL challenge witness — including different future source parents and states — yields the **same frozen native-safe cancellation capability**. Independently prove complete-public FALSE and unauthorized hard-TRUE QPT recovery or native forgery reduces *without representation/query-log handoff* to an ACTUAL qualifying ORIGINAL certificate or an independent PQ hash/native break, under correlated auxiliary/sibling capsules, malicious ceremony and contextual source checks. The next equation is a **cryptographically source-earned, noninteractive, full-certificate-consistent issuer**, not a public shared SHA midstate or another post-extraction verifier.

Disposition: **NONQUALIFYING.** No PR comment, notification, production edit, deployment, or automation-stop is warranted.
