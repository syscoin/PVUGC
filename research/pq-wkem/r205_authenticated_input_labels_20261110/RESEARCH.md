# R205 — Source-authenticated Boolean-garbling input-label compiler, full-public failure and attempted repairs

**Classification:** substantive hash-only ORIGINAL-release construction/repair attempt; **NO completed key release, no qualifying bridge breakthrough**. The tested public-input-label scheme has a deterministic FALSE-instance break even with perfect SHA. This note is a negative checkpoint and should not generate a routine PR progress comment.

## Provenance

Repository syscoin/PVUGC, existing draft/open PR #1, branch research/pq-wkem-validation-20260918; observed starting head 2526e4747ea0e192a2dd92dbd459bae8b67b412b. Latest read exact R204 source-activation checkpoint: research/pq-wkem/r204_static_slot_compiler_20261110/CHECKPOINT_01.md, blob a3a9c21a92db26fc5d6c793e1d7effd7e0631dc1. Read R203 MASH source Merkle normalizer (blob 06c1da021ae998aa54544b468928d9fb32d247a5) to avoid duplicating its single-root pad argument. Latest ordinary PR comments since 2026-11-10T12:00Z: none. The intermediate R205 hypothesis was committed at 392c4c8a67822b4e71fd2150af35226f708dcfb9, with parent 2526e4747ea0e192a2dd92dbd459bae8b67b412b. No external web/literature, independent agent, other repository modification, production changes or QPT simulation.

## ORIGINAL target, and what is/isn't inside this experiment

The original bridge challenge is a public OFF-CHAIN relation: R1 strictly higher cumulative-work relevant Bitcoin competitor, OR R2 actual claim-bound missing/invalid proof-of-burn, OR R3 qualified conflicting Syscoin claim-prefix history or authenticated AuxPoW tag fault, respecting activation, real header/coinbase/Merkle/ancestor proofs, tag parsing, relevance, source heights/windows, and Bitcoin chain qualification. One notary initiates within an N-of-N preauthorized spending graph; ANY watcher with qualifying evidence must recover a **fixed**, path- and claim-scoped native cancellation capability from the same capsule. No Bitcoin VM/proof verification, online label issuer or new source signing obligations are permitted. R204's mutable SegWit activation is independent and not decided in this run.

Here we examine only an attempted hash-garbled ORIGINAL Boolean verifier's **public label interface**; no complete SHA256 circuit, source verifier, native signatures or Bitcoin inclusion were implemented. Honest classical PPT algorithms and arbitrary QPT adversaries with complete public programs, keys, manifest, sibling capsules, auxiliary input and source history remain the intended model. All attacks below are classical straight-line, hence fall within QPT, without relying on random oracle hardness.

## G205: genuine Build/Open-shaped attempted gate

Build samples two private 256-bit labels L[i,0], L[i,1] for each Boolean verifier wire, and garbles each binary gate g. Let A[a], B[b] be input labels and O[v] output labels. Publish 4 permuted rows

    G[a,b] = O[g(a,b)] XOR SHA256(domain_row, context, gate_id, A[a], B[b]).

NOT has two analogous rows. Freeze native signature sigma and publish

    D = sigma XOR SHA256(domain_out, context, O[1]),
    CK = SHA256(domain_check, context, sigma).

The intended honest Open maps one ORIGINAL evidence witness w to source-wire labels, evaluates a hash-garbled SHA/AuxPoW/PoB/chainwork verifier and, upon reaching output label O[1], computes sigma = D XOR SHA256(domain_out,context,O[1]). This is source-verification *inside* the intended garbled evaluation, not an honest post-hoc if-check. But correctness on honest evaluations is insufficient: the adversary sees all public rows, the input encoder and any other capsules. No internal trace or representation is required from the adversary.

The first public-input scheme publishes both L[i,0] and L[i,1], allowing any future source-witness input bit. A related scheme derives them as H_label(fixed_public_source_anchor,i,b). Both are full-public label issuers; a Boolean bit or a hash of a public source anchor does not authenticate the original certificate.

## Exact unconditional FALSE-instance break: local wire saturation

It is not enough to say an attacker can choose a *fake witness*: the honest garbled verifier would reject a fake witness if its internal wires were globally consistent. The actual attack is **local gate occurrence mixing** across incompatible Boolean evaluations, which recovers an accepting output label even when no satisfying witness exists.

Choose the unsatisfiable relation

    R_false := exists b in {0,1}: b AND (NOT b) = 1.

Construct a NOT gate using input wire x and a subsequent AND gate taking x and NOT x. Honest evaluation at either b=0 or b=1 yields rejection output Z[0], never the frozen signature. The public adversary, holding X[0] and X[1], evaluates the NOT gate on BOTH values, learns Y[0] and Y[1] and then independently feeds (X[1],Y[1]) into the AND gate. These wire labels correspond respectively to x=1 and NOT x=1, which cannot coexist in a single global witness. Nonetheless each local row decrypts correctly, so the accepting output label Z[1] and sigma are recovered. The fixed checking key accepts sigma. No hash collision, preimage search, or legitimate ORIGINAL witness is involved.

A concrete published reproduction implements NOT and AND garbled rows with SHA256 domain-separated pads, 256-bit per-wire labels, point/permutation bits and a frozen 32-byte test signature:

    unsat_circuit_checker.py, Git blob f50a8333306fc6a633d513457c04beedd3fea30d
    unsat_output.json, Git blob 1b92d302549b8bc77a8361c5a02942550380992f

The checker was actually run twice locally with byte-identical output: 128 seeds, 256 honest evaluations that all reject, 128 mathematical empty-relation checks, 128 explicit unauthorized accepting-output recoveries and 128 gate-saturation checks: 640 functional assertions. This is a synthetic cryptographic counterexample, not a real SHA or QPT experiment. It establishes a break against *this public-label circuit garbling* even for a FALSE Boolean relation. The attack is permitted to an arbitrary QPT adversary because it is entirely classical.

For nonconstant binary gates the broader pattern is inductive: knowing both labels for both local gate inputs permits evaluating all 4 rows; if the gate produces both outputs over its truth table, both output labels are exposed. This does not automatically imply every globally unsatisfiable circuit leaks through constant/other gates, but disproves G205's proposed generic guarantee. Crucially, using the SAME variable label on its two occurrences does not block the mixed-input attack.

## Repair A — only one source-authorized label per input

A private-input garbled circuit is meaningful if only the correct wire labels are revealed, in a globally consistent assignment, to an authorized evaluator. But actual Bitcoin/Syscoin ORIGINAL evidence consists of SHA headers, parent-coinbase commitments, Merkle paths, authenticated tags, height/lag and source records: it does NOT contain G205's setup-sampled secret wire labels. A future source witness cannot manufacture L[i,b] from its ordinary bits unless Build supplies a cryptographic encoder. An online label issuer or secret-holding source signer is expressly excluded. Prepublishing only one choice per input bit prevents some honest ORIGINAL witnesses needing the other bit; restoring both choices recreates the attack.

Putting the labels in a public procedure reading "if VerifyOriginal(w): return private labels" is *not* a repair unless one constructs and proves a full-public secure representation of that procedure. Plain program constants can be extracted, and a separately checked honest Open is bypassable. That secure conditional label issuer is effectively the missing ORIGINAL-dependent release algorithm and cannot be assumed as a primitive.

## Repair B — bind labels to future authenticated SHA/AuxPoW transcript

Try L[i,b;w] = SHA256(domain_label, x, SHA256(FullOriginalEvidence(w)), i,b). This makes labels dependent on actual source evidence rather than a free b. However w is generated AFTER the frozen cancellation setup. Two different qualified ORIGINAL witnesses w1 and w2 will typically have distinct SHA transcript hashes t1,t2 (the checkers exercise this only as a fixture, not as a security theorem). Rows garbled for t1 cannot decrypt under labels computed for t2. Build cannot precommit a single fixed table and terminal pad, violating every-witness SAME-capability completeness. Replacing t(w) by a fixed, publicly known claim/source-prefix t0 lets setup pre-garble, but everyone can derive both labels for both bits, reopening the previous attack.

Hiding t0 from attackers makes the input encoder unusable for arbitrary permissionless watchers unless ORIGINAL evidence *itself* exposes the fixed hidden t0 when and only when a qualifying fault happens. No such source-certified secret in the ordinary AuxPoW/tag/Bitcoin work evidence has been constructed. A simple Merkle commitment or its root-child pair does not create it: the prior R203 checker established nonchallenge membership can expose root children and dishonest source builders may retain them. A post-hoc source predicate after decryption is not enough.

## First toy checker and results

    checker.py, Git blob 78cb14a268e45376c327d64d67ade0d93a06be05
    captured.json, Git blob 3f6f7fa5822ed90e60a87926e7d0e73af740d485

Actually executed locally twice, byte-identical results: 128 SHA256-garbled 2-input AND fixtures, all 4 truth-table rows each, fake public-label accepting input, public source-anchor label derivation, and future-transcript mismatch. 1,152 functional assertions. In the script the source SHA256 is 42bc7de7b73fcd0985c9384dad1bbb78d05ab6489d22a90bbfc62ca888fb6b05. The unsat checker source SHA256 is 9272bad6ee46e5ad38a072bb8a3a81214bdd1fdd469e86af2cc4586962d2c71b. SHA output inequalities in deterministic fixtures are not proof of quantum collision resistance; the public-label attack itself needs no hash hardness break.

## Exact uninstantiated equation and next constructive step

Neither repair supplies a public SHA-dependent Build/Open pair for the ACTUAL ORIGINAL R1/R2/R3. Full-public FALSE secrecy and hard-TRUE QPT extraction remain absent; malicious N-of-N setup, related capsules, source-selected/retained coins and the native Bitcoin endpoint have not been discharged. Do not optimize this restricted garbling, or claim a secure source compiler because a verifier circuit can be represented in Boolean form.

A viable next step requires a fixed polynomial-size public capsule and a **globally consistent, computationally inaccessible evidence-input representation** under the *actual* SHA/AuxPoW authenticated source structure, without publicly mixable labels, without future unknown transcript-specific garbling, and without an online issuer or assumed WE/iO service. It must define the full-joint QPT simulator/extractor simultaneously. Specifically:

    Build_hash(R_original, x_slot, sigma_cancel) -> C  [classical PPT]
    Open_hash(C,w) = same sigma_cancel for EVERY R_original(x_slot,w)=1
    arbitrary QPT final-key recovery / accepted native forgery
       -> ACTUAL R_original witness or independently justified PQ break.

The present result is a precise negative regression about one attempted hash-only source gate, not an ORIGINAL construction advance. Store attempted equations/checks; no ordinary PR comment or user notification warranted under the reporting threshold.
