# R233 — Same-outpoint irreversible challenge release across nonmonotone source histories

**Research-only: an exact temporal policy condition, NOT an instantiated hash-only ORIGINAL Build/Open or QPT result.** R225 already identified different wtxids sharing one fixed pre-signed cancellation outpoint; this pass investigates how source challenge admission changing across reorgs affects any successfully released bearer signature. This is not promoted as a key-release breakthrough.

## Scope and provenance

PR #1 branch `research/pq-wkem-validation-20260918`, observed start `fb2cb0f47853bc3b5985453e68c56aa64be96458` (tree `38ae07b0464a5435d707a5cfa2a34c02def5b535`). Read current R232 `r232_source_label_gate_20261111/RESEARCH.md` blob `88cf22e9d42a4d94f5838c2ae1ec2aab12f298ec`; latest top-level PR comments since 2026-11-11 18:00Z: none. Intermediate hypothesis saved locally before executing the test. No web, external sources, real source chain, native signature, independent agent or QPT test. Original bridge remains one-notary initiation, ANYONE challenge, N-of-N preauthorization with one honest participant, three OR challenge predicates and fixed claim-scoped native cancellation.

Full local Python checker executed twice with identical outputs, 210 conditional functional assertions: source SHA256 `45906546f627eb2621b001f562085cb545df8437b2c1ef8126a723ee0241dc83`; captured SHA256 `dc900c65e681adc689fc6d2ef6381b5e1843ea1cf2a716e6e193161fe75e77db`. The full checker and output are LOCAL ONLY. A separately executed compact reproduction is included here: reproduce.py SHA256 `d04faa770d4fec02d8990a163448be75d6cb06f38bdda8b30a366fa0da032a6a`, reproduce_output.json SHA256 `46d48b25b0309b0d93c9126fccd18bb40d205f051cbe810d13b3d10575411784`. Fixtures serialize synthetic SegWit-shaped txs and use abstract source policy Booleans. These results are not consensus/security evidence.

## The exact persistence condition

Let `s` and `s'` be source-history states connected by a legal chain evolution/reorg, each retaining the SAME cancellable Bitcoin outpoint `O`, native message `M`, and native VK. Let `G_x(s)` mean **some ACTUAL ORIGINAL qualified work/burn/fork evidence** is admitted for the immutable withdrawal statement `x` in state `s`. Assume correct public release of frozen native signature `sigma` when `G_x(s)=1`. If `G_x(s')=0` but the native Bitcoin verifier still accepts `sigma` for `O` and `M` in `s'`, an attacker can cache and replay `sigma` in `s'`. Proof is a straight-line copy of signature bytes. This is information theoretic and holds even for perfect earlier hiding and any possible post-quantum mechanism.

Therefore for a policy requiring a *freshly qualified* challenge to cancel at each history, a NECESSARY condition in this fixed-outpoint bearer model is

    G_x(s)=1 and s ->* s' and same_native_outpoint(O)
         implies G_x(s')=1,

unless Bitcoin's native acceptance changes with the activation/history. Merely domain-separating a public WE capsule by activation wtxid, manifest root or source epoch does not affect an already signed spending message. This is a temporal **authorization** condition, not an impossibility theorem for hash-based witness encryption.

### Three ORIGINAL predicates and source admission

* Challenge 1: greater-work *competing* Bitcoin history relative to a frozen comparison anchor. Exact work against frozen headers is arithmetic; whether the competing history remains a currently admitted canonical candidate may change with reorg.
* Challenge 2: absence or invalidity of exact authorized burn in a fixed, consensus-authenticated root is an immutable Merkle statement (assuming proper root binding and hash soundness). Admissibility of that root as the relevant Bitcoin/Syscoin source can nevertheless change on reorg. No claim that Syscoin currently exposes a proposed sparse burn map.
* Challenge 3: proof that two FULLY qualified histories have differing pure-child ancestors by relevant claim height, with correct LC depth and all BTC/AuxPoW tags, remains an existing historical object. If qualification requires current canonical BTC inclusion or freshness, admitting the evidence can be nonmonotone. Same-child alternate parent work certificates are not a fork.

Do NOT assume a random privately mined AuxPoW block or irrelevant old fork is admitted. A tag-fault challenge must authenticate the outer coinbase/parent/child commitment without first requiring the disputed tag to pass; exact claim, outpoint, source anchor/window, native cancel message and VK are bound in x.

## Two exact scoped repairs; neither is a source-to-secret compiler

1. **Slot-global irreversible fault**: define eligibility as existence of at least one previously admitted qualifying challenge in the allowed window and allow cancellation even after that observation was orphaned. This makes the intended authorization predicate monotone *if the historical admission is itself verifiable* and matches the bearer capability. It trades liveness for safety. Historical best-chain admission without an irrevocable anchored receipt cannot be conjured by naming it `G_ever`; propagation and deep reorg remain assumptions.
2. **Activation-specific native outpoint/message**: the native verifier must distinguish activations via a different signed outpoint/consensus-enforced field, not just via ciphertext or SegWit witness data. That may sacrifice R191's flexible fixed-txid activation and cannot be assumed under the no-new-Bitcoin-opcode constraint.

A proposed hash repair `manifest_id=H(x,activation_wtxid,capsule_root)` fails after release: the *capsule labels* differ but the already frozen `Sign(sk,M_fixed_cancel)` bytes remain usable on either history with the same cancellable output. The compact reproduction shows the txid/outpoint identity and divergent witness hashes; it is not native consensus validation.

## Remaining actual cryptographic obligation

The above conditional result does **NOT** give classical PPT `Build_hash(R_original,x,sigma)` and public `Open_hash(C,w)=same sigma` for every qualified original witness. It does not transfer a private gate label from actual SHA/AuxPoW source certificates, establish FALSE or hard-TRUE QPT security, original witness extraction, malicious setup, full-public related-capsule simulation, or native PQ unforgeability. A proposed monotone source admission is no substitute for original source evidence or source-dependent cryptographic release. Exact next step is still construction and joint-public proof of that gate, not packing, PRG, additional hash puzzles, assumed online source signers or a renamed witness-encryption oracle. No ordinary PR progress comment warranted.
