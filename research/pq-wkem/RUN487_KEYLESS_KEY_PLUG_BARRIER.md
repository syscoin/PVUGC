# Run 487 — native-key plugging barrier for keyless release

Date: 2026-10-13. Verified start: `ec14788eb8bc9e780276599c0ae04d2dc642d109`, `syscoin/PVUGC#1` on `research/pq-wkem-validation-20260918`. Last substantive ordinary comment: 6067040320. This is one scoped result, not a practical WKEM.

## Precise theorem

Let Sig=(KeyGen,Sign,Verify) be a classical-PPT native signature scheme secure against arbitrary QPT existential forgery with no signing queries (EUF-NMA). Let the ORIGINAL NP relation R(x,w) have a classical-PPT sampler producing a TRUE pair (x,w), independently of a native signing challenge key. The statement and selected fresh transaction message bind relation identity, claim/UTXO, branch, anchors/window, and sighash.

Suppose a proposed public keyless interface includes `Plug(x,vk;r)->P`: given **any externally supplied** native `vk` drawn from honest `KeyGen`, it produces a fully accepted capsule without the signing secret. Suppose `Open(P,w)`, for a valid ORIGINAL witness independent of that signing key, produces a credential that can sign the bound fresh message under this supplied `vk` with probability >= 1-epsilon.

**Reduction.** Given the EUF-NMA challenger `vk`, sample (x,w), run `P=Plug(x,vk;r)`, use `Open(P,w)`, and sign the fresh intended message. This straight-line classical-PPT algorithm forges with probability >= 1-epsilon, contradicting QPT EUF-NMA if epsilon is negligible. It uses ONE known valid ORIGINAL witness; SAME-capability correctness for ALL witnesses is stronger than required for this contradiction. No quantum rewinding, QROM programming, or secret-key knowledge extractor is needed.

The assumption that `Plug` accepts independently challenger-selected `vk` **is essential**. It is not a theorem ruling out nonprogrammable `Build(x;r)->vk_x,P_x` that binds the key to relation/context and builder entropy. Nor does it rule out a source relation where finding a valid witness already requires inverting this particular native verification key. An arbitrary Syscoin fork/tag counterwitness is NOT inherently that inversion witness.

## Separate malicious-setup substitution

If the public accepted format permits such external `vk`, a malicious builder can call ordinary `KeyGen`, retain the secret, plug its public key into a FALSE-source claim, and sign without any ORIGINAL witness. If honest keyless verification objects have the same native-public-key distribution, checking only the public key cannot recognize this retained-secret origin. A nonprogrammable, binding public derivation or honest contributed entropy may block this substitution, but neither is itself a protected release proof. This does not attack the original one-honest-participant erasure-based N-of-N baseline.

## Scope / taxonomy

(5) chosen native-key injection is decisive; (6) malicious retained native key defeats the plug-in format; (7) a reused private credential allows fresh cross-branch signatures, not merely replay; (8) native `vk` and all public capsule outputs are included. No mask seam, gauge alignment, statistical fingerprint, multi-capsule cancellation, or coherent quantum attack is needed (1-4,9); the attack is classical and therefore also QPT. The reduction requires publicly simulatable side information and correctness of the externally programmed capsule, not a unique setup-correlated quantum advice state. A single-capsule break suffices regardless of claimed multi-capsule security.

## Executed checker

The exact attached JavaScript source was executed to produce the attached deterministic validation: 4864 assertions, 128 contexts, 2048 accepted signature tests. It uses an easily invertible **8-bit permutation** and toy Lamport-style four-bit signature: a demonstrator of the interface, emphatically NOT a QPT-secure signature, LWE scheme, local mixer, WE, or Bitcoin deployment. Independent extended local Python checker: 3,328 assertions.

## Assumption/dependency ledger and handoff

Run 486's known-key Goldreich–Levin implication to one-bit WE remains correct within its stated model; this result **does not** extend that proof to all keyless builders. Instead it falsifies externally programmable native verification keys whenever the ORIGINAL relation has independently samplable valid witnesses. Run 483 authenticates an accepted COMPLETE stream and Run 259 may extract an ORIGINAL witness from a qualifying representation; neither proves a native signature produces that representation.

Still UNPROVED: a classical practical nonprogrammable source-conditioned local release, all-witness SAME native capability, false-instance full-public-output arbitrary-QPT hiding, true-instance native forgery/key recovery -> COMPLETE source representation or independent QPT break, malicious N-of-N ceremony/abort/erasure and graph, related-capsule composition, concrete >=128-bit quantum parameters, and the conditional P2MR/native-SLH Bitcoin endpoint.

Next constructive target: give an actual `vk_x=Build(x;r)` derivation that is not externally programmable, prove that the builder cannot learn its native secret even retaining all coins or maliciously choosing allowed coins, and show **every ORIGINAL Syscoin evidence witness** recovers that same secret without merely assuming WE/WPRF. No complete WKEM; production unchanged; draft PR unmerged.
