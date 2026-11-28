# R196 — Source-authenticated SHA ratchet and fork-convergence experiment

**STATUS: unsuccessful construction candidate. No ORIGINAL hash-only Build/Open, no QPT theorem, no useful release improvement and no progress comment.** This is a bounded source-dependent construction/repair pass, not a new generalized impossibility result.

## Exact continuity and provenance

- syscoin/PVUGC PR #1, actual open/draft branch research/pq-wkem-validation-20260918, observed starting SHA 8a1f108068fd4d9277b02a2ac2444ab8c4552cd0.
- Read R195 RESEARCH.md at exact blob ce5732366c9d104097adb70c9e44ae697e6f60d9. Latest relevant ordinary comments since 2026-11-10T08:00Z: none.
- Genuine intermediate local checkpoint CHECKPOINT_01.md was created before checker execution. Python SHA256 checker ran twice byte-identically: full local checker SHA256 91c449bf73056134d3a8e8c2c736f4a12c8c88608a1b96929dfc1d9ee9295130, captured stdout SHA256 6d92bee984bf70ec0af72c7f35e8c76f9773485e8349db7eb5a66a0fc0a1f1a9; 768 functional checks.
- This directory contains a SHORT, independently executed reproduction (128 checks); its exact Git blobs are recorded in the commit. It does not contain the larger local-only checker. No online search, external literature, production changes, synthetic header mining, native signing, independent researcher or QPT security test.

## Named candidate and target

Target the actual Syscoin/BTC-qualified source relation for one fixed N-of-N preauthorized cancellation slot. One notary activates; any challenger with authenticated BTC-work, PoB-fault, or qualified Syscoin AuxPoW/child-history inconsistency evidence should recover the SAME frozen native cancellation capability, off chain. Only claim/window-relevant authenticated histories qualify, not a random PoW solution. Source headers, coinbases, Merkle paths, all required tags, descendant links, anchors, interval rules and original burn identity remain in R_original; this pass did NOT implement the full verifier.

Given an eligible authenticated source history with pure-child hashes c_1,...,c_m, try to derive a public source-dependent label using SHA:

    s_0 = H(domain, x.public_anchor)
    s_{i+1} = H("step", s_i, c_i)
    F(w) = H("pad",s_m)
    Build(x,sigma;w_baseline): E = sigma XOR F(w_baseline)
    Open(E,w): E XOR F(w).

This is an explicit attempted release mechanism, not a cipher with a genuine original-witness binding. It depends on Build knowing a baseline history but not future valid fork histories. It is *not* an independently costly hash puzzle.

## Classical functional analysis

For two future eligible divergent SYS histories w_A,w_B, the pure-child records change after the first divergent child. In the bounded tested SHA fixtures, F(w_A) != F(w_B), and E fixed for w_A fails to open the same sigma using w_B. A classical random-function/lazy-sampling analogy predicts nonconvergence absent a collision, but this is not a theorem about deployed SHA and is **not** lifted to coherent QPT attackers. It already fails universal every-ORIGINAL-witness correctness.

Including mutable Bitcoin AuxPoW parent work wrappers in the ratchet introduces an additional semantic error: the same pure Syscoin child with different parent work certificates would generate different labels. Removing wrappers repairs that identity error but cannot make genuinely divergent pure-child traces converge. The R195 exact-height U_claim projection addresses source semantics, not a common secret.

## Explicit repair experiments and their outcomes

1. **Converge at common ancestor/prefix.** All histories share the pre-fork prefix, hence its hash mask is common. But the prefix is already public before any challenge, so E = sigma XOR H(common_prefix) reveals sigma immediately without an ORIGINAL witness.
2. **Explicit merge table.** Builder can publish a separate row M_s = sigma XOR H(s) for every previously known terminal state s. All those known states recover the same sigma. A future, not-yet-known valid source state lacks a row. Building rows for every possible future 256-bit source state is not classical-polynomial setup; this note does not attempt packing or a restricted optimization.
3. **Universal publicly evaluable row.** A public function returning M_s for any s permits an attacker to choose a fabricated unqualified state s_fake and recover sigma before a source event. A parallel explicit secant repair, with public p(t)=K t + r, reveals K from any two adversary-chosen evaluations even if their tags do not authenticate a fork. This is an attack on this proposed family, not on all nonblackbox SHA witness encryption.

The source-state authenticity checks CANNOT be implemented only as a visible "if verifier accepts" before returning a publicly computable mask: an arbitrary malicious recovery circuit can bypass that check. A source-dependent correlation must make actual authenticated ORIGINAL evidence necessary to compute the hidden label *cryptographically*. Merkle commitments authenticate bytes but do not supply an unpredictable setup secret to future miners.

## Proof boundary

Honest Build/Open must be classical PPT. The actual security game must expose complete R,x,capsule,native VK,checking key,source commitments,all related capsules,auxiliary inputs,correlated public labels and source-selected retained secrets; attackers may be arbitrary QPT with coherent hash/source queries. Neither the full local fixture nor the published checker implements BTC/SYS consensus authentication, native cancel signatures, all-witness recovery or a quantum experiment. No assumption promising hidden common-value release is imported. Tested SHA outputs merely falsify candidate functionality.

## Next exact unfinished obligation

Construct an actual joint pair Build_hash(R_original,x,sigma) and PublicOpen_hash(C,w), with every authenticated and qualifying BTC-work/PoB-fault/SYS-inconsistency witness releasing the SAME precommitted native cancel capability, while arbitrary QPT recovery or accepted native forgery without that ORIGINAL witness reduces to original source evidence extraction or independently justified PQ hash/native break. No source authority, no online release committee and no Bitcoin NP verifier.

A fresh candidate needs a *nonblackbox* source-to-hidden-label compiler binding global SHA/AuxPoW/PoB trace consistency inside the release, rather than a raw hash ratchet, a public merge table, or a post-hoc verifier. Missing this compiler is an algorithm gap, not proof polish.

No ordinary PR comment is warranted solely by this negative result; task remains unfinished.
