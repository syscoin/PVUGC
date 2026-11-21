# R173 — Hash-only source-equivocation release: exact bounded constructor and retained-key failure

**Status: research-only attempt with a complete, efficient release for a restricted *signed-equivocation* predicate, NOT a generic ORIGINAL-NP witness-KEM. The restricted predicate is NOT a substitute for the required original Syscoin/BTC source. The candidate fails the stated malicious-source safety/completeness conditions. Do not treat the successful toy checks as evidence of PQ security.**

## Continuity and provenance

- Repository: syscoin/PVUGC PR #1, draft/open/unmerged; branch research/pq-wkem-validation-20260918.
- Observed starting SHA: a66979b8d1b730d1981ef67ba2101e502691efe3. Read R172 at exact blob b78d3a4c491592f7c24cb4febc87a97a984d9516. A latest relevant PR comment query since 2026-11-09T00:00Z returned no comments. The intermediate genuine hypothesis/checkpoint was committed before finishing tests as 5eb039f9d9a42400fbfdfd524878ab51a72fc3f9.
- Hash-only, no web/external literature, lattice, group, online service *assumed* for the proposal, independent subagent, or production change. The alleged release mechanism is tested adversarially below, not promoted.
- Executed standard-library Python checker.py twice with byte-identical output captured.json. Source SHA-256 8a55d5d066f8d588c8436cd8c21e51d174d027634f97e80ade2459eef6885067, Git blob eba392c9ed4c2139b9379963699c8443664035fb. Captured SHA-256 de6b12effdeb73c54ac9863fcad829b22278b9d073cc2cc06525927f211784df, Git blob a49097ce75e93263e83b8046862e445d52b36ff4. This file is the derivation; no QPT cryptanalysis was run. 780 *functional assertions*, not security experiments.

## Candidate R173: cryptographically authenticated dual opening

Take a precommitted frozen native path signature sigma and context c=(relation ID, exact claim/UTXO, branch, source anchor/observation slot, challenge message, intended VK, capsule ID). Model a semantic source **OutcomeID** by an injective L-bit encoding e(o). A distinct Bitcoin parent-work certificate **WorkID** for the *same* authenticated child does not change e(o).

For j=1..N signers/participants independently choose random 256-bit share K_j and for each i=1..L uniformly random 256-bit labels (s_{j,i,0},s_{j,i,1}); K = XOR_j K_j. Publish domain-separated hash verification tags

    V_{j,i,b}=H_ver(c,j,i,b,s_{j,i,b})

and release rows

    E_{j,i}=K_j XOR H_pair(c,j,i,s_{j,i,0},s_{j,i,1}).

Publish CK=H_check(c,K) and D=sigma XOR H_pad(c,K), plus the native VK/message and all necessary checking/auxiliary fields. A hash-based one-time signature on semantic outcome o reveals the labels s_{j,i,e(o)_i} for every i. A hypothetical authenticated source witness carrying **two** valid incompatible outcome signatures *from the same j* reveals, at any differing index i, both labels. The public decryptor recovers

    K_j=E_{j,i} XOR H_pair(c,j,i,s_{j,i,0},s_{j,i,1})

and combines every K_j into K. If CK matches, unmask sigma and verify its original native challenge path. This is genuinely one common K for every pair of differing signed outcomes; no canonically shared source preimage is needed, and different work proofs for the same outcome do not count as two outcomes.

**Precise proved functional statement:** Under correct tags/signatures and injective outcome encoding, for any two distinct o0,o1 that EACH have these same N source signers' complete valid signatures, the algorithm reconstructs precisely the setup K and sigma. Proof: e(o0) != e(o1), choose i with differing bits; the two signatures contain exactly the two labels installed in row E_{j,i}; XOR cancels H_pair for each j, and XOR_j K_j = K. No security assumption is needed for this identity. Signing twice or retaining both labels is not itself a proof of the ORIGINAL relation. The real Bitcoin/Syscoin evidence does not carry these invented OTS tags.

## Executed adversarial functionality

The executed fixture uses eight direct outcome bits, three independently generated signer shares, SHA256 domain-separated tags/pads, 60 deterministic seeds, and a synthetic 32-byte stand-in for sigma. For each fixture eight distinct outcome pairs recover exactly the same frozen value (480 checks). A different WorkID for the same semantic child cannot trigger a pair, a label transcript for a wrong outcome fails signature verification, and independent share-combination behaves as specified. A signer-participant retaining BOTH initial label families can reconstruct its own share immediately; **all** malicious source signer-participants retaining both can reconstruct the full K and sigma **before any source event**. The executed repaired N-of-N configuration with one honest participant withholding its second signed outcome blocks corrupted signers from reconstructing the final K, but also blocks release for otherwise genuine conflicting outcomes. Prepublishing the honest participant's second opening for offline completeness makes the key available before the source event. Rerun output is byte identical.

Crucial distinction: the two-source-signature input is a synthetic statement, NOT actual ChainLock/AuxPoW/coinbase proof. No true Bitcoin header, real best-chain membership or full ORIGINAL verifier was implemented; no honest source-signing protocol with these Lamport-style labels is known to exist in current Syscoin consensus from this run. Native sigma in the test is a SHA256 fixture and *not* an SLH-DSA or production native signature.

## Why this is not a repair to the required WKEM

1. **Unconditional dishonest source-key retention attack:** the source signer (or all N colluding signers) owns the two preimages for each index before any authentic fork. E and both labels recover K directly. It can bypass the honest original-source verifier, including missing ancestor/tag/window/height/coinbase/source history. There need not be any ORIGINAL witness. This violates false-instance and hard-TRUE unauthorized-recovery safety even with perfect SHA.
2. **Honest erasure versus release liveness:** if one honest participant prevents the retained-label attack by refusing to open both incompatible values, then the future genuine source pair need not contain its second label. Full common-capability release fails. Giving that honest participant discretion to sign the second source condition *after* seeing it adds an online release authority expressly excluded by the use case. Prepublishing both reveals K immediately. This is a family-specific dichotomy, not a theorem that every hash-based WKEM needs an online authority.
3. **Special-source relation is not ORIGINAL:** An OTS signature pair authenticates only the messages under the bespoke OTS verification keys. Even valid signatures on different child outcomes do NOT establish actual Syscoin child parent-linking, Bitcoin canonical work inclusion, coinbase tags, claimed burn/UTXO, ancestor, interval, lag or censorship/finality. Replacing the original evidence with these signatures silently changes the protected predicate and is impermissible. Existing source block hashes by themselves do not expose the precommitted opposite labels.
4. **Context and witness consistency:** To permit cryptographic release from genuine original source alone, the **same actual source** must contain a pair of hidden label preimages certified *by that source*, with neither a colluding source actor nor a setup actor able to obtain both before the qualified event. Merely hashing an invalid work transcript or committing this table root to a coinbase does not implement that rule. Qualifying incompatible child outcomes and distinct parent work solutions must remain separate.
5. **QPT proof not obtained:** A one-opened-signature ideal QROM experiment might remain hiding under unknown opposite label preimages, but a source signer initially holds both. No complete public-output simulator, auxiliary/multi-capsule quantum extraction, malicious N-of-N ceremony, or native EUF-CMA reduction was established. One-wayness of H_ver alone does not automatically justify a QROM programmed-oracle proof.

## The attempted repair and exact next missing equation

Replacing K by N-of-N shares makes the carrier safe against corrupted participants **only while some honest label share remains inaccessible**. For honest *source-independent* release, that same share has to become computable from a complete ORIGINAL authenticated witness without online discretion, prepublished opposite labels, or a private issuer. The required uninstantiated equation is

    Build_hash(R_original,x,sigma) -> (C,CK,Aux) in classical PPT
    PublicDerive_hash(C,w) = same sigma for EVERY R_original(x,w)=1
    unauthorized QPT recovery/native forgery
        -> FULL ORIGINAL w or independently justified PQ hash break.

A genuine repair must let future authenticated work produce a **precommitted, computationally hidden cross-witness correlation**, not just prove that a signer saw two source events. The natural alternative is to search for a nonblackbox correlation across the actual SHA256/Syscoin source constraint computation and *simultaneously* provide its joint-public quantum simulator. A circuit that publicly contains K, an independent hash puzzle, an enumerated witness table, a hidden online signer, or a verifier that only checks validity **after** raw release does not count.

This pass does not solve arbitrary-NP, FALSE security, hard-TRUE extraction, malicious setup, DA, censoring/timely watch, or the native Bitcoin endpoint. No ordinary PR comment is warranted under the user's reporting threshold.
