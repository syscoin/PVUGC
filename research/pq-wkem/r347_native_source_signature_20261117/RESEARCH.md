# R347 — Native hash-signature route for an original source witness (NONQUALIFYING)

## Exact continuity and change of mechanism

Started from open/draft syscoin/PVUGC PR #1 on research/pq-wkem-validation-20260918 at 66d83f4706582142e57919349b25acaf7b7fa5ff (R346, note blob 2b3dec3bc8dec454dceb799097c4c6f25219106a). Recent top-level comments since 2026-11-16 returned none. Core #609 was NOT re-read for this attempt; it makes no new claim about active Core admission or public activation. No web/literature, real Bitcoin/Syscoin certificates, native SLH-DSA or quantum experiment.

The exact R346 missing source-earned edge cannot be replaced by an arbitrary setup-issued token. This iteration tests a distinct, direct **hash-only native** route: could an ORIGINAL qualifying future certificate itself serve as signing material or Merkle membership for the ordinary Bitcoin-native safe cancellation, eliminating public evaluator obfuscation? The relevant change from R346 is to move the source gate into the native fixed Merkle verification key, rather than split a dealer-chosen secret into graph shares. This is a preliminary screen, not a claim of a release mechanism.

## Explicit attempted Build / Open

Let x_W bind the original protocol/chain IDs, claim/outpoint, assertion/burn/amount/recipient, reserve, baseline, BTC anchors/window, relevant height, exact LC fork depth and all strict active AuxPoW rules, deadline/reset/capsule ID and the safe cancellation message m_cancel and VK. For each possible ORIGINAL certificate w, consider a source-derived hash-only one-time secret:

    sk(w,j,b) = H("OTS-secret", x_W, w, j, b)
    pk(w,j,b) = H("OTS-pub", sk(w,j,b))
    Leaf(w)    = H("leaf", concat_{j,b} pk(w,j,b)).

Tentative Build would construct a fixed Merkle root VK containing Leaf(w) for EVERY future qualifying ORIGINAL w. Tentative Open, given w, would derive the Lamport/WOTS-style private signing pieces for m_cancel and an authentication path from Leaf(w) to the fixed VK. If all these ingredients were available, the Bitcoin verifier would see an ordinary native signature and no source NP verifier. This proposal is NOT an instantiated Build, because the future qualifying leaf population and authentication paths are unknown at funding.

Two logically separate tasks arise: (A) fix a native root accepting all future ORIGINAL certificates without enumerating them; (B) ensure only authenticated/relevant ORIGINAL evidence earns any accepted private signing material. In addition, the user demands the SAME frozen signature/cancellation capability from every valid w, not merely two native signatures on the same message.

## Constructive repair screen and exact failure

**Explicit Merkle enrollment.** Build can enumerate a polynomial-size set W_0 of setup-known witnesses, construct all leaf PKs, and emit exact authentication paths. This is classical-PPT only for such finite W_0. It is not all-witness complete: an unanticipated qualifying w_* has Leaf(w_*) outside the fixed tree. Substituting its leaf into another authentication path changes the root unless a suitable hash collision/preimage is found. No general lower bound on non-Merkle schemes follows from this observation.

**Source-free credentials.** The source-derived signing material sk(w,j,b) exists for any arbitrary byte string w_bad. Native Lamport/WOTS checks alone verify a hash preimage for the enrolled public key and a Merkle path; they DO NOT check original historical BTC membership, exact modern child chain ID, canonical tag, semantic ancestor inconsistency, burn validity, relevance or LC depth. If arbitrary leaves are enrolled or the path is publicly synthesizable, an invalid w_bad can sign without a qualifying source certificate. Moving VerifyOriginal into the honest Open code AFTER deriving accepted native material is not a cryptographic release condition. An authenticated source Merkle root is not automatically a hash-based signing root.

**Reversible-root repair.** To accommodate every possible future Leaf(w) without pre-enrollment, replace a binding root by an algebraically completable root such as Root'(w)=H(Leaf(w) XOR (Leaf(w) XOR t))=H(t). If t is public, even a fabricated w_bad computes its complement and the same root, so no source authentication remains. If t is secret, a valid w has no method to derive it from original AuxPoW/BTC source evidence. Retaining collision-resistant Merkle compression instead makes the absent path a hash-preimage requirement for the honest witness. This is a two-sided repair test, NOT a generic impossibility theorem.

**Frozen-capability mismatch.** For distinct enrolled w_A and w_B, signatures obtained from their independently source-derived OTS secrets differ even when both authorize the same m_cancel. The approved original Build/Open instead requires Open(C,w_A)=Open(C,w_B)=the SAME frozen sigma_cancel. Accepting two distinct signatures would change this required API and would not solve native activation portability of a preauthorized common-outpoint signature (R225).

## Joint public output and security limit

Try appending a ciphertext D=sigma_cancel XOR K with fresh uniform independent K. For fixed public x_W, native VK and source material generated independently of K, the entire available source/native-path view contains no information about K: a valid source certificate can derive a different native signature but cannot decrypt D. The restricted (VK,D) FALSE view is perfectly maskable for fixed VK and independent K, but this same independence kills TRUE correctness. This restricted distribution is NOT a complete-public QPT simulator for a native VK correlated with sigma_cancel or malformed N-of-N setup, and it does not cover malicious source coins, sibling capsules or selective openings.

Choosing K=H("release",x_W,w) allows a witness-specific key, but a single frozen D cannot decrypt to the same sigma_cancel for two independently unknown distinct valid w_A and w_B without a separate, source-gated key-translation construction. Choosing K from the public fixed VK exposes sigma_cancel to everyone. No independent SHA or QROM security assumption solves the missing projective translation, and no ideal source-gated evaluator is counted as a component.

## Executed bounded toy and exact provenance

A SHA256-based eight-message-bit Lamport toy checked a two-leaf Merkle root for enrolled synthetic w_A,w_B. It verifies both native toy signatures on the same message, observes them differ, and verifies that a third synthetic qualified w_C cannot reuse the fixed root path. An arbitrary fabricated w_bad derives a locally valid toy Lamport key/signature; it is NOT authenticated by the original source relation. A publicly XOR-completable root accepts w_bad as well. These are explicit functional controls only, NOT original source certificates, Core tests, deployed SLH-DSA or quantum experiments. Two local executions gave byte-identical JSON.

Local-only reproducibility archive: /mnt/data/R347_native_cert_merkle_20261117.tar.gz, SHA256 e53256ba9f4c381bd4fe02ac9a56f0b8fe78f6cee60608d92c37422ad7499793. The script SHA256 is dc53530a7de610c5ff298fa11bd4a8854f7358fd1094d1f50ca87eabc2f74aff; both output SHA256 values are df4e9af29f8335999229c1edb8dc6a4b67559a70320aecabb7131a6e5d7af5ae. Checker and JSON are LOCAL ONLY; this note alone is being proposed for GitHub publication. No claimed sandbox persistence beyond the executed local file.

## Decision / next unsolved equation

**NONQUALIFYING.** Ordinary native hash-signature/Merkle proof verification is not a cryptographic substitute for source-earned release; explicit enrollment misses arbitrary future ORIGINAL witnesses, and a public universal root-completion rule admits fake source. Do not continue by increasing native tree depth or toy parameters. This does not disprove other source-specific hash-only release constructions.

Still missing: a serialized classical-PPT Build_inc(x_W,sigma_cancel)->C and PUBLIC Open_inc(C,w)=SAME frozen sigma_cancel for every authenticated relevant ORIGINAL witness across all three independent OR branches, with full-public FALSE/hard-TRUE QPT unauthorized recovery/accepted-native-forgery -> ACTUAL qualifying ORIGINAL certificate or justified independent PQ hash/native break, including malicious setup, source-coin retention, auxiliary input, native VK, siblings and selective opening. N-of-N preauthorization remains a separate setup boundary; any one notary initiates; anyone with original evidence challenges; large evidence off-chain; native Bitcoin signatures only. No PR comment or production mutation is warranted.
