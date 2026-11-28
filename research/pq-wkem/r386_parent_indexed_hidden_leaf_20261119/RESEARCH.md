# R386 — Fixed-parent root indexing versus unknown source-opening release (NONQUALIFYING)

## Live continuity and candidate choice

This bounded pass read open/draft **syscoin/PVUGC#1** at `da4e7d26bf93ca2ce44173e48519c9ae4bcf1746`, branch `research/pq-wkem-validation-20260918`. Its last substantive note is R385, `research/pq-wkem/r385_hash_pointer_width_20261119/RESEARCH.md`, blob `f7b5af5ad60c529b00344d0dc794ac068b8d2b3a`. R385 shows that explicit public directional hash edges are correct for a finite accepted path language but that enumerating future SHA-pointer states has exponential width. Recent top-level comments since Nov 18 19:24 UTC were read as `[]`. No Core source needed rereading: the following uses the previously inspected post-PQ contextual uniqueness rules *conditionally* and does not claim latest Core binaries/tests or deployment. No web or external source used.

**One named repair hypothesis:** instead of enumerating arbitrary future child hashes, index an offline source gate by the **finite, authentic Bitcoin parent certificates** in an already frozen claim-relevant Bitcoin window. This changes the state representation meaningfully: a strict modern AuxPoW parent commitment can certify at most one Syscoin child, even with nonzero chain Merkle depth. The candidate attempts to transport the setup-frozen key to that *unknown but unique committed child* via a hash/Merkle opening. The release and full-public false simulation must be considered jointly; uniqueness alone cannot be promoted to FE.

## 1. Exact restricted finite-parent structure

Assume only for this subproblem a completely authenticated, fixed, claim-relevant set of Bitcoin parent carriers `P={p_1,...,p_B}` known to Build. For each parent p_j, its authenticated coinbase fixes child-chain Merkle root `R_j`, tree size/depth and merge-mining nonce. Modern chain ID fixes the valid child slot `i_j`. The canonical parent SYS ancestor tag remains a *different* commitment to the scheduled older child ancestor; it does NOT expose current child hash. The reference schedule is `h_ref(n)=10 floor((n-6)/10)`, not the LC maturity depth. A full child certificate contains child header `h_j` and chain-Merkle siblings `s_j`, together with independent contextual source/ancestry/relevance evidence.

**Conditional binding lemma:** for a fixed authenticated parent, fixed `R_j`, `i_j`, and leaf serialization, two different valid Merkle openings `(h,s)`, `(h',s')` with `h != h'` yield a collision in the fixed binary SHA Merkle combiner. Follow both paths upwards from the unequal leaves to the first level where their computed values agree. Their parent inputs differ but their output hashes agree. This is a collision-reduction argument, not a performed hash-break or an equality guarantee across *different* parents. It assumes the actual coinbase/root is authenticated and contextual modern chain-ID/index checks hold.

Thus the **number of actual child identities certified by this fixed parent set is at most B** in the computational binding model. It is not a count of immediately computable children. The miner may have withheld a valid child header and sibling path: seeing `R_j` does not recover `h_j` or `s_j`. Distinct parents can certify the *same* child (not a fork). Even a unique child opening is not automatically an ORIGINAL inconsistency witness: the complete conflicting-history pair and LC-depth/relevance are still necessary.

This narrows the explicit-state *cardinality of actual committed children* compared with an arbitrary virtual SHA-state table, but **does not** bound the number of possible hidden openings Build must support before it knows them, and does not solve the initial case where qualifying future Bitcoin parent carriers themselves are unknown at N-of-N preauthorization.

## 2. Source-committed opening transport attempt

Fix secret frozen safe cancellation capability `S`. For each p_j choose a private random 256-bit key `k_j`, and define

    D_j = S XOR SHA256("payload"||sid||j||k_j).

The required new operation is a *serialized public* transport capsule `T_j` such that

    Transport(T_j, p_j, w_j) = k_j    if w_j is ACTUAL qualifying ORIGINAL evidence
    Transport(T_j, p_j, arbitrary input) != k_j, without a valid original certificate,

while full public bytes, sibling capsules, checking keys, native signature context, malicious source coins, and QPT joint processing hide `k_j` before such evidence. Then every qualifying j decrypts the SAME S via `D_j`. A global OR can have independent j-specific transport as long as every qualifying ORIGINAL branch is covered. This is a *construction obligation*, not an instantiated operation.

A natural first attempt makes the parent-root hash a replacement for a secret Merkle opening:

    T_j = k_j XOR SHA256("root"||sid||j||R_j).

It is a complete public encoding but its **entire public joint transcript fails**: the parent root `R_j` is public, so anyone computes `k_j=T_j XOR SHA256(...R_j)`, then S from D_j, without any source certificate. This leakage applies on TRUE and FALSE instances alike, independent of circuit confidentiality, QPT advice or chosen source coins.

A natural *repair* instead sets

    T_j = k_j XOR SHA256("opening"||sid||j||CanonicalMerkleOpening(w_j)).

Here the pad is unknown before a hidden leaf/path is learned, and an actual Merkle opening would be a source-derived input rather than an invented puzzle. But **Build cannot compute T_j** from the public root when it does not know `w_j`. Computing all T_j for unknown possible openings is the original exponential table problem. Asking a source miner to reveal a private opening at setup changes the source/timing distribution and would fail coverage for other parents or later withheld certificates; a miner's retained opening is not a setup secret supplied by every challenger. Retaining `k_j` in a private evaluator, or a ZK proof that it was generated correctly, does not give a public transport algorithm.

Trying to substitute a Merkle commitment to private labels for the per-state table has the same precise missing edge: an authenticated **source** Merkle path proves membership under `R_j`; it is not an opening under the independently generated **capsule label** root. If the two roots are forced to agree by using only public source leaves as labels, there is no setup-hidden transfer key. If they remain independent, a witness cannot manufacture a secret-label opening under the capsule root without extra cryptography. This is not a claim that Merkle hashing or arbitrary hash-only FE is impossible; it rejects this particular transport representation.

## 3. Joint-public security analysis and exact scope

The fully serialized `T_j(root)` variant has the explicit unconditional extractor above. There is **no valid full-public false simulator hiding S** because public decryption succeeds even if no authentic original certificate exists.

The `T_j(opening)` variant may conceptually conceal a pad, but the honest classical-PPT builder cannot form its ciphertext under the required sender-unknown-opening distribution. One cannot claim a simulator or QPT security theorem for nonexistent public bytes. A sender-knows-opening hash lock is a different restricted statement and does not open every possible ORIGINAL witness. Exact per-parent Merkle binding only says there is *at most one* possible child at that parent; it does not yield its private opening, nor a release when two distinct parent histories conflict.

The root-index trick is **not a route to enforce a full source challenge by testing a leaf alone**. An evidence verifier must still enforce, within the cryptographic gate, protocol/chain IDs; claim, UTXO, burn/amount/recipient/reserve/replay context; baseline and actual claim-relevant child ancestry; canonical postactivation tag and deterministic merged-mining proof; authenticated independent carrier for a tag fault; BTC anchors and exact work, LC depth and interval tags; deadline/reset; exact cancel message/VK/capsule. The separate original OR grounds (strictly greater qualified BTC work; finite authenticated burn fault; qualified Syscoin inconsistency/tag fault) must remain independently usable. No greater Syscoin work or winning-fork choice is added. The bridge must not treat a locally computable arbitrary Merkle preimage as an admitted Syscoin history.

## 4. Exact unfinished operation / anti-spin checkpoint

For *already known parent roots* the missing cryptographic operation is

    SourceOpen_R(C, root_j, original_certificate_w)
       -> SAME S for every R_orig(x,w)=1,

with serialized classical-PPT `Build_R(x,S)` **without knowledge of the future leaf/path**, plus independent joint-public FALSE and unauthorized hard-TRUE QPT recovery/accepted native forgery -> ACTUAL qualifying ORIGINAL certificate or independently justified hash/native break. Future unknown parent commitments make this obligation stronger still. If a candidate works only after receiving a parent miner's private opening at Build, it must be rejected for the original source distribution.

**NONQUALIFYING.** This pass identified a limited finite-parent source reduction but **did not construct** the critical source-conditioned key transport, public FE, simulator, QPT reduction, native spend, or work budget theorem. This is a research checkpoint and regression for a concrete repair attempt, not a breakthrough or an approval. No Core tests, actual source certificates, synthetic checker results or specialist agents were claimed for this pass. No ordinary PR progress comment, production edits, deployments, transfers, or automation changes.
