# R257 — source-prefix pivot release gate (NONQUALIFYING)

Outcome: **no hash-only ORIGINAL bridge witness-KEM, QPT security theorem, or native release implementation**. This research-only checkpoint studies a distinct construction class from R256's first-different-tag-bit partition: keys derived from the *fork height/common ancestor pivot* on an independently authenticated baseline.

## Provenance, source and exact relation
syscoin/PVUGC PR #1, existing branch research/pq-wkem-validation-20260918. Starting PR head 12666476ba0d59a5e0c56a229859c06d2685ad53 (R256); R256 note blob a1a6cedef5228a7a2da704ecde08d9a0256163bc and R255 digest-gate note reviewed. Core #609 source correction (one valid post-PQ Syscoin child per authenticated Bitcoin parent commitment, canonical 41-byte SYS tag, modern child chain ID) inherited from earlier authorized inspection; current Core PR metadata head c91539de3c34937e57d7f5fda47c7b0502ff33f6 was observed but source was NOT reaudited in R257. No Core tests rerun.

x_W includes exact claim/UTXO/source slot, burn/amount/recipient/authorization, independently authenticated baseline A and claim-relevant height h_rel, BTC anchors/history/window, deadlines/reset, fixed safe native cancellation message/VK and capsule ID. One notary initiates; any qualified independent observer challenges; N-of-N preauthorization is separate. ORIGINAL inconsistency evidence B requires Bitcoin/Syscoin admissibility, full AuxPoW coinbase and chain Merkle link, modern child ID, canonical tag, all required interval tags, authenticated ancestry and first divergent child d<=h_rel, source relevance, and timing. Two Bitcoin work certificates for the same child do not count. Bitcoin higher-work, burn fault and explicitly scoped tag-fault remain separate OR grounds. A malformed tag is not itself a valid Syscoin history.

## Construction attempt and exact full-public failure
Write A_j for the SHA256d-hashed child header of the public baseline at height j; for two linked histories first divergent at d, the *common fork pivot* is p_d=A_(d-1)=B_(d-1). Crucially ALL p_d for 1<=d<=h_rel are already in PUBLIC A, with polynomially many candidate d. For frozen claim-scoped signature sigma and uniformly random K, try:

D_d = SHA256d("PVUGC/PIVOT/257" || x_W || uint32LE(d) || p_d)
T_d = K XOR D_d
E = sigma XOR K
C = (x_W,VK,E,{T_d},full checking context and manifest).

Honest Open would verify all ORIGINAL evidence conditions and identify first divergence d, then return E XOR T_d XOR D_d = sigma for every qualifying B, including distinct B sharing d. This is exact symbolic same-capability correctness for the displayed bytes, NOT actual source-conditioned cryptographic release or implemented native signing.

Full-public adversary: pick ANY publicly enumerated d, recompute D_d from A and x_W, output E XOR T_d XOR D_d = sigma. This is a deterministic classical attack without original certificate, valid PoW, or fork, even for a synthetically FALSE original relation. Native VK and correlated checking data do not protect a fully recovered original sigma. Thus no full-public FALSE or unauthorized hard-TRUE security (and hence no arbitrary-QPT security) for this transparent construction.

## Concrete repair checks
(1) Make D_d depend on the SHA256d of the *first different future child* B_d. Then T_d frozen against future B1 does not generally work for another independent qualified B2 with the same first divergence d, so every-witness same-capability correctness is lost. Synthetic examples demonstrate distinct pads; no theorem is claimed for every actual Bitcoin/Syscoin source distribution.

(2) Publish only SHA256 commitments com_d=SHA256("commit"||d||T_d) rather than T_d. This authenticates a withheld token, but original source B supplies public p_d, not its preimage T_d; Open is missing. Publishing T_d or its source-independent opening restores immediate adversarial recovery.

(3) Hash a common BTC anchor, source-prefix hash, target-implied prefix or pivot class; all are public before the fork. Software VerifyOriginal before raw decryption does not bind raw public ciphertext algebra. This does not rule out a nontransparent original-source cryptographic release, but no such hash-only source compiler was instantiated.

## Executed checks and resource limits
Two byte-identical local executions of checker.py (SHA256 38c1c1c682b4411454921580f68a19671516b3104b4f9d3ee75b10b2efcb1cb6) produced JSON SHA256 0c3da1c27d5a52b43deaa53874ebca80ef7e912026923c3af336913eee979fa3: 80 synthetic chain-fork honest opens (d=1..40, two distinct branches each), 40 no-witness public recoveries, 40 same-d future-child pad nonconvergences, 40 falsely admitted-case public recoveries. A second checker commitment_repair.py (SHA256 0eea9e90e83fff53c1519f4cbe38cbd88d71062bf6bbb268023695c920e08554) ran twice with identical result SHA256 00d8584e74092d7b3723aceedf1571f65a141fe2d761ba4c370f836265ea92dc: 40 correct commitments, 40 token recoveries when made public, 40 raw fake-source recoveries. The token-withheld public Open is **not implemented**. CHECKPOINT_01 (SHA256 80c01ef37f9b29bad05278aa20bc4ff3f5a43b0eb79e949776ab996d67189b5c) preceded first checks; CHECKPOINT_02 (SHA256 5130e906bf9e6ba8bdd2bb4f853c44c2ba59b48dd26c54ac7a9562ffe6c68933) preceded commitment check. Complete expanded scripts/checkpoints and derivation are in a local archive, not presumed persistent.

SHA256d-linked child strings are synthetic fixtures, NOT Bitcoin PoW or complete AuxPoW, BTC bestchain, Syscoin validity, burn verification, native SLH-signatures or quantum security experiments. Tag reference height h_ref(n)=10 floor((n-6)/10); local first-tag maturity is n_min(d)=10 ceil(d/10)+6, 6–15 height difference, not complete proof length or inclusion guarantee. No production/release change or ordinary PR comment.

## Exact remaining equation
Implement classical-PPT Build_inc(x_W,sigma) and public Open_inc(C,B) for *every* independently qualified ORIGINAL future evidence B returning the identical frozen safe native cancellation authorization, without publicly bypassable selectors or source-generated secret labels. Prove arbitrary QPT full-public FALSE and unauthorized hard-TRUE recovery/native-forgery -> ACTUAL ORIGINAL certificate or independently justified PQ hash/native break; account for malicious N-of-N setup, abort/DA, quantum oracle interfaces, VK/auxiliary correlations, sibling selective openings, claim-scoped native spend and Bitcoin censorship. This checkpoint does not reduce that cryptographic obligation; no breakthrough notification is warranted.
