# R348 — transport of genuine source Merkle paths into a fixed native hash-signature root (NONQUALIFYING)

## Provenance and precise constructive change
At start the actual open draft syscoin/PVUGC PR #1 had head `5947f875f8f1c04a22f9205d246aa3d165287cf9` on `research/pq-wkem-validation-20260918`, latest R347 research blob `65acfd7c51d7efec1c669ffad10c340e17031b79`. Read R347 and R346 (blob `2b3dec3bc8dec454dceb799097c4c6f25219106a`) and R327 (`ab7602bfc54403bf68294034557206f62d69a5dc`), plus top-level PR comments since 2026-11-16 (empty). Core PR #609 was consulted only for read-only metadata, head `b3b4f643383a2149807a25fe38d26b5f058daa60`; no new Core claims/tests. No external web/literature. R316 is merely a stale-tag-coverage regression, NOT an LC failure.

R347's attempted native-Lamport route needed an advance commitment over every possible future witness leaf, which cannot be pre-enrolled in polynomial time. This run tries a **different operation**: reusing original source's already-authenticated coinbase-to-parent and child-to-AuxPoW Merkle branches as **native hash-signature authentication paths**, so future w itself brings a path and the builder need not enumerate future certificates.

## Candidate Build/Open and the exact fixed-root obstruction
Fix x_W to the original claim, chain IDs, UTXO, assertion/burn/amount/recipient/reserve, anchored histories and work, relevant ancestor, strict contextual AuxPoW, exact LC depth, deadlines/reset, capsule ID, and frozen safe native cancel m/VK. All three independently sufficient ORIGINAL challenge branches remain allowed (greater exact BTC work, finite authenticated specific-burn fault, mature qualified Syscoin inconsistency/tag fault). One notary initiates; anyone with ORIGINAL evidence challenges; no additional signer responds.

An ORIGINAL AuxPoW source witness w carries authenticated Merkle information for ITS OWN parent transaction root `R_parent(w)`, and, separately, a valid child-chain Merkle branch / deterministic chain-ID leaf under contextual admission. The parent root differs in general across different legitimate source carriers; multiple Bitcoin parents certifying the SAME child are not themselves forks. A BTC authenticated path is a path to R_parent(w), not a pre-enrolled path to a frozen Bitcoin-native hash-signature root U.

Try `Build_transport(x_W,sigma)` that fixes one native VK/root U, and maybe `D=sigma XOR K`, before the unknown future certificate. `Open_transport(C,w)` tries to derive a native opening from w's supplied source path, without enumerating its future source leaf. The missing primitive is the exact root translator
```
   SourceVerify(w, anchor, R_parent(w), pi_BTC(w)) = 1
         DOES NOT IMPLY
   NativeVerify(U_fixed, m_cancel, NativePathFrom(w)) = 1.
```
Setting U=R_parent(w) afterwards changes the already preauthorized key. Setting U to the common PUBLIC ancestor gives no secret signing preimage and misorients the hash proof: Bitcoin descendant headers prove predecessor linkage (and child commitments), not native leaf-to-fixed-root inclusion. Source Bitcoin SHA256d and conditional native SHAKE/SLH-like signature verification are not identical hash functions; even granting an identical idealized Merkle hash does not fix the key mismatch.

## Merkle binding lemma (proved only for this attempted transport)
Use a fixed-height binary tree with fixed leaf indices and domain/level-separated collision-resistant H_leaf/H_inner. Builder knows a fixed native committed leaf L_i and path pi_i at each position, yielding U. If a novel source leaf L'_i != L_i and path pi'_i at the SAME position yield the SAME U, then:
(1) if H_leaf(L'_i)=H_leaf(L_i), the two distinct leaf messages form a collision;
(2) otherwise, compute both bottom-up node sequences. Their first nodes differ, their final roots coincide. At the first level where these nodes become equal, different ordered child input strings hash to the same parent digest, yielding an explicit H_inner collision.
Thus absent a collision, an un-enrolled source leaf cannot reuse one of the existing native tree indices, regardless of what merkle path authenticates it inside Bitcoin. **This does not forbid distinct legitimate leaves at distinct positions inside a PRECOMPUTED Merkle tree and does not prove a general WE impossibility.** A source-derived invariant mapping every w to a known enrolled leaf must still prove that this leaf earns secret signing material; a public common anchor fails that requirement.

## Joint-public distribution and same-frozen-capability check
If Build chooses independent uniform K and publishes D=sigma XOR K, authentic source certificates carry no automatically correlated access to K; FALSE masking holds only in this restricted ciphertext-only view, while TRUE Open is absent. Picking K=H(R_parent(w)) instead fails Build-before-future-w correctness and all-witness convergence: different authentic parent roots generally produce different keys. Picking K=H(public common ancestor) makes D decryptable even on FALSE. Source verification as a plain conditional inside honest Open does not prevent a public attacker from using the raw native material. No full-public QPT simulator/reduction was constructed; native VK/signature correlations, retained malicious source coins, siblings and selective opening remain open.

A full public root translator T(C,w) that returns the SAME precommitted native cancel capability for all qualifying ORIGINAL w and cannot be accessed on fabricated/incompatible evidence would constitute the missing source-conditioned release mechanism. This candidate DOES NOT implement it. Do not rename T as an oracle/signer/obfuscator or as a source Merkle proof.

## Executed structural checker — bounded and local-only
A Python3 standard-library checker instantiated both source and native using the SAME domain/level-separated SHA256-based Merkle tree (more favorable than actual different hash domains), truncated digests to 12 bits solely to synthesize an explicit toy collision, and used a two-level fixed native Merkle root. A distinct future leaf with the same fixed native root appeared on trial 1,797; the algorithm extracted an exact level-0 internal hash collision from the two different authenticated paths. Distinct source-parent histories gave distinct roots, the second not equal to the fixed native root. Two checker executions produced byte-identical JSON. This is NOT a 256-bit collision, a real source certificate, Core test, native SLH signature, QPT experiment or security evaluation. Checker SHA256: `19e71857f027ec5ecd738e35f414b4c180fee064a9151814ee4619ffa4237959`. Each output SHA256: `0f2ee36961bac5f11ab92615816271d7ae846cea7cd4e6bcf65f14b3c30bc1d6`. Complete derivation, code and both outputs are **local only** in `/mnt/data/R348_root_transport_20261117.tar.gz`, SHA256 `4e5f2dc04c52d43d64799b221c639609766e7d730a4fa9ce6e5b9891f246e73d`. Local archive is not a GitHub-published test artifact.

## Nonqualifying decision and next exact equation
This reuse of genuine source Merkle paths avoids anticipating future leaves but cannot make their variable authenticated roots equal one frozen native signing root. It establishes no hash-only ORIGINAL witness-KEM, no classical-PPT public Build/Open, and no full-public independent QPT security. Root-translation is STILL the missing operation, not a library adapter. Avoid revisiting tree depth, leaf positions, or hashing the public ancestor as purported repairs. Preserve R225 native activation portability and slot-global veto vs truly activation-bound native messages.

Required next:
```
 Build_inc(x_W,sigma_cancel)->C            classical PPT, before original event
 Open_inc(C,w)=SAME frozen sigma_cancel     for EVERY qualified ORIGINAL w
 Unauthorized recovery/accepted native forgery (full public, QPT) ->
       an ACTUAL ORIGINAL authenticated certificate or an independently
       specified PQ hash/native break, without volunteered adversary logs.
```
Preserve complete FALSE security, hard-TRUE source extraction, malicious N-of-N setup, all three independent OR grounds, full claim/UTXO/source/LC/maturity/DA/window binding, related capsules/auxiliary input, and only native Bitcoin cancellation signatures (large evidence off-chain). No progress comment, production edit or automation change is justified by this result.