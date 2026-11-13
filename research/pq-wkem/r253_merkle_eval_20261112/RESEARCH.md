# R253 — opaque SHA-Merkle evaluation repair of R251 (NONQUALIFYING)

**No cryptographic advance.** The attempted repair removes literal public coefficients from R251's source-gated polynomial, but ordinary salted hash commitments cannot provide future original-source witnesses with private polynomial evaluations and decommitments. A full classical-PPT original-source Build/Open and QPT theorem remain missing. This is a bounded construction/repair investigation, not a generic witness-encryption impossibility.

## Continuity
Observed PVUGC PR #1 on `research/pq-wkem-validation-20260918` at 61a4b0e1654e0bba265b46c68423771b59dbbffd, after R252. Exact prior note: `research/pq-wkem/r252_auxpow_source_bound_20261112/RESEARCH.md`, blob `f5690fcd5c32eeda1c1dadbc0bb66fcdc4bd06cf`. R251's exposed-mask dual attack was the specific repair target (blob `a1617d92727e4dd6e254cdc57aa4c95e7eb55a71`). The previous Core #609 activated unique canonical tag and modern chain-ID source facts remain inherited, **not rereviewed or redeployed**. No websites/external literature/other repositories were accessed.

## Exact candidate: MERKLE-EVAL-253
Hypothetically faithfully arithmetize the ORIGINAL withdrawal-bound source relation (including actual SHA256d/AuxPoW, canonical parent tag, height/ancestry/Bitcoin anchor, relevance, burn, deadline and native safe-cancel VK/message) into constraints `c_j(z)=0`. This source compiler was **not instantiated** here. With secret `s in F_q` and sampled masks `U_j(z)`, let

```
P_x(z) = s + sum_j c_j(z) U_j(z) mod q
E = sigma_cancel XOR KDF(x_W,capsule_id,s)
L_z = SHA256("R253-L" || encode(z) || salt_z || encode(P_x(z)))
root = SHA256 Merkle root of the evaluation commitments L_z
C = (x_W,native_VK,root,E,manifest).
```

For each ORIGINAL valid witness `w`, `P_x(w)=s` gives the **same precommitted** `sigma_cancel`, *if* the opener can obtain `P_x(w)`, the unknown `salt_w` and its authenticated Merkle path. Ordinary hash commitments provide **verification after disclosure**, not those decommitment bytes. The only honest API tested was `Open(C,w,private_eval_w,private_path_w)`; it is NOT the required public `Open(C,w)`.

**Repair A (publish openings).** Publishing a plaintext accepted evaluation/path gives out `s` directly without a source-certificate gate. Publishing one selected opening loses every-witness completeness; publishing enough openings to cover arbitrary future source evidence either requires preknowing source witnesses, includes the actual certificate publicly, or costs exponential enumeration. An ordinary off-chain `VerifyOriginal(w)` before using already-public plaintext cannot undo raw recovery. The toy accepted row index is **not** an ORIGINAL qualified certificate; no claim of a demonstrated hard-TRUE ORIGINAL extractor failure is made.

**Repair B (derive witness-indexed salts).** `salt_w=SHA256("salt"||w)` would be derivable from the future source certificate, but the earlier builder cannot precompute `L_w=SHA256(w||salt_w||s)` across all unknown SHA256d parent/coinbase/child certificates without enumeration or a genuinely new compact, source-gated public evaluator. A fixed known BTC anchor or rounded tag height replaces this with a public, source-independent pad and loses the actual gate. This is a causality failure of the explicit hashed-table design, not a general no-go theorem.

**Repair C (compressed sparse default tree).** All possible witness indices can share one committed default leaf `H("DEFAULT"||salt||s)` with an `O(n)` public authentication path. Every index now authenticates the same *opaque commitment*; none obtains `s` without its preimage. Publishing `(salt,s)` releases the key to everybody without witness evidence. Hash authentication and conditional decryption are different obligations.

## Executed bounded checks
Local Python standard library, F_101 with six Boolean variables, `P(z)=s+(1-z0)U(z)`, accepting toy predicate `z0=1` (32 accepting assignments). Across 64 reproducible instances: 4,096 authenticated Merkle membership checks, 64 published-evaluation immediate secret recoveries, accepted-row same-s correctness, and wrong-leaf tamper rejection. Additional 16 all-default sparse-tree instances checked 1,024 public membership paths, confirming that they authenticate an opaque leaf, not reveal `s`. Two complete runs produced byte-identical JSON. These are toy finite algebra/hash tests and NOT source security, real consensus, native PQ signature or QPT proof.

Local expanded note `/mnt/data/r253_merkle_eval_20261112/RESEARCH.md` SHA256 `5fb15aa794fb76b35c0369f8d3bb6f0e0c941ba334b4925ac805ee25e5704aa6`; executed `checker.py` SHA256 `465e680f701c88181649937a2a2cf7099d7aac22ee98ef0ebd0051d4ec6d01da`; captured `results.json` SHA256 `055c2ceccc1e0fe34d55b8c675b05a55904ff133bec1c498324fefa005c056da`. Actual initial/intermediate checkpoints SHA256 `a42eaaa88191ff469dd864825f64c464cde99f5c1dbb63daa64a71fc9f1d1a69`, `f590a3dd18dc1234960c0e2c94ac3690b874cb26f132d6f45606a6bfa5cbae92`. Local resources are not assumed persistent; only this note is published if the file-create action succeeds.

## Remaining equation
Need **actual** classical-PPT `Build_inc(x_W,sigma_cancel)` and public `Open_inc(C,w)` where EVERY independently qualifying ORIGINAL authenticated AuxPoW/source-fault/BTC-work/burn-fault certificate returns the SAME frozen claim-scoped native cancellation authorization. No greater SYS work or second notary; no raw parent PoW alone. Simultaneously require full-public FALSE and hard-TRUE unauthorized QPT recovery/native-forgery -> an ACTUAL qualifying ORIGINAL certificate or independently justified PQ hash/native break, under malicious N-of-N setup, sibling capsules, selective openings, VK/check correlations, malicious source coins and source timing/censorship assumptions. Merkle commitments do not instantiate this compiler. No ordinary PR comment or user notification warranted.
