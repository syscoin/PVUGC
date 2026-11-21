# R262 — SHA256 midstate source-correlation gate (NONQUALIFYING)

**Result:** Rejected this narrowly specified hash-only release attempt. No original-source Build/Open, arbitrary-QPT reduction, Bitcoin/Syscoin consensus test or native PQ signature implementation was established.

## Provenance
On open/draft syscoin/PVUGC#1 branch `research/pq-wkem-validation-20260918`, read start head `bbfb5960b9735debd6f8c8db129f6ded784761e6` and R261 note blob `daa536cf8359be4b076ff8111468befeb5f22f4d`. Reviewed R259's native-SUF separation and R251's transparent ideal-mask analysis, and latest substantive ordinary PR comment R225 (#6796383617). Did **not** re-read Core #609 code or rerun its tests; rely only on user-supplied corrected contextual post-activation modern chain-ID, exact 41-byte canonical tag and one-modern-child-per-authenticated-parent-commitment facts. This is not a deployment claim.

The frozen slot-global x and all ORIGINAL three OR branches remain unchanged: (1) authenticated same-anchor strictly greater Bitcoin chainwork, (2) finite authenticated withdrawal-bound invalid/missing burn authorization, (3) authenticated, relevant claim-prefix Syscoin inconsistency or separately admitted qualified tag fault at LC depth. Source verification must enforce complete contextual AuxPoW/coinbase, chain history, tags, ancestry, window, fork depth, deadline and scope. No second notary, greater Syscoin work or private miner/signing assumptions are introduced.

## Exact attempted Build/Open and public-view simulator
Bitcoin header serialization is
`B=version[4]||prevhash[32]||merkleRoot[32]||time[4]||bits[4]||nonce[4]`. For the actual SHA256 of this 80-byte header define
`Mid(B)=SHA256Compress(IV,B[0:64])`. Crucially this first 64-byte block contains the 4-byte version, 32-byte prevhash and **first 28 bytes of Merkle root**. Two conflicting Syscoin child commitments require distinct authenticated parent coinbase commitments; Bitcoin parent headers need not have the same Merkle root or SHA256 first-block midstate. The shared Bitcoin prevhash on two parent candidates does not impose shared SHA midstate. Distinct Bitcoin work certificates for one Syscoin child do not constitute a semantic fork. Equal mids for distinct inputs are not mathematically excluded (e.g., changed Merkle suffix only); the security argument does not assume universal collision-free SHA compression.

Proposed `Build_mid(x,sigma;B0)` uses a publicly authenticated baseline parent header B0 and publishes
`E = sigma XOR SHA256d("MID-PAD" || Mid(B0))`.
Proposed `Open_mid(C,w)` identifies an ORIGINAL-qualified future parent B from w and outputs
`sigma_B = E XOR SHA256d("MID-PAD" || Mid(B))` if the exact frozen native VK/message checks. Every-witness correctness would require that same pad for every qualifying B; the ORIGINAL source relation does **not** enforce it. Independently, the complete-public adversary reads B0 from x, computes its public midstate and XORs E to recover sigma without any original evidence. This classical straight-line attack also applies to QPT, quantum auxiliary input and sibling capsules without requesting internal query logs or a representation. A post-hoc CheckSource on the output cannot restrict this raw recovery.

## Repair attempts
1. Replace Mid with a version/prevhash-derived shared ancestor key. It converges across same-prevhash parents but both header fields are public, so it decrypts immediately.
2. Add a secret setup salt r to the pad. If r is withheld, arbitrary future ORIGINAL certificates do not supply it, so public Open fails. If r is disclosed, the full-public bypass returns. Supposing miners/notaries later reveal r changes the relation/introduces a retained source secret.
3. Rely on nonce grinding to share Mid. With the same coinbase Merkle root changing only the nonce keeps Mid fixed, but does not supply two distinct modern Syscoin child commitments. Thus this SHA correlation does not supply the demanded fork-triggered gate.

These are exact impossibilities **for the named transparent hash-midstate pad family**, not a general impossibility for source-specific computational hash-only WE, and not a proof about concrete SHA's quantum security.

## Executed bounded offline experiment
A standard-library Python checker implemented SHA256's 64-round compression and compared complete 80-byte SHA256 against hashlib. It generated 16 deterministic **synthetic** pairs of distinct depth-5 child commitment hashes, embedded them in MOCK coinbase preimages (not real canonical Syscoin/Bitcoin coinbase transactions), obtained synthetic one-transaction parent Merkle roots and mined toy SHA256d headers with 12 leading zero bits. In 16/16 cases distinct child commitments and parent roots gave distinct first-block SHA mids and pads; changing only nonce for a fixed parent root kept Mid in 16/16; the public 36-byte ancestor-prefix pad allowed immediate key recovery in 16/16. Total 176 local assertions; two runs byte-identical. Counterexamples do not estimate security or establish collision nonexistence. NO full CAuxPow::check, Core contextual admission, actual Bitcoin compact targets/main-chain work, real Syscoin branch comparison, native PQ signing or QPT experiment was executed.

Full derivation/checker/results are available in the local archive; the checker is **not** asserted uploaded to this PR. Exact locally executed checker SHA256: `7cb5b3fe27ecd6e5b07178f4cd4f2dce931d2075bfabf2f3b8ec0fdae03396d7`. Repeated result SHA256: `6921ee7de9a0e16db81e1885d2ca2d5b50639afecb91d3a69db9cd359135623c`. Full local note SHA256: `ea0cab5724bbb8bb606f7e45ccc32cda1d98c8dc1cdb8a6fdba0bbb1f48a6f90`.

## Unfinished equation
Still required: classical-PPT `C=Build_inc(x_slot,sigma_cancel;r)` and public `Open_inc(C,w)=sigma_cancel` from **every** independently qualified ORIGINAL w, with the entire public, sibling, VK, auxiliary and selective-opening distribution simulatable, full-public FALSE security and unauthorized hard-TRUE QPT recovery/native forgery straight-line reducible to an ACTUAL original source certificate or independent PQ hash/native break. The missing object is a **nontransparent, cryptographically source-enforced common-key delivery representation** which can be frozen without predicting future parent headers or retaining a miner secret. No such representation was instantiated in this run. R261 endpoint scope remains the explicitly selected slot-global veto (liveness tradeoff).

Keep the research task active. Nonqualifying: no PR progress comment or user notification.
