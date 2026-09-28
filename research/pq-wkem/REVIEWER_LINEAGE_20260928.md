# PQ witness-KEM: reviewer guide and evidence lineage

**Document ID:** REVIEWER_LINEAGE_20260928. **Purpose:** a new navigation and review record, not a new cryptographic result or an independent audit certificate.

## 1. Snapshot and honest status

Repository/PR: `syscoin/PVUGC#1`. Branch: `research/pq-wkem-validation-20260918`.

The connected GitHub snapshot reviewed for this guide is **`9d3a4dd419a18e6be08d1c8eca9b719f514ed6f3`**, whose commit message is `research: add Run 152 CMV MinRank laconic QPT source bridge`. The PR was open, draft, and unmerged. Its changed-file listing contained 541 files, all under `research/pq-wkem/`. Latest ordinary conversation comment read: `5859816284`.

**There is no completed practical generic-NP post-quantum witness-KEM in this record.** The best-supported published artifacts are algebraic source interfaces, scoped negative results, conditional extraction/reduction statements, and reproducible finite checks. Publication and passing tests are not security proofs. A high run number, assertion count, or confident assistant description is not additional evidence.

This guide preserves the original documents. It does not silently repair their text, rerun historical experiments, or elevate provisional claims. It distinguishes the last committed research checkpoint from later conversation reports that are not on the branch. The PR body's older pinned SHA and file count describe an early checkpoint, not this snapshot.

## 2. Current application contract

The required flow is **ORIGINAL witness/proof evaluated off chain -> protected common branch key/capability recovered off chain -> ordinary native transaction signature**. Bitcoin is not to execute the source circuit or adjudicate a VM/PCP/general-proof challenge. Witness privacy is optional; conditional release is not.

The statement must bind the relation, claim/UTXO, branch, anchors/window and relevant context. Every valid witness must obtain the same branch capability under the claimed correctness quantifiers. A counterwitness may authorize a challenge; normal settlement may instead be governed by an already-preauthorized timeout graph. A proof of global absence of unseen forks is not assumed.

The baseline permits an abortable N-of-N setup with at least one honest participant and required erasure. Permissionless observers later use public release algorithms; they are not an online secret-release committee. The optional single-builder branch has a stronger retained-state game and cannot use generate/encrypt/delete. These two setup games must not be conflated.

P2MR-like removal of an EC key path and native SLH-DSA-like verification are conditional endpoint assumptions supplied by the project, not deployment predictions or verified activated features in this editorial pass. CAT, an NP-verifier opcode and a chain-state oracle are not assumed. Whole-UTXO ownership is unrestricted after legitimate settlement; pre-settlement challenge enforcement remains an obligation. ChainLocks are optional, not a mandatory replacement for the generic relation.

## 3. Read the published spine, not every experiment chronologically

The following are summaries of the cited committed documents, **not fresh independent theorem validations**.

| Read | Role in the lineage | What is retained | What is not established |
|---|---|---|---|
| [Run 79][r79] | Source and capsule interface | Public honest anchor; rank-based all-witness decoding; complete-output Fourier characterization | A small bias for each character does not establish joint hiding; the structured spectrum is still needed |
| [Run 129][r129] | Actual-source normalization and negative control | Public decomposition into anchor-zero kernel plus a normalized representative; precise public-quotient failure | A public normalized class is not a hidden release value; nonlinear/secret-mode mechanisms are not ruled out |
| [Run 102][r102] | Quantum extraction machinery | Conditional one-copy Fourier sampling with mixed quantum advice using a circuit dilation and its adjoint | Not an opaque forward-only oracle extractor; not an unconditional construction; application-specific source/spectral hypotheses remain |
| [Run 123][r123] | Alternative dual-mode specification | Mode-independent canonical target and statistical complete-view switch yield a clean conditional extraction argument | SDMSH is a target interface, not an instantiated standard-LWE primitive |
| [Run 126][r126] | Compatibility test for that specification | An extraction-mode view must not efficiently regenerate an accepted target or compatible hash secret on a source-hard instance | Does not refute every dual-mode construction; identical public marginals alone do not imply joint secret samplability |
| [Run 147][r147] | Native-key payload wrapper | A suitable one-bit QPT release primitive would suffice for a polynomial-length signing seed; accepted-signature reduction is explicit | Does not construct that primitive or port a classical PAoK/Goldreich-Levin proof to QPT by assertion |
| [Run 152][r152] | Latest committed combined candidate | Actual-source affine residuals meet the CMV-form capsule and conditional one-copy source extraction | Neither structured false-instance hiding nor the required true-instance spectral bounds have been instantiated for a full practical scheme |

A useful reading graph is:

`79 + 129 -> actual-source residual -> 152`

`102 -> conditional quantum extraction used by 152`

`123 + 126 -> alternative dual-mode requirements, not an implemented replacement`

`a completed source-release primitive -> 147 -> native signature endpoint`

The last arrow must not be read backwards: having a native signature scheme or a seed wrapper does not construct witness-restricted release.

## 4. Scope ledger: why approaches stopped, and what would reopen them

| Published observation | Exact restriction being tested | Do not overgeneralize to | Evidence needed to reopen |
|---|---|---|---|
| Run 129 public anchor quotient | Public linear/affine evaluation after forgetting the anchor-zero source directions | All canonicalization or all secret-mode hashing | An explicit construction not publicly evaluable from the normalized representative, with its complete-view security proof |
| [Run 109][r109] hidden-input EPHF boundary | The recorded universal projection of a fixed-input opening relation | All functional commitments, HPSs, or lattice encodings | A concrete future-input encoding that avoids the exposed gadget/ambient evaluation, and an ORIGINAL-source reduction |
| Run 126 resampling barrier | Efficiently obtaining an extraction trapdoor together with a compatible accepted target | Impossibility of indistinguishable public modes | A justified secret correlation preventing target resampling in the complete extraction view; not a newly named hardness claim restating the goal |
| [Run 82][r82] near-gap family | Explicit false-source family and specified field/parameter regime | Insecurity of every rank capsule or every field conversion | Actual structured distribution/parameter evidence defeating the relevant test; retain the exact field and normalization assumptions |
| Runs 79/152 Fourier bounds | Complete transcript laws and explicit spectral sufficient conditions | A proof that a large upper bound or large chi-square value alone is an efficient attack | Either a usable hiding bound or an actual efficient distinguishing/recovery argument in the relevant experiment |
| Run 147 native escrow | Composition assuming the core release theorem | Standard signatures, a public proof, or escrow alone supplying release | The missing QPT core primitive and the complete branch/setup composition |

A negative experiment should be tagged **counterexample to this syntax/parameter family**, **failed proof strategy**, **implementation error**, or **out of application scope**. Those are different conclusions. Reopening is justified when a candidate escapes the demonstrated premise; changing names without changing that premise is not progress.

## 5. Corrections already traceable in the published record

- **Quantum advice:** Run 102 explicitly corrects Run 101's unnecessarily restrictive re-preparable/purifiable-advice formulation. Preserve the positive one-copy result together with its non-black-box circuit/adjoint requirement and spectral conditions.
- **Native public-key correlations:** Run 147 explicitly corrects the stronger concern that every setup-generated public-key correlation necessarily needs a separately assumed arbitrary-auxiliary-input theorem. Simulatable reduction state and external, unreproducible classical/quantum auxiliary input must be separated. The latter remains a theorem obligation.
- **Canonical value versus source witness:** Run 129 separates the public anchor quotient from the exact honest-witness difference space. A useful algebraic normalization must not be advertised as a hidden common key.
- **Security scope:** Run 152 does not import CMV's random-instance security into statement-derived keys, and does not turn classical generic-group security into concrete PQ security. Its title must not be read as proof that all displayed spectral premises hold.
- **Deployment scope:** the earlier published keyless-native discussion uses a generalized witness-aware signature verifier and explicitly disclaims unchanged Bitcoin/stock-verifier compatibility. That remains a separately scoped observation, not completion of the current native-signature-only release contract. See [the published scope comment][keyless-comment].

A later report saying an earlier idea failed is itself reviewable. Preserve the earlier statement, the alleged counterexample, the failed hypothesis and the corrected statement when those artifacts are available. Do not erase a concept simply because the assistant later called it a dead end.

## 6. What an independent reviewer should challenge first

**The source arrow.** Pin the field, matrix space, anchor and allowed rank. Keep prime-field, characteristic-two and binary-descent claims distinct. An extracted ambient short vector or rank-one matrix is not automatically an ORIGINAL witness. State what happens if the anchor is zero on a false-source space; do not assume normalization is always available without handling that case.

**The public-distribution arrow.** Include every projection key, proof/verification datum, setup transcript, capsule, branch checking key and correlated auxiliary value. Small fixed-character bias, a minimum-rank promise or resistance to tested attacks is not complete-output hiding. Distinguish information-theoretic sufficiency from computational reduction, and distinguishing from final-key recovery.

**The quantum arrow.** Identify the circuit access required, the advice distribution and its dependence on the challenge, the exact low/high spectral hypotheses, and the extraction probability. One-copy extraction does not license resetting or cloning that state for amplification. A theorem for a raw key, a supplied representation or a bit predictor is not automatically a theorem for a derived native signing capability.

**Correctness and composition.** Check the quantifier over all witnesses versus probability over one shared setup/capsule, exceptional cases, multiple-capsule composition and exact agreement of the final key. Prove that a native accepted spend without explicit key output is covered. Only after the core is sound should the malicious setup, abort, erasure, pre-signature availability and challenge timing be composed.

These are review obligations, not newly proved defects in every cited scheme.

## 7. Publication gaps are part of the lineage

The current branch already contains Runs **129, 131-134, 140, 147 and 152**. The ordinary comment [5859816284][catchup] verifies the earlier 129/131-134 catch-up. Those sets must not be uploaded again as missing results.

In the recent Run-129-through-168 window, no labeled artifact sets for **130, 135-139, 141-146, 148-151, or 153-168** appear in the current PR changed-file listing: **32 run sets**. Original local ZIPs for all 32 were found and passed ZIP-integrity checks in this session; their four-member sets total **128 files**. The accompanying [inventory](reviewer-artifact-inventory-20260928.json) records archive hashes and availability metadata, not republished research contents.

Historical conversation reports, and for the earlier range the cited catch-up comment, record safety-denied publication attempts. No supported resolution was established here. Accordingly, this guide does not retry those payloads, republish orphaned fragments, or reconstruct compressed mathematical summaries of denied material as a workaround. The earlier denial reports remain reports; this session did not retrieve their original execution logs.

This means the GitHub record is **not yet a complete scientific history through Run 168**. Later conversation reports must not be treated as peer-reviewed corrections or as remotely reproducible evidence merely because their run IDs and hashes are inventoried. Conversely, their absence from GitHub must not be interpreted as proof they were invalid. Preserve them for a supported publication/review process rather than silently discarding them.

## 8. Evidence and maintenance rules

Keep the reviewer-facing spine compact. For each consequential result, retain a full exact-version note, its actual executed checker, captured output and provenance. Put tangent detail behind references rather than repeating it in summaries. A summary should state its parents, claim type, exact assumptions, what failed, what survived, and how to reopen it.

Do not sum assertion counts across overlapping fixtures or treat integrity verification as a fresh test execution. Do not claim a paper was fully audited from an abstract. Do not rewrite historical failures into successes after a later upload. Record a later correction as a new linked entry.

**Work done for this guide:** connected GitHub state/comment/file-list reads; source reading of the nine checkpoint notes below; local ZIP CRC and SHA-256 inventory. **Not done:** new cryptographic research, checker re-execution, fresh literature audit, proof certification, production edits or automation changes.

### Exact source-note anchors at the snapshot

| Run | Git blob SHA |
|---|---|
| 79 | `30084603c3b35c449be4e154f6d214533526d3c5` |
| 82 | `6430557fd1596308db029d17b48549f9ed9490c8` |
| 102 | `5ec37cfcf47fcdc68d279af1dc1b6c90a7287c8d` |
| 109 | `91ebfdb8d712bc9a092b30af21048ea7bd04a109` |
| 123 | `2eefa25de7f5a9b9c65abf15a20bb4ae6564702e` |
| 126 | `94d1a6246da77f561ecacd84ce78917d6121dc33` |
| 129 | `cb74329d418b365abd325270185673b29fb10560` |
| 147 | `440a59de11556424cefe51aa5433d383c757ee7b` |
| 152 | `398b93af491d0b11cc486e86c89295a05b714804` |

The list has nine source notes: core reading plus the two targeted boundary notes. Reads were for editorial scoping; full theorem/implementation revalidation is left to the reviewer.

**Stopping status remains unmet.** The published record does not supply a practical full-public-output QPT construction with all-witness correctness, ORIGINAL-source extraction, exact justified assumptions, malicious setup/abort composition and concrete resources.

[r79]: https://github.com/syscoin/PVUGC/blob/9d3a4dd419a18e6be08d1c8eca9b719f514ed6f3/research/pq-wkem/ANCHOR_SHIFT_MINRANK_RUN79.md
[r82]: https://github.com/syscoin/PVUGC/blob/9d3a4dd419a18e6be08d1c8eca9b719f514ed6f3/research/pq-wkem/FINITE_DIFFERENCE_LOWRANK_RUN82.md
[r102]: https://github.com/syscoin/PVUGC/blob/9d3a4dd419a18e6be08d1c8eca9b719f514ed6f3/research/pq-wkem/FULL_KEY_ONE_COPY_QPT_EXTRACTION_RUN102.md
[r109]: https://github.com/syscoin/PVUGC/blob/9d3a4dd419a18e6be08d1c8eca9b719f514ed6f3/research/pq-wkem/HIDDEN_INPUT_EPHF_BOUNDARY_RUN109.md
[r123]: https://github.com/syscoin/PVUGC/blob/9d3a4dd419a18e6be08d1c8eca9b719f514ed6f3/research/pq-wkem/STAT_DUAL_MODE_SOURCE_HASH_QPT_EXTRACTION_RUN123.md
[r126]: https://github.com/syscoin/PVUGC/blob/9d3a4dd419a18e6be08d1c8eca9b719f514ed6f3/research/pq-wkem/DUAL_MODE_HASH_SECRET_RESAMPLING_BARRIER_RUN126.md
[r129]: https://github.com/syscoin/PVUGC/blob/9d3a4dd419a18e6be08d1c8eca9b719f514ed6f3/research/pq-wkem/HAIR_SAHAI_PUBLIC_ANCHOR_QUOTIENT_BARRIER_RUN129.md
[r147]: https://github.com/syscoin/PVUGC/blob/9d3a4dd419a18e6be08d1c8eca9b719f514ed6f3/research/pq-wkem/BITWISE_LACONIC_EXTWE_NATIVE_ESCROW_RUN147.md
[r152]: https://github.com/syscoin/PVUGC/blob/9d3a4dd419a18e6be08d1c8eca9b719f514ed6f3/research/pq-wkem/CMV_MINRANK_LACONIC_QPT_SOURCE_BRIDGE_RUN152.md
[keyless-comment]: https://github.com/syscoin/PVUGC/pull/1#issuecomment-5852515576
[catchup]: https://github.com/syscoin/PVUGC/pull/1#issuecomment-5859816284
