# Publication synchronization: Runs 78 and 79

Date: 24 September 2026.

This is a publication/reproducibility maintenance update, not a new research run or a new security theorem. The user explicitly requested continued GitHub publication. The live connector accepted the writes in this session.

## Scope and historical status

Starting PR head verified: `78a64c95f241814673f1ffbe76a4047033a7331c`.

The current PR comments and complete changed-file list were read before writing. Neither Run 78 nor Run 79 was present. The eight archived files were added through the connected GitHub tool, reaching `0aa76e627324ca339def55f8f4b3bcb4e5fca2f8` before this synchronization note.

The original proof and provenance files are preserved byte-for-byte. Their statements that publication failed or remained local describe the original runs. They are historical, not the current publication status. This note supersedes those status fields for publication only; it does not strengthen any cryptographic claim.

No production file was modified. The PR remains draft and unmerged. No previously failed write was falsely recorded as successful.

## Source archives

- Run 78: `wkem_minrank_dual_syndrome_run78.zip`, SHA-256 `976deb846176e54a2812b49061b0d7183ea7aea02a8be6de94a0adf2d7663864`.
- Run 79: `wkem_anchor_shift_minrank_run79.zip`, SHA-256 `f74456d9fe33a8b7905250046050bdd58e9047a7231895344fb038740eed99e1`.

Both archives were available as mounted conversation attachments. Their hashes match the previously supplied archives.

## Reproduction actually performed in this publication session

The two archived checkers were inspected and each was executed once in this session. Both exited with code zero and empty stderr. Each stdout matched its archived validation file byte-for-byte.

| Run | Checker SHA-256 | Reproduced stdout SHA-256 |
|---|---|---|
| 78 | `c8522798f0dcb48562b0d141362c3800d51fbc563bc116ea681205b714f96cd2` | `571086a3425f0c7f28866f0aef7cbcfe20c6a2dc95984953d4e4e0903563ec14` |
| 79 | `e5ae70b206bb39f2b0f1728925961c5bc6cee55e3d1a07b409049214c65f4933` | `14213525ccbb88d2ccde8beb00e7bb56ca1eb63ce50b14e8f32784208ab48b7c` |

These are reproducibility reruns, not additional independent research coverage and not evidence of security. This session did not independently re-review all external papers or re-prove every archived claim.

Reproduction from the repository root:

```sh
python research/pq-wkem/minrank_dual_syndrome_run78_check.py > /tmp/run78.json
cmp /tmp/run78.json research/pq-wkem/minrank-dual-syndrome-run78-validation.json
python research/pq-wkem/anchor_shift_minrank_run79_check.py > /tmp/run79.json
cmp /tmp/run79.json research/pq-wkem/anchor-shift-minrank-run79-validation.json
```

## Exact remote readback

All eight files were fetched at `0aa76e627324ca339def55f8f4b3bcb4e5fca2f8`. Their returned Git blob IDs match the IDs calculated from the corresponding local archived bytes:

| File under research/pq-wkem/ | Verified Git blob |
|---|---|
| `MINRANK_DUAL_SYNDROME_RUN78.md` | `4155a986ee4bf0d22b436dcebbe118a2c5b72ae1` |
| `minrank_dual_syndrome_run78_check.py` | `4086c08c7c59ff068e4b3c64a01fa88f003c54c2` |
| `minrank-dual-syndrome-run78-validation.json` | `4c4c43eef4e573a85d2c510a5e712ae3d5906291` |
| `MINRANK_DUAL_SYNDROME_RUN78_PROVENANCE.json` | `e97db2451d51f31fa547466648a2444f1db67103` |
| `ANCHOR_SHIFT_MINRANK_RUN79.md` | `30084603c3b35c449be4e154f6d214533526d3c5` |
| `anchor_shift_minrank_run79_check.py` | `8b16e6ebb50937628c3a0a0d1a8ceef7762f76aa` |
| `anchor-shift-minrank-run79-validation.json` | `7b922aa38059538a3aa4101023d3781ce4ceadca` |
| `ANCHOR_SHIFT_MINRANK_RUN79_PROVENANCE.json` | `a0e9e2c46b312c11f5e024c9db7fe6a2b801645c` |

The compare from the starting head to that eight-file head reports eight new files, all under `research/pq-wkem/`, and no deletions. This note is the ninth new research file in the maintenance update.

## Handoff

Runs 78 and 79 are now repository-readable inputs for subsequent hourly work rather than chat-only artifacts. The latest constructive candidate is the anchored low-rank syndrome release; its exact rank correctness and character identities do not establish full-output PQ hiding or arbitrary source extraction.

Continue with the actual rank-weight spectrum for the statement-derived source space and/or the restricted correlated trapdoor/prefix distribution identified in the Tsabary audit. Do not assume a standard random-MinRank or LWE theorem applies to a different correlated distribution.

Publish substantive intermediate findings and tested research artifacts incrementally through the connected GitHub tools, then verify readback before claiming publication. A past failed write does not establish permanent lack of repository access. Conversely, a fresh tool block must be reported accurately and must not be circumvented.

The practical generic-NP PQ witness-KEM stopping condition is not met. The existing hourly task must remain enabled.
