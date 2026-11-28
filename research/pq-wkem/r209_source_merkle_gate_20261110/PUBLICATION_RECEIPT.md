# R209 exact published file/commit reconciliation

**Not a security advance or report threshold.** This receipt supersedes the "full scripts local only" provenance statement that was true at the first R209 research commit but became outdated after the complete local checkers were uploaded.

- Existing syscoin/PVUGC PR #1 draft branch research/pq-wkem-validation-20260918; observed starting HEAD 10fff30d4dd7becf9205b99ef224d01f8e699087.
- Intermediate hypothesis commit: 103464601922cdde16a96bab7cc9c43d80300624 (expected-head fast-forward, parent is start SHA).
- Research note and smaller reproduced test commit: f16fdf175acd36dbba03d38dbf104f926750caf8 (parent 1034646).
- Full original executed scripts and output committed at 604b9f9fcd2530057de7b988fcd417bdcb604e3d (parent f16fdf).
- Git blob of research note: f3ad3b4f3f69c43f9a245cc204089fe29818d558.
- Exact local-and-remote-matched repro.py blob: caf80cc976a18c35d2cbe8bd5fc395cf02783cfe.
- Exact local-and-remote-matched repro_output.json blob: ab61751482ce7836abae1f24d78e2ccbe71a7402.
- Exact local-and-remote-matched checker.py blob: 0223f4760d3fc3b6752cb03846eb39bec3303826.
- Exact local-and-remote-matched captured.json blob: 9a3743be1a850779f3b50ec8b31145b2fcc6957d.
- Exact local-and-remote-matched collision_extractor.py blob: 3fefe466bac5e223b09b649f362c1d922bd5b752.
- Exact local-and-remote-matched collision_output.json blob: 1badac6a801797b204ef10a81ec264c5594f13df.
- Each published test was executed twice locally; output was byte identical in the two runs. The source SHA256s and test counts are preserved in RESEARCH.md and captured output. The branch and commit parents were read back after the publish action. No ordinary PR comment posted; no independently verified QPT security or original bridge Build/Open.

All paths exclusively under research/pq-wkem/r209_source_merkle_gate_20261110/. No production/write changes elsewhere. The actual unpublished helper rerun.json duplicates captured.json and collision_rerun.json duplicates collision_output.json, so exact captured bytes already preserved on GitHub.
