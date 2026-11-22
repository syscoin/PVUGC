# SAI117 reproducibility provenance

Live read start head of open draft PVUGC#1: 8b5cf52542fa340966125f63e12b699c72d4e85a, branch research/pq-wkem-validation-20260918. Previous SAI116 note blob bfd3e24d8222282b2881673d8b8cf5aacb7a7a0b. Top-level issue comments since 2026-11-21 00:00 UTC: [].

Two STANDARD-LIBRARY Python3 checker variants actually ran locally with exit code 0 in the active execution. The longer independent diagnostic (not checked into GitHub) is /mnt/data/sai117_global_variance_20261122/check.py, SHA256 f73c59640a7e768c1d46b404ba4e25f87f86354b3a5e29658dda3e2f6751559d, with output.json SHA256 a697d96d22965ff3a7e37f52c78a444f2bf96efbe4324f86d3154bf4293aa37b. The longer output additionally records an invalid pre-power matrix digest and scope.

The COMMITTED compact checker, check.py, was independently executed locally as compact_check.py with exit code 0, SHA256 4add311a31dd75da6da2535cd6ca7c7df265eb261a6f85e79f4ec22753ec9b9e, Git blob ba00223c731e7ce8b5b1d3b2f4a613e065550ff6. The compact captured output is COMMITTED as output_reference.json; local compact_output.json SHA256 1bc80699beb94301d17eb92eb739485809a6cb9b4489be72d78fd25169762167, Git blob e33a034456d72482e3f506296dfed0bf3dd87461. The outputs agree on all shared substantive assertions. RESEARCH.md blob 9db94603c4bb2e7c2e65c5882c26da539c32ab93. All these blob IDs were read directly from created tree 901edbdf0d0bbbf779297218ad4a5b2e4fa99e9e before adding this provenance entry.

No FE/WE implementation or source certificate was created, no Bitcoin native signature test, Core source edit/test, ZK, QPT proof, productive FE security model or real network challenge. This is NONQUALIFYING, and no GitHub progress comment or user notification is warranted. No production changes, merges or deployment.
