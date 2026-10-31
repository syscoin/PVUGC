# Uniform-FALSE binary-ISIS: restricted full-public QPT-LWE theorem (2026-10-31)

**Status: one genuine but narrow average-case composition theorem. NOT generic PQ witness-KEM, NOT arbitrary FALSE or hard-TRUE security, NOT a deployed Bitcoin primitive.**

This is a research-only continuation of the original statement-bound binary-ISIS release, with a fully instantiated random-FALSE source, source-dependent LWE encryption, all-ORIGINAL-witness release and straight-line joint-public QPT challenge simulator. The full formal derivation, access/advice restrictions, correlation model, exhaustive finite-field checker and provenance are attached in this directory.

- `RESEARCH.md.gz`: gzip-compressed exact full `RESEARCH.md`; decompress with `gzip -dc RESEARCH.md.gz`. Its uncompressed SHA-256 is `8b35fe6e73f6c115025c041dbe458d27f7ba463b3d6bf280f76ecd1dcc29512f`.
- `checker.py`: exact Python standard-library checker executed twice, SHA-256 `d32b1f4840c9023dea393ef8f47ac67b9a5343b380c5e9fcaa3f0d88285aeb10`.
- `output.json`: exact captured deterministic output of both executions, SHA-256 `8c85669411e6c5d058ca7a94c8a2c8204aba6ba1c8133f695361389df4a7e9e3`.
- `PROVENANCE.json`: verified starting head, exact predecessor blob, script and output hashes, executed commands.

For uniform `A∈F_q^{d×n},t∈F_q^d`, the binary-ISIS relation is `w∈{0,1}^n,Aw=t`. A uniformly random source is TRUE with probability at most `δ=2^n/q^d`. Consequently the source conditional on FALSE is within statistical distance `δ` of independently uniform `(A,t)`. Honest classical setup uses native `(sk,vk)` and independent per-bit source-and-ciphertext samples `β=Aᵀs+e, τ=tᵀs+e*+gk`. Every valid ORIGINAL witness cancels `s` and recovers the SAME `k` under the documented correctness bound. For any polynomial number `T` of unopened related bit ciphertexts sharing the same source and genuine vk, ordinary **nonuniform QPT decisional LWE** permits `T` straight-line hybrids where the challenge matrix is **exactly** `[Aᵀ;tᵀ]`, not an assumed SOURCE-opening oracle. The final random-ciphertext game embeds the genuine native verifier's EUF-CMA challenge key. Restricted unauthorized native-forgery probability is bounded by `δ+T Adv_QPT_LWE+Adv_QPT_native_EUF-CMA` (plus explicitly quantified correctness loss). Aux may be generated only efficiently from public inputs/vk; no secret-dependent advice or protected selective opening.

**Central unsolved requirement:** this theorem does not cover adversarial FALSE instances: `A=[1],t=3` has no binary witness but the public nonbinary opener 3 recovers all 512 mock bits. In the low-density regime `δ≪1`, any planted TRUE source is statistically at least `1−δ` from the uniform source, so this FALSE reduction cannot prove hard-TRUE security. There remains no generic, classical-PPT ORIGINAL-to-source compiler preserving every witness and the necessary full-public QPT simulator/extraction. N-of-N malicious setup/abort/DA, SYS/BTC qualification and the hypothetical native PQ Bitcoin endpoint remain open.

Executed checker: **10,036 assertions twice with byte-identical outputs**, including exhaustive small-FALSE counts, 300 random FALSE samples, 3,072 releases using two distinct valid ORIGINAL witnesses, and 512 chosen-FALSE nonwitness recoveries. Toy finite fields and mock checking key; no QPT hardness or native signature implementation was tested.

PR #1 branch only; no main, production, workflows, approvals, merges or deployments. Do not disable the continuing research task.
