# R224 publication addendum and verified local evidence

The R224 RESEARCH.md was originally written when two detailed checkers were local-only. Those exact files and their captured output are now also published on this PR branch (separate follow-up commit). No broader security claim changes.

Exact files / Git object identities (computed locally with git hash-object and compared to GitHub create_blob responses):
- checker.py: 167cb1cd90d1f6bef03acd142d78ab736c161211; captured.json: e39d05cd5c250b3c17d23ccc7acdce349eef3fb5.
- garbled_false_instance.py: 45cc3d42fdebc38a7686718d2da685aa8e72d365; garbled_output.json: ef42eb92950e5fb788a110c4a696854e52639e65.
- global_binding_repair.py: e517e02a686a0d633a838fa3e5f9e9d7001cae9e; global_binding_output.json: 175f1406fff25286e2a8e992ff3a309a81f0278b.

All three scripts were actually executed twice locally, and each pair of outputs matched byte for byte. They execute synthetic classical assertions only. No native signature, real BTC/SYS source verifier, original source certificate or QPT experiment. Git blob identity is not an independent security audit.

Run started from 8aee989b7cc6a3417328d0cedc420be851a9a6be on research/pq-wkem-validation-20260918, with intermediate checkpoint 749a0a2c91eb1373053d4b6d6c50e8f416a0c92a and research commit 36d2eb491a1947ec500b56f81f1040a525e75e94. No routine PR comment was issued. The remaining polynomial ORIGINAL-dependent Build/PublicOpen and full-public QPT reduction were **not** constructed.
