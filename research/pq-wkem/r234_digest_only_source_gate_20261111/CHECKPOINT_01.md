# R234 intermediate — the source-factorization gate and a repair to test

**Nonqualifying interim checkpoint.** This run continues the exact uninstantiated hash-only source-to-hidden-input interface, not generic packing. No native Bitcoin deployment, cryptographic key release, QPT security or original evidence is claimed.

Starting pointer from current PR #1 metadata: head \`7356d2669cda9fe48b63d5f5cf676bc46b012eb4\`, with R233 temporal-capability note at exact blob \`5f05e5f8e986c41d749f645e179e574e7a9e63a1\` and R232 source-label gate at exact blob \`88cf22e9d42a4d94f5838c2ae1ec2aab12f298ec\`; latest recent ordinary comment was R225. Subsequent commit must recheck head.

Named subproblem: can a public hash-carrier produce one frozen cancellation signature from ANY real SHA/AuxPoW contradictory history without treating fabricated semantic tag bits as a source certificate?

A full-public semantic-first candidate uses a fixed baseline b, 8 public rows E_i = sigma XOR SHA256("pad", L_i), and first differing bit i. The label L_i is derived from public baseline and target bit. For every alternative value v != b, the row gives the SAME sigma. The code in checker.py confirms exhaustive 8-bit semantic coverage (255 values). But replacing the actual qualified source with any fabricated v produces exactly the same release (255 failures of source soundness). This excludes only the semantic/digest-factorizing class; it is not a universal impossibility of hash-only WE.

Repair 1 keeps the L_i private at setup. It blocks public arbitrary-value opening but the ORIGINAL future work certificate lacks the secret L_i. Repair 2 takes L_i from the future work transcript; it becomes source-dependent, but the builder cannot preseal rows for arbitrary unknown later work certificates. Repair 3 uses only the public fixed prefix of proof-of-work output; the prefix can be synthesized without mining, opening the key early. None is a genuine source-certified transfer.

**Deeper next step in this pass:** test whether fully authenticated Merkle branch paths associated with fixed source roots can provide a hash-only nonlocal label inaccessible to a fabricated outcome while remaining precomputable for EVERY later alternative root, including two parent-work certificates for one child. The test must not substitute Merkle verification in ordinary evaluator control flow for cryptographic release; root/path provenance and qualified source anchoring remain part of the original relation. Preserve all exact outputs/code and distinguish an original hash collision from a normal Syscoin fork.
