# R252 — authenticated AuxPoW source kernel and attempted hash-pad release (NONQUALIFYING)

**No cryptographic advance.** No classical-PPT source-conditioned Build/Open, QPT security, native cancel signature, real BTC best-chain proof, or full Syscoin state check was established. This is an unpublished-in-the-product, research-only checkpoint.

## Continuity and provenance
Observed PVUGC PR #1 branch `research/pq-wkem-validation-20260918` at starting SHA `83c26428bcb8ee5adf7ce48aa45218b801cb2472` (R251), whose exact note blob `a1617d92727e4dd6e254cdc57aa4c95e7eb55a71` was read. Last substantive ordinary PR comment was R225 (#6796383617). Read-only Core PR #609 current head `c91539de3c34937e57d7f5fda47c7b0502ff33f6`, `src/validation.cpp` blob `a33bb28089a5f5b8b4e68fbe78e17de6209d88de`, and `src/auxpow.cpp` blob `656cb66a322b65348c6e2e0cccce16e42f63ade0`. The PQ activated modern chain ID, exact 41-byte canonical one-tag rule and ancestor schedule remain in code; current public-network profile is release-disabled. No web or other repo write.

## Named candidate CANON-252
Built a local Python partial source kernel using real SHA256d of serialized 80-byte parent headers and a witness-stripped one-input, one-output coinbase, parent coinbase Merkle-root check, AuxPoW one-deep chain Merkle commitment with deterministic index, MM marker/root/size/nonce, the exact canonical SYS tag `OP_RETURN PUSH39 ('sys'||ancestor_hash||LE32(height))`, and six child-header links back to height 110 from a candidate at 116. The kernel differentiated two canonical post-PQ parent/child/ref-hash fixtures, one alternate Bitcoin parent certifying the *same* child (not a Syscoin fork), six independently parent-authenticated malformed-tag fixtures that failed their inner tag check, and a tampered coinbase failing the outer commitment.

**Critical limitation:** This kernel is NOT a complete original-source verifier. It supports only a fixed synthetic one-input/one-output coinbase, a 1-deep child Merkle proof, a regtest-scale synthetic PoW target, fixed heights, and no arbitrary witness serialization, duplicate-output scanning, Bitcoin main-chain membership, full Syscoin state, actual source burn/authorization, challenge admission/window or native signing. The test fixture's labels are not real network-admission evidence. It is not a PublicDerive source compiler.

The jointly examined attempted key release was
```
K(W) = SHA256d("R252-PAD" || SHA256d(parent_header(W)))
C = sigma_cancel XOR K(W0)
Open(C,W) = C XOR K(W)
```
Even giving the builder the impossible advantage of knowing one future qualifying W0, a second qualifying W1 with a different parent produces a different K(W1), so same-capability correctness fails. The #609 unique child-per-parent rule does **not** make different authenticated parents' hashes equal.

Repair attempt: replace K(W) with `Kcommon=SHA256d("R252-COMMON" || A)` for the pre-withdrawal authenticated source anchor A already bound in public x_W. Then every witness computes the same Kcommon, but so does an attacker from x_W and C *without* source evidence. Full-public FALSE/hard-TRUE secrecy fails classically. A post-hoc `VerifyOriginal(W)` check cannot protect an already-public raw key computation.

This is a failure ONLY of the tested local-pad/common-public-prefix family. It is neither a generic hash-WE impossibility nor a secure witness-KEM. The actual Build/Open and arbitrary-QPT final-key recovery-to-original-certificate reduction are still entirely missing.

## Execution and persistence boundary
Executed the local kernel twice and byte-compared its JSON output. Locally preserved `source_kernel.py` SHA256 `f9cf34ba3f34d7a4efe75c3f238f8597ad89db8d241be4dc6ae92ad581561eb3`, JSON SHA256 `35863e845133ec173b0a23ed1c557d20add691662e2dcf8583f9de085e2aa22d`, initial checkpoint SHA256 `c700fa35fa28eb0b1fe14720cb34ddd45fdc9c2a5082725ab0f657dd4d99d1cc`, intermediate SHA256 `d8ec6253d3ca361b657679f22671908c0a0e9157b76adc0394a421e52818218e`, and full local note SHA256 `87cf9501b7f9874e314ceb6d08d151f2c7d46890782973a352efbe2f1609b104`. These checker/checkpoint bytes are LOCAL ONLY, not uploaded or independently Core-tested; a sandbox archive may not survive a future run. Only this note is intended for GitHub in this action. No ordinary PR comment or notification.

**Next construction:** A transparent full-public joint source-circuit/key-release simulator must make *actual* qualified original SHA/AuxPoW certificates cryptographically indispensable to recover the SAME frozen claim/path-scoped native cancellation authorization, while avoiding fabricated-credential raw evaluation, public anchor-key computation, pre-known future witnesses, retained issuer secrets and an online releaser. Preserve all three independently qualifying OR branches, malicious N-of-N setup, sibling capsules, and arbitrary QPT extraction.
