# R192 — source-hash gate: trying direct PoW-derived common release

Run initiated against syscoin/PVUGC PR #1, existing branch research/pq-wkem-validation-20260918. Starting head observed by exact PR metadata: 4be2434d30898c42f1201b49cd7381d4ff52ca24 (open/draft/unmerged). Latest ordinary comments since 2026-11-09 20:00 UTC returned none. Read exact R191 research file; no broad history read.

This is a hypothesis checkpoint, not an achievement. Focus the one missing cryptographic equation on actual source-dependent release, not proof formatting, setup fees or packing.

## Candidate SHA-OR (direct PoW derived release)

Setup participant i fixes one native cancel signature sigma_i bound to exact graph/claim slot and chooses fresh 256-bit K_i. Publish capsule C_i with D_i=sigma_i XOR Hpad(K_i) and checking commitment CK_i=Hcheck(K_i), plus an alleged work-conditioned public reconstruction function F_i(x,w).

For any qualified ORIGINAL work, burn-fault or Syscoin-fork witness w, public Open would need F_i(x,w)=K_i, independent of divergent parent header, nonce, tag and proof path. It must not be computable from public x,C without a qualifying original witness. Since actual Bitcoin/Syscoin source transcripts contain no K_i-dependent preimages introduced by setup, test whether a direct hash of stable anchor, mining nonces, child hash, or full authenticated transcript can supply the common value without accidentally making it public or witness-specific.

The analysis must not confuse a toy locally mined PoW header with Bitcoin/Syscoin admissibility, and may not claim that an attack on this simple F_i rules out nonblackbox SHA circuit encodings. Test a concrete small target/nonce space, then attempt a source-linked repair if the direct construction fails.

Missing from this checkpoint: executed checks, complete final proof reasoning, any working Build/Open, QPT theorem. No deployment/source-code change.
