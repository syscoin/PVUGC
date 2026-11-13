# R214 — One-sided source-label bootstrap (SLB): pre-test checkpoint

STATUS: hypothesis, not source-dependent WE, not a QPT proof, not implementation progress.

PR #1 syscoin/PVUGC, open/draft, branch research/pq-wkem-validation-20260918. Observed starting head cca3912e367765d1c97a6285e060419f32995fde. Exact-version current R213 and R212 research notes read. Latest ordinary comments since 2026-11-10T16:00Z: none. Pinned Syscoin AuxPoW source semantics only, no current deployed claim. No external literature/web, independent agent, real mining or native PQ signing.

Exact original target: x_W binds vault UTXO, claim, burn/authorization, BTC/SYS anchors/window, claim-relevant height, baseline claim-prefix pure-child digest u0, native cancel path/signature, LC depth and capsule ID. For ANY qualifying independently authenticated future source history P with U_claim(P)!=u0 (plus separately specified fault and other OR challenges), a watcher must recover the SAME frozen sigma without live notary/issuer. Pure parent work variants of one child are not different outcomes.

Named hypothesis: bootstrap a source-derived second label against fixed known baseline. Candidate hash-only pair:

  L0 = SHA256("baseline" || x_W || u0)
  L1(u) = SHA256("alternate" || x_W || u)
  E(u) = sigma XOR SHA256("pair" || L0 || L1(u)).

Problem to actually test: builder must commit an E BEFORE unknown future u exists, but every valid future u must unlock sigma. If L1 is a public label for a branch bit, fabricated unauthenticated input reveals it. If L1 is builder-sampled secret, actual SHA/AuxPoW evidence does not supply the preimage. If L1 is hash of full future certificate, separate legitimate certificates vary. Replacing u with fixed public baseline normalizes labels but releases without a fork.

The local experiment will model two distinct qualified future pure-child digests and one fabricated digest, verify predicted correctness and early-recovery behavior, and attempt a repair with a public source-derived label. It is a toy fixture; it does not instantiate source authentication. Any conditional verification performed only by honest Open cannot protect the raw key.

Full public target includes all public x_W/C/checking/VK/source commitments, related capsules, auxiliary QPT advice, and retained malicious source coins. The required unanswered equation remains a classical-PPT Build/Open that binds original authenticated evidence INSIDE the cryptographic release, all-witness identical sigma, FALSE/hard-TRUE QPT security and malicious N-of-N setup. Intermediate publication is research provenance, not progress. No ordinary PR comment warranted.
