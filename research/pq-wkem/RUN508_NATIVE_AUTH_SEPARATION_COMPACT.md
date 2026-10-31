# Run 508: native authorization is not seed recovery or ORIGINAL extraction

2026-10-14 UTC; syscoin/PVUGC#1; branch research/pq-wkem-validation-20260918; starting head 9ba7756d9ed03e9d7f0694d69f6189e837eabe37. Research-only, no production changes. This is a sharply scoped composition counterexample, NOT a flaw demonstrated in the actual Bitcoin graph, a Run-507 local-mixing break, or a practical witness-KEM.

## Separation

For claim-bound relation x and exact native sighash m_x, distinguish: (1) recovery of hidden common signing seed K_x, from (2) early output of ANY sigma accepted by VerifyNative(VK_x,m_x,sigma) without ORIGINAL evidence. Neither Run 507 ideal false-instance key hiding nor Run 259 extraction from a supplied complete representation z implies the second property. In particular, a native signature is not such a representation.

Consider any hypothetical witness-release capsule with SAME-K correctness. Suppose an otherwise correctly generated N-of-N graph package additionally publishes sigma_x=Sign(SK_x,m_x), where the branch m_x was supposed to require a future ORIGINAL challenge witness. Anyone copies sigma_x. Native verification accepts for that exact branch even when ORIGINAL is false. No witness, seed recovery, cryptanalysis, bad setup randomness, or alternate signature forgery is needed. Correct UTXO/branch domain binding only prevents replay to a DIFFERENT transaction; it cannot reject an already authorized signature for the exact target. One-message auxiliary key-hiding may still hold if independently assumed; we do NOT infer it from EUF-CMA or these tests. Ordinary EUF-CMA does not classify reuse of a publicly issued signature on a previously signed message as forgery.

## Conditional QPT one-wayness theorem

Let F be classical-PPT one-way against nonuniform QPT, and let R(y,w)=[F(w)=y] where y=F(w*) for unknown uniform w*. Suppose Setup(y,SK) is classical PPT and needs no w*. Suppose setup is permitted to publicly pre-sign the branch m(y), independently of w*. If a uniform or fixed-advice QPT extractor could take the honest public setup plus this valid native sigma and return a valid ORIGINAL w with nonnegligible probability for every such signing transcript, a QPT inverter given y would independently run KeyGen, Setup, Sign and then the extractor, recovering an F-preimage. This is a straight-line, no-rewinding, no-QROM reduction; fixed quantum advice must be independent of the challenge y. Therefore such an unrestricted signature-only extractor contradicts the stated OWF assumption. This is not an impossibility for a protocol that excludes those pre-signatures by exact graph design.

## Exact local execution

The committed Python checker uses OpenSSL 3.5.5 with actual SLH-DSA-SHA2-128f, 192f and 256f, signing an immutable synthetic claim-A/challenge message without any source witness. Each signature verifies, and both an altered claim and altered branch fail under the same public verification key. Signature sizes are 17,088, 35,664, 49,856 bytes. 13 explicit assertions passed; two executions were byte-identical and Python syntax check passed. Key material/signature bytes are ephemeral and never printed. This tests API semantics, NOT QPT key hiding, a concrete mixer, or actual Bitcoin sighash/graph safety.

## Attack taxonomy / obligations

Seam, gauge, statistical fingerprints, and nonlinear local mixing are not used. One public signature suffices; multiple graph pre-signatures and related claims require composition analysis. It is an honest-setup attack IF the actual graph design intentionally exposes the exact target signature, not a claim of malicious retained randomness. Public VK confirms the exact signature; distinct bound claim/branch messages reject replay. A classical copy attack is available to QPT attackers, but no new coherent quantum attack is claimed. Run 259 does not apply because no complete accepted representation z is produced.

Audit all actual pre-signed edges, sighashes, script leaves, UTXOs, timelocks, and allowed successor paths before funding; distinguish false-veto griefing from unsafe payouts and from legitimate post-timeout authorization. This note does not allege that an actual public signature crosses the intended graph boundary. Setup-ZK can prove generation rules but cannot remove an intentionally permitted bypass. Honest-erasure N-of-N setup and conditional P2MR/native SLH endpoint remain separate assumptions.

## Core handoff

A compact protected Run-507 terminal, all-witness SAME-seed recovery, false-instance full-view arbitrary-QPT hiding, arbitrary unauthorized true-instance authorization -> complete ORIGINAL representation or independent break, malicious N-of-N setup, multiple-capsule security, and practical 128-bit parameters are still UNPROVED. The next local-mixing candidate must prove source-conditioned *native authorization*, not just hidden-seed confidentiality; its exact public graph pre-signatures belong in the game. No finished WKEM, merge, review, or production modification.
