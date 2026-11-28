# R220 — PROOF-TRANSCRIPT-SEAL: conditional release from a hash-based proof transcript

**Disposition: unsuccessful ORIGINAL-dependent Build/Open attempt, not a witness-KEM, QPT proof, actual ZK system, or deployable Bitcoin/Syscoin evidence verifier. Do not notify or post a routine PR comment.**

## Continuity and provenance

Existing open/draft syscoin/PVUGC PR #1, branch research/pq-wkem-validation-20260918. Observed start commit cea0ceb939f8e21de2968b3218346afd1c9b9e03 (tree b277e525b475e00c2fbb5324dafb6963b8a03cf9). Relevant exact-version reads: R219 RESEARCH blob 6118f42d9498fa1491f1750afb2d7b4cb3f3d7d0; R218 RESEARCH blob f1b6205d0fdca9f4051858075dfdd6bb3ba2ff71; R211 independent-OR composition; R214/R215 source labels and SHA midstate; R208/R212/R213 explicit polynomial residual/factorization/projection failures. Recent ordinary PR comments query since 2026-11-10T14:00Z returned none. An intermediate mathematical hypothesis was locally checkpointed BEFORE running tests and published at commit 8b586704dee5cc0704d2ccf00271c41dcb4cbafc (parent cea0ceb), Git blob 200b277b3aca8515570dc269302ca19bc67c4cad, byte-identical to the local CHECKPOINT_01.md. No web, outside literature, independent agent, actual mining, native signing, current chain validation, ZK system or quantum experiment.

Full standard-library Python checker in this directory was ACTUALLY executed twice, outputs byte-identical. Exact source SHA256 bbb6c427742c78027eaee0184a445435fcd4a51ef2a61af182fb54836b3dea8c; Git blob 4208086446dfed045eba1e9772e4fdc0b675936d. Exact captured output SHA256 7d2606b6322c1ce1b8654710955861c783f25f028c2cc5bb03106b31b5388fa2; Git blob c81fa010b35d10e3feaa1f4767ed4d6aa28761b3. These are source/output identities, NOT proof of cryptographic security. A more detailed local analysis was written, SHA256 e4d2f99e1781c0cad4733109282061dd43d8491932fe463c9b19885fc346e33a; it is not represented as an independently tested/peer-reviewed proof.

## ORIGINAL relation, unchanged

A single notary activates a source-bound withdrawal in an N-of-N preauthorized, no-bypass graph; anyone with one genuine R1 contradictory higher-work BTC history, R2 finite authenticated absent/invalid PoB for the ACTUAL admitted withdrawal, or R3 qualified authenticated Syscoin claim-prefix fork/appropriate tag fault must recover the SAME precommitted claim/UTXO/path-specific cancellation capability OFF CHAIN. That original relation includes actual SHA256d PoW targets, difficulty, Bitcoin anchoring, Syscoin AuxPoW coinbase/ancestor/tag parsing, all relevant interval tags and heights, original burn and recipient, activation witness/wtxid, window/depth/DA, malicious source coins and no online release authority. Different parent work certificates for the SAME child do not constitute a fork. Only a native cancellation authorization reaches Bitcoin; no general verifier, PCP/BitVM disputes or new opcode is assumed. The present mock does NOT implement this original relation, and a QPT game must include the complete public C, x, native VK, CK if any, auxiliary state, sibling capsules and malicious setup.

## Candidate: proof-transcript-sealed pre-signed cancel signature

Let x be the fixed claim/withdrawal statement, sigma be a frozen valid native signature, and Proof(x,w;r) a publicly reproducible, potentially Fiat-Shamir or transparent proof from a genuine ORIGINAL witness w and prover randomness r. Attempt to avoid R219 raw public polynomial evaluation by sealing under the hash of a valid proof transcript:

    Build_A(x,sigma,pi0):
        K0=SHA256(domain,x,pi0)
        D=sigma XOR K0; publish C=(x,D,proof description)
    Open_A(C,w,r):
        pi=Proof(x,w;r)
        return D XOR SHA256(domain,x,pi)

This grants even more than actual setup by letting Build somehow know one valid proof pi0 BEFORE future source evidence exists. Every-witness SAME-sigma correctness requires H(x,pi0)=H(x,pi1) for every valid future pi1; that identity is not implied by soundness, ZK, succinctness, Fiat-Shamir or SHA collision resistance. Valid proofs can differ for distinct witnesses AND for distinct prover randomness on the same witness. A full public proof verifier placed in honest Open does not fix changing pads.

The executable source mock uses typed SHA256 with a synthetic 12-leading-zero-bit work condition on SHA256(anchor,child,nonce) and child != baseline, then a typed transparent transcript child||nonce||salt. This mock is NOT a Bitcoin header, AuxPoW proof, authenticated best-chain membership, ZK proof or QPT experiment. For 32 deterministic contexts it constructed two different synthetically valid children and two transcripts for the same valid child. All 32 designated proofs opened the synthetic signature, while all 32 alternate valid child transcripts and all 32 same-child different-salt transcripts produced DIFFERENT would-be signatures. The checker counted 308 functional assertions in total; none establish a hash-security theorem.

## Repairs attempted and exact failure criteria

**Public canonicalization.** Replace the proof-dependent pad with H(domain,x), or normalize any proof to its statement/acceptance bit. Every valid proof now yields the same output, but a caller computes the same public pad from x and opens before ANY authenticated challenge. The checker confirms 32 normal source openings and 32 fake-proof early openings. Even source-invalid child/nonce is rejected by the mock verifier while raw public decryption succeeds; post-hoc source checking is insufficient.

**Frozen target / proof grinding.** Include a lambda-bit target T fixed at Build and require the witness-holder to grind a free proof nonce r until H(Proof(x,w;r)) truncated to lambda bits equals T. For a fresh independent classical random oracle target and q distinct nonadaptive/adaptive classically queried candidates, success probability is exactly 1-(1-2^-lambda)^q, at most q/2^lambda. For lambda=256 no classical PPT prover can guarantee recovery even when it ALREADY has a valid ORIGINAL witness. The proof-grinding is also an extra independent work task, not original BTC/SYS PoW. A calibration using 12-bit truncated SHA256, q<=4096, 20 deterministic samples observed 16 successes, whereas ideal-model success probability is 0.632165; the discrepancy is a small finite sample, not evidence against the formula, and does not justify a QROM theorem. Arbitrary coherent quantum queries require a separate actual QROM analysis, not a classical label.

**Unique proof with setup simulation.** Suppose all valid ORIGINAL witnesses can produce EXACTLY ONE proof pi*(x) and an N-of-N setup simulator can compute that same pi*(x) without a witness before activation. Then a builder could compute H(pi*) and seal sigma, but ordinary transparent hash-based proofs do NOT implement this two-sided exact byte equality. Worse, positing a hidden common pi* known to Build and publicly derivable from all ORIGINAL witnesses already posits the source-dependent common-secret-release primitive itself; naming it a unique-proof simulator does not instantiate the missing leaf or an independent reduction. The simulator trapdoor's retention by a malicious setup/source also exposes the capability early. No such trapdoor, protocol or QPT simulator was built. A proof public to all before the event defeats secrecy.

**Adding secret K to proof's relation.** A legitimate source challenger does not know the setup secret K; requiring K breaks completeness. Publishing K leaks the signature. Hash-committing K only proves consistency if it is later opened by somebody, which reintroduces an issuer. A different proof or source certificate produces a different hash; there is no common hidden source token already in ordinary SHA/AuxPoW evidence.

## Exact conclusion / next missing equation

Proof verification, ZK, proof uniqueness as a title, and a shared public challenge do not themselves provide cryptographically conditional common-capability release. This is a restricted-class algebraic obstruction, NOT a theorem that general hash-only WE is impossible or that a particular deployed proof is insecure. The actual necessary algorithm is still missing:

    Build_hash(R_original,x_W,sigma_cancel;coins) -> public capsule C
    Open_hash(C,w) = EXACT SAME frozen sigma_cancel
      for EVERY qualifying genuine R1/R2/R3 source witness w,
    arbitrary full-public QPT unauthorized recovery/native forgery
      -> actual ORIGINAL certificate or independently justified PQ hash/native break.

Any proposed nonfactorized hash/SHA/AuxPoW encoding must be given together with its joint simulator and a malicious setup/source/auxiliary/multi-capsule security analysis; no online authority, independent hash puzzle, lattice, public zero-residual value or generic NP prerequisite substitutes. This negative pass does not warrant an ordinary PR comment or user-level progress report. Keep the research task enabled.
