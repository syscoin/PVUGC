# Hash-only hidden-arithmetic release port: screened before implementation (2026-11-23)

**NONQUALIFYING ORIGINAL-gate research handoff — do not notify, PR-comment, or claim progress.** The attempt does not construct a hash-only witness KEM, an ORIGINAL-source public Build/Open, a QPT proof, or a native signing mechanism. It was rejected at the exact missing operation rather than padding it with a toy benchmark or an unimplemented ideal evaluator.

## Scope and provenance

The read-only continuity source is open/draft/unmerged [syscoin/PVUGC#1](https://github.com/syscoin/PVUGC/pull/1), branch `research/pq-wkem-validation-20260918`, starting head `a3ae55fa3df4c75312c58e35b49850aaf3ba4648`. Read PR metadata and the most recent relevant substantive top-level comments; read the exact-head `research/pq-wkem/r_original_root_index_screen_20261123/RESEARCH.md` (previous root-table screen) and `research/pq-wkem/praxis_review_20261123/RESEARCH.md` (the restricted classical group-based common-key recovery equation). No web, original outside paper, Core code, external network witness, independent agent, code checker, quantum computation, deployment or funding action was used in this iteration. The prior Praxis investigation is not represented as a result proved in this iteration.

**Original operation still required:** classical-PPT `Build_inc(x_W,sigma_cancel)->C` and *public* `Open_inc(C,w)->sigma_cancel` for EVERY authentic and claim-relevant ORIGINAL certificate from the disjunction: strictly greater exact BTC cumulative work from the relevant common anchor; a finite authenticated fault of this withdrawal's burn authorization; or a qualified Syscoin history inconsistency/tag fault at the actual LC depth. The same frozen safe native capability must emerge, regardless of the witness and without a common witness preimage. The full public view includes native message/VK, context, claimed baseline, claim and source binding, auxiliary information, maliciously retained source coins and sibling/related capsules. Invalid synthetic histories must not release the capability even if they satisfy an easy local algebraic equation.

## Candidate selected before implementation: replace encoded group arithmetic with salted SHA commitments

The motivation is the actual common-output *algebraic* identity recorded by the Praxis review, not its disallowed discrete-log, pairing or lattice foundation:

    Lambda_w = xi_w*kappa + r_w*psi_w
    Psi_w    = psi_w
    kappa    = xi_w^(-1) * (Lambda_w - r_w*Psi_w),   xi_w != 0.

Its intended strength is that different qualified witnesses w can have different `xi_w,r_w,psi_w` and still recover the *same* `kappa`, which in turn seals exactly one precommitted cancellation signature. That addresses common-output correctness without forcing the witness strings to converge.

Attempted hash-only replacement (field for symbolic analysis only, not a proposed hard assumption):

    Com_c(v;rho) = SHA256("PVUGC/value" || c || rho || encode(v)).

The builder knows `kappa` and secret blinders, publishes commitments to the hidden arithmetic factors and one fixed signature seal `D=sigma_cancel XOR KDF(kappa,c)`. The witness contributes only the ORIGINAL public source certificate. A hoped-for public evaluator would make the committed `Lambda_w` and `Psi_w` available, preserve the *same* underlying committed `kappa` for all valid w, and reject unauthenticated/fabricated source histories *inside* the key-release computation. Commitment domains include complete claim/native/chain/capsule context.

### Why the closest recorded attack is not merely replayed

R327 recovered raw low-degree additive private-coefficient evaluators from invalid-trace queries. Here all scalars and blinders would remain hidden behind keyed-salt hashes; a public invalid-trace caller has no raw polynomial evaluation oracle. R289's XOR split-mask splice also does not directly combine opaque hash commitments into a target scalar. This changes the earlier attack's accessible algebra. It does **not** establish the new system's correctness or security.

### Exact required new public equation

A functioning candidate must give serialized, classical-PPT algorithms with no retained private issuer:

    (P_w,Q_w) = HashEval(C,w)                  // for ANY authentic ORIGINAL w
    kappa     = HashRecover(C,w,P_w,Q_w)       // scalar, not commitment digest
    sigma     = D XOR KDF(kappa,c)

The scalar `kappa` must be returned for every qualifying ORIGINAL w; calls with fake source certificates must not yield it even if a caller ignores honest-code validation branches. In addition, the public `HashEval` and its output must admit a joint full-public QPT simulator and arbitrary unauthorized recovery/native-forgery reduction without a volunteered query trace or representation.

The only native operations on independent SHA commitments in the proposed encoding are recomputing a hash from a *known opening* and checking a candidate opening. In particular there is no supplied public map

    (Com(a;ra), Com(b;rb), u, v)
       -> (Com(u*a+v*b; r'), an opening sufficient to compute u*a+v*b)

for **hidden** `a,b`. SHA collision resistance/one-wayness alone is not a homomorphic-opening algorithm. Publishing `Lambda_w` and `Psi_w` as raw field elements does not fix the issue: the builder has not constructed them for unknown future w, and any total public arithmetic evaluator then needs a cryptographic restriction binding its readout to authentic ORIGINAL evidence rather than to an algebraic input chosen by the attacker.

A transparent hash/Merkle proof or a SHA-based ZK/STARK proof can verify that *someone with openings* performed the algebra. It does not create those undisclosed openings for a future original witness. Asking the source witness to supply the committed scalar opening changes the relation: ordinary BTC headers/AuxPoW, finite burn refutations and Syscoin LC histories carry no setup-chosen `kappa` opening. Giving the prover a hidden opening/key at challenge time is an online issuer. Letting a public `SourceOpen` provide it merely assumes the missing mechanism. A fixed list of prepared witness-indexed openings reverts to the exponential/all-future-coverage failure screened in the prior exact-head root note.

An elementary correctness sanity check in the ideal hiding-commitment abstraction illustrates the missing information flow. Fix a valid original (x,w) before sampling an honest independent uniform `kappa`; publish only hiding commitments to `kappa`/blinders plus the signature seal under `KDF(kappa,c)`. Absent any extra witness-dependent correlation, the given public w is independent of that honest secret. A public PPT opener cannot reconstruct an independently hidden random `kappa` from a commitment merely because a separate public source-verifier returns true. This is a claim **only for this restricted commitment-only candidate**, not an impossibility claim for all hash-only WE; adding a new source-correlated ciphertext is precisely the absent construction.

## End-to-end adversarial screening

- **Every-original-witness completeness:** not met. `HashEval` cannot form recoverable values for unknown future qualifying BTC/SYS evidence with salted SHA commitments alone.
- **FALSE full public:** commitments are intended to hide values, but no full-public security proof is given; the added seal, CK, native message, source relations, capsule correlations, auxiliary advice and selective opens have not been simulated. Hash preimage/collision claims are not a QROM joint theorem.
- **Unauthorized hard TRUE:** no reduction exists because there is no honest public opener to begin with. A public proof of the source predicate alone does not cryptographically authorize a secret from unrelated hiding commitments.
- **Malicious setup and source:** no enforceable proof of correct, decryptable capsules under one honest N-of-N participant; retaining a private scalar or publishing an opening violates the source-independent setup requirement. A malicious notary may keep its own source coins; that cannot be used to fake a missing release.
- **Native endpoint:** even a future repaired release must be restricted to the exact precommitted safe cancel message/outpoint or an explicit slot-global veto. A witness-id/wtxid attached after signing does not repair common-outpoint portability (R225); ordinary EUF is not a same-message signature-uniqueness theorem.
- **Actual source qualification:** the three OR grounds retain the exact policy, anchor, work, burn, LC depth, ancestry, tag, activation, deadline/reset and relevance requirements. No claim that private PoW alone proves BTC best-chain membership, or that Syscoin requires a higher-work winner, was made.

## Decision / exact reusable handoff

**Reject this hash-commitment translation before implementation.** The mathematical improvement sought was *hidden* nonadditive, globally witness-consistent arithmetic instead of publicly probeable linear labels; this would prevent the specific old splice/probe if a real hidden-evaluation primitive existed. A salted SHA commitment supplies hiding and binding, **not public recoverable hidden arithmetic**. The missing equation is the source-dependent `HashEval/HashRecover` pair above, with a source-correlated ciphertext distribution and a joint QPT simulator. Neither a conventional SHA commitment, an ordinary proof of commitment arithmetic, nor the prior group-based Praxis identity implements it.

Do not repeat this with different hash domains, coefficients, Merkle encodings, longer fixtures or a merely asserted hidden evaluator. A later candidate should first show its full classical-PPT `Build/Open` source-to-capability flow on *the actual ORIGINAL OR relation*, then check R289/R303/R327 attacks and the full-public QPT reduction. No code or testing was appropriate after the pre-implementation screen. No PR conversation checkpoint or user notification is warranted.
